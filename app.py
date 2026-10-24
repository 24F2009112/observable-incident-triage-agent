"""Observable Incident Triage Agent.

A deterministic, policy-gated incident triage API with SQLite-backed audit state.
No LLM/API key is required. The action executor records an auditable operational
result; wire an approved operations control plane before using it against real
production infrastructure.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

APP_NAME = "Observable Incident Triage Agent"
APP_VERSION = "1.0.0"
DATABASE_PATH = os.getenv("DATABASE_PATH", os.path.join(os.getcwd(), "incident_agent.sqlite3"))
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")

app = FastAPI(
    title=APP_NAME,
    description=(
        "Diagnoses incidents from supplied observations, runs narrowly scoped read-only "
        "diagnostics, applies policy gates before an action, and persists action results "
        "with linked telemetry for audit and replay."
    ),
    version=APP_VERSION,
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE_PATH, timeout=20, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=20000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    parent = os.path.dirname(os.path.abspath(DATABASE_PATH))
    os.makedirs(parent, exist_ok=True)
    with db_connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS checks (
                check_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                request_json TEXT NOT NULL,
                diagnosis_json TEXT NOT NULL,
                diagnostics_json TEXT NOT NULL,
                decision_json TEXT NOT NULL,
                action_result_id TEXT,
                response_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS action_results (
                action_result_id TEXT PRIMARY KEY,
                check_id TEXT NOT NULL,
                incident_id TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                success INTEGER NOT NULL,
                result_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(check_id) REFERENCES checks(check_id)
            );
            CREATE TABLE IF NOT EXISTS telemetry (
                telemetry_id TEXT PRIMARY KEY,
                check_id TEXT NOT NULL,
                incident_id TEXT NOT NULL,
                action_result_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                created_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                FOREIGN KEY(check_id) REFERENCES checks(check_id),
                FOREIGN KEY(action_result_id) REFERENCES action_results(action_result_id)
            );
            CREATE INDEX IF NOT EXISTS idx_checks_incident ON checks(incident_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_telemetry_check ON telemetry(check_id, created_at);
            CREATE TABLE IF NOT EXISTS save_history (
                save_id TEXT PRIMARY KEY,
                check_id TEXT NOT NULL,
                saved_at TEXT NOT NULL,
                snapshot_hash TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                FOREIGN KEY(check_id) REFERENCES checks(check_id)
            );
            CREATE TABLE IF NOT EXISTS latest_save (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                save_id TEXT NOT NULL,
                check_id TEXT NOT NULL,
                saved_at TEXT NOT NULL,
                snapshot_hash TEXT NOT NULL,
                snapshot_json TEXT NOT NULL
            );
            """
        )


@app.on_event("startup")
def startup() -> None:
    init_db()


# ---------- Input normalization / evidence extraction ----------
def norm_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value).lower()).strip("_")


def truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "y", "1", "reached", "enabled", "healthy"}
    return False


def flatten(obj: Any, prefix: str = "") -> List[Tuple[str, Any, str]]:
    """Return (normalized key, value, dotted path) triples from nested request data."""
    found: List[Tuple[str, Any, str]] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            found.append((norm_key(key), value, path))
            if isinstance(value, (dict, list)):
                found.extend(flatten(value, path))
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            path = f"{prefix}[{i}]"
            if isinstance(value, (dict, list)):
                found.extend(flatten(value, path))
            else:
                found.append(("item", value, path))
    return found


def get_values(obj: Any, aliases: Iterable[str]) -> List[Tuple[Any, str]]:
    wanted = {norm_key(alias) for alias in aliases}
    return [(value, path) for key, value, path in flatten(obj) if key in wanted]


def first_value(obj: Any, aliases: Iterable[str], default: Any = None) -> Any:
    items = get_values(obj, aliases)
    return items[0][0] if items else default


def first_number(obj: Any, aliases: Iterable[str]) -> Optional[float]:
    for value, _ in get_values(obj, aliases):
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            match = re.search(r"-?\d+(?:\.\d+)?", value.replace(",", ""))
            if match:
                try:
                    return float(match.group(0))
                except ValueError:
                    pass
    return None


def first_bool(obj: Any, aliases: Iterable[str]) -> Optional[bool]:
    for value, _ in get_values(obj, aliases):
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        if isinstance(value, str):
            lower = value.strip().lower()
            if lower in {"true", "yes", "y", "1", "reached", "enabled"}:
                return True
            if lower in {"false", "no", "n", "0", "not_reached", "disabled"}:
                return False
    return None


def collect_text(obj: Any) -> str:
    pieces: List[str] = []
    for key, value, path in flatten(obj):
        if isinstance(value, (str, int, float, bool)):
            pieces.append(f"{key} {value} {path}")
    return " ".join(pieces).lower()


def unwrap_incident(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {"description": str(payload)}
    # Most APIs send an incident under one of these envelope keys.
    for key in ("incident", "input", "payload", "data", "incident_data", "context"):
        value = payload.get(key)
        if isinstance(value, dict):
            merged = dict(value)
            for outer_key, outer_value in payload.items():
                if outer_key not in {key, "message", "jsonrpc", "id", "method", "params"} and outer_key not in merged:
                    merged[outer_key] = outer_value
            return merged
    params = payload.get("params")
    if isinstance(params, dict):
        for key in ("incident", "input", "payload", "data"):
            if isinstance(params.get(key), dict):
                return params[key]
        return params
    return payload


def make_incident_id(incident: Dict[str, Any]) -> str:
    candidate = first_value(incident, ("incident_id", "id", "event_id", "alert_id", "ticket_id"))
    return str(candidate).strip() if candidate is not None and str(candidate).strip() else f"inc-{uuid.uuid4().hex[:12]}"


# ---------- Diagnostics and diagnosis ----------
def determine_capacity_limit(data: Dict[str, Any]) -> Tuple[bool, List[str]]:
    evidence: List[str] = []
    aliases = (
        "at_scaling_limit", "scaling_limit_reached", "max_replicas_reached",
        "at_max_capacity", "capacity_limit_reached", "autoscaling_at_limit",
        "at_max_replicas", "scaling_saturated", "maximum_capacity_reached",
    )
    for value, path in get_values(data, aliases):
        if truthy(value):
            evidence.append(f"{path}={value}")
    current = first_number(data, ("current_replicas", "replicas", "instance_count", "current_instances", "desired_replicas", "running_instances"))
    maximum = first_number(data, ("max_replicas", "maximum_replicas", "max_instances", "instance_limit", "scaling_limit", "capacity_limit"))
    if current is not None and maximum is not None and maximum >= 0 and current >= maximum:
        evidence.append(f"current capacity {current:g} is at or above configured maximum {maximum:g}")
    remaining = first_number(data, ("remaining_capacity", "scale_capacity_remaining", "available_replica_slots", "remaining_replicas"))
    if remaining is not None and remaining <= 0:
        evidence.append(f"remaining scaling capacity is {remaining:g}")
    return bool(evidence), evidence


def is_disallowed(data: Dict[str, Any], aliases: Iterable[str]) -> bool:
    return first_bool(data, aliases) is False


def explicit_allowed_actions(data: Dict[str, Any]) -> Optional[set[str]]:
    raw = first_value(data, ("permitted_actions", "allowed_actions", "approved_actions", "allowed_responses", "permitted_responses"))
    if raw is None:
        return None
    if isinstance(raw, str):
        values = re.split(r"[,;|]", raw)
    elif isinstance(raw, list):
        values = raw
    else:
        return None
    aliases = {
        "scale": "scale_out", "scale_up": "scale_out", "scaleout": "scale_out", "scale_out": "scale_out",
        "page": "page_owner", "page_oncall": "page_owner", "notify_owner": "page_owner", "page_owner": "page_owner",
        "roll_back": "rollback", "roll_back_deployment": "rollback", "rollback_deployment": "rollback", "rollback": "rollback",
        "fail_over": "failover", "failover": "failover", "no_op": "no_action", "observe": "no_action", "no_action": "no_action",
    }
    allowed = set()
    for item in values:
        key = norm_key(item)
        allowed.add(aliases.get(key, key))
    return allowed


def choose_cause(data: Dict[str, Any]) -> Tuple[str, str, float, List[str], str]:
    flat = flatten(data)
    text = collect_text(data)
    cap_reached, cap_evidence = determine_capacity_limit(data)
    evidence: List[str] = []
    severity = str(first_value(data, ("severity", "priority", "urgency"), "medium")).lower()

    # Explicit signal fields are evidence, not authoritative policy overrides.
    cpu = first_number(data, ("cpu_percent", "cpu_usage_percent", "cpu_utilization", "cpu", "processor_usage"))
    memory = first_number(data, ("memory_percent", "memory_usage_percent", "memory_utilization", "memory_usage"))
    disk = first_number(data, ("disk_percent", "disk_usage_percent", "disk_utilization", "disk_usage"))
    error_rate = first_number(data, ("error_rate_percent", "http_5xx_percent", "5xx_rate_percent", "error_percent"))
    latency = first_number(data, ("p95_latency_ms", "p99_latency_ms", "latency_ms", "response_time_ms"))
    queue = first_number(data, ("queue_depth", "backlog", "pending_jobs", "queue_length"))
    db_connections = first_number(data, ("db_connection_usage_percent", "database_connection_usage_percent", "connection_pool_percent"))
    db_latency = first_number(data, ("db_latency_ms", "database_latency_ms", "query_latency_ms"))

    if cap_reached:
        evidence.extend(cap_evidence)
        if cpu is not None:
            evidence.append(f"CPU utilization is {cpu:g}%" if cpu <= 100 else f"CPU metric is {cpu:g}")
        if latency is not None:
            evidence.append(f"observed request latency is {latency:g} ms")
        if error_rate is not None:
            evidence.append(f"observed error rate is {error_rate:g}%")
        return (
            "capacity_limit_reached",
            "The service is at its configured scaling limit; additional scaling is not permitted. The owner must be paged rather than scaling beyond the limit.",
            0.98,
            evidence,
            "critical" if severity in {"critical", "sev0", "sev1", "p0", "p1"} else "high",
        )

    deployment_bad = any(term in text for term in ("bad_deploy", "failed_deploy", "deployment_regression", "recent_release_caused", "config_regression", "bad_configuration", "rollback_candidate"))
    deployment_status = str(first_value(data, ("deployment_status", "release_status", "deploy_status"), "")).lower()
    rollback_hint = truthy(first_value(data, ("rollback_candidate", "rollback_recommended", "regression_after_deploy"), False))
    if deployment_bad or deployment_status in {"failed", "degraded", "regression", "bad"} or rollback_hint:
        evidence.append("recent deployment/configuration regression is indicated by the incident payload")
        if deployment_status:
            evidence.append(f"deployment status is {deployment_status}")
        return "deployment_regression", "A recent deployment or configuration change is the strongest evidenced cause.", 0.91, evidence, "high"

    if any(term in text for term in ("database unavailable", "database_unavailable", "db_unavailable", "connection pool exhausted", "connection_pool_exhausted", "too many connections", "database timeout", "db timeout", "query timeout")) or (db_connections is not None and db_connections >= 95) or (db_latency is not None and db_latency >= 1000):
        evidence.append("database availability, connection-pool, or query-latency signal detected")
        if db_connections is not None:
            evidence.append(f"database connection-pool utilization is {db_connections:g}%")
        if db_latency is not None:
            evidence.append(f"database latency is {db_latency:g} ms")
        return "database_saturation_or_failure", "Database saturation or unavailability is indicated; scaling application replicas could amplify load, so avoid doing so without evidence that it helps.", 0.88, evidence, "high"

    if any(term in text for term in ("dependency unavailable", "dependency_unavailable", "upstream unavailable", "upstream_failure", "third_party outage", "dependency timeout", "upstream timeout")):
        evidence.append("an upstream/dependency availability or timeout signal is present")
        return "dependency_failure", "An upstream dependency appears unavailable or too slow.", 0.87, evidence, "high"

    if disk is not None and disk >= 90 or any(term in text for term in ("disk full", "disk_full", "no space left", "filesystem full")):
        if disk is not None:
            evidence.append(f"disk utilization is {disk:g}%")
        evidence.append("disk-pressure signal detected")
        return "disk_pressure", "Disk capacity is exhausted or close to exhaustion. Deleting files automatically is unsafe without a retention policy.", 0.9, evidence, "high"

    if memory is not None and memory >= 90 or any(term in text for term in ("out of memory", "oom killed", "memory pressure", "memory exhausted")):
        if memory is not None:
            evidence.append(f"memory utilization is {memory:g}%")
        evidence.append("memory-pressure signal detected")
        return "memory_saturation", "Memory pressure is the strongest evidenced resource constraint.", 0.87, evidence, "high"

    if queue is not None and queue >= 100 or any(term in text for term in ("queue backlog", "queue_backlog", "worker backlog", "jobs are backing up")):
        if queue is not None:
            evidence.append(f"queue/backlog depth is {queue:g}")
        evidence.append("work queue is accumulating pending work")
        return "queue_backlog", "The work queue is accumulating pending work; worker capacity or a downstream dependency may be constrained.", 0.82, evidence, "high"

    if cpu is not None and cpu >= 85 or any(term in text for term in ("cpu saturation", "cpu_saturated", "high cpu", "cpu overload", "cpu pressure")):
        if cpu is not None:
            evidence.append(f"CPU utilization is {cpu:g}%")
        evidence.append("CPU-saturation signal detected")
        return "cpu_saturation", "CPU saturation is the strongest evidenced cause of service degradation.", 0.88, evidence, "high"

    if error_rate is not None and error_rate >= 5 or any(term in text for term in ("http 500", "http 502", "http 503", "http 504", "5xx spike", "elevated 5xx", "increased 5xx", "internal server error")):
        if error_rate is not None:
            evidence.append(f"HTTP error rate is {error_rate:g}%")
        evidence.append("elevated server-error signal detected")
        return "server_error_rate_elevated", "The service is returning elevated server errors, but the supplied evidence does not isolate a more specific cause.", 0.72, evidence, "high"

    if latency is not None and latency >= 1000 or any(term in text for term in ("high latency", "latency spike", "slow response", "p95 regression")):
        if latency is not None:
            evidence.append(f"request latency is {latency:g} ms")
        evidence.append("latency-degradation signal detected")
        return "latency_regression", "Elevated latency is observed, but a causal resource or dependency signal is not yet conclusive.", 0.68, evidence, "medium"

    status = str(first_value(data, ("status", "health", "service_status", "probe_status"), "")).lower()
    if status in {"down", "unhealthy", "failed", "critical"} or any(term in text for term in ("service down", "health check failed", "unhealthy service", "incident triggered")):
        evidence.append(f"service health/status signal is {status or 'unhealthy'}")
        return "service_health_failure", "The service health signal is failing, but the supplied data does not yet establish a specific root cause.", 0.65, evidence, "high"

    evidence.append("No high-confidence causal metric or failure signature was found in the supplied observations.")
    return "insufficient_evidence", "There is not enough evidence to safely attribute the incident to a specific cause.", 0.35, evidence, "medium"


def run_minimal_diagnostics(data: Dict[str, Any], cause: str, evidence: List[str]) -> List[Dict[str, Any]]:
    """Represent focused read-only diagnostics against the submitted observations."""
    requested = []
    # Keep diagnostics narrowly coupled to the diagnosis instead of spraying probes.
    if cause == "capacity_limit_reached":
        requested = ["scaling_capacity", "service_metrics"]
    elif cause == "deployment_regression":
        requested = ["recent_deployments", "service_health"]
    elif cause == "database_saturation_or_failure":
        requested = ["database_health", "connection_pool"]
    elif cause == "dependency_failure":
        requested = ["dependency_health", "service_health"]
    elif cause == "disk_pressure":
        requested = ["disk_metrics"]
    elif cause == "memory_saturation":
        requested = ["memory_metrics", "service_health"]
    elif cause == "queue_backlog":
        requested = ["queue_metrics", "worker_health"]
    elif cause == "cpu_saturation":
        requested = ["cpu_metrics", "scaling_capacity"]
    elif cause in {"server_error_rate_elevated", "latency_regression", "service_health_failure"}:
        requested = ["service_health", "recent_logs"]
    else:
        requested = ["service_health", "key_metrics"]

    supplied_text = collect_text(data)
    out: List[Dict[str, Any]] = []
    for name in requested:
        # The diagnostic observation is tied to the exact request evidence and is marked
        # missing rather than inventing a metric when the caller supplied no such signal.
        matching = {
            "scaling_capacity": ("scaling", "replica", "instance", "capacity", "max_replicas", "max_instances"),
            "service_metrics": ("cpu", "memory", "latency", "error_rate", "5xx", "request_rate"),
            "recent_deployments": ("deployment", "deploy", "release", "rollback", "commit"),
            "service_health": ("health", "status", "probe", "up", "down", "unhealthy"),
            "database_health": ("database", "db_", "sql", "query", "connection"),
            "connection_pool": ("connection", "pool", "database", "db_"),
            "dependency_health": ("dependency", "upstream", "third_party", "external_service"),
            "disk_metrics": ("disk", "filesystem", "storage", "space"),
            "memory_metrics": ("memory", "oom", "ram"),
            "queue_metrics": ("queue", "backlog", "pending_jobs", "worker"),
            "worker_health": ("worker", "queue", "job", "backlog"),
            "cpu_metrics": ("cpu", "processor", "load"),
            "recent_logs": ("log", "exception", "trace", "error", "stack"),
            "key_metrics": ("metric", "latency", "error", "cpu", "memory", "status"),
        }.get(name, (name,))
        hit = any(token in supplied_text for token in matching)
        out.append({
            "name": name,
            "kind": "read_only",
            "status": "observed" if hit else "not_provided",
            "source": "submitted_incident_observations",
            "evidence": [item for item in evidence if any(token in item.lower() for token in matching)][:3],
        })
    return out


def action_permitted(action: str, data: Dict[str, Any], cap_reached: bool) -> Tuple[bool, str]:
    allowed = explicit_allowed_actions(data)
    if allowed is not None and action not in allowed:
        return False, f"The request's explicit permitted_actions policy does not include '{action}'."
    if action == "scale_out":
        if cap_reached:
            return False, "Scaling is forbidden because the service is already at its configured capacity limit."
        if is_disallowed(data, ("scaling_permitted", "scale_permitted", "autoscaling_allowed")):
            return False, "Scaling is explicitly disabled by the incident policy."
        if first_bool(data, ("scaling_permitted", "scale_permitted", "autoscaling_allowed")) is None:
            # Allowed only when the payload doesn't deny it and capacity headroom is established.
            current = first_number(data, ("current_replicas", "replicas", "instance_count", "current_instances"))
            maximum = first_number(data, ("max_replicas", "maximum_replicas", "max_instances", "instance_limit"))
            if current is not None and maximum is not None and current >= maximum:
                return False, "No confirmed scaling headroom is available."
    if action == "rollback":
        if is_disallowed(data, ("rollback_permitted", "rollback_allowed", "rollback_safe")):
            return False, "Rollback is explicitly disallowed or marked unsafe."
        if first_bool(data, ("rollback_permitted", "rollback_allowed", "rollback_safe")) is not True and first_bool(data, ("rollback_candidate", "rollback_recommended", "regression_after_deploy")) is not True:
            return False, "Rollback requires a confirmed safe rollback permission or candidate."
    if action == "failover":
        if is_disallowed(data, ("failover_permitted", "failover_allowed")):
            return False, "Failover is explicitly disallowed."
        if first_bool(data, ("healthy_failover_target", "failover_target_healthy", "standby_healthy")) is not True:
            return False, "No healthy failover target was confirmed."
    return True, "Action is permitted by the available evidence and policy gates."


def choose_action(data: Dict[str, Any], cause: str, severity: str) -> Tuple[str, str, bool]:
    cap_reached, _ = determine_capacity_limit(data)
    candidates: List[Tuple[str, str]] = []
    if cap_reached:
        candidates = [("page_owner", "Capacity is already at the permitted limit; page the owner instead of scaling.")]
    elif cause == "deployment_regression":
        candidates = [("rollback", "A recent deployment/configuration regression is indicated; rollback is considered only with explicit safe permission.") , ("page_owner", "Rollback was not confirmed as safe/permitted, so escalate to the owner.")]
    elif cause == "dependency_failure":
        candidates = [("failover", "A healthy failover target is used only when explicitly confirmed and permitted."), ("page_owner", "No confirmed safe failover path; page the owner.")]
    elif cause == "cpu_saturation":
        candidates = [("scale_out", "CPU saturation may be relieved by scaling only when capacity headroom and policy permit it."), ("page_owner", "Scaling is not permitted or there is no confirmed headroom; page the owner.")]
    elif cause in {"database_saturation_or_failure", "disk_pressure", "memory_saturation", "queue_backlog", "server_error_rate_elevated", "latency_regression", "service_health_failure"}:
        candidates = [("page_owner", "The evidence does not justify an automated disruptive change; notify the responsible owner.")]
    else:
        # Unknown cause: safe escalation beats speculative remediation.
        candidates = [("page_owner", "Root cause is uncertain; page the owner instead of taking a speculative action."), ("no_action", "No response was permitted by policy.")]

    rejected: List[str] = []
    for action, reason in candidates:
        permitted, gate_reason = action_permitted(action, data, cap_reached)
        if permitted:
            return action, reason, True
        rejected.append(f"{action}: {gate_reason}")
    # If explicit policy forbids page_owner as well, record a no-op rather than bypass policy.
    return "no_action", "No remediation action passed the policy gate. " + " ".join(rejected), True


# ---------- Action execution, persistence, and linked telemetry ----------
def execute_action(action: str, incident: Dict[str, Any], check_id: str, incident_id: str, cause: str, evidence: List[str]) -> Dict[str, Any]:
    """Run an auditable local operation; no unmanaged infrastructure mutation occurs here."""
    action_result_id = f"act-{uuid.uuid4().hex}"
    created_at = utc_now()
    target = str(first_value(incident, ("service", "service_name", "service_id", "target"), "unknown-service"))

    if action == "page_owner":
        status = "completed"
        message = f"Owner escalation event recorded for {target}; connect an approved paging adapter to deliver an external page."
        success = True
        result = {"operation": "page_owner", "target_service": target, "notification_recorded": True, "external_delivery": False, "message": message}
    elif action == "scale_out":
        current = first_number(incident, ("current_replicas", "replicas", "instance_count", "current_instances"))
        maximum = first_number(incident, ("max_replicas", "maximum_replicas", "max_instances", "instance_limit"))
        if determine_capacity_limit(incident)[0] or (current is not None and maximum is not None and current >= maximum):
            status, success = "blocked", False
            result = {"operation": "scale_out", "blocked": True, "reason": "scaling limit reached; never scale beyond permitted capacity"}
        else:
            status, success = "accepted", True
            result = {"operation": "scale_out", "request_recorded": True, "current_replicas_observed": current, "max_replicas_observed": maximum, "external_infrastructure_changed": False, "message": "Scale request was recorded by the local executor; an approved infrastructure adapter is required to change production capacity."}
    elif action == "rollback":
        status, success = "accepted", True
        result = {"operation": "rollback", "request_recorded": True, "external_deployment_changed": False, "message": "Rollback request was recorded; an approved deployment adapter is required to perform the rollback."}
    elif action == "failover":
        status, success = "accepted", True
        result = {"operation": "failover", "request_recorded": True, "external_routing_changed": False, "message": "Failover request was recorded; an approved routing adapter is required to change production traffic."}
    else:
        status, success = "completed", True
        result = {"operation": "no_action", "change_made": False, "message": "No remediation action was executed because no safe permitted action was available."}

    return {
        "action_result_id": action_result_id,
        "check_id": check_id,
        "incident_id": incident_id,
        "action": action,
        "status": status,
        "success": success,
        "observed": True,
        "created_at": created_at,
        "result": result,
    }


def telemetry_for(action_result: Dict[str, Any], cause: str, diagnostics: List[Dict[str, Any]], decision_reason: str) -> Dict[str, Any]:
    payload = {
        "event": "incident_action_observed",
        "incident_id": action_result["incident_id"],
        "check_id": action_result["check_id"],
        "action_result_id": action_result["action_result_id"],
        "action": action_result["action"],
        "action_status": action_result["status"],
        "action_success": action_result["success"],
        "diagnosis_cause": cause,
        "diagnostic_count": len(diagnostics),
        "decision_reason": decision_reason,
        "observed_at": action_result["created_at"],
    }
    canonical = json_dumps(payload)
    return {
        "telemetry_id": f"tel-{uuid.uuid4().hex}",
        "check_id": action_result["check_id"],
        "incident_id": action_result["incident_id"],
        "action_result_id": action_result["action_result_id"],
        "event_type": "incident_action_observed",
        "created_at": action_result["created_at"],
        "payload": payload,
        "payload_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    }


def persist_check(check_id: str, incident_id: str, request_payload: Dict[str, Any], diagnosis: Dict[str, Any], diagnostics: List[Dict[str, Any]], decision: Dict[str, Any], action_result: Dict[str, Any], telemetry: Dict[str, Any], response: Dict[str, Any]) -> None:
    with db_connect() as conn:
        conn.execute(
            "INSERT INTO checks(check_id,incident_id,created_at,request_json,diagnosis_json,diagnostics_json,decision_json,action_result_id,response_json) VALUES(?,?,?,?,?,?,?,?,?)",
            (check_id, incident_id, response["created_at"], json_dumps(request_payload), json_dumps(diagnosis), json_dumps(diagnostics), json_dumps(decision), action_result["action_result_id"], json_dumps(response)),
        )
        conn.execute(
            "INSERT INTO action_results(action_result_id,check_id,incident_id,action,status,success,result_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (action_result["action_result_id"], check_id, incident_id, action_result["action"], action_result["status"], 1 if action_result["success"] else 0, json_dumps(action_result), action_result["created_at"]),
        )
        conn.execute(
            "INSERT INTO telemetry(telemetry_id,check_id,incident_id,action_result_id,event_type,created_at,payload_json) VALUES(?,?,?,?,?,?,?)",
            (telemetry["telemetry_id"], check_id, incident_id, telemetry["action_result_id"], telemetry["event_type"], telemetry["created_at"], json_dumps(telemetry)),
        )


def build_check(payload: Any) -> Dict[str, Any]:
    request_payload = payload if isinstance(payload, dict) else {"input": payload}
    incident = unwrap_incident(request_payload)
    incident_id = make_incident_id(incident)
    check_id = f"chk-{uuid.uuid4().hex}"
    created_at = utc_now()

    cause, summary, confidence, evidence, severity = choose_cause(incident)
    diagnostics = run_minimal_diagnostics(incident, cause, evidence)
    action, decision_reason, permitted = choose_action(incident, cause, severity)
    cap_reached, cap_evidence = determine_capacity_limit(incident)
    # A hard guard remains in the executor as defense in depth, even if caller data is inconsistent.
    if cap_reached and action == "scale_out":
        action = "page_owner"
        decision_reason = "Hard policy guard: capacity is at its limit, so page the owner instead of scaling."
    diagnosis = {
        "cause": cause,
        "summary": summary,
        "confidence": confidence,
        "severity": severity,
        "evidence": evidence,
    }
    decision = {
        "action": action,
        "permitted": permitted,
        "requires_human_approval": action in {"rollback", "failover", "scale_out"},
        "reason": decision_reason,
        "policy_checks": {
            "scaling_limit_reached": cap_reached,
            "scaling_blocked_at_limit": bool(cap_reached),
            "explicit_action_allowlist_present": explicit_allowed_actions(incident) is not None,
        },
    }
    action_result = execute_action(action, incident, check_id, incident_id, cause, evidence)
    telemetry = telemetry_for(action_result, cause, diagnostics, decision_reason)
    response = {
        "ok": True,
        "status": "completed",
        "agent": APP_NAME,
        "check_id": check_id,
        "incident_id": incident_id,
        "created_at": created_at,
        "diagnosis": diagnosis,
        "diagnostics_run": diagnostics,
        "decision": decision,
        "action_result": action_result,
        "telemetry": telemetry,
        "audit": {
            "persisted": True,
            "action_result_id": action_result["action_result_id"],
            "telemetry_id": telemetry["telemetry_id"],
            "action_telemetry_match": action_result["action_result_id"] == telemetry["action_result_id"],
        },
    }
    persist_check(check_id, incident_id, request_payload, diagnosis, diagnostics, decision, action_result, telemetry, response)
    return response


# ---------- HTTP contract ----------
@app.get("/")
def root() -> Dict[str, Any]:
    return {
        "name": APP_NAME,
        "version": APP_VERSION,
        "status": "ok",
        "health": "/health",
        "agent_card": "/.well-known/agent-card.json",
        "check": "/check",
        "save": "/save",
        "replay": "/replay",
        "v2_incidents": "/v2/incidents",
        "v2_health": "/v2/health",
        "v2_telemetry": "/v2/telemetry",
        "docs": "/docs",
    }


@app.get("/health")
@app.get("/healthz")
def health() -> Dict[str, Any]:
    try:
        with db_connect() as conn:
            conn.execute("SELECT 1").fetchone()
        db_status = "ok"
    except Exception as exc:  # health endpoint should expose the cause without secrets
        db_status = f"error: {type(exc).__name__}"
    return {"ok": db_status == "ok", "status": "healthy" if db_status == "ok" else "degraded", "service": APP_NAME, "version": APP_VERSION, "database": db_status, "timestamp": utc_now()}


def agent_card(request: Optional[Request] = None) -> Dict[str, Any]:
    if PUBLIC_BASE_URL:
        base = PUBLIC_BASE_URL
    elif request is not None:
        proto = request.headers.get("x-forwarded-proto", request.url.scheme).split(",")[0].strip()
        host = request.headers.get("x-forwarded-host", request.headers.get("host", request.url.netloc)).split(",")[0].strip()
        base = f"{proto}://{host}"
    else:
        base = "http://localhost:8000"
    return {
        "name": APP_NAME,
        "description": "Diagnose observable incidents before acting, run only relevant read-only diagnostics, choose policy-permitted responses, and persist action results linked to telemetry.",
        "url": base,
        "version": APP_VERSION,
        "protocolVersion": "0.3.0",
        "preferredTransport": "JSONRPC",
        "capabilities": {"streaming": False, "pushNotifications": False, "stateTransitionHistory": True},
        "defaultInputModes": ["application/json", "text/plain"],
        "defaultOutputModes": ["application/json", "text/plain"],
        "skills": [
            {"id": "incident-triage", "name": "Observable incident triage", "description": "Diagnose incident evidence, run relevant read-only checks, and select a permitted response.", "tags": ["incident", "observability", "diagnostics", "safe-remediation"], "examples": ["Triage a service with high CPU and scaling headroom", "At the scaling limit, page the owner rather than scaling", "Save action results and matching telemetry"]},
            {"id": "audit-replay", "name": "Audit and replay", "description": "Persist action results and matching telemetry and replay the latest saved result without repeating an action.", "tags": ["audit", "telemetry", "replay"]},
        ],
        "endpoints": {"health": "/health", "check": "/check", "save": "/save", "replay": "/replay", "state": "/state", "telemetry": "/telemetry", "v2_incidents": "/v2/incidents", "v2_telemetry": "/v2/telemetry"},
    }


@app.get("/.well-known/agent-card.json")
def well_known_agent_card(request: Request) -> Dict[str, Any]:
    return agent_card(request)


@app.get("/.well-known/agent.json")
def well_known_agent_json(request: Request) -> Dict[str, Any]:
    card = agent_card(request)
    # Keep the legacy card compatible with simple agent-card consumers.
    card["capabilities"] = {"diagnostics": True, "triage": True, "audit": True, "replay": True}
    return card


@app.post("/check")
@app.post("/api/check")
@app.post("/triage")
@app.post("/incident/check")
@app.post("/api/incident/check")
@app.post("/v1/incidents/check")
@app.post("/api/v1/incidents/check")
async def check_endpoint(request: Request) -> Dict[str, Any]:
    try:
        payload = await request.json()
    except Exception:
        payload = {"description": (await request.body()).decode("utf-8", "replace")}
    try:
        return build_check(payload)
    except Exception as exc:
        # Do not expose input data or stack traces in public error responses.
        raise HTTPException(status_code=500, detail=f"Incident check failed: {type(exc).__name__}") from exc


def fetch_check(check_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    with db_connect() as conn:
        if check_id:
            row = conn.execute("SELECT response_json FROM checks WHERE check_id=?", (check_id,)).fetchone()
        else:
            row = conn.execute("SELECT response_json FROM checks ORDER BY created_at DESC LIMIT 1").fetchone()
    return json.loads(row["response_json"]) if row else None


def save_check(payload: Dict[str, Any]) -> Dict[str, Any]:
    check_id = payload.get("check_id") or payload.get("checkId")
    if not check_id:
        # If Save is called directly, create an assessment from the submitted incident.
        existing = fetch_check()
        if existing is None:
            result = build_check(payload)
        else:
            result = existing
    else:
        result = fetch_check(str(check_id))
        if result is None:
            raise HTTPException(status_code=404, detail="check_id was not found; run Check first or submit a valid check_id")
    # A supplied check_id always wins over the latest record; no fabricated action/telemetry is accepted.
    check_id = result["check_id"]
    action_result = result["action_result"]
    telemetry = result["telemetry"]
    if action_result.get("action_result_id") != telemetry.get("action_result_id") or telemetry.get("check_id") != check_id:
        raise HTTPException(status_code=409, detail="Action result and telemetry do not match; refusing to save inconsistent audit state")

    saved_at = utc_now()
    snapshot = {
        "ok": True,
        "saved": True,
        "save_id": f"save-{uuid.uuid4().hex}",
        "check_id": check_id,
        "incident_id": result["incident_id"],
        "saved_at": saved_at,
        "diagnosis": result["diagnosis"],
        "decision": result["decision"],
        "action_result": action_result,
        "telemetry": telemetry,
        "audit": {
            "action_result_id": action_result["action_result_id"],
            "telemetry_action_result_id": telemetry["action_result_id"],
            "matching_action_result_and_telemetry": action_result["action_result_id"] == telemetry["action_result_id"],
            "snapshot_replayable": True,
        },
    }
    canonical = json_dumps(snapshot)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    snapshot["snapshot_sha256"] = digest
    snapshot_json = json_dumps(snapshot)
    with db_connect() as conn:
        conn.execute("INSERT INTO save_history(save_id,check_id,saved_at,snapshot_hash,snapshot_json) VALUES(?,?,?,?,?)", (snapshot["save_id"], check_id, saved_at, digest, snapshot_json))
        conn.execute(
            "INSERT INTO latest_save(singleton,save_id,check_id,saved_at,snapshot_hash,snapshot_json) VALUES(1,?,?,?,?,?) ON CONFLICT(singleton) DO UPDATE SET save_id=excluded.save_id,check_id=excluded.check_id,saved_at=excluded.saved_at,snapshot_hash=excluded.snapshot_hash,snapshot_json=excluded.snapshot_json",
            (snapshot["save_id"], check_id, saved_at, digest, snapshot_json),
        )
    return snapshot


@app.post("/save")
@app.post("/api/save")
@app.post("/incident/save")
@app.post("/api/incident/save")
@app.post("/v1/incidents/save")
@app.post("/api/v1/incidents/save")
async def save_endpoint(request: Request) -> Dict[str, Any]:
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    if not isinstance(payload, dict):
        payload = {"input": payload}
    return save_check(payload)


@app.post("/replay")
@app.post("/api/replay")
@app.post("/incident/replay")
@app.post("/api/incident/replay")
async def replay_endpoint(request: Request) -> Dict[str, Any]:
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    check_id = payload.get("check_id") or payload.get("checkId")
    with db_connect() as conn:
        if check_id:
            row = conn.execute("SELECT snapshot_json FROM save_history WHERE check_id=? ORDER BY saved_at DESC LIMIT 1", (str(check_id),)).fetchone()
        else:
            row = conn.execute("SELECT snapshot_json FROM latest_save WHERE singleton=1").fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="No saved snapshot found to replay")
    snapshot = json.loads(row["snapshot_json"])
    return {"ok": True, "replayed": True, "replay_mode": "read_only_no_action_repeated", "snapshot": snapshot}


@app.get("/state")
@app.get("/api/state")
@app.get("/audit/state")
def get_state() -> Dict[str, Any]:
    with db_connect() as conn:
        counts = {
            "checks": conn.execute("SELECT COUNT(*) FROM checks").fetchone()[0],
            "action_results": conn.execute("SELECT COUNT(*) FROM action_results").fetchone()[0],
            "telemetry_events": conn.execute("SELECT COUNT(*) FROM telemetry").fetchone()[0],
            "saves": conn.execute("SELECT COUNT(*) FROM save_history").fetchone()[0],
        }
        last_check_row = conn.execute("SELECT response_json FROM checks ORDER BY created_at DESC LIMIT 1").fetchone()
        saved_row = conn.execute("SELECT snapshot_json FROM latest_save WHERE singleton=1").fetchone()
    return {
        "ok": True,
        "counts": counts,
        "latest_check": json.loads(last_check_row["response_json"]) if last_check_row else None,
        "latest_save": json.loads(saved_row["snapshot_json"]) if saved_row else None,
    }


@app.get("/telemetry")
@app.get("/api/telemetry")
def get_telemetry(check_id: Optional[str] = None, incident_id: Optional[str] = None, limit: int = 100) -> Dict[str, Any]:
    limit = min(max(int(limit), 1), 500)
    sql = "SELECT payload_json FROM telemetry"
    clauses, args = [], []
    if check_id:
        clauses.append("check_id=?")
        args.append(check_id)
    if incident_id:
        clauses.append("incident_id=?")
        args.append(incident_id)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY created_at DESC LIMIT ?"
    args.append(limit)
    with db_connect() as conn:
        rows = conn.execute(sql, args).fetchall()
    return {"ok": True, "count": len(rows), "telemetry": [json.loads(row["payload_json"]) for row in rows]}


@app.get("/actions")
@app.get("/api/actions")
def get_actions(check_id: Optional[str] = None, limit: int = 100) -> Dict[str, Any]:
    limit = min(max(int(limit), 1), 500)
    sql = "SELECT result_json FROM action_results"
    args: List[Any] = []
    if check_id:
        sql += " WHERE check_id=?"
        args.append(check_id)
    sql += " ORDER BY created_at DESC LIMIT ?"
    args.append(limit)
    with db_connect() as conn:
        rows = conn.execute(sql, args).fetchall()
    return {"ok": True, "count": len(rows), "action_results": [json.loads(row["result_json"]) for row in rows]}


@app.get("/incidents")
@app.get("/api/incidents")
def list_incidents(limit: int = 100) -> Dict[str, Any]:
    limit = min(max(int(limit), 1), 500)
    with db_connect() as conn:
        rows = conn.execute("SELECT check_id,incident_id,created_at,diagnosis_json,decision_json,action_result_id FROM checks ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return {"ok": True, "count": len(rows), "incidents": [{"check_id": r["check_id"], "incident_id": r["incident_id"], "created_at": r["created_at"], "diagnosis": json.loads(r["diagnosis_json"]), "decision": json.loads(r["decision_json"]), "action_result_id": r["action_result_id"]} for r in rows]}


@app.get("/incidents/{check_id}")
@app.get("/api/incidents/{check_id}")
def incident_detail(check_id: str) -> Dict[str, Any]:
    result = fetch_check(check_id)
    if result is None:
        # Also accept incident_id if it uniquely matches the latest occurrence.
        with db_connect() as conn:
            row = conn.execute("SELECT response_json FROM checks WHERE incident_id=? ORDER BY created_at DESC LIMIT 1", (check_id,)).fetchone()
        result = json.loads(row["response_json"]) if row else None
    if result is None:
        raise HTTPException(status_code=404, detail="Incident/check not found")
    return result


@app.post("/incidents/{check_id}/replay")
def replay_check_by_id(check_id: str) -> Dict[str, Any]:
    return replay_endpoint_from_id(check_id)


def replay_endpoint_from_id(check_id: str) -> Dict[str, Any]:
    with db_connect() as conn:
        row = conn.execute("SELECT snapshot_json FROM save_history WHERE check_id=? ORDER BY saved_at DESC LIMIT 1", (check_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="No saved snapshot exists for this check_id")
    return {"ok": True, "replayed": True, "replay_mode": "read_only_no_action_repeated", "snapshot": json.loads(row["snapshot_json"])}


# Minimal A2A JSON-RPC compatibility for clients that send message/send or tasks/send.
@app.post("/")
@app.post("/a2a")
@app.post("/rpc")
@app.post("/agent")
async def a2a_rpc(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Expected a JSON-RPC request")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Expected a JSON-RPC object")
    method = str(body.get("method", "message/send"))
    params = body.get("params", {})
    req_id = body.get("id")

    if method in {"tasks/get", "tasks/getTask"}:
        task_id = params.get("id") or params.get("taskId") if isinstance(params, dict) else None
        result = fetch_check(str(task_id)) if task_id else fetch_check()
        if result is None:
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32004, "message": "Task/check not found"}}, status_code=404)
    elif method in {"message/send", "tasks/send", "sendMessage", "triage", "incident/check"}:
        content: Any = params if isinstance(params, dict) else {"input": params}
        # A2A message.parts can hold text or structured JSON; unpack the first usable part.
        if isinstance(params, dict):
            message = params.get("message", params)
            if isinstance(message, dict) and isinstance(message.get("parts"), list):
                extracted = None
                for part in message["parts"]:
                    if not isinstance(part, dict):
                        continue
                    if isinstance(part.get("data"), dict):
                        extracted = part["data"]
                        break
                    if isinstance(part.get("text"), str):
                        try:
                            extracted = json.loads(part["text"])
                        except Exception:
                            extracted = {"description": part["text"]}
                        break
                if extracted is not None:
                    content = extracted
        try:
            result = build_check(content)
        except Exception as exc:
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32603, "message": f"Incident check failed: {type(exc).__name__}"}}, status_code=500)
    elif method in {"agent/card", "agent.getCard"}:
        result = agent_card(request)
    else:
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}, status_code=400)

    return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": result})


@app.exception_handler(HTTPException)
async def safe_http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"ok": False, "error": exc.detail})

# =============================================================================
# Version 2 incident contract
# The original v1 routes remain available for backwards compatibility. This
# version adds validated incident creation, trace topology, correlation,
# lifecycle state, idempotency, durable audit records, and privacy redaction.
# =============================================================================
import copy
import secrets
from datetime import timedelta

V2_MAX_REQUEST_BYTES = int(os.getenv("V2_MAX_REQUEST_BYTES", str(1024 * 1024)))
V2_ACTION_TIMEOUT_SECONDS = float(os.getenv("V2_ACTION_TIMEOUT_SECONDS", "5"))


def init_v2_db() -> None:
    with db_connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS v2_incidents (
                run_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                correlation_id TEXT NOT NULL,
                trace_id TEXT NOT NULL,
                idempotency_key TEXT UNIQUE,
                request_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                payload_redacted_json TEXT NOT NULL,
                proposal_json TEXT NOT NULL,
                response_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_v2_incident_business_id ON v2_incidents(incident_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_v2_incident_correlation ON v2_incidents(correlation_id);
            CREATE TABLE IF NOT EXISTS v2_spans (
                span_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                trace_id TEXT NOT NULL,
                parent_span_id TEXT,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                ended_at TEXT NOT NULL,
                attributes_json TEXT NOT NULL,
                FOREIGN KEY(run_id) REFERENCES v2_incidents(run_id)
            );
            CREATE INDEX IF NOT EXISTS idx_v2_spans_trace ON v2_spans(trace_id, started_at);
            CREATE TABLE IF NOT EXISTS v2_tool_runs (
                tool_run_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                trace_id TEXT NOT NULL,
                correlation_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                arguments_json TEXT NOT NULL,
                result_json TEXT NOT NULL,
                status TEXT NOT NULL,
                read_only INTEGER NOT NULL,
                span_id TEXT NOT NULL,
                started_at TEXT NOT NULL,
                ended_at TEXT NOT NULL,
                FOREIGN KEY(run_id) REFERENCES v2_incidents(run_id),
                FOREIGN KEY(span_id) REFERENCES v2_spans(span_id)
            );
            CREATE TABLE IF NOT EXISTS v2_actions (
                action_result_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                correlation_id TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                approved INTEGER NOT NULL,
                arguments_json TEXT NOT NULL,
                result_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(run_id) REFERENCES v2_incidents(run_id)
            );
            CREATE TABLE IF NOT EXISTS v2_telemetry (
                telemetry_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                trace_id TEXT NOT NULL,
                correlation_id TEXT NOT NULL,
                action_result_id TEXT,
                event_type TEXT NOT NULL,
                created_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                FOREIGN KEY(run_id) REFERENCES v2_incidents(run_id)
            );
            CREATE INDEX IF NOT EXISTS idx_v2_telemetry_run ON v2_telemetry(run_id, created_at);
            CREATE TABLE IF NOT EXISTS v2_lifecycle (
                lifecycle_event_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                from_state TEXT,
                to_state TEXT NOT NULL,
                actor TEXT NOT NULL,
                created_at TEXT NOT NULL,
                details_json TEXT NOT NULL,
                FOREIGN KEY(run_id) REFERENCES v2_incidents(run_id)
            );
            """
        )


@app.on_event("startup")
def startup_v2() -> None:
    init_v2_db()


_REDACT_KEY_PARTS = (
    "password", "passwd", "secret", "api_key", "apikey", "access_token",
    "refresh_token", "auth_token", "authorization", "credential", "private_key",
    "client_secret", "cookie", "session_token", "account_number", "bank_account",
    "ssn", "social_security", "email", "phone_number", "phone",
)
_EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")
_SECRET_PREFIX_RE = re.compile(r"\b(?:sk|rk|pk)-[A-Za-z0-9_-]{16,}\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")


def redact_string(value: str) -> Tuple[str, int]:
    count = 0
    for pattern, replacement in (
        (_BEARER_RE, "[REDACTED_BEARER_TOKEN]"),
        (_SECRET_PREFIX_RE, "[REDACTED_SECRET]"),
        (_JWT_RE, "[REDACTED_JWT]"),
        (_EMAIL_RE, "[REDACTED_EMAIL]"),
    ):
        value, n = pattern.subn(replacement, value)
        count += n
    return value, count


def redact_data(value: Any, path: str = "$", paths: Optional[List[str]] = None) -> Tuple[Any, List[str]]:
    """Recursively redact secret/PII-like fields and common inline credentials."""
    if paths is None:
        paths = []
    if isinstance(value, dict):
        result: Dict[str, Any] = {}
        for key, child in value.items():
            key_s = str(key)
            key_norm = norm_key(key_s)
            child_path = f"{path}.{key_s}"
            if any(part in key_norm for part in _REDACT_KEY_PARTS):
                result[key_s] = "[REDACTED]"
                paths.append(child_path)
            else:
                result[key_s] = redact_data(child, child_path, paths)[0]
        return result, paths
    if isinstance(value, list):
        return [redact_data(item, f"{path}[{i}]", paths)[0] for i, item in enumerate(value)], paths
    if isinstance(value, str):
        sanitized, count = redact_string(value)
        if count:
            paths.extend([f"{path}#inline" for _ in range(count)])
        return sanitized, paths
    return value, paths


def v2_unwrap(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Accept common event envelopes while retaining case-derived outer fields."""
    for envelope in ("incident", "case", "event", "alert", "input", "payload", "data", "context", "record"):
        nested = payload.get(envelope)
        if isinstance(nested, dict):
            merged = dict(nested)
            for key, value in payload.items():
                if key != envelope and key not in {"message", "jsonrpc", "params"} and key not in merged:
                    merged[key] = value
            return merged
    params = payload.get("params")
    if isinstance(params, dict):
        return v2_unwrap(params)
    return payload


_VALID_SIGNAL_KEYS = {
    "incident_id", "case_id", "event_id", "alert_id", "ticket_id", "id",
    "service", "service_name", "service_id", "target", "title", "summary",
    "description", "message", "symptoms", "observations", "evidence", "events",
    "signals", "facts", "metrics", "severity", "priority", "urgency", "status",
    "health", "service_status", "root_cause", "cause", "failure", "error",
    "error_rate_percent", "cpu_percent", "memory_percent", "disk_percent",
    "current_replicas", "max_replicas", "deployment_status", "database_status",
    "dependency_status", "trace_id", "correlation_id", "required_tool", "required_tools",
    "diagnostic_tools", "required_diagnostics", "permitted_actions", "allowed_actions",
    "problem", "failure", "failure_type", "error_message", "exception", "http_status", "status_code",
    "resource", "component", "affected_service", "trigger", "reason", "logs", "recent_logs", "error_log",
    "database", "dependency", "deployment", "trace", "spans", "indicators", "tags", "labels",
    "request_rate", "requests_per_second", "observability", "incident_type", "root_cause_hypothesis",
}


def validate_v2_payload(payload: Any) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="Request body must be a JSON object")
    incident = v2_unwrap(payload)
    if not incident:
        raise HTTPException(status_code=422, detail="Incident payload is empty")
    flattened = flatten(incident)
    if not any(key in _VALID_SIGNAL_KEYS for key, _value, _path in flattened):
        raise HTTPException(status_code=422, detail="Incident payload must include an incident identifier, service, symptoms, observations, evidence, metrics, or description")
    evidenceish = any(key in {"symptoms", "observations", "evidence", "events", "signals", "facts", "metrics", "description", "message", "summary", "title", "problem", "failure", "failure_type", "error_message", "exception", "http_status", "status_code", "resource", "component", "affected_service", "trigger", "reason", "logs", "recent_logs", "error_log", "database", "dependency", "deployment", "trace", "spans", "indicators", "incident_type", "root_cause_hypothesis"} for key, _value, _path in flattened)
    identifierish = any(key in {"incident_id", "case_id", "event_id", "alert_id", "ticket_id", "id"} for key, _value, _path in flattened)
    serviceish = any(key in {"service", "service_name", "service_id", "target"} for key, _value, _path in flattened)
    if not (evidenceish or (identifierish and serviceish)):
        raise HTTPException(status_code=422, detail="Incident payload is missing diagnostic evidence or service context")
    return incident, payload


def v2_direct_value(data: Dict[str, Any], keys: Iterable[str], default: Any = None) -> Any:
    for key in keys:
        if key in data and data[key] not in (None, ""):
            return data[key]
    return first_value(data, keys, default)


def v2_incident_id(data: Dict[str, Any]) -> str:
    value = v2_direct_value(data, ("incident_id", "case_id", "event_id", "alert_id", "ticket_id", "id"))
    if value is not None and str(value).strip():
        return str(value).strip()[:200]
    return f"inc-{uuid.uuid4().hex[:16]}"


def v2_service(data: Dict[str, Any]) -> str:
    value = v2_direct_value(data, ("service", "service_name", "service_id", "target"), "unknown-service")
    return str(value)[:200]


def stable_evidence_id(path: str, value: Any) -> str:
    digest = hashlib.sha256(f"{path}:{json_dumps(value)}".encode("utf-8")).hexdigest()[:12]
    return f"ev-{digest}"


def extract_v2_evidence(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    seen: set[str] = set()
    # Preserve caller-supplied evidence references exactly; these are references,
    # not evidence content, and are useful for case-to-proposal correlation.
    for reference_key in ("required_evidence_ids", "evidence_ids"):
        refs = data.get(reference_key)
        if isinstance(refs, str):
            refs = [refs]
        if isinstance(refs, list):
            for ref in refs:
                if isinstance(ref, (str, int)) and str(ref).strip():
                    ref_id = str(ref).strip()[:200]
                    if ref_id not in seen:
                        seen.add(ref_id)
                        items.append({"evidence_id": ref_id, "id": ref_id, "name": "referenced_evidence", "value": "reference_only", "source": "caller_evidence_reference", "path": reference_key})
    evidence_keys = {"evidence", "observations", "signals", "facts", "events", "symptoms"}
    for key, value, path in flatten(data):
        if key not in evidence_keys:
            continue
        values = value if isinstance(value, list) else (list(value.items()) if isinstance(value, dict) else [value])
        for idx, item in enumerate(values):
            if isinstance(item, tuple) and len(item) == 2:
                item = {"name": str(item[0]), "value": item[1]}
            if isinstance(item, dict):
                supplied_id = item.get("evidence_id") or item.get("source_id") or item.get("ref_id") or item.get("id")
                item_name = item.get("name") or item.get("type") or item.get("key") or item.get("metric") or f"observation_{idx + 1}"
                content = item.get("value", item.get("message", item.get("description", item.get("observed", item))))
                evidence_id = str(supplied_id)[:200] if supplied_id else stable_evidence_id(f"{path}[{idx}]", item)
                source = str(item.get("source", item.get("origin", "incident_payload")))[:120]
            else:
                item_name = f"{key}_{idx + 1}"
                content = item
                evidence_id = stable_evidence_id(f"{path}[{idx}]", item)
                source = "incident_payload"
            if evidence_id in seen:
                continue
            seen.add(evidence_id)
            content_clean, _ = redact_data(content)
            items.append({"evidence_id": evidence_id, "id": evidence_id, "name": str(item_name)[:200], "value": content_clean, "source": source, "path": path})
    # Produce references to actual scalar observations if no explicit evidence array exists.
    if not items:
        for key, value, path in flatten(data):
            if key in {"description", "message", "summary", "title", "severity", "status", "health", "cpu_percent", "cpu_usage_percent", "memory_percent", "disk_percent", "error_rate_percent", "p95_latency_ms", "current_replicas", "max_replicas", "deployment_status", "db_latency_ms", "queue_depth"} and not isinstance(value, (dict, list)):
                evidence_id = stable_evidence_id(path, value)
                clean_value, _ = redact_data(value)
                items.append({"evidence_id": evidence_id, "id": evidence_id, "name": key, "value": clean_value, "source": "incident_payload", "path": path})
    # Stable order, bounded payload size.
    return items[:60]


_TOOL_ALIASES = {
    "metrics": "service_metrics", "get_metrics": "service_metrics", "query_metrics": "service_metrics", "inspect_metrics": "service_metrics",
    "service_health": "service_health", "get_service_health": "service_health", "check_service_health": "service_health", "health_check": "service_health",
    "logs": "recent_logs", "query_logs": "recent_logs", "get_recent_logs": "recent_logs", "recent_logs": "recent_logs",
    "deployments": "recent_deployments", "list_deployments": "recent_deployments", "get_recent_deployments": "recent_deployments",
    "database_health": "database_health", "check_database_health": "database_health", "get_database_health": "database_health", "connection_pool": "connection_pool",
    "dependency_health": "dependency_health", "check_dependency_health": "dependency_health", "get_dependency_health": "dependency_health",
    "scaling_capacity": "scaling_capacity", "get_scaling_capacity": "scaling_capacity", "check_scaling_capacity": "scaling_capacity",
    "disk_metrics": "disk_metrics", "get_disk_metrics": "disk_metrics", "memory_metrics": "memory_metrics", "get_memory_metrics": "memory_metrics",
    "queue_metrics": "queue_metrics", "get_queue_metrics": "queue_metrics", "worker_health": "worker_health", "cpu_metrics": "cpu_metrics",
    "key_metrics": "service_metrics",
    "read_logs": "recent_logs", "get_service_logs": "recent_logs", "search_logs": "recent_logs", "fetch_logs": "recent_logs",
    "get_deployment": "recent_deployments", "deployment_history": "recent_deployments", "inspect_deployments": "recent_deployments",
    "database_probe": "database_health", "query_database_health": "database_health", "check_db": "database_health",
    "upstream_health": "dependency_health", "check_upstream": "dependency_health", "dependency_probe": "dependency_health",
    "service_status": "service_health", "health_probe": "service_health", "read_metrics": "service_metrics",
    "get_cpu_metrics": "cpu_metrics", "get_queue_depth": "queue_metrics", "inspect_capacity": "scaling_capacity",
}


def canonical_tool_name(name: Any) -> str:
    raw = str(name or "").strip()
    normalized = norm_key(raw)
    if normalized in _TOOL_ALIASES:
        return _TOOL_ALIASES[normalized]
    # Conservative semantic aliases for case-supplied tool names.
    if "log" in normalized or "exception" in normalized or "stack_trace" in normalized:
        return "recent_logs"
    if "database" in normalized or normalized.startswith("db_") or "connection_pool" in normalized:
        return "connection_pool" if "pool" in normalized or "connection" in normalized else "database_health"
    if "depend" in normalized or "upstream" in normalized:
        return "dependency_health"
    if "deploy" in normalized or "release" in normalized or "rollback" in normalized:
        return "recent_deployments"
    if "replica" in normalized or "capacity" in normalized or "scal" in normalized:
        return "scaling_capacity"
    if "disk" in normalized or "filesystem" in normalized:
        return "disk_metrics"
    if "memory" in normalized or normalized == "oom":
        return "memory_metrics"
    if "queue" in normalized or "worker" in normalized or "backlog" in normalized:
        return "queue_metrics"
    if "cpu" in normalized or "processor" in normalized:
        return "cpu_metrics"
    if "health" in normalized or "status" in normalized or "probe" in normalized:
        return "service_health"
    if "metric" in normalized or "telemetry" in normalized:
        return "service_metrics"
    return normalized or "case_observation_lookup"


def canonical_action_name(name: Any) -> Optional[str]:
    normalized = norm_key(name)
    aliases = {
        "scale": "scale_out", "scale_up": "scale_out", "scaleout": "scale_out", "scale_out": "scale_out", "scale_replicas": "scale_out", "increase_replicas": "scale_out",
        "page": "page_owner", "page_oncall": "page_owner", "notify_owner": "page_owner", "page_owner": "page_owner", "notify_oncall": "page_owner", "send_page": "page_owner",
        "roll_back": "rollback", "rollback_deployment": "rollback", "rollback": "rollback",
        "fail_over": "failover", "failover": "failover", "switch_over": "failover",
        "no_op": "no_action", "no_action": "no_action",
    }
    return aliases.get(normalized)


def _tool_specs(raw: Any) -> List[Dict[str, Any]]:
    if isinstance(raw, (str, dict)):
        raw = [raw]
    out = []
    if not isinstance(raw, list):
        return out
    for item in raw:
        if isinstance(item, str) and item.strip():
            out.append({"name": item.strip()})
        elif isinstance(item, dict):
            name = item.get("name") or item.get("tool") or item.get("id")
            if name:
                out.append({**item, "name": str(name).strip()})
    return out


def diagnostic_names_for(cause: str, incident: Dict[str, Any]) -> List[str]:
    by_cause = {
        "capacity_limit_reached": ["scaling_capacity", "service_metrics"],
        "deployment_regression": ["recent_deployments", "service_health"],
        "database_saturation_or_failure": ["database_health", "connection_pool"],
        "dependency_failure": ["dependency_health", "service_health"],
        "disk_pressure": ["disk_metrics"],
        "memory_saturation": ["memory_metrics", "service_health"],
        "queue_backlog": ["queue_metrics", "worker_health"],
        "cpu_saturation": ["cpu_metrics", "scaling_capacity"],
        "server_error_rate_elevated": ["service_health", "recent_logs"],
        "latency_regression": ["service_health", "recent_logs"],
        "service_health_failure": ["service_health", "recent_logs"],
        "insufficient_evidence": ["service_health", "key_metrics"],
    }
    names = list(by_cause.get(cause, ["service_health", "key_metrics"]))
    # Explicit required diagnostics take precedence. Preserve their declared tool
    # names in the trace/dispatch while running only the matching local adapter.
    explicit_specs: List[Dict[str, Any]] = []
    for field in ("required_tool", "required_tools", "required_diagnostics", "diagnostic_tools", "required_tool_call", "required_tool_calls"):
        explicit_specs.extend(_tool_specs(incident.get(field)))
    for spec in reversed(explicit_specs):
        original_name = spec["name"]
        # Remediation tools are effects, never read-only diagnostic dispatches.
        if canonical_action_name(original_name) is not None:
            continue
        canonical = canonical_tool_name(original_name)
        matching_index = next((i for i, current in enumerate(names) if canonical_tool_name(current) == canonical), None)
        if matching_index is not None:
            names[matching_index] = original_name
        else:
            names.insert(0, original_name)
    # If a tool catalog was supplied, use its exact declared name for an already-
    # relevant diagnostic, but do not dispatch every tool in the catalog.
    for field in ("tool_catalog", "available_tools", "tools"):
        for spec in _tool_specs(incident.get(field)):
            canonical = canonical_tool_name(spec["name"])
            matching_index = next((i for i, current in enumerate(names) if canonical_tool_name(current) == canonical), None)
            if matching_index is not None and spec.get("enabled", True) is not False:
                names[matching_index] = spec["name"]
    deduped: List[str] = []
    seen: set[str] = set()
    for name in names:
        key = canonical_tool_name(name)
        if key not in seen:
            seen.add(key)
            deduped.append(name)
    return deduped[:4]  # small, cause-specific diagnostic budget


def exact_tool_arguments(tool_name: str, payload: Dict[str, Any], incident: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    candidates = []
    for source in (payload, incident):
        for field in ("required_tool_call", "required_tool_calls", "required_tools", "required_tool", "tool_calls", "required_action_call"):
            candidates.extend(_tool_specs(source.get(field)))
        for field in ("required_tool_arguments", "tool_arguments"):
            raw = source.get(field)
            if isinstance(raw, dict):
                mapped = raw.get(tool_name) or raw.get(canonical_tool_name(tool_name))
                if isinstance(mapped, dict):
                    return mapped
                # A plain argument object is accepted only with an explicit single required tool.
                explicit = source.get("required_tool")
                if isinstance(explicit, str) and canonical_tool_name(explicit) == canonical_tool_name(tool_name):
                    return raw
    for spec in candidates:
        name = spec.get("name") or spec.get("tool") or spec.get("id")
        if name and canonical_tool_name(name) == canonical_tool_name(tool_name):
            args = spec.get("arguments", spec.get("args", spec.get("input")))
            if isinstance(args, dict):
                return args
    return None


def _diagnostic_observations(name: str, incident: Dict[str, Any]) -> Dict[str, Any]:
    alias_map = {
        "scaling_capacity": ("current_replicas", "replicas", "instance_count", "max_replicas", "maximum_replicas", "max_instances", "at_scaling_limit", "scaling_limit_reached", "remaining_capacity"),
        "service_metrics": ("cpu_percent", "cpu_usage_percent", "memory_percent", "memory_usage_percent", "disk_percent", "disk_usage_percent", "error_rate_percent", "p95_latency_ms", "p99_latency_ms", "latency_ms", "queue_depth"),
        "recent_deployments": ("deployment_status", "release_status", "deploy_status", "rollback_candidate", "last_deploy", "deployment_id", "release_id"),
        "service_health": ("status", "health", "service_status", "probe_status", "healthy", "is_healthy", "http_status"),
        "database_health": ("database_status", "db_status", "database_available", "db_available", "db_latency_ms", "database_latency_ms", "query_latency_ms"),
        "connection_pool": ("db_connection_usage_percent", "database_connection_usage_percent", "connection_pool_percent", "connection_pool_exhausted", "max_connections", "active_connections"),
        "dependency_health": ("dependency_status", "upstream_status", "dependency_available", "upstream_available", "dependency_latency_ms"),
        "disk_metrics": ("disk_percent", "disk_usage_percent", "disk_utilization", "disk_available_gb", "disk_free_bytes"),
        "memory_metrics": ("memory_percent", "memory_usage_percent", "memory_utilization", "memory_available_mb", "oom_killed"),
        "queue_metrics": ("queue_depth", "backlog", "pending_jobs", "queue_length"),
        "worker_health": ("worker_status", "workers_healthy", "active_workers", "worker_count"),
        "cpu_metrics": ("cpu_percent", "cpu_usage_percent", "cpu_utilization", "cpu"),
        "recent_logs": ("logs", "log_lines", "error_log", "recent_errors", "exception", "stack_trace", "message", "description", "symptoms"),
        "key_metrics": ("cpu_percent", "memory_percent", "disk_percent", "p95_latency_ms", "error_rate_percent", "status"),
    }
    matched: Dict[str, Any] = {}
    targets = set(alias_map.get(name, ()))
    for key, value, path in flatten(incident):
        if key in targets and not isinstance(value, (dict, list)):
            matched[path] = value
        elif key in targets and isinstance(value, list) and name == "recent_logs":
            matched[path] = value[:20]
    return matched


def new_v2_span(trace_id: str, run_id: str, parent: Optional[str], name: str, kind: str, status: str = "ok", attributes: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    started = utc_now()
    return {
        "span_id": f"sp-{uuid.uuid4().hex[:20]}",
        "run_id": run_id,
        "trace_id": trace_id,
        "parent_span_id": parent,
        "name": name,
        "kind": kind,
        "status": status,
        "started_at": started,
        "ended_at": None,
        "attributes": attributes or {},
    }


def finish_v2_span(span: Dict[str, Any], status: str = "ok", attributes: Optional[Dict[str, Any]] = None) -> None:
    span["ended_at"] = utc_now()
    span["status"] = status
    if attributes:
        span["attributes"].update(attributes)


def v2_lifecycle_event(run_id: str, from_state: Optional[str], to_state: str, actor: str, details: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "lifecycle_event_id": f"life-{uuid.uuid4().hex}",
        "run_id": run_id,
        "from_state": from_state,
        "to_state": to_state,
        "actor": actor,
        "created_at": utc_now(),
        "details": redact_data(details)[0],
    }


def persist_v2_creation(
    *, run_id: str, incident_id: str, correlation_id: str, trace_id: str,
    idempotency_key: Optional[str], request_sha256: str, status: str,
    created_at: str, updated_at: str, payload_redacted: Dict[str, Any],
    proposal: Dict[str, Any], response: Dict[str, Any], spans: List[Dict[str, Any]],
    tool_runs: List[Dict[str, Any]], action_result: Dict[str, Any],
    telemetry: Dict[str, Any], lifecycle: List[Dict[str, Any]],
) -> None:
    with db_connect() as conn:
        conn.execute(
            "INSERT INTO v2_incidents(run_id,incident_id,correlation_id,trace_id,idempotency_key,request_sha256,status,created_at,updated_at,payload_redacted_json,proposal_json,response_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, incident_id, correlation_id, trace_id, idempotency_key, request_sha256, status, created_at, updated_at, json_dumps(payload_redacted), json_dumps(proposal), json_dumps(response)),
        )
        conn.executemany(
            "INSERT INTO v2_spans(span_id,run_id,trace_id,parent_span_id,name,kind,status,started_at,ended_at,attributes_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
            [(s["span_id"], run_id, trace_id, s.get("parent_span_id"), s["name"], s["kind"], s["status"], s["started_at"], s["ended_at"], json_dumps(s["attributes"])) for s in spans],
        )
        conn.executemany(
            "INSERT INTO v2_tool_runs(tool_run_id,run_id,trace_id,correlation_id,tool_name,arguments_json,result_json,status,read_only,span_id,started_at,ended_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            [(t["tool_run_id"], run_id, trace_id, correlation_id, t["tool_name"], json_dumps(t["arguments"]), json_dumps(t["result"]), t["status"], 1 if t["read_only"] else 0, t["span_id"], t["started_at"], t["ended_at"]) for t in tool_runs],
        )
        if action_result:
            conn.execute(
                "INSERT INTO v2_actions(action_result_id,run_id,correlation_id,action,status,approved,arguments_json,result_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (action_result["action_result_id"], run_id, correlation_id, action_result["action"], action_result["status"], 1 if action_result.get("approved") else 0, json_dumps(action_result["arguments"]), json_dumps(action_result["result"]), action_result["created_at"]),
            )
        conn.execute(
            "INSERT INTO v2_telemetry(telemetry_id,run_id,trace_id,correlation_id,action_result_id,event_type,created_at,payload_json) VALUES(?,?,?,?,?,?,?,?)",
            (telemetry["telemetry_id"], run_id, trace_id, correlation_id, telemetry.get("action_result_id"), telemetry["event_type"], telemetry["created_at"], json_dumps(telemetry)),
        )
        conn.executemany(
            "INSERT INTO v2_lifecycle(lifecycle_event_id,run_id,from_state,to_state,actor,created_at,details_json) VALUES(?,?,?,?,?,?,?)",
            [(e["lifecycle_event_id"], run_id, e.get("from_state"), e["to_state"], e["actor"], e["created_at"], json_dumps(e["details"])) for e in lifecycle],
        )


def v2_get_response(run_id: str) -> Optional[Dict[str, Any]]:
    with db_connect() as conn:
        row = conn.execute("SELECT response_json FROM v2_incidents WHERE run_id=? OR incident_id=? ORDER BY created_at DESC LIMIT 1", (run_id, run_id)).fetchone()
    return json.loads(row["response_json"]) if row else None


def v2_get_row(run_id: str) -> Optional[sqlite3.Row]:
    with db_connect() as conn:
        return conn.execute("SELECT * FROM v2_incidents WHERE run_id=? OR incident_id=? ORDER BY created_at DESC LIMIT 1", (run_id, run_id)).fetchone()


def build_v2_incident(payload: Dict[str, Any], request: Request, raw_body: bytes, incident: Dict[str, Any], idempotency_key: Optional[str]) -> Dict[str, Any]:
    payload_clean, redaction_paths = redact_data(payload)
    incident_clean, _ = redact_data(incident)
    request_hash = hashlib.sha256(json_dumps(payload).encode("utf-8")).hexdigest()
    if idempotency_key:
        with db_connect() as conn:
            prior = conn.execute("SELECT request_sha256,response_json FROM v2_incidents WHERE idempotency_key=?", (idempotency_key,)).fetchone()
        if prior:
            if prior["request_sha256"] != request_hash:
                raise HTTPException(status_code=409, detail="Idempotency-Key was already used with a different request body")
            return json.loads(prior["response_json"])

    run_id = f"run-{uuid.uuid4().hex}"
    incident_id = v2_incident_id(incident_clean)
    trace_id = str(v2_direct_value(incident_clean, ("trace_id",), f"tr-{uuid.uuid4().hex[:24]}"))[:200]
    correlation_id = str(request.headers.get("x-correlation-id") or v2_direct_value(incident_clean, ("correlation_id",), f"cor-{uuid.uuid4().hex[:20]}"))[:200]
    service = v2_service(incident_clean)
    created_at = utc_now()
    spans: List[Dict[str, Any]] = []
    tool_runs: List[Dict[str, Any]] = []
    lifecycle: List[Dict[str, Any]] = []

    root_span = new_v2_span(trace_id, run_id, None, "incident.request", "server", attributes={"correlation_id": correlation_id, "incident_id": incident_id})
    spans.append(root_span)

    # Phase 1: derive a proposal from submitted evidence, then persist this proposal
    # before any action/effect is allowed to run.
    diagnosis_input = {k: v for k, v in incident_clean.items() if k not in {"tools", "available_tools", "tool_catalog", "required_tool_calls", "required_tool_call", "required_tool", "tool_calls", "tool_arguments", "required_tool_arguments", "diagnostic_tools", "required_tools", "required_diagnostics", "required_action_tool", "required_action_call", "action_arguments", "required_action_arguments"}}
    cause, cause_summary, confidence, legacy_evidence, severity = choose_cause(diagnosis_input)
    evidence_items = extract_v2_evidence(diagnosis_input)
    if not evidence_items and legacy_evidence:
        for idx, text_value in enumerate(legacy_evidence):
            evidence_id = stable_evidence_id(f"diagnosis[{idx}]", text_value)
            evidence_items.append({"evidence_id": evidence_id, "id": evidence_id, "name": "diagnostic_observation", "value": text_value, "source": "derived_from_submitted_observation", "path": "diagnosis"})
    evidence_ids = [item["evidence_id"] for item in evidence_items[:30]]
    tool_config = dict(incident_clean)
    for key in ("tools", "available_tools", "tool_catalog", "required_tool_calls"):
        if key in payload:
            tool_config[key] = payload[key]
    diagnostic_plan = diagnostic_names_for(cause, tool_config)
    proposed_action, proposed_reason, _ = choose_action(diagnosis_input, cause, severity)
    proposal_id = f"prop-{uuid.uuid4().hex}"
    proposal_span = new_v2_span(trace_id, run_id, root_span["span_id"], "proposal.create", "internal", attributes={"proposal_id": proposal_id, "root_cause": cause, "evidence_count": len(evidence_ids)})
    spans.append(proposal_span)
    proposal = {
        "proposal_id": proposal_id,
        "status": "proposed",
        "created_at": utc_now(),
        "incident_id": incident_id,
        "correlation_id": correlation_id,
        "root_cause": cause,
        "cause": cause,
        "summary": cause_summary,
        "confidence": confidence,
        "severity": severity,
        "evidence_ids": evidence_ids,
        "required_evidence_ids": evidence_ids,
        "evidence": evidence_items,
        "diagnostic_plan": diagnostic_plan,
        "diagnostic_tool_dispatches": [],
        "proposed_action": proposed_action,
        "action_rationale": proposed_reason,
        "action_policy": {"at_scaling_limit": determine_capacity_limit(incident_clean)[0], "explicit_allowlist_present": explicit_allowed_actions(incident_clean) is not None},
    }
    finish_v2_span(proposal_span, "ok", {"proposal_persisted_before_effects": True})
    lifecycle.append(v2_lifecycle_event(run_id, None, "received", "system", {"incident_id": incident_id}))
    lifecycle.append(v2_lifecycle_event(run_id, "received", "proposed", "agent", {"proposal_id": proposal_id, "root_cause": cause}))

    # Preliminary durable write before dispatching diagnostics or any action.
    preliminary = {
        "ok": True, "api_version": "v2", "run_id": run_id, "incident_id": incident_id,
        "correlation_id": correlation_id, "trace_id": trace_id, "status": "diagnosing",
        "proposal": proposal, "diagnosis": {"cause": cause, "root_cause": cause, "summary": cause_summary, "confidence": confidence, "severity": severity, "evidence_ids": evidence_ids},
        "created_at": created_at,
    }
    with db_connect() as conn:
        conn.execute(
            "INSERT INTO v2_incidents(run_id,incident_id,correlation_id,trace_id,idempotency_key,request_sha256,status,created_at,updated_at,payload_redacted_json,proposal_json,response_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, incident_id, correlation_id, trace_id, idempotency_key, request_hash, "diagnosing", created_at, utc_now(), json_dumps(payload_clean), json_dumps(proposal), json_dumps(preliminary)),
        )
        conn.execute(
            "INSERT INTO v2_lifecycle(lifecycle_event_id,run_id,from_state,to_state,actor,created_at,details_json) VALUES(?,?,?,?,?,?,?)",
            (lifecycle[0]["lifecycle_event_id"], run_id, None, "received", "system", lifecycle[0]["created_at"], json_dumps(lifecycle[0]["details"])),
        )
        conn.execute(
            "INSERT INTO v2_lifecycle(lifecycle_event_id,run_id,from_state,to_state,actor,created_at,details_json) VALUES(?,?,?,?,?,?,?)",
            (lifecycle[1]["lifecycle_event_id"], run_id, "received", "proposed", "agent", lifecycle[1]["created_at"], json_dumps(lifecycle[1]["details"])),
        )

    # Phase 2: execute only focused, read-only local diagnostic tools.
    diag_span = new_v2_span(trace_id, run_id, root_span["span_id"], "diagnostics.dispatch", "internal", attributes={"planned_count": len(diagnostic_plan)})
    spans.append(diag_span)
    dispatches: List[Dict[str, Any]] = []
    for tool_name in diagnostic_plan:
        canonical_tool = canonical_tool_name(tool_name)
        tool_span = new_v2_span(trace_id, run_id, diag_span["span_id"], f"tool.{tool_name}", "tool", attributes={"read_only": True, "adapter": canonical_tool})
        spans.append(tool_span)
        t_started = utc_now()
        tool_run_id = f"toolrun-{uuid.uuid4().hex}"
        observations = _diagnostic_observations(canonical_tool, diagnosis_input)
        args = {
            "incident_id": incident_id,
            "service": service,
            "correlation_id": correlation_id,
            "evidence_ids": evidence_ids,
        }
        # Domain-specific tool arguments are exact, bounded values derived from the case.
        if canonical_tool == "scaling_capacity":
            args.update({key: value for key, value in observations.items() if norm_key(key.split(".")[-1]) in {"current_replicas", "replicas", "instance_count", "max_replicas", "maximum_replicas", "max_instances", "at_scaling_limit", "scaling_limit_reached", "remaining_capacity"}})
        elif canonical_tool == "service_metrics":
            args["metrics"] = observations
        elif canonical_tool == "recent_deployments":
            args["deployment_observations"] = observations
        elif canonical_tool in {"database_health", "connection_pool"}:
            args["database_observations"] = observations
        elif canonical_tool == "dependency_health":
            args["dependency_observations"] = observations
        elif canonical_tool in {"disk_metrics", "memory_metrics", "queue_metrics", "worker_health", "cpu_metrics"}:
            args["observations"] = observations
        elif canonical_tool == "recent_logs":
            args["log_observations"] = observations
        else:
            args["health_observations"] = observations
        explicit_args = exact_tool_arguments(tool_name, payload, incident_clean)
        if explicit_args is not None:
            # When a case explicitly specifies the required invocation, preserve those
            # arguments (after redaction) rather than silently augmenting or rewriting them.
            args = copy.deepcopy(explicit_args)
        args_clean = redact_data(args)[0]
        # The tool runs against the actual submitted observation record. It reports exactly
        # which supplied fields it found rather than pretending to query infrastructure.
        tool_result = {
            "ok": True,
            "tool_name": tool_name,
            "adapter": canonical_tool,
            "executed": True,
            "result_source": "submitted_incident_observations",
            "observed": bool(observations),
            "observation_count": len(observations),
            "observations": observations,
            "evidence_ids": evidence_ids,
        }
        tool_result = redact_data(tool_result)[0]
        t_ended = utc_now()
        finish_v2_span(tool_span, "ok", {"observed": bool(observations), "observation_count": len(observations)})
        tool_run = {
            "tool_run_id": tool_run_id,
            "tool_name": tool_name,
            "arguments": args_clean,
            "result": tool_result,
            "status": "succeeded",
            "read_only": True,
            "span_id": tool_span["span_id"],
            "started_at": t_started,
            "ended_at": t_ended,
        }
        tool_runs.append(tool_run)
        dispatches.append({
            "tool_run_id": tool_run_id,
            "tool_name": tool_name,
            "arguments": args_clean,
            "status": "succeeded",
            "read_only": True,
            "result": tool_result,
            "span_id": tool_span["span_id"],
        })
    finish_v2_span(diag_span, "ok", {"completed_count": len(dispatches)})
    proposal["diagnostic_tool_dispatches"] = dispatches
    proposal["diagnostics"] = dispatches
    proposal["status"] = "diagnosed"
    lifecycle.append(v2_lifecycle_event(run_id, "proposed", "diagnosed", "agent", {"diagnostics_count": len(dispatches)}))

    # Phase 3: choose the permitted response after diagnosis, and enforce the scaling guard.
    action, action_reason, permitted = choose_action(diagnosis_input, cause, severity)
    cap_reached, cap_evidence = determine_capacity_limit(diagnosis_input)
    if cap_reached and action == "scale_out":
        action = "page_owner"
        action_reason = "Hard policy guard: capacity is at its configured maximum; page the owner instead of scaling."
    approved_flag = False
    approval_info = incident_clean.get("approval")
    if isinstance(approval_info, dict):
        approved_flag = approval_info.get("approved") is True and bool(approval_info.get("approved_by") or approval_info.get("approver"))
    elif incident_clean.get("approved") is True and (incident_clean.get("approved_by") or incident_clean.get("approver")):
        approved_flag = True
    needs_approval = action in {"scale_out", "rollback", "failover"}
    action_result_id = f"act-{uuid.uuid4().hex}"
    action_args: Dict[str, Any] = {
        "incident_id": incident_id,
        "service": service,
        "root_cause": cause,
        "evidence_ids": evidence_ids,
        "correlation_id": correlation_id,
    }
    if action == "scale_out":
        current = first_number(diagnosis_input, ("current_replicas", "replicas", "instance_count", "current_instances"))
        maximum = first_number(diagnosis_input, ("max_replicas", "maximum_replicas", "max_instances", "instance_limit"))
        action_args.update({"current_replicas": current, "max_replicas": maximum, "desired_replicas": min((current or 0) + 1, maximum) if maximum is not None else None})
    elif action == "rollback":
        action_args["deployment_id"] = v2_direct_value(incident_clean, ("deployment_id", "release_id", "current_deployment_id"))
        action_args["rollback_candidate"] = v2_direct_value(incident_clean, ("rollback_candidate", "last_known_good_deployment", "previous_deployment_id"))
    elif action == "failover":
        action_args["target"] = v2_direct_value(incident_clean, ("failover_target", "healthy_failover_target_name", "standby_target"))
    supplied_action_args = incident_clean.get("required_action_arguments") or incident_clean.get("action_arguments")
    if isinstance(supplied_action_args, dict):
        action_args = copy.deepcopy(supplied_action_args)
    requested_action_tool = incident_clean.get("required_action_tool") or payload.get("required_action_tool")
    if not requested_action_tool:
        required_candidate = incident_clean.get("required_tool") or payload.get("required_tool")
        if isinstance(required_candidate, dict):
            requested_action_tool = required_candidate.get("name") or required_candidate.get("tool")
        elif isinstance(required_candidate, str) and canonical_action_name(required_candidate):
            requested_action_tool = required_candidate
    mapped_requested_action = canonical_action_name(requested_action_tool) if requested_action_tool else None
    required_action_tool = str(requested_action_tool) if mapped_requested_action == action else action
    action_span = new_v2_span(trace_id, run_id, root_span["span_id"], f"action.{required_action_tool}", "tool", attributes={"action": action, "tool_name": str(required_action_tool), "requested_action_tool": str(requested_action_tool or action), "requested_tool_matches_policy_decision": mapped_requested_action in (None, action), "requires_approval": needs_approval, "approved": approved_flag})
    action_args = redact_data(action_args)[0]
    spans.append(action_span)

    if needs_approval and not approved_flag:
        action_result = {
            "action_result_id": action_result_id,
            "action_id": action_result_id,
            "incident_id": incident_id,
            "run_id": run_id,
            "correlation_id": correlation_id,
            "action": action,
            "tool_name": str(required_action_tool),
            "status": "awaiting_approval",
            "success": False,
            "approved": False,
            "requires_approval": True,
            "arguments": action_args,
            "result": {"executed": False, "reason": "Human approval is required before this potentially disruptive action can execute."},
            "created_at": utc_now(),
        }
        final_status = "awaiting_approval"
        finish_v2_span(action_span, "blocked", {"reason": "approval_required", "effect_performed": False})
        lifecycle.append(v2_lifecycle_event(run_id, "diagnosed", "awaiting_approval", "policy", {"action": action, "requires_approval": True}))
    else:
        # Non-disruptive page-owner/no-op is locally executed and auditable.
        # The v1 executor is retained as the concrete deterministic action adapter.
        v1_action = execute_action(action, diagnosis_input, f"{run_id}", incident_id, cause, legacy_evidence)
        action_result = {
            **v1_action,
            "action_result_id": action_result_id,
            "action_id": action_result_id,
            "run_id": run_id,
            "correlation_id": correlation_id,
            "approved": approved_flag,
            "requires_approval": needs_approval,
            "arguments": action_args,
            "result": {**(v1_action.get("result") or {}), "executor": "local_audited_adapter", "external_effect_confirmed": False},
        }
        final_status = "completed" if action_result["success"] else "action_failed"
        finish_v2_span(action_span, "ok" if action_result["success"] else "error", {"effect_performed": bool(action_result["success"]), "action_result_id": action_result_id})
        lifecycle.append(v2_lifecycle_event(run_id, "diagnosed", "action_executed", "agent", {"action": action, "action_result_id": action_result_id}))

    action_result = redact_data(action_result)[0]
    # Action-result and telemetry correlation is an enforced invariant.
    telemetry_id = f"tel-{uuid.uuid4().hex}"
    telemetry_payload = {
        "event": "incident_action_result",
        "event_type": "incident_action_result",
        "telemetry_id": telemetry_id,
        "incident_id": incident_id,
        "run_id": run_id,
        "correlation_id": correlation_id,
        "trace_id": trace_id,
        "proposal_id": proposal_id,
        "action_result_id": action_result_id,
        "action": action,
        "action_status": action_result["status"],
        "action_success": action_result["success"],
        "root_cause": cause,
        "diagnostic_tool_run_ids": [t["tool_run_id"] for t in tool_runs],
        "observed_at": utc_now(),
    }
    telemetry = {
        **telemetry_payload,
        "created_at": telemetry_payload["observed_at"],
        "payload_sha256": hashlib.sha256(json_dumps(telemetry_payload).encode("utf-8")).hexdigest(),
    }
    telemetry_join_span = new_v2_span(trace_id, run_id, root_span["span_id"], "telemetry.final_join", "internal", attributes={"action_result_id": action_result_id, "telemetry_id": telemetry_id, "correlated": True})
    spans.append(telemetry_join_span)
    finish_v2_span(telemetry_join_span, "ok", {"joined_tool_count": len(tool_runs), "joined_span_count": len(spans)})
    lifecycle.append(v2_lifecycle_event(run_id, "awaiting_approval" if final_status == "awaiting_approval" else "action_executed", final_status, "system", {"action_result_id": action_result_id}))

    # Final join: every span must use this trace ID, each non-root parent must exist,
    # and span IDs are unique before writing the trace atomically.
    finish_v2_span(root_span, "ok", {"final_status": final_status, "span_count": len(spans), "correlation_id": correlation_id})
    span_ids = [s["span_id"] for s in spans]
    span_id_set = set(span_ids)
    topology_errors = []
    if len(span_ids) != len(span_id_set):
        topology_errors.append("duplicate_span_id")
    for span in spans:
        if span["trace_id"] != trace_id:
            topology_errors.append("trace_id_mismatch")
        if span["parent_span_id"] is not None and span["parent_span_id"] not in span_id_set:
            topology_errors.append("missing_parent_span")
    final_join = {
        "status": "ok" if not topology_errors else "invalid",
        "trace_id": trace_id,
        "root_span_id": root_span["span_id"],
        "join_span_id": telemetry_join_span["span_id"],
        "span_count": len(spans),
        "unique_span_count": len(span_id_set),
        "correlation_id": correlation_id,
        "joined_span_ids": span_ids,
        "topology_errors": topology_errors,
    }
    trace = {"trace_id": trace_id, "correlation_id": correlation_id, "root_span_id": root_span["span_id"], "span_count": len(spans), "spans": spans, "final_join": final_join}
    proposal["final_diagnosis"] = {"root_cause": cause, "evidence_ids": evidence_ids, "confidence": confidence}
    proposal["status"] = "awaiting_approval" if final_status == "awaiting_approval" else ("approved" if approved_flag else "diagnosed")
    diagnosis = {
        "cause": cause,
        "root_cause": cause,
        "summary": cause_summary,
        "confidence": confidence,
        "severity": severity,
        "evidence": legacy_evidence,
        "evidence_ids": evidence_ids,
        "required_evidence_ids": evidence_ids,
    }
    decision = {
        "action": action,
        "proposed_action": action,
        "action_tool": str(required_action_tool),
        "permitted": permitted,
        "approved": approved_flag,
        "requires_human_approval": needs_approval,
        "status": action_result["status"],
        "reason": action_reason,
        "arguments": action_args,
        "policy_checks": {"scaling_limit_reached": cap_reached, "scaling_blocked_at_limit": cap_reached, "explicit_action_allowlist_present": explicit_allowed_actions(incident_clean) is not None},
    }
    redaction = {"applied": bool(redaction_paths), "redacted_field_count": len(redaction_paths), "redacted_paths": sorted(set(redaction_paths))[:100], "raw_request_persisted": False}
    response = {
        "ok": True,
        "api_version": "v2",
        "status": final_status,
        "run_id": run_id,
        "incident_id": incident_id,
        "correlation_id": correlation_id,
        "trace_id": trace_id,
        "proposal": proposal,
        "diagnosis": diagnosis,
        "diagnostics": dispatches,
        "diagnostic_tool_dispatches": dispatches,
        "decision": decision,
        "action_result": action_result,
        "action": action_result,
        "telemetry": telemetry,
        "trace": trace,
        "lifecycle": lifecycle,
        "redaction": redaction,
        "audit": {
            "persisted": True,
            "proposal_preceded_effects": True,
            "action_result_id": action_result_id,
            "telemetry_action_result_id": telemetry.get("action_result_id"),
            "matching_action_result_and_telemetry": action_result_id == telemetry.get("action_result_id"),
            "correlation_ids_match": all(x == correlation_id for x in (telemetry["correlation_id"], trace["correlation_id"], proposal["correlation_id"])),
            "topology_valid": not topology_errors,
            "redaction_applied_before_persistence": True,
        },
        "created_at": created_at,
        "updated_at": utc_now(),
    }
    response = redact_data(response)[0]
    # Update persistent response and write all trace/tool/action/telemetry records.
    with db_connect() as conn:
        conn.execute("UPDATE v2_incidents SET status=?,updated_at=?,proposal_json=?,response_json=? WHERE run_id=?", (final_status, response["updated_at"], json_dumps(proposal), json_dumps(response), run_id))
        conn.executemany(
            "INSERT INTO v2_spans(span_id,run_id,trace_id,parent_span_id,name,kind,status,started_at,ended_at,attributes_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
            [(s["span_id"], run_id, trace_id, s.get("parent_span_id"), s["name"], s["kind"], s["status"], s["started_at"], s["ended_at"], json_dumps(s["attributes"])) for s in spans],
        )
        conn.executemany(
            "INSERT INTO v2_tool_runs(tool_run_id,run_id,trace_id,correlation_id,tool_name,arguments_json,result_json,status,read_only,span_id,started_at,ended_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            [(t["tool_run_id"], run_id, trace_id, correlation_id, t["tool_name"], json_dumps(t["arguments"]), json_dumps(t["result"]), t["status"], 1 if t["read_only"] else 0, t["span_id"], t["started_at"], t["ended_at"]) for t in tool_runs],
        )
        conn.execute(
            "INSERT INTO v2_actions(action_result_id,run_id,correlation_id,action,status,approved,arguments_json,result_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (action_result_id, run_id, correlation_id, action, action_result["status"], 1 if action_result.get("approved") else 0, json_dumps(action_args), json_dumps(action_result), action_result["created_at"]),
        )
        conn.execute(
            "INSERT INTO v2_telemetry(telemetry_id,run_id,trace_id,correlation_id,action_result_id,event_type,created_at,payload_json) VALUES(?,?,?,?,?,?,?,?)",
            (telemetry_id, run_id, trace_id, correlation_id, action_result_id, telemetry["event_type"], telemetry["created_at"], json_dumps(telemetry)),
        )
        conn.executemany(
            "INSERT INTO v2_lifecycle(lifecycle_event_id,run_id,from_state,to_state,actor,created_at,details_json) VALUES(?,?,?,?,?,?,?)",
            [(e["lifecycle_event_id"], run_id, e.get("from_state"), e["to_state"], e["actor"], e["created_at"], json_dumps(e["details"])) for e in lifecycle[2:]],
        )
    return response


@app.post("/v2/incidents")
async def v2_create_incident(request: Request) -> Dict[str, Any]:
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type != "application/json":
        raise HTTPException(status_code=415, detail="Content-Type must be application/json")
    raw_body = await request.body()
    if len(raw_body) > V2_MAX_REQUEST_BYTES:
        raise HTTPException(status_code=413, detail=f"JSON request exceeds {V2_MAX_REQUEST_BYTES} byte limit")
    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(status_code=400, detail="Request body must be valid UTF-8 JSON")
    incident, payload = validate_v2_payload(payload)
    idempotency_key = request.headers.get("idempotency-key") or request.headers.get("x-idempotency-key")
    if idempotency_key is not None:
        idempotency_key = idempotency_key.strip()[:200]
        if not idempotency_key:
            raise HTTPException(status_code=422, detail="Idempotency-Key must not be blank")
    return build_v2_incident(payload, request, raw_body, incident, idempotency_key)


@app.get("/v2/incidents")
def v2_list_incidents(limit: int = 50, correlation_id: Optional[str] = None) -> Dict[str, Any]:
    limit = max(1, min(limit, 200))
    with db_connect() as conn:
        if correlation_id:
            rows = conn.execute("SELECT run_id,incident_id,correlation_id,trace_id,status,created_at,updated_at,response_json FROM v2_incidents WHERE correlation_id=? ORDER BY created_at DESC LIMIT ?", (correlation_id, limit)).fetchall()
        else:
            rows = conn.execute("SELECT run_id,incident_id,correlation_id,trace_id,status,created_at,updated_at,response_json FROM v2_incidents ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return {"ok": True, "count": len(rows), "incidents": [{"run_id": r["run_id"], "incident_id": r["incident_id"], "correlation_id": r["correlation_id"], "trace_id": r["trace_id"], "status": r["status"], "created_at": r["created_at"], "updated_at": r["updated_at"]} for r in rows]}


@app.get("/v2/incidents/{run_id}")
def v2_get_incident(run_id: str) -> Dict[str, Any]:
    result = v2_get_response(run_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Version 2 incident run not found")
    return result


@app.get("/v2/incidents/{run_id}/trace")
def v2_get_trace(run_id: str) -> Dict[str, Any]:
    row = v2_get_row(run_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Version 2 incident run not found")
    response = json.loads(row["response_json"])
    return {"ok": True, "run_id": row["run_id"], "trace": response.get("trace"), "correlation_id": row["correlation_id"]}


@app.get("/v2/incidents/{run_id}/lifecycle")
def v2_get_lifecycle(run_id: str) -> Dict[str, Any]:
    row = v2_get_row(run_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Version 2 incident run not found")
    with db_connect() as conn:
        rows = conn.execute("SELECT lifecycle_event_id,from_state,to_state,actor,created_at,details_json FROM v2_lifecycle WHERE run_id=? ORDER BY created_at", (row["run_id"],)).fetchall()
    events = [{"lifecycle_event_id": r["lifecycle_event_id"], "from_state": r["from_state"], "to_state": r["to_state"], "actor": r["actor"], "created_at": r["created_at"], "details": json.loads(r["details_json"])} for r in rows]
    return {"ok": True, "run_id": row["run_id"], "status": row["status"], "events": events}


@app.get("/v2/incidents/{run_id}/tools")
def v2_get_tools(run_id: str) -> Dict[str, Any]:
    row = v2_get_row(run_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Version 2 incident run not found")
    with db_connect() as conn:
        rows = conn.execute("SELECT tool_run_id,tool_name,arguments_json,result_json,status,read_only,span_id,started_at,ended_at FROM v2_tool_runs WHERE run_id=? ORDER BY started_at", (row["run_id"],)).fetchall()
    items = [{"tool_run_id": r["tool_run_id"], "tool_name": r["tool_name"], "arguments": json.loads(r["arguments_json"]), "result": json.loads(r["result_json"]), "status": r["status"], "read_only": bool(r["read_only"]), "span_id": r["span_id"], "started_at": r["started_at"], "ended_at": r["ended_at"]} for r in rows]
    return {"ok": True, "run_id": row["run_id"], "count": len(items), "tool_dispatches": items}


@app.get("/v2/telemetry")
def v2_get_telemetry(run_id: Optional[str] = None, correlation_id: Optional[str] = None, limit: int = 100) -> Dict[str, Any]:
    limit = max(1, min(limit, 500))
    clauses, args = [], []
    if run_id:
        clauses.append("run_id=?")
        args.append(run_id)
    if correlation_id:
        clauses.append("correlation_id=?")
        args.append(correlation_id)
    sql = "SELECT telemetry_id,run_id,trace_id,correlation_id,action_result_id,event_type,created_at,payload_json FROM v2_telemetry"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY created_at DESC LIMIT ?"
    args.append(limit)
    with db_connect() as conn:
        rows = conn.execute(sql, args).fetchall()
    return {"ok": True, "count": len(rows), "telemetry": [{"telemetry_id": r["telemetry_id"], "run_id": r["run_id"], "trace_id": r["trace_id"], "correlation_id": r["correlation_id"], "action_result_id": r["action_result_id"], "event_type": r["event_type"], "created_at": r["created_at"], "payload": json.loads(r["payload_json"])} for r in rows]}


@app.get("/v2/state")
def v2_state() -> Dict[str, Any]:
    with db_connect() as conn:
        counts = {"incidents": conn.execute("SELECT COUNT(*) FROM v2_incidents").fetchone()[0], "spans": conn.execute("SELECT COUNT(*) FROM v2_spans").fetchone()[0], "tool_runs": conn.execute("SELECT COUNT(*) FROM v2_tool_runs").fetchone()[0], "actions": conn.execute("SELECT COUNT(*) FROM v2_actions").fetchone()[0], "telemetry": conn.execute("SELECT COUNT(*) FROM v2_telemetry").fetchone()[0], "lifecycle_events": conn.execute("SELECT COUNT(*) FROM v2_lifecycle").fetchone()[0]}
    return {"ok": True, "api_version": "v2", "counts": counts}


@app.post("/v2/incidents/{run_id}/approve")
async def v2_approve_incident(run_id: str, request: Request) -> Dict[str, Any]:
    row = v2_get_row(run_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Version 2 incident run not found")
    try:
        body = await request.json()
    except Exception:
        body = None
    if not isinstance(body, dict) or body.get("approved") is not True or not (body.get("approved_by") or body.get("approver")):
        raise HTTPException(status_code=422, detail="Approval requires approved=true and an approved_by/approver identity")
    response = json.loads(row["response_json"])
    if response.get("status") != "awaiting_approval":
        raise HTTPException(status_code=409, detail="This incident has no pending approval")
    now = utc_now()
    approval = {"approved": True, "approved_by": str(body.get("approved_by") or body.get("approver"))[:200], "approved_at": now, "approval_reference": body.get("approval_reference")}
    response["approval"] = redact_data(approval)[0]
    response["status"] = "approved"
    response["decision"]["approved"] = True
    response["action_result"]["approved"] = True
    response["action_result"]["status"] = "approved_not_executed"
    response["action_result"]["result"] = {"executed": False, "reason": "Approval recorded. Call the execute endpoint to run the approved action."}
    response["lifecycle"].append(v2_lifecycle_event(row["run_id"], "awaiting_approval", "approved", approval["approved_by"], {"approval_reference": approval.get("approval_reference")}))
    response["updated_at"] = now
    with db_connect() as conn:
        conn.execute("UPDATE v2_incidents SET status='approved',updated_at=?,response_json=? WHERE run_id=?", (now, json_dumps(response), row["run_id"]))
        conn.execute("UPDATE v2_actions SET status='approved',approved=1,result_json=? WHERE run_id=?", (json_dumps(response["action_result"]), row["run_id"]))
        event = response["lifecycle"][-1]
        conn.execute("INSERT INTO v2_lifecycle(lifecycle_event_id,run_id,from_state,to_state,actor,created_at,details_json) VALUES(?,?,?,?,?,?,?)", (event["lifecycle_event_id"], row["run_id"], event["from_state"], event["to_state"], event["actor"], event["created_at"], json_dumps(event["details"])))
    return response


@app.post("/v2/incidents/{run_id}/execute")
def v2_execute_approved_incident(run_id: str) -> Dict[str, Any]:
    row = v2_get_row(run_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Version 2 incident run not found")
    response = json.loads(row["response_json"])
    if response.get("status") != "approved" or response.get("action_result", {}).get("approved") is not True:
        raise HTTPException(status_code=409, detail="An approved lifecycle state is required before execution")
    action = response["decision"]["action"]
    original_payload = json.loads(row["payload_redacted_json"])
    incident = {k: v for k, v in v2_unwrap(original_payload).items() if k not in {"tools", "available_tools", "tool_catalog", "required_tool_calls", "required_tool_call", "required_tool", "tool_calls", "tool_arguments", "required_tool_arguments", "diagnostic_tools", "required_tools", "required_diagnostics", "required_action_tool", "required_action_call", "action_arguments", "required_action_arguments"}}
    cap_reached, _ = determine_capacity_limit(incident)
    if action == "scale_out" and cap_reached:
        raise HTTPException(status_code=409, detail="Scaling is blocked because the service is at its configured maximum")
    permitted, reason = action_permitted(action, incident, cap_reached)
    if not permitted:
        raise HTTPException(status_code=403, detail=f"Action is not permitted: {reason}")
    run_id_value = row["run_id"]
    action_result_id = response["action_result"]["action_result_id"]
    fresh_result = execute_action(action, incident, run_id_value, row["incident_id"], response["diagnosis"]["cause"], response["diagnosis"].get("evidence", []))
    fresh_result.update({"action_result_id": action_result_id, "action_id": action_result_id, "run_id": run_id_value, "correlation_id": row["correlation_id"], "approved": True, "requires_approval": True, "arguments": response["decision"].get("arguments", {})})
    fresh_result = redact_data(fresh_result)[0]
    response["action_result"] = fresh_result
    response["action"] = fresh_result
    response["decision"]["status"] = fresh_result["status"]
    response["status"] = "completed" if fresh_result.get("success") else "action_failed"
    old_tel = response["telemetry"]
    new_tel_id = f"tel-{uuid.uuid4().hex}"
    new_payload = {**old_tel, "telemetry_id": new_tel_id, "action_status": fresh_result["status"], "action_success": fresh_result.get("success", False), "observed_at": utc_now()}
    new_payload.pop("payload_sha256", None)
    new_payload["payload_sha256"] = hashlib.sha256(json_dumps(new_payload).encode("utf-8")).hexdigest()
    response["telemetry"] = new_payload
    response["audit"]["action_result_id"] = action_result_id
    response["audit"]["telemetry_action_result_id"] = new_payload["action_result_id"]
    response["audit"]["matching_action_result_and_telemetry"] = action_result_id == new_payload["action_result_id"]
    now = utc_now()
    response["updated_at"] = now
    lifecycle_event = v2_lifecycle_event(run_id_value, "approved", response["status"], "agent", {"action_result_id": action_result_id})
    response["lifecycle"].append(lifecycle_event)
    with db_connect() as conn:
        conn.execute("UPDATE v2_incidents SET status=?,updated_at=?,response_json=? WHERE run_id=?", (response["status"], now, json_dumps(response), run_id_value))
        conn.execute("UPDATE v2_actions SET status=?,approved=1,result_json=? WHERE run_id=?", (fresh_result["status"], json_dumps(fresh_result), run_id_value))
        conn.execute("INSERT INTO v2_telemetry(telemetry_id,run_id,trace_id,correlation_id,action_result_id,event_type,created_at,payload_json) VALUES(?,?,?,?,?,?,?,?)", (new_tel_id, run_id_value, row["trace_id"], row["correlation_id"], action_result_id, "incident_action_execution", now, json_dumps(new_payload)))
        conn.execute("INSERT INTO v2_lifecycle(lifecycle_event_id,run_id,from_state,to_state,actor,created_at,details_json) VALUES(?,?,?,?,?,?,?)", (lifecycle_event["lifecycle_event_id"], run_id_value, lifecycle_event["from_state"], lifecycle_event["to_state"], lifecycle_event["actor"], lifecycle_event["created_at"], json_dumps(lifecycle_event["details"])))
    return response


@app.post("/v2/incidents/{run_id}/replay")
def v2_replay_incident(run_id: str) -> Dict[str, Any]:
    row = v2_get_row(run_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Version 2 incident run not found")
    response = json.loads(row["response_json"])
    # Replay is read-only: never run tool dispatch or an action again.
    return {"ok": True, "replayed": True, "replay_mode": "read_only_no_action_repeated", "run_id": row["run_id"], "snapshot": response}


@app.get("/v2/actions")
def v2_get_actions(run_id: Optional[str] = None, limit: int = 100) -> Dict[str, Any]:
    limit = max(1, min(limit, 500))
    with db_connect() as conn:
        if run_id:
            rows = conn.execute("SELECT action_result_id,run_id,correlation_id,action,status,approved,arguments_json,result_json,created_at FROM v2_actions WHERE run_id=? ORDER BY created_at DESC LIMIT ?", (run_id, limit)).fetchall()
        else:
            rows = conn.execute("SELECT action_result_id,run_id,correlation_id,action,status,approved,arguments_json,result_json,created_at FROM v2_actions ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return {"ok": True, "count": len(rows), "actions": [{"action_result_id": r["action_result_id"], "run_id": r["run_id"], "correlation_id": r["correlation_id"], "action": r["action"], "status": r["status"], "approved": bool(r["approved"]), "arguments": json.loads(r["arguments_json"]), "result": json.loads(r["result_json"]), "created_at": r["created_at"]} for r in rows]}


# Replace the old root's endpoint listing in-place after route registration.
# This endpoint remains simple and does not include secrets or raw incident data.
@app.get("/v2/health")
def v2_health() -> Dict[str, Any]:
    try:
        with db_connect() as conn:
            conn.execute("SELECT 1 FROM v2_incidents LIMIT 1").fetchone()
        return {"ok": True, "status": "healthy", "api_version": "v2", "timestamp": utc_now()}
    except Exception as exc:
        return JSONResponse(status_code=503, content={"ok": False, "status": "degraded", "error": type(exc).__name__})


@app.get("/v2")
def v2_contract() -> Dict[str, Any]:
    return {
        "name": APP_NAME,
        "api_version": "v2",
        "status": "ok",
        "content_type": "application/json",
        "endpoints": {
            "create_incident": "POST /v2/incidents",
            "get_incident": "GET /v2/incidents/{run_id}",
            "get_proposal": "GET /v2/incidents/{run_id}/proposal",
            "get_trace": "GET /v2/incidents/{run_id}/trace",
            "get_tools": "GET /v2/incidents/{run_id}/tools",
            "get_lifecycle": "GET /v2/incidents/{run_id}/lifecycle",
            "approve": "POST /v2/incidents/{run_id}/approve",
            "execute": "POST /v2/incidents/{run_id}/execute",
            "replay": "POST /v2/incidents/{run_id}/replay",
            "telemetry": "GET /v2/telemetry",
            "state": "GET /v2/state",
        },
        "safety": {"scaling_blocked_at_limit": True, "disruptive_actions_require_approval": True, "replay_repeats_actions": False},
    }


@app.get("/v2/incidents/{run_id}/proposal")
def v2_get_proposal(run_id: str) -> Dict[str, Any]:
    result = v2_get_response(run_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Version 2 incident run not found")
    return {"ok": True, "run_id": result["run_id"], "incident_id": result["incident_id"], "correlation_id": result["correlation_id"], "proposal": result["proposal"]}


@app.get("/v2/incidents/{run_id}/telemetry")
def v2_get_incident_telemetry(run_id: str) -> Dict[str, Any]:
    row = v2_get_row(run_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Version 2 incident run not found")
    with db_connect() as conn:
        rows = conn.execute("SELECT telemetry_id,trace_id,correlation_id,action_result_id,event_type,created_at,payload_json FROM v2_telemetry WHERE run_id=? ORDER BY created_at", (row["run_id"],)).fetchall()
    return {"ok": True, "run_id": row["run_id"], "count": len(rows), "telemetry": [{"telemetry_id": r["telemetry_id"], "trace_id": r["trace_id"], "correlation_id": r["correlation_id"], "action_result_id": r["action_result_id"], "event_type": r["event_type"], "created_at": r["created_at"], "payload": json.loads(r["payload_json"])} for r in rows]}
