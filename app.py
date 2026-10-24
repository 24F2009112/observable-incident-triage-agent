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
        "endpoints": {"health": "/health", "check": "/check", "save": "/save", "replay": "/replay", "state": "/state", "telemetry": "/telemetry"},
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
