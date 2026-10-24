"""Smoke-test the deployed incident-agent API. Usage: python smoke_test.py https://your-service.onrender.com"""
import json
import sys
import urllib.error
import urllib.request


def call(base, path, method="GET", payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(base.rstrip("/") + path, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=25) as response:
            raw = response.read().decode()
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        raise AssertionError(f"{method} {path}: HTTP {exc.code}: {raw}") from exc


def require(condition, message):
    if not condition:
        raise AssertionError(message)
    print("PASS", message)


def main():
    if len(sys.argv) != 2:
        print("Usage: python smoke_test.py https://your-service.onrender.com")
        raise SystemExit(2)
    base = sys.argv[1].rstrip("/")
    status, health = call(base, "/health")
    require(status == 200 and health.get("ok") is True, "health endpoint")
    status, card = call(base, "/.well-known/agent-card.json")
    require(status == 200 and card.get("name") and card.get("skills"), "Agent Card contract")

    # Hard safety scenario: no scaling action may occur at the configured maximum.
    case = {
        "incident_id": "smoke-capacity-limit",
        "service": "checkout-api",
        "severity": "critical",
        "symptoms": ["high latency", "HTTP 503 spike"],
        "metrics": {"cpu_percent": 97, "p95_latency_ms": 2400, "error_rate_percent": 12},
        "current_replicas": 8,
        "max_replicas": 8,
        "permitted_actions": ["page_owner", "scale_out"],
    }
    status, checked = call(base, "/check", "POST", case)
    require(status == 200 and checked.get("ok") is True, "incident check completes")
    require(checked.get("diagnosis", {}).get("cause") == "capacity_limit_reached", "scaling-limit diagnosis")
    require(checked.get("decision", {}).get("action") == "page_owner", "page owner at scaling limit (never scale)")
    action = checked.get("action_result", {})
    telemetry = checked.get("telemetry", {})
    require(action.get("action_result_id") == telemetry.get("action_result_id"), "action result matches telemetry")

    status, saved = call(base, "/save", "POST", {"check_id": checked["check_id"]})
    require(status == 200 and saved.get("saved") is True, "save persists latest result")
    require(saved.get("audit", {}).get("matching_action_result_and_telemetry") is True, "saved action and telemetry IDs match")

    status, replayed = call(base, "/replay", "POST", {"check_id": checked["check_id"]})
    require(status == 200 and replayed.get("replayed") is True, "replay returns saved snapshot")
    require(replayed.get("replay_mode") == "read_only_no_action_repeated", "replay does not repeat action")

    status, state = call(base, "/state")
    require(status == 200 and state.get("counts", {}).get("checks", 0) >= 1, "stored state is queryable")
    print("ALL SMOKE TESTS PASSED")


if __name__ == "__main__":
    main()
