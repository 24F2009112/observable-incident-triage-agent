"""Local contract test for the v2 observable incident agent.

Run with the server started in another terminal:
    python v2_contract_test.py http://127.0.0.1:8000
It never needs an OpenAI API key and does not call any external production system.
"""
import json
import sys
import urllib.error
import urllib.request


def call(base, path, method="GET", payload=None, headers=None):
    all_headers = {"Accept": "application/json"}
    if payload is not None:
        all_headers["Content-Type"] = "application/json"
    all_headers.update(headers or {})
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(base.rstrip("/") + path, data=data, method=method, headers=all_headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            body = response.read().decode("utf-8")
            return response.status, response.headers.get("Content-Type", ""), json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        try:
            decoded = json.loads(body)
        except Exception:
            decoded = {"raw": body}
        return exc.code, exc.headers.get("Content-Type", ""), decoded


def require(condition, message):
    if not condition:
        raise AssertionError(message)
    print("PASS", message)


def main():
    if len(sys.argv) != 2:
        print("Usage: python v2_contract_test.py http://127.0.0.1:8000")
        raise SystemExit(2)
    base = sys.argv[1]
    status, content_type, health = call(base, "/v2/health")
    require(status == 200 and health.get("ok") is True, "v2 health")
    status, content_type, invalid = call(base, "/v2/incidents", "POST", {})
    require(status in (400, 422), "invalid incident payload rejected with 400/422")

    case = {
        "incident_id": "test-capacity-limit",
        "service": "checkout-api",
        "severity": "critical",
        "symptoms": ["high latency", "HTTP 503 spike"],
        "metrics": {"cpu_percent": 97, "p95_latency_ms": 2400, "error_rate_percent": 12},
        "current_replicas": 8,
        "max_replicas": 8,
        "permitted_actions": ["page_owner", "scale_out"],
        "contact_email": "private@example.com",
        "notes": "Authorization: Bearer secret-token-for-testing",
    }
    status, content_type, result = call(base, "/v2/incidents", "POST", case, {"X-Correlation-ID": "test-correlation-001", "Idempotency-Key": "v2-contract-test-001"})
    require(status == 200 and "application/json" in content_type, "POST /v2/incidents responds 200 JSON")
    require(result.get("api_version") == "v2", "response identifies API version")
    require(result.get("proposal", {}).get("root_cause") == "capacity_limit_reached", "proposal identifies scaling capacity root cause")
    require("page_owner" == result.get("decision", {}).get("action"), "capacity guard pages owner instead of scaling")
    require(result.get("diagnostic_tool_dispatches"), "diagnostic tool dispatches are present")
    require(result.get("audit", {}).get("matching_action_result_and_telemetry") is True, "action/telemetry IDs match")
    trace = result.get("trace", {})
    spans = trace.get("spans", [])
    span_ids = [span.get("span_id") for span in spans]
    ids_set = set(span_ids)
    require(len(span_ids) >= 5 and len(span_ids) == len(ids_set), "trace contains unique spans")
    require(all(s.get("trace_id") == trace.get("trace_id") for s in spans), "trace continuity")
    require(all(s.get("parent_span_id") is None or s.get("parent_span_id") in ids_set for s in spans), "trace parent links valid")
    require(trace.get("final_join", {}).get("status") == "ok", "final trace join valid")
    serialized = json.dumps(result)
    require("private@example.com" not in serialized and "secret-token-for-testing" not in serialized, "response redacts email/token values")
    require(result.get("audit", {}).get("correlation_ids_match") is True, "correlation propagated")
    run_id = result["run_id"]
    status, _, replay = call(base, f"/v2/incidents/{run_id}/replay", "POST", {})
    require(status == 200 and replay.get("replayed") is True, "read-only replay works")
    status, _, detail = call(base, f"/v2/incidents/{run_id}")
    require(status == 200 and detail.get("run_id") == run_id, "durable incident retrieval works")
    status, _, telemetry = call(base, "/v2/telemetry", "GET")
    require(status == 200 and telemetry.get("count", 0) >= 1, "telemetry is queryable")
    print("ALL V2 CONTRACT TESTS PASSED")


if __name__ == "__main__":
    main()
