# Observable Incident Triage Agent

A public HTTPS FastAPI service for incident diagnosis, scoped read-only diagnostics, policy-gated remediation, correlation, traces, audit telemetry, and replay. It does not require an OpenAI key.

## The important fix

The evaluator calls **`POST /v2/incidents`**. This route now exists, validates input, responds with JSON, and returns the proposal, evidence references, diagnostic tool dispatches, action decision/result, trace topology, lifecycle events, correlation IDs, redaction metadata, and matching telemetry.

## Deploy on Render

This repository includes `render.yaml`. In Render select **New + → Blueprint**, connect this GitHub repository, and deploy. Alternatively use a Python web service:

- Build: `pip install -r requirements.txt`
- Start: `uvicorn app:app --host 0.0.0.0 --port $PORT`
- Health: `/v2/health` or `/health`

The application stores state in SQLite at `DATABASE_PATH`. The current Render configuration defaults to `/tmp/incident_agent.sqlite3`, which persists across requests on the live instance, but Render's free filesystem is not durable across redeploys/restarts. For strict cross-restart durability, configure a persistent disk or managed PostgreSQL database and point `DATABASE_PATH` to persistent storage.

## v2 endpoints

- `GET /v2/health`
- `POST /v2/incidents` — validates and creates an incident run, proposes a root cause, dispatches targeted read-only diagnostic tools, selects a permitted response, writes an action result and matching telemetry, and builds a joined trace.
- `GET /v2/incidents` — list runs.
- `GET /v2/incidents/{run_id}` — retrieve the saved incident result.
- `GET /v2/incidents/{run_id}/trace` — trace and final join.
- `GET /v2/incidents/{run_id}/tools` — diagnostic dispatches and their results.
- `GET /v2/incidents/{run_id}/lifecycle` — state changes.
- `POST /v2/incidents/{run_id}/approve` — record an explicit human approval for a pending disruptive action.
- `POST /v2/incidents/{run_id}/execute` — execute only an approved, still-permitted action.
- `POST /v2/incidents/{run_id}/replay` — replay the saved result without repeating tools/actions.
- `GET /v2/telemetry`, `GET /v2/actions`, and `GET /v2/state`.

The earlier `/check`, `/save`, `/replay`, `/telemetry`, `/actions` and `/state` endpoints remain for backwards compatibility.

## Example request

```json
{
  "incident_id": "checkout-503-001",
  "service": "checkout-api",
  "severity": "critical",
  "symptoms": ["high latency", "HTTP 503 spike"],
  "metrics": {
    "cpu_percent": 97,
    "p95_latency_ms": 2400,
    "error_rate_percent": 12
  },
  "current_replicas": 8,
  "max_replicas": 8,
  "permitted_actions": ["page_owner", "scale_out"]
}
```

When current replicas are at the configured maximum, the hard guard selects `page_owner` and blocks scaling even if scaling appears in the request's allowlist. Disruptive actions (`scale_out`, `rollback`, and `failover`) require an explicit approval state before they can execute. `page_owner` is recorded by the bundled local adapter; it does **not** mean an external paging provider was contacted. To perform actual production effects, connect an approved paging/deployment/autoscaling adapter and preserve the current policy gates.

## Proposal, trace, correlation, durability, redaction

- The proposal and evidence references are persisted before dispatching any action.
- Diagnostic dispatches are read-only and limited to the selected cause.
- Trace spans have unique IDs, consistent trace IDs, resolvable parent links and a final join record.
- `X-Correlation-ID` and `Idempotency-Key` are supported. Reusing an idempotency key with a different body returns `409`.
- Action results and telemetry carry the same `action_result_id`; replay never executes the action again.
- API keys, auth tokens, passwords, email fields, inline bearer tokens, common secret prefixes, and JWT-like strings are redacted before response/persistence. The original raw request body is not stored.
- Empty or semantically unsupported payloads return `422`; malformed JSON returns `400`; requests above 1 MiB return `413`; a non-JSON content type returns `415`.

## Local setup on Windows PowerShell

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
uvicorn app:app --reload
```

In another PowerShell window:

```powershell
python v2_contract_test.py http://127.0.0.1:8000
python smoke_test.py http://127.0.0.1:8000
```

The test scripts should be run locally first. Avoid running write tests against the challenge URL immediately before the final Save, because the challenge says only the most recent Save counts and each Check/Save consumes a quota slot.
