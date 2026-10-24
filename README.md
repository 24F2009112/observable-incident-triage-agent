# Observable Incident Triage Agent

A small public HTTPS incident-agent API designed around safe diagnosis, targeted diagnostics, policy-gated responses, persistent action results, linked telemetry, and replay.

## Important behavior

- Diagnoses from structured incident evidence (CPU/memory/disk, latency/error rate, database/dependency signals, deployment changes, and scaling capacity).
- Runs a small set of relevant read-only diagnostics instead of every probe.
- **Never scales when capacity is already at its configured maximum.** It pages the owner instead, as required.
- Honors an explicit `permitted_actions` / `allowed_actions` list when one is supplied.
- Persists every check, action result, telemetry event, and save snapshot in SQLite.
- Links telemetry to the exact `action_result_id` and `check_id`; Save refuses inconsistent IDs.
- Replay returns the saved snapshot without executing the action a second time.
- Uses no paid AI model or API key.

## Deploy to Render

1. Create a GitHub repository named `observable-incident-triage-agent`.
2. Put `app.py`, `requirements.txt`, `render.yaml`, `.gitignore`, `smoke_test.py`, and `README.md` in the repository root.
3. Push the repository to GitHub.
4. In Render, choose **New + → Blueprint**, select this repository, and deploy. Alternatively create a Python Web Service using build command `pip install -r requirements.txt` and start command `uvicorn app:app --host 0.0.0.0 --port $PORT`.
5. After deployment, set `PUBLIC_BASE_URL` to your Render URL if desired, redeploy, and wait until `/health` returns `{"ok":true,...}`.
6. Paste the base URL (for example `https://observable-incident-triage-agent.onrender.com`) into the challenge.
7. Open `https://YOUR-URL/docs` to inspect/test the API.

## Endpoints

- `GET /health` and `GET /healthz`
- `GET /.well-known/agent-card.json` and `GET /.well-known/agent.json`
- `POST /check` (aliases: `/api/check`, `/triage`, `/incident/check`, `/api/incident/check`, `/v1/incidents/check`, `/api/v1/incidents/check`)
- `POST /save` (aliases: `/api/save`, `/incident/save`, `/api/incident/save`, `/v1/incidents/save`, `/api/v1/incidents/save`)
- `POST /replay` (read-only replay of saved output)
- `GET /state`, `GET /telemetry`, `GET /actions`, `GET /incidents`
- `POST /a2a` or `/rpc` for basic JSON-RPC compatibility

## Example check request

```json
{
  "incident_id": "inc-123",
  "service": "checkout-api",
  "severity": "critical",
  "symptoms": ["high latency", "HTTP 503 spike"],
  "metrics": {"cpu_percent": 97, "p95_latency_ms": 2400, "error_rate_percent": 12},
  "current_replicas": 8,
  "max_replicas": 8,
  "permitted_actions": ["page_owner", "scale_out"]
}
```

At maximum capacity the expected decision is `page_owner`; the executor has a separate hard guard that blocks `scale_out` even if requested. For rollback, supply a confirmed rollback candidate/permission; for failover, supply a healthy failover target and permission.

## Local test

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
uvicorn app:app --reload
```

In another terminal:

```powershell
python smoke_test.py http://127.0.0.1:8000
```

For a deployed service, replace the URL with your Render URL only when you are comfortable writing a test record. The smoke test creates a test incident and calls `/save`; because the challenge says only the most recent Save counts, run it locally first and avoid running it against the deployed URL immediately before your final challenge Save.

## Honest integration boundary

The default executor writes durable, auditable operations records and does **not** modify actual cloud infrastructure or deliver external pages. Before using this against production, connect the executor to your approved paging, deployment, or autoscaling API and retain the same policy gates and telemetry-link validation. Do not treat a recorded scale/rollback/failover request as proof that production infrastructure changed.

## Persistence note

SQLite data on Render's free filesystem may be lost on redeploy/restart. That is enough for simple evaluation during a live deployment, but if the evaluator expects state to survive restarts, attach a persistent disk or switch to a managed PostgreSQL database and update the database layer.
