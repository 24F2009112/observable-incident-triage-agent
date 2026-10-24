# Observable Incident Triage Agent — GA5 v2 contract

This service implements the receipt-driven contract at `POST /v2/incidents`, `POST /v2/incidents/{runId}/receipts`, and `GET /v2/incidents/{runId}`. It does not execute tools directly; the grader's authoritative receipts drive retries, approval state, terminal state, and audit logging.

## Required model configuration

The contract requires a real OpenAI planning call for every first-seen `runId`. Configure these variables in Render → Environment:

- `OPENAI_API_KEY`: your OpenAI API key. Set it only as a Render secret; never commit it.
- `OPENAI_MODEL`: optional model override. Defaults to `gpt-4.1-mini`.

The service calls OpenAI's official API at `https://api.openai.com/v1/chat/completions`. It intentionally ignores legacy Gemini settings and `LLM_BASE_URL`, so stale settings cannot silently route requests to another provider. The service never accepts an API key from the challenge form. If the key is missing, `POST /v2/incidents` returns a safe 503 and does not create a run.

The planner receives the transcript, allowed root causes, tool catalog and policy but not the top-level `sensitive` object. Model request span attributes record only the configured model name; prompts and transcript are not recorded in OTLP. Receipt handling and replay never call the model.

## Routes

- `POST /v2/incidents`: validates the exact GA5 profile, calls the model once for first-seen run IDs, returns diagnosis and 1–3 diagnostic dispatches.
- `POST /v2/incidents/{runId}/receipts`: validates and stores grader outcomes/approval decisions, performs the single allowed 503 retry, suppresses dependent effects after diagnostic failures/timeouts, and emits an effect only after successful diagnostics and approval when required.
- `GET /v2/incidents/{runId}`: returns the current stored state.
- `GET /v2/health`, `GET /health`, `GET /v2`, and `/docs` are operational helpers.

Run IDs and receipt IDs are idempotent. Same request/receipt content replays stored JSON; changed content for an existing ID returns 409. SQLite stores state before responses are returned. `DATABASE_PATH` can point at persistent storage; Render's free ephemeral filesystem is not durable across instance replacement.

## Local run and protocol tests (PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:PLANNER_TEST_MODE = "true"
uvicorn app:app --reload
```

In a second PowerShell window:

```powershell
python protocol_test.py http://127.0.0.1:8000
```

`PLANNER_TEST_MODE=true` is a deterministic test stub only. **Do not set it in Render**; remove it if it exists in service Environment. Render must have the model API key so each new grader run makes a real planning call. Unset the test mode before using a production provider locally:

```powershell
Remove-Item Env:PLANNER_TEST_MODE -ErrorAction SilentlyContinue
```

## Security and trace notes

The top-level `sensitive` object is excluded from model input and is never stored or returned. OTLP includes only contract-required correlation and span attributes; it never includes transcripts, prompts, tool arguments/results, authorization values, or raw observation bodies. Approval digests are SHA-256 of recursively key-sorted compact JSON. The agent returns dispatches but does not perform real production effects; tool outcomes are authoritative receipts supplied by the challenge runner.


## Planner safety update (v2.2.0)
The OpenAI planning prompt explicitly enforces the challenge's scaling-limit rule: when replicas are already at the permitted maximum, it must not select a capacity-increasing effect and should choose `page_owner` when that tool is permitted. It also explicitly prohibits arbitrary diagnostic argument values, including unsupported generic time windows. This is a prompt-level improvement; the hidden challenge must still verify exact incident-specific choices.
