# Observable Incident Triage Agent — GA5 v2 contract

This service implements the receipt-driven contract at `POST /v2/incidents`, `POST /v2/incidents/{runId}/receipts`, and `GET /v2/incidents/{runId}`. It does not execute tools directly; the grader's authoritative receipts drive retries, approval state, terminal state, and audit logging.

## Required model configuration

The grader explicitly expects a real planning call for every first-seen `runId`. Configure a hosted model in Render Environment settings. The default provider is Gemini's OpenAI-compatible endpoint:

- `GEMINI_API_KEY`: your secret Google AI Studio API key (set only in Render Environment, never commit it)
- `LLM_BASE_URL`: `https://generativelanguage.googleapis.com/v1beta/openai/`
- `LLM_MODEL`: `gemini-3.8-flash`

Alternatively set `OPENAI_API_KEY` with an OpenAI-compatible provider, plus `LLM_BASE_URL` and `LLM_MODEL`. The service never takes a key from the challenge form. If the key is missing, `POST /v2/incidents` returns a safe 503 and does not create a run.

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
