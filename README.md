# Prompt_Injection_Trigger

Steps to set up a prompt injection simulation and the watsonx Orchestrate controls that mitigate it.

## PI Trigger: prompt injection guard for watsonx Orchestrate

A watsonx Orchestrate (wxO) control that checks every user message before the agent sees it.
If the message looks like a prompt injection, it is blocked and a ServiceNow incident is raised
with the agent as caller. The guard service is a small FastAPI app that runs on IBM Cloud Code Engine.

```
wxO agent -> control (agent_pre_invoke) -> OpenAPI tool -> HTTPS -> FastAPI service -> ServiceNow
```

Full documentation, architecture diagrams, step-by-step setup and test prompts:
**[docs/PI_GUARD.md](docs/PI_GUARD.md)**

## Layout

| Path | Purpose |
|---|---|
| `server/pi_guard_core.py` | Detection rules and ServiceNow incident helper |
| `server/pi_guard_server.py` | FastAPI plug-in endpoint (`POST /agent_pre_invoke`, `GET /health`) |
| `Dockerfile`, `requirements.txt` | Container build for Code Engine |
| `openapi/pi_guard_plugin.yaml` | Plug-in tool definition imported into wxO |
| `agents/pi_guard_test_agent.yaml` | Sandbox agent for testing |
| `scripts/` | Control artifact registration, ServiceNow caller provisioning, ticket listing |
| `tests/test_detect.py` | Local detector tests |

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install "ibm-watsonx-orchestrate==2.18.2" fastapi "uvicorn[standard]"
cp .env.example .env        # fill in credentials
.venv/bin/python tests/test_detect.py
.venv/bin/uvicorn server.pi_guard_server:app --port 8765
```

Deploying to Code Engine and wiring up wxO is covered in section 4 of the documentation.

## Security notes

- Never commit `.env` or `secrets.txt` (both are in `.gitignore`).
- The endpoint has no authentication unless `PI_GUARD_TOKEN` is set. See Part D of the documentation.
- The detector is rule-based and misses paraphrases, other languages and obfuscated text.
