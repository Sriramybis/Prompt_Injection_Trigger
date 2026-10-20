"""Prompt injection guard - OpenAPI plug-in service.

watsonx Orchestrate POSTs {payload, context} to /agent_pre_invoke before the
agent sees a message. We return continue_processing=false when the text looks
like a prompt injection, and raise a ServiceNow incident.

Run: .venv/bin/uvicorn server.pi_guard_server:app --port 8765
"""
import hmac
import json
import os
import pathlib
import sys
import urllib.parse
import urllib.request

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from pi_guard_core import _SSL_CTX, BLOCK_MESSAGE, THRESHOLD, _create_incident, detect_injection  # noqa: E402


def _load_env(path: pathlib.Path) -> None:
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())


_load_env(ROOT / ".env")

app = FastAPI(title="PI Guard Plug-in", version="1.0.0")


class PluginRequest(BaseModel):
    payload: dict
    context: dict = {}


_AGENT_NAMES: dict[str, str] = {}  # agent_id -> name; agent names rarely change


def _wxo_token() -> str:
    data = urllib.parse.urlencode({
        "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
        "apikey": os.environ["WxO_API_Key"],
    }).encode()
    with urllib.request.urlopen("https://iam.cloud.ibm.com/identity/token", data=data, timeout=10, context=_SSL_CTX) as r:
        return json.load(r)["access_token"]


def _agent_name(agent_id: str) -> str:
    """Resolve an agent UUID to its name via the wxO API. Returns '' on any failure."""
    if not agent_id:
        return ""
    if agent_id in _AGENT_NAMES:
        return _AGENT_NAMES[agent_id]
    try:
        base = os.environ["WxO_Service_Instance_URL"].rstrip("/")
        req = urllib.request.Request(
            f"{base}/v1/orchestrate/agents/{agent_id}",
            headers={"Authorization": f"Bearer {_wxo_token()}", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10, context=_SSL_CTX) as r:
            name = json.load(r).get("name") or ""
        if name:
            _AGENT_NAMES[agent_id] = name
        return name
    except Exception as exc:
        print(f"[PI-GUARD] agent name lookup failed: {type(exc).__name__}", flush=True)
        return ""


def _last_user_text(payload: dict) -> str:
    messages = payload.get("messages") or []
    if not messages:
        return ""
    content = messages[-1].get("content")
    if isinstance(content, dict):
        return content.get("text") or ""
    return content if isinstance(content, str) else ""


@app.get("/health")
def health():
    return {"status": "ok", "threshold": THRESHOLD}


@app.post("/agent_pre_invoke", operation_id="pi_guard_pre")
def agent_pre_invoke(req: PluginRequest, x_api_key: str | None = Header(default=None)):
    expected = os.environ.get("PI_GUARD_TOKEN")
    if expected and not hmac.compare_digest(x_api_key or "", expected):
        raise HTTPException(status_code=401, detail="invalid token")
    text = _last_user_text(req.payload)
    finding = detect_injection(text)
    if not finding["is_injection"]:
        return {"continue_processing": True}

    ctx = req.context or {}
    system_ctx = ctx.get("system_context") or {}
    request_ctx = ctx.get("request_context") or {}
    agent_id = str(req.payload.get("agent_id", ""))
    agent_name = _agent_name(agent_id)
    incident = _create_incident(
        finding,
        text,
        agent_id=agent_id,
        agent_name=agent_name,
        user=str(system_ctx.get("wxo_user_name") or request_ctx.get("wxo_email_id") or ""),
        request_id=str(request_ctx.get("wxo_run_id") or system_ctx.get("wxo_run_id") or ""),
    )
    print(f"[PI-GUARD] BLOCKED agent={agent_name or agent_id} score={finding['score']} rules={finding['rules']} incident={incident}", flush=True)

    blocked = dict(req.payload)
    blocked["messages"] = [{"role": "user", "content": {"type": "text", "text": BLOCK_MESSAGE}}]
    return {"continue_processing": False, "modified_payload": blocked}
