"""Prompt injection detector and ServiceNow incident helper (no wxO SDK dependency).

ServiceNow settings come from the environment: SERVICENOW_URL, SERVICENOW_USER,
SERVICENOW_PASSWORD.
"""
import base64
import json
import os
import re
import ssl
import urllib.parse
import urllib.request

try:  # some Python builds (e.g. python.org on macOS) ship without a CA bundle
    import certifi
    _SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _SSL_CTX = ssl.create_default_context()

BLOCK_MESSAGE = (
    "This request was blocked by the prompt injection guard and has been "
    "reported to the security team."
)

# (rule name, weight, pattern). A message is blocked when the total weight
# reaches THRESHOLD, so one weak signal alone does not trigger a block.
RULES = [
    ("override_instructions", 3, r"\b(ignore|disregard|forget|override|bypass)\b.{0,40}\b(previous|prior|above|earlier|all|any|your)\b.{0,30}\b(instructions?|rules?|prompts?|guidelines?|directives?|constraints?)\b"),
    ("reveal_system_prompt", 3, r"\b(reveal|show|print|repeat|output|display|leak|tell me)\b.{0,40}\b(system|hidden|initial|original|secret)\b.{0,20}\b(prompt|instructions?|message)\b"),
    ("persona_switch", 2, r"\b(you are now|act as|pretend (to be|you are)|from now on you)\b.{0,60}\b(dan|developer mode|jailbroken|unrestricted|no restrictions|without (any )?(rules|restrictions|filters))\b"),
    ("developer_mode", 2, r"\b(developer|debug|admin|god|sudo)\s+mode\b"),
    ("skip_safety_checks", 2, r"\b(skip|disable|turn off|without|no)\b.{0,25}\b(fraud|safety|security|validation|verification|approval)\b.{0,15}\b(check|checks|scoring|filter|review)?\b"),
    ("forced_approval", 2, r"\b(approve|auto[- ]?approve|pay out|payout)\b.{0,60}\b(regardless|no matter|without (any )?(review|check|verification))\b"),
    ("fake_system_role", 3, r"(^|\n)\s*(system|assistant)\s*:\s*|<\|?(system|im_start|im_end)\|?>|\[/?(INST|SYS)\]"),
    ("tool_exfiltration", 2, r"\b(list|reveal|show|dump)\b.{0,25}\b(all )?(your )?(tools?|functions?|api keys?|credentials|secrets?|environment variables?)\b"),
]
THRESHOLD = 3
_COMPILED = [(n, w, re.compile(p, re.IGNORECASE | re.DOTALL)) for n, w, p in RULES]


def detect_injection(text: str) -> dict:
    """Score the text against the rule set. Pure function, safe to unit test."""
    hits = [(n, w) for n, w, rx in _COMPILED if rx.search(text or "")]
    score = sum(w for _, w in hits)
    return {"is_injection": score >= THRESHOLD, "score": score, "rules": [n for n, _ in hits]}


def _sn_request(url: str, username: str, password: str, path: str, body: dict | None = None) -> dict:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    req = urllib.request.Request(
        f"{url}{path}",
        data=json.dumps(body).encode() if body is not None else None,
        headers={
            "Authorization": f"Basic {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST" if body is not None else "GET",
    )
    with urllib.request.urlopen(req, timeout=15, context=_SSL_CTX) as resp:
        return json.load(resp)


def _find_caller_sys_id(url: str, username: str, password: str, agent_name: str) -> str:
    """Return the sys_id of the ServiceNow user whose user_name is the agent name, or ''."""
    if not agent_name:
        return ""
    q = urllib.parse.quote(f"user_name={agent_name}")
    try:
        rows = _sn_request(url, username, password, f"/api/now/table/sys_user?sysparm_query={q}&sysparm_fields=sys_id&sysparm_limit=1")["result"]
        return rows[0]["sys_id"] if rows else ""
    except Exception:
        return ""


def _create_incident(finding: dict, text: str, agent_id: str, user: str, request_id: str, agent_name: str = "") -> str:
    """Create a ServiceNow incident. Returns the incident number or an error string.

    The agent is set as the incident caller when a ServiceNow user with
    user_name == agent_name exists (see scripts/provision_snow_caller.py).
    """
    url = os.environ.get("SERVICENOW_URL", "").rstrip("/")
    username = os.environ.get("SERVICENOW_USER", "")
    password = os.environ.get("SERVICENOW_PASSWORD", "")
    if not (url and username and password):
        return "not-created: ServiceNow settings missing"

    caller_sys_id = _find_caller_sys_id(url, username, password, agent_name)
    body = {
        "short_description": f"[PI-Guard] Prompt injection blocked (score {finding['score']})",
        "description": (
            f"Prompt injection attempt blocked by watsonx Orchestrate.\n"
            f"Agent: {agent_name or 'unknown'} (id {agent_id})\n"
            f"Caller user record: {'linked' if caller_sys_id else 'not found - run scripts/provision_snow_caller.py'}\n"
            f"User: {user}\nRequest id: {request_id}\n"
            f"Rules matched: {', '.join(finding['rules'])}\n"
            f"Score: {finding['score']} (threshold {THRESHOLD})\n\n"
            f"Message excerpt:\n{text[:500]}"
        ),
        "category": "software",
        "urgency": "2",
        "impact": "2",
    }
    if caller_sys_id:
        body["caller_id"] = caller_sys_id
    try:
        return _sn_request(url, username, password, "/api/now/table/incident", body)["result"]["number"]
    except Exception as exc:  # the block must still happen if ServiceNow is down
        return f"not-created: {type(exc).__name__}"
