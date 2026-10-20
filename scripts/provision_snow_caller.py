"""Create (or find) a ServiceNow user record to represent a wxO agent as an incident caller.

The incident caller_id field is a reference to sys_user, so each agent that
should appear as a caller needs a user whose user_name equals the agent name.
Creating users needs an admin session, which the pi_trigger_svc account lacks.

Usage (needs SERVICENOW_URL in the environment):
  SN_ADMIN_USER=admin SN_ADMIN_PASSWORD=... \
    .venv/bin/python scripts/provision_snow_caller.py pi_guard_test_agent "PI Guard Test Agent"
"""
import os
import re
import sys

import requests

BASE = os.environ["SERVICENOW_URL"].rstrip("/")


def main(user_name: str, display: str) -> int:
    s = requests.Session()
    # Basic auth REST is blocked for admin on this instance, so log in with the
    # web form and use the session token (g_ck) as X-UserToken.
    page = s.post(
        f"{BASE}/login.do",
        data={"user_name": os.environ["SN_ADMIN_USER"], "user_password": os.environ["SN_ADMIN_PASSWORD"], "sys_action": "sysverb_login"},
        timeout=60,
    )
    m = re.search(r"g_ck = '([0-9a-f]+)", page.text)
    if not m:
        print("Admin login failed (no session token).")
        return 1
    h = {"X-UserToken": m.group(1), "Accept": "application/json", "Content-Type": "application/json"}

    found = s.get(f"{BASE}/api/now/table/sys_user", headers=h, timeout=30,
                  params={"sysparm_query": f"user_name={user_name}", "sysparm_fields": "sys_id,user_name", "sysparm_limit": 1}).json()
    if found.get("result"):
        print(f"Already exists: {user_name} ({found['result'][0]['sys_id']})")
        return 0

    first, _, last = display.partition(" Agent")
    created = s.post(f"{BASE}/api/now/table/sys_user", headers=h, timeout=30, json={
        "user_name": user_name,
        "first_name": first.strip() or user_name,
        "last_name": "Agent",
        "active": "true",
        "web_service_access_only": "true",
        "description": "watsonx Orchestrate agent used as incident caller by the PI Guard plug-in.",
    }).json()
    if "result" not in created:
        print("Create failed:", created)
        return 1
    print(f"Created: {user_name} ({created['result']['sys_id']})")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))
