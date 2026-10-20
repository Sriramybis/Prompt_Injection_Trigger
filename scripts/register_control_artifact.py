"""Register the pi_guard_pre OpenAPI plug-in tool as a custom control artifact.

The ADK CLI can only bind built-in artifact types, so this calls the platform's
policy-artifacts API directly (the same call the UI's "Use existing OpenAPI
tool" option makes). Idempotent: if the artifact already exists it just prints it.

Usage (after `orchestrate env activate <env>` and importing the tool):
  .venv/bin/python scripts/register_control_artifact.py
Then bind it to an agent:
  orchestrate controls create --artifact pi_guard_artifact_v2 --name pi_guard_control \
      --hook agent_pre_invoke --priority 50 --agent pi_guard_test_agent
"""
import sys

from ibm_watsonx_orchestrate.client.utils import instantiate_client
from ibm_watsonx_orchestrate_clients.controls.controls_client import ControlsClient
from ibm_watsonx_orchestrate_clients.tools.tool_client import ToolClient

TOOL_NAME = "pi_guard_pre"
ARTIFACT_NAME = "pi_guard_artifact_v2"


def main() -> int:
    controls = instantiate_client(ControlsClient)

    for a in controls.list_artifacts():
        if a.get("name") == ARTIFACT_NAME:
            print(f"Artifact already exists: {a['id']} (tool {a.get('tool_id')})")
            return 0

    tools = instantiate_client(ToolClient).get_draft_by_name(TOOL_NAME)
    tools = tools if isinstance(tools, list) else [tools]
    if not tools or not tools[0]:
        print(f"Tool '{TOOL_NAME}' not found. Import it first: orchestrate tools import -k openapi -f openapi/pi_guard_plugin.yaml")
        return 1

    resp = controls._request("POST", "/policies/artifacts", json={
        "name": ARTIFACT_NAME,
        "display_name": "Prompt Injection Guard",
        "description": "Blocks prompt injection and raises a ServiceNow incident (OpenAPI plug-in pi_guard_pre).",
        "hooks": ["agent_pre_invoke"],
        "runtime_type": "openapi_tool",
        "tool_id": tools[0]["id"],
    })
    if resp.status_code != 201:
        print("Create failed:", resp.status_code, resp.text[:500])
        return 1
    print("Created artifact:", resp.json()["id"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
