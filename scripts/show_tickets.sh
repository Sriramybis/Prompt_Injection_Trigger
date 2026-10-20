#!/usr/bin/env bash
# List the most recent PI-Guard incidents in ServiceNow.
# Usage: ./scripts/show_tickets.sh [count]
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; . ./.env; set +a
N="${1:-5}"
curl -s -m 30 -u "$SERVICENOW_USER:$SERVICENOW_PASSWORD" -H 'Accept: application/json' \
  "$SERVICENOW_URL/api/now/table/incident?sysparm_query=short_descriptionLIKEPI-Guard^ORDERBYDESCsys_created_on&sysparm_limit=$N&sysparm_fields=number,short_description,urgency,state,sys_created_on,sys_id" \
| python3 -c "
import sys, json, os
rows = json.load(sys.stdin).get('result', [])
base = os.environ['SERVICENOW_URL']
if not rows:
    print('No PI-Guard incidents found.')
for r in rows:
    print(f\"{r['number']}  {r['sys_created_on']} UTC  urgency={r['urgency']}  {r['short_description']}\")
    print(f\"    {base}/nav_to.do?uri=incident.do?sys_id={r['sys_id']}\")
"
