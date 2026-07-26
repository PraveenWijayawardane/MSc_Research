import json
from datetime import datetime, timezone

def parse_time(value):
    if not value:
        return None

    value = value.strip()

    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    if len(value) >= 5 and value[-5] in "+-" and value[-3] != ":":
        value = value[:-2] + ":" + value[-2:]

    return datetime.fromisoformat(value).astimezone(timezone.utc)

with open("data/live_wazuh_events.json", encoding="utf-8-sig") as f:
    wazuh = json.load(f)

if not isinstance(wazuh, list):
    wazuh = wazuh.get("hits", {}).get("hits", [])

wazuh = [x.get("_source", x) for x in wazuh]

with open("data/live_zeek_conn.json", encoding="utf-8-sig") as f:
    zeek = json.load(f)

if not isinstance(zeek, list):
    zeek = zeek.get("events", [])

matches = []

for z in zeek:
    ztime = parse_time(z.get("ts"))
    source_ip = str(z.get("id.orig_h") or "")
    destination_ip = str(z.get("id.resp_h") or "")

    if not ztime:
        continue

    for w in wazuh:
        agent_ip = str(w.get("agent", {}).get("ip") or "")
        wtime = parse_time(w.get("timestamp"))

        if not agent_ip or not wtime:
            continue

        if agent_ip not in {source_ip, destination_ip}:
            continue

        difference = abs((ztime - wtime).total_seconds())

        if difference <= 300:
            matches.append({
                "difference_seconds": round(difference, 3),
                "wazuh_time": w.get("timestamp"),
                "wazuh_agent_ip": agent_ip,
                "wazuh_level": w.get("rule", {}).get("level"),
                "wazuh_description": w.get("rule", {}).get("description"),
                "zeek_time": z.get("ts"),
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "destination_port": z.get("id.resp_p"),
            })

matches.sort(key=lambda x: x["difference_seconds"])

print("Candidate matches within 5 minutes:", len(matches))

for match in matches[:20]:
    print(json.dumps(match, indent=2))
