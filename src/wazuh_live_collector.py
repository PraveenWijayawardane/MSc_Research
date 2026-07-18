import json
import requests
from requests.auth import HTTPBasicAuth


WAZUH_INDEXER_URL = "https://localhost:9200"
WAZUH_INDEX = "wazuh-alerts-*"
USERNAME = "readall"
PASSWORD = "NQcWO3yRfScBUZw45nH*tbu?4QiNsCBH"


def fetch_latest_wazuh_alerts(size=20):
    url = f"{WAZUH_INDEXER_URL}/{WAZUH_INDEX}/_search"

    query = {
        "size": size,
        "sort": [
            {
                "timestamp": {
                    "order": "desc"
                }
            }
        ],
        "_source": [
            "timestamp",
            "agent.ip",
            "agent.name",
            "rule.id",
            "rule.description",
            "data.srcuser",
            "data.dstuser",
            "data.uid",
            "predecoder.program_name",
            "full_log"
        ]
    }

    response = requests.get(
        url,
        auth=HTTPBasicAuth(USERNAME, PASSWORD),
        headers={"Content-Type": "application/json"},
        json=query,
        verify=False
    )

    response.raise_for_status()

    data = response.json()
    hits = data.get("hits", {}).get("hits", [])

    return hits


def main():
    alerts = fetch_latest_wazuh_alerts(size=10)

    output_file = "data/live_wazuh_events.json"

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    print(f"Fetched {len(alerts)} Wazuh alerts")
    print(f"Saved to {output_file}")


if __name__ == "__main__":
    main()