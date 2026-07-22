import json
import os
import requests
# pyrefly: ignore [missing-import]
import urllib3
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()


WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200")
WAZUH_INDEX = os.getenv("WAZUH_INDEX", "wazuh-alerts-*")
USERNAME = os.getenv("WAZUH_USERNAME", "readall")
PASSWORD = os.getenv("WAZUH_PASSWORD")
OUTPUT_FILE = "data/live_wazuh_events.json"


def fetch_latest_wazuh_alerts(size=100):
    if not PASSWORD:
        raise ValueError("WAZUH_PASSWORD is missing. Add it to the .env file.")

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
        verify=False,
        timeout=30
    )

    response.raise_for_status()

    data = response.json()
    return data.get("hits", {}).get("hits", [])


def main():
    alerts = fetch_latest_wazuh_alerts(size=100)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    print(f"Fetched {len(alerts)} Wazuh alerts")
    print(f"Saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()