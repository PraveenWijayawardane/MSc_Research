import json
import os
import requests
import urllib3
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()


OPENSEARCH_URL = os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200")
USERNAME = os.getenv("WAZUH_USERNAME")
PASSWORD = os.getenv("WAZUH_PASSWORD")
INDEX_NAME = os.getenv("RISK_OUTPUT_INDEX", "healthcare-risk-events")

SCORED_EVENTS_FILE = "output/scored_events.json"


def build_dashboard_documents(scored_data):
    documents = []

    for event in scored_data.get("wazuh_results", []):
        documents.append({
            "@timestamp": event.get("timestamp"),
            "detection_type": "wazuh_host_event",
            "source_host": event.get("host"),
            "source_ip": event.get("ip"),
            "source_role": event.get("role"),
            "rule_id": event.get("rule_id"),
            "description": event.get("description"),
            "risk_score": event.get("risk_score"),
            "classification": event.get("classification"),
            "reasons": event.get("reasons")
        })

    for event in scored_data.get("zeek_results", []):
        documents.append({
            "@timestamp": event.get("timestamp"),
            "detection_type": "zeek_network_event",
            "source_ip": event.get("source_ip"),
            "source_role": event.get("source_role"),
            "destination_ip": event.get("destination_ip"),
            "destination_role": event.get("destination_role"),
            "destination_port": event.get("destination_port"),
            "service": event.get("service"),
            "risk_score": event.get("risk_score"),
            "classification": event.get("classification"),
            "reasons": event.get("reasons")
        })

    for event in scored_data.get("correlated_results", []):
        documents.append({
            "@timestamp": event.get("zeek_timestamp") or event.get("wazuh_timestamp"),
            "detection_type": "correlated_host_network_event",
            "source_ip": event.get("source_ip"),
            "source_host": event.get("source_host"),
            "source_role": event.get("source_role"),
            "destination_ip": event.get("destination_ip"),
            "destination_role": event.get("destination_role"),
            "destination_port": event.get("destination_port"),
            "service": event.get("service"),
            "risk_score": event.get("total_risk_score"),
            "wazuh_score": event.get("wazuh_score"),
            "zeek_score": event.get("zeek_score"),
            "correlation_score": event.get("correlation_score"),
            "classification": event.get("classification"),
            "time_difference_minutes": event.get("time_difference_minutes"),
            "reasons": event.get("reasons")
        })

    return documents


def push_bulk_documents(documents):
    if not USERNAME or not PASSWORD:
        raise ValueError("OpenSearch username/password missing in .env file.")

    bulk_lines = []

    for document in documents:
        bulk_lines.append(json.dumps({"index": {"_index": INDEX_NAME}}))
        bulk_lines.append(json.dumps(document))

    bulk_payload = "\n".join(bulk_lines) + "\n"

    response = requests.post(
        f"{OPENSEARCH_URL}/_bulk",
        auth=HTTPBasicAuth(USERNAME, PASSWORD),
        headers={"Content-Type": "application/x-ndjson"},
        data=bulk_payload,
        verify=False,
        timeout=30
    )

    response.raise_for_status()
    result = response.json()

    if result.get("errors"):
        print("Some documents failed to index:")
        print(json.dumps(result, indent=4))
    else:
        print(f"Indexed {len(documents)} documents into {INDEX_NAME}")


def main():
    with open(SCORED_EVENTS_FILE, "r", encoding="utf-8") as file:
        scored_data = json.load(file)

    documents = build_dashboard_documents(scored_data)

    if not documents:
        print("No scored events found to push.")
        return

    push_bulk_documents(documents)


if __name__ == "__main__":
    main()