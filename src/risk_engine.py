import json
import yaml
from datetime import datetime


HOST_INVENTORY_FILE = "config/host_inventory.json"
RISK_RULES_FILE = "config/risk_rules.yaml"
#SAMPLE_WAZUH_FILE = "data/sample_wazuh_events.json"
SAMPLE_WAZUH_FILE = "data/live_wazuh_events.json"
SAMPLE_ZEEK_FILE = "data/live_zeek_conn.json"
#SAMPLE_ZEEK_FILE = "data/sample_zeek_conn.json"


def load_json(file_path):
    """Load JSON file."""
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def load_yaml(file_path):
    """Load YAML file."""
    with open(file_path, "r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def classify_score(score, classification_rules):
    """Classify final risk score."""
    if score <= classification_rules["legitimate_max"]:
        return "Legitimate"
    elif score <= classification_rules["low_suspicion_max"]:
        return "Low Suspicion"
    elif score <= classification_rules["suspicious_max"]:
        return "Suspicious"
    else:
        return "Likely Malicious"


def parse_timestamp(timestamp):
    """
    Parse different Wazuh timestamp formats.

    Supported examples:
    2026-05-11T12:09:07.175+0000
    2026-05-11T12:09:07.175+00:00
    2026-05-11T12:09:07.175Z
    """
    if not timestamp:
        return None

    try:
        timestamp = timestamp.replace("Z", "+00:00")

        # Convert +0000 to +00:00
        if len(timestamp) >= 5 and timestamp[-5] in ["+", "-"] and timestamp[-3] != ":":
            timestamp = timestamp[:-2] + ":" + timestamp[-2:]

        return datetime.fromisoformat(timestamp)

    except Exception:
        return None

def time_difference_minutes(timestamp1, timestamp2):
    """
    Calculate absolute time difference between two timestamps in minutes.
    """
    time1 = parse_timestamp(timestamp1)
    time2 = parse_timestamp(timestamp2)

    if time1 is None or time2 is None:
        return None

    difference = abs((time1 - time2).total_seconds()) / 60
    return difference

def is_off_hours(timestamp):
    """
    Normal working hours = 08:00 to 18:00.
    Anything before 08:00 or after/equal 18:00 is treated as off-hours.
    """
    event_time = parse_timestamp(timestamp)

    if event_time is None:
        return False

    hour = event_time.hour
    return hour < 8 or hour >= 18


def analyze_wazuh_event(event, host_inventory, rules):
    """
    Analyze one Wazuh event and calculate contextual risk score.
    """
    score = 0
    reasons = []

    source = event.get("_source", {})
    agent = source.get("agent", {})
    rule = source.get("rule", {})
    data = source.get("data", {})
    predecoder = source.get("predecoder", {})

    hostname = agent.get("name", "unknown")
    agent_ip = agent.get("ip")

    if not agent_ip:
        agent_ip, host_context = find_host_by_name(host_inventory, hostname)
    else:
        host_context = host_inventory.get(agent_ip, {})

    rule_id = str(rule.get("id", ""))
    description = rule.get("description", "")
    timestamp = source.get("timestamp", "")
    program_name = predecoder.get("program_name", "")

    #host_context = host_inventory.get(agent_ip, {})

    # Rule 5501 = PAM session opened / successful authentication
    if rule_id == "5501":
        score += rules["scores"]["wazuh_success_login"]
        reasons.append("Successful PAM login/session opened detected")

    # Root escalation detection
    if data.get("dstuser") == "root" or str(data.get("uid")) == "0":
        score += rules["scores"]["wazuh_root_escalation"]
        reasons.append("Root-level session or privilege escalation detected")

    # Failed login detection
    if "failed" in description.lower() or "authentication failure" in description.lower():
        score += rules["scores"]["wazuh_failed_login"]
        reasons.append("Failed login or authentication failure detected")

    # Sudo usage detection
    if program_name == "sudo" or "sudo" in description.lower():
        score += rules["scores"]["wazuh_sudo_usage"]
        reasons.append("Sudo command usage detected")

    # New user creation detection
    if "new user" in description.lower() or "user added" in description.lower():
        score += rules["scores"]["wazuh_new_user_created"]
        reasons.append("New user creation activity detected")

    # Service restart detection
    if "service" in description.lower() and (
        "started" in description.lower()
        or "stopped" in description.lower()
        or "restarted" in description.lower()
    ):
        score += rules["scores"]["wazuh_service_restart"]
        reasons.append("Service start/stop/restart activity detected")

    # Off-hours activity
    if is_off_hours(timestamp):
        score += rules["scores"]["off_hours_activity"]
        reasons.append("Activity occurred outside normal working hours")

    # Unknown host context
    if not host_context:
        score += rules["scores"]["unknown_source_host"]
        reasons.append("Source host is not found in host inventory")

    # Context reduction: trusted admin/monitoring host
    if host_context.get("trusted_admin_host") is True:
        score += rules["reductions"]["trusted_admin_host"]
        reasons.append("Activity came from trusted admin/monitoring host")

    classification = classify_score(score, rules["classification"])

    result = {
        "timestamp": timestamp,
        "host": hostname,
        "ip": agent_ip,
        "role": host_context.get("role", "unknown"),
        "rule_id": rule_id,
        "description": description,
        "risk_score": score,
        "classification": classification,
        "reasons": reasons
    }

    return result

def analyze_zeek_conn_event(event, host_inventory, rules):
    """
    Analyze one Zeek conn.log event and calculate contextual risk score.
    """
    score = 0
    reasons = []

    src_ip = event.get("id.orig_h", "unknown")
    dst_ip = event.get("id.resp_h", "unknown")
    dst_port = int(event.get("id.resp_p", 0))
    service = event.get("service", "")
    timestamp = event.get("ts", "")

    src_context = host_inventory.get(src_ip, {})
    dst_context = host_inventory.get(dst_ip, {})

    src_role = src_context.get("role", "unknown")
    dst_role = dst_context.get("role", "unknown")

    allowed_destinations = src_context.get("allowed_destinations", [])
    allowed_ports = src_context.get("allowed_ports", [])

    # Unknown source host
    if not src_context:
        score += rules["scores"]["unknown_source_host"]
        reasons.append("Source IP is not found in host inventory")

    # Internal SSH detection
    if dst_port == 22 or service == "ssh":
        score += rules["scores"]["zeek_internal_ssh"]
        reasons.append("Internal SSH connection detected")

    # SMB detection
    if dst_port == 445 or service == "smb":
        score += rules["scores"]["zeek_smb_activity"]
        reasons.append("SMB activity detected")

    # RDP detection
    if dst_port == 3389 or service == "rdp":
        score += rules["scores"]["zeek_rdp_activity"]
        reasons.append("RDP activity detected")

    # Unauthorized destination
    if dst_ip not in allowed_destinations and src_context:
        score += rules["scores"]["zeek_new_internal_destination"]
        reasons.append("Connection to non-approved destination for this host role")

    # Unauthorized port
    if dst_port not in allowed_ports and src_context:
        score += rules["scores"]["zeek_unauthorized_port"]
        reasons.append("Connection to non-approved destination port for this host role")

    # Workstation direct DB access
    if src_role == "workstation" and dst_role == "database" and dst_port == 5432:
        score += rules["scores"]["direct_db_access_from_workstation"]
        reasons.append("Workstation directly accessed database server")

    # Expected communication reduction
    if dst_ip in allowed_destinations and dst_port in allowed_ports:
        score += rules["reductions"]["expected_communication"]
        reasons.append("Communication matches expected host role behavior")

    # Off-hours activity
    if is_off_hours(timestamp):
        score += rules["scores"]["off_hours_activity"]
        reasons.append("Network activity occurred outside normal working hours")

    classification = classify_score(score, rules["classification"])

    result = {
        "timestamp": timestamp,
        "source_ip": src_ip,
        "source_role": src_role,
        "destination_ip": dst_ip,
        "destination_role": dst_role,
        "destination_port": dst_port,
        "service": service,
        "risk_score": score,
        "classification": classification,
        "reasons": reasons
    }

    return result

def correlate_wazuh_zeek_events(wazuh_results, zeek_results, rules, correlation_window_minutes=5):
    """
    Correlate Wazuh host events with Zeek network events.

    Logic:
    - Match Wazuh host IP with Zeek source IP
    - Check if events happened within the correlation time window
    - Add additional contextual risk for suspicious chains
    """
    correlated_results = []

    for wazuh_event in wazuh_results:
        for zeek_event in zeek_results:
            wazuh_ip = wazuh_event.get("ip")
            zeek_src_ip = zeek_event.get("source_ip")

            if wazuh_ip != zeek_src_ip:
                continue

            time_diff = time_difference_minutes(
                wazuh_event.get("timestamp"),
                zeek_event.get("timestamp")
            )

            if time_diff is None:
                continue

            if time_diff <= correlation_window_minutes:
                correlation_score = rules["scores"]["correlated_host_network_activity"]
                correlation_reasons = [
                    f"Wazuh host event and Zeek network event occurred within {round(time_diff, 2)} minutes"
                ]

                wazuh_reasons = wazuh_event.get("reasons", [])
                zeek_reasons = zeek_event.get("reasons", [])

                has_privilege_activity = any(
                    "Root-level session" in reason or "privilege escalation" in reason
                    for reason in wazuh_reasons
                )

                has_db_access = (
                    zeek_event.get("destination_role") == "database"
                    or zeek_event.get("destination_port") == 5432
                )

                has_smb_activity = (
                    zeek_event.get("destination_port") == 445
                    or zeek_event.get("service") == "smb"
                )

                has_ssh_activity = (
                    zeek_event.get("destination_port") == 22
                    or zeek_event.get("service") == "ssh"
                )

                if has_privilege_activity and has_db_access:
                    correlation_score += rules["scores"]["correlated_privilege_and_db_access"]
                    correlation_reasons.append("Privilege activity followed by database access")

                if has_privilege_activity and has_smb_activity:
                    correlation_score += rules["scores"]["correlated_privilege_and_smb_activity"]
                    correlation_reasons.append("Privilege activity followed by SMB activity")

                if has_privilege_activity and has_ssh_activity:
                    correlation_score += rules["scores"]["correlated_privilege_and_ssh_activity"]
                    correlation_reasons.append("Privilege activity followed by SSH activity")

                total_score = (
                    wazuh_event.get("risk_score", 0)
                    + zeek_event.get("risk_score", 0)
                    + correlation_score
                )

                classification = classify_score(total_score, rules["classification"])

                correlated_result = {
                    "wazuh_timestamp": wazuh_event.get("timestamp"),
                    "zeek_timestamp": zeek_event.get("timestamp"),
                    "time_difference_minutes": round(time_diff, 2),
                    "source_ip": wazuh_ip,
                    "source_host": wazuh_event.get("host"),
                    "source_role": wazuh_event.get("role"),
                    "destination_ip": zeek_event.get("destination_ip"),
                    "destination_role": zeek_event.get("destination_role"),
                    "destination_port": zeek_event.get("destination_port"),
                    "service": zeek_event.get("service"),
                    "wazuh_score": wazuh_event.get("risk_score", 0),
                    "zeek_score": zeek_event.get("risk_score", 0),
                    "correlation_score": correlation_score,
                    "total_risk_score": total_score,
                    "classification": classification,
                    "reasons": wazuh_reasons + zeek_reasons + correlation_reasons
                }

                correlated_results.append(correlated_result)

    return correlated_results

def normalize_wazuh_events(wazuh_data):
    """
    Support both:
    1. Single Wazuh event as a dictionary
    2. Multiple Wazuh events as a list
    """
    if isinstance(wazuh_data, list):
        return wazuh_data

    if isinstance(wazuh_data, dict):
        return [wazuh_data]

    return []

def find_host_by_name(host_inventory, hostname):
    """
    Find host context by hostname when agent.ip is missing from Wazuh.
    Returns IP and host context.
    """
    for ip, context in host_inventory.items():
        if context.get("hostname") == hostname:
            return ip, context

    return "unknown", {}


def main():
    host_inventory = load_json(HOST_INVENTORY_FILE)
    rules = load_yaml(RISK_RULES_FILE)

    wazuh_data = load_json(SAMPLE_WAZUH_FILE)
    wazuh_events = normalize_wazuh_events(wazuh_data)

    zeek_events = load_json(SAMPLE_ZEEK_FILE)

    wazuh_results = []
    zeek_results = []

    for event in wazuh_events:
        result = analyze_wazuh_event(event, host_inventory, rules)
        wazuh_results.append(result)

    for event in zeek_events:
        result = analyze_zeek_conn_event(event, host_inventory, rules)
        zeek_results.append(result)

    correlated_results = correlate_wazuh_zeek_events(
        wazuh_results,
        zeek_results,
        rules,
        correlation_window_minutes=5
    )

    final_output = {
        "wazuh_results": wazuh_results,
        "zeek_results": zeek_results,
        "correlated_results": correlated_results
    }

    output_file = "output/scored_events.json"

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(final_output, file, indent=4)

    print(f"Scoring completed. Results saved to {output_file}")
    print(json.dumps(final_output, indent=4))


if __name__ == "__main__":
    main()