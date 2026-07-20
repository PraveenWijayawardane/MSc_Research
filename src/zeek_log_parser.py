import json
from datetime import datetime, timezone


ZEEK_CONN_LOG_FILE = "data/live_zeek_conn.log"
OUTPUT_JSON_FILE = "data/live_zeek_conn.json"


def convert_zeek_timestamp(ts):
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    except Exception:
        return ""


def convert_value(value):
    if value in ["-", "(empty)", ""]:
        return None
    return value


def parse_zeek_conn_log(file_path):
    fields = []
    events = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue

            if line.startswith("#"):
                continue

            if not fields:
                continue

            values = line.split("\t")

            if len(values) != len(fields):
                continue

            event = {}

            for field, value in zip(fields, values):
                event[field] = convert_value(value)

            for port_field in ["id.orig_p", "id.resp_p"]:
                if event.get(port_field) is not None:
                    try:
                        event[port_field] = int(event[port_field])
                    except Exception:
                        pass

            for number_field in [
                "duration",
                "orig_bytes",
                "resp_bytes",
                "missed_bytes",
                "orig_pkts",
                "orig_ip_bytes",
                "resp_pkts",
                "resp_ip_bytes",
                "ip_proto"
            ]:
                if event.get(number_field) is not None:
                    try:
                        event[number_field] = float(event[number_field])
                    except Exception:
                        pass

            event["ts"] = convert_zeek_timestamp(event.get("ts"))

            events.append(event)

    return events


def main():
    events = parse_zeek_conn_log(ZEEK_CONN_LOG_FILE)

    with open(OUTPUT_JSON_FILE, "w", encoding="utf-8") as file:
        json.dump(events, file, indent=4)

    print(f"Parsed {len(events)} Zeek conn events")
    print(f"Saved to {OUTPUT_JSON_FILE}")


if __name__ == "__main__":
    main()