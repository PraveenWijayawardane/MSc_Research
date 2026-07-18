#Telemetry ingestion and normalisation. 
from pathlib import Path
import pandas as pd

def load_jsonl(path: str) -> pd.DataFrame:
    return pd.read_json(Path(path), lines=True)

wazuh = load_jsonl("data/wazuh/archives.json")
zeek_conn = load_jsonl("data/zeek/conn.log")

wazuh["event_time"] = pd.to_datetime(wazuh["timestamp"], utc=True)
zeek_conn["event_time"] = pd.to_datetime(zeek_conn["ts"], unit="s", utc=True)


#Correlation and enrichment.

inventory = pd.read_csv("data/reference/assets.csv")  # hostname, ip, role, criticality

host_events = wazuh.merge(inventory, how="left", left_on="agent.ip", right_on="ip")
net_events = zeek_conn.merge(
    inventory.add_prefix("dst_"),
    how="left",
    left_on="id.resp_h",
    right_on="dst_ip",
)

#Scoring and detection logic. 

joined = pd.merge_asof(
    host_events.sort_values("event_time"),
    net_events.sort_values("event_time"),
    on="event_time",
    tolerance=pd.Timedelta("5min"),
    direction="nearest",
)

joined["risk_score"] = (
    3 * joined["rule.level"].fillna(0)
    + 2 * joined["service"].isin({"ssh", "rdp", "smb"}).astype(int)
    + joined["criticality"].map({"low": 1, "medium": 2, "high": 3}).fillna(1)
)

# Automation and result exposure.

from fastapi import FastAPI

app = FastAPI(title="Insider Threat Scoring API")

@app.get("/alerts/high-risk")
def high_risk(limit: int = 20):
    rows = joined.loc[joined["risk_score"] >= 8].head(limit)
    return rows[["event_time", "hostname", "service", "risk_score"]].to_dict("records")
