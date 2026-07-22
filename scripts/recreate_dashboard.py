import json
import requests
import urllib3
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
DASHBOARD_URL = "https://localhost:8443"
USERNAME = "admin"
PASSWORD = "zo7F5MaVCIzU70*.sA*rYkJnqZSh6Nmr"
INDEX_PATTERN_ID = "bd2d5f80-8391-11f1-a9b6-45089fa870e0"
DASHBOARD_ID = "healthcare-contextual-risk-dashboard"
DASHBOARD_TITLE = "Healthcare Contextual Risk Dashboard"

HEADERS = {
    "osd-xsrf": "true",
    "Content-Type": "application/json"
}
AUTH = HTTPBasicAuth(USERNAME, PASSWORD)

VIS_IDS = [
    "de2ca5b0-83a0-11f1-a9b6-45089fa870e0", # Risk Classification Count
    "74dd0090-83a1-11f1-a9b6-45089fa870e0", # Detection Type Count
    "d10783e0-83a1-11f1-a9b6-45089fa870e0", # Risk Score Over Time
    "6e2ab7f0-83a2-11f1-a9b6-45089fa870e0", # Top Risky Source Hosts
    "4b312330-83a5-11f1-a9b6-45089fa870e0", # Top Destination Ports
    "8a7f1010-83aa-11f1-a9b6-45089fa870e0", # High Risk Event Details
    "9b8f2020-83aa-11f1-a9b6-45089fa870e0"  # Correlated Host Network Events
]


def delete_saved_object(obj_type, obj_id):
    url = f"{DASHBOARD_URL}/api/saved_objects/{obj_type}/{obj_id}"
    res = requests.delete(url, auth=AUTH, headers=HEADERS, verify=False, timeout=10)
    if res.status_code == 200:
        print(f"Successfully deleted {obj_type}: {obj_id}")
    elif res.status_code == 404:
        print(f"{obj_type} {obj_id} not found (already deleted).")
    else:
        print(f"Failed to delete {obj_type} {obj_id}: {res.status_code} - {res.text}")


def create_saved_object(obj_type, obj_id, attributes, references=None):
    if references is None:
        references = []
    
    url = f"{DASHBOARD_URL}/api/saved_objects/{obj_type}/{obj_id}?overwrite=true"
    payload = {
        "attributes": attributes,
        "references": references
    }
    
    res = requests.post(url, auth=AUTH, headers=HEADERS, json=payload, verify=False, timeout=10)
    if res.status_code in [200, 201]:
        print(f"Successfully created/updated {obj_type}: {attributes.get('title', obj_id)}")
    else:
        print(f"Error creating {obj_type} {obj_id}: {res.status_code} - {res.text}")


def main():
    print("Step 1: Deleting existing dashboard, visualizations, and index pattern...")
    
    # Delete Dashboard
    delete_saved_object("dashboard", DASHBOARD_ID)
    
    # Delete Visualizations
    for vis_id in VIS_IDS:
        delete_saved_object("visualization", vis_id)
        
    # Delete Index Pattern
    delete_saved_object("index-pattern", INDEX_PATTERN_ID)
    
    print("\nStep 2: Creating new Index Pattern 'healthcare-risk-events*'...")
    index_pattern_attributes = {
        "title": "healthcare-risk-events*",
        "timeFieldName": "@timestamp"
    }
    create_saved_object("index-pattern", INDEX_PATTERN_ID, index_pattern_attributes)

    print("\nStep 3: Creating new Visualizations...")

    # 1. Risk Classification Count (Pie Chart)
    vis_1_state = {
        "title": "Risk Classification Count",
        "type": "pie",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
            {
                "id": "2",
                "enabled": True,
                "type": "terms",
                "params": {
                    "field": "classification.keyword",
                    "orderBy": "1",
                    "order": "desc",
                    "size": 5,
                    "otherBucket": False,
                    "missingBucket": False,
                    "customLabel": "Risk Classification Count"
                },
                "schema": "segment"
            }
        ],
        "params": {
            "addLegend": True,
            "addTooltip": True,
            "isDonut": True,
            "labels": {"last_level": True, "show": False, "truncate": 100, "values": True},
            "legendPosition": "right",
            "type": "pie"
        }
    }
    create_saved_object("visualization", VIS_IDS[0], {
        "title": "Risk Classification Count",
        "visState": json.dumps(vis_1_state),
        "uiStateJSON": "{}",
        "description": "",
        "version": 1,
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({
                "query": {"language": "kuery", "query": ""},
                "filter": [],
                "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"
            })
        }
    }, [
        {"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": INDEX_PATTERN_ID}
    ])

    # 2. Detection Type Count (Vertical Bar Chart)
    vis_2_state = {
        "title": "Detection Type Count",
        "type": "histogram",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
            {
                "id": "2",
                "enabled": True,
                "type": "terms",
                "params": {
                    "field": "detection_type.keyword",
                    "orderBy": "1",
                    "order": "desc",
                    "size": 10,
                    "otherBucket": False,
                    "missingBucket": False,
                    "customLabel": "Detection Type Count"
                },
                "schema": "segment"
            }
        ],
        "params": {
            "type": "histogram",
            "grid": {"categoryLines": False},
            "categoryAxes": [{
                "id": "CategoryAxis-1",
                "type": "category",
                "position": "bottom",
                "show": True,
                "style": {},
                "scale": {"type": "linear"},
                "labels": {"show": True, "filter": True, "truncate": 100},
                "title": {}
            }],
            "valueAxes": [{
                "id": "ValueAxis-1",
                "name": "LeftAxis-1",
                "type": "value",
                "position": "left",
                "show": True,
                "style": {},
                "scale": {"type": "linear", "mode": "normal"},
                "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                "title": {"text": "Count"}
            }],
            "seriesParams": [{
                "show": True,
                "type": "histogram",
                "mode": "stacked",
                "data": {"label": "Count", "id": "1"},
                "valueAxis": "ValueAxis-1",
                "drawLinesBetweenPoints": True,
                "lineWidth": 2,
                "showCircles": True
            }],
            "addTooltip": True,
            "addLegend": True,
            "legendPosition": "right",
            "times": [],
            "addTimeMarker": False,
            "labels": {"show": False},
            "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"}
        }
    }
    create_saved_object("visualization", VIS_IDS[1], {
        "title": "Detection Type Count",
        "visState": json.dumps(vis_2_state),
        "uiStateJSON": "{}",
        "description": "",
        "version": 1,
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({
                "query": {"language": "kuery", "query": ""},
                "filter": [],
                "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"
            })
        }
    }, [
        {"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": INDEX_PATTERN_ID}
    ])

    # 3. Risk Score Over Time (Line Chart)
    vis_3_state = {
        "title": "Risk Score Over Time",
        "type": "line",
        "aggs": [
            {"id": "1", "enabled": True, "type": "avg", "params": {"field": "risk_score"}, "schema": "metric"},
            {
                "id": "2",
                "enabled": True,
                "type": "date_histogram",
                "params": {
                    "field": "@timestamp",
                    "timeRange": {"from": "now-24h", "to": "now"},
                    "useNormalizedOpenSearchInterval": True,
                    "scaleMetricValues": False,
                    "interval": "auto",
                    "drop_partials": False,
                    "min_doc_count": 1,
                    "extended_bounds": {}
                },
                "schema": "segment"
            }
        ],
        "params": {
            "type": "line",
            "grid": {"categoryLines": False},
            "categoryAxes": [{
                "id": "CategoryAxis-1",
                "type": "category",
                "position": "bottom",
                "show": True,
                "style": {},
                "scale": {"type": "linear"},
                "labels": {"show": True, "filter": True, "truncate": 100},
                "title": {}
            }],
            "valueAxes": [{
                "id": "ValueAxis-1",
                "name": "LeftAxis-1",
                "type": "value",
                "position": "left",
                "show": True,
                "style": {},
                "scale": {"type": "linear", "mode": "normal"},
                "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                "title": {"text": "Average risk_score"}
            }],
            "seriesParams": [{
                "show": True,
                "type": "line",
                "mode": "normal",
                "data": {"label": "Average risk_score", "id": "1"},
                "valueAxis": "ValueAxis-1",
                "drawLinesBetweenPoints": True,
                "lineWidth": 2,
                "interpolate": "linear",
                "showCircles": True
            }],
            "addTooltip": True,
            "addLegend": True,
            "legendPosition": "right",
            "times": [],
            "addTimeMarker": False,
            "labels": {},
            "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"}
        }
    }
    create_saved_object("visualization", VIS_IDS[2], {
        "title": "Risk Score Over Time",
        "visState": json.dumps(vis_3_state),
        "uiStateJSON": "{}",
        "description": "",
        "version": 1,
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({
                "query": {"language": "kuery", "query": ""},
                "filter": [],
                "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"
            })
        }
    }, [
        {"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": INDEX_PATTERN_ID}
    ])

    # 4. Top Risky Hosts (Horizontal Bar Chart)
    vis_4_state = {
        "title": "Top Risky Source Hosts",
        "type": "histogram",
        "aggs": [
            {"id": "1", "enabled": True, "type": "max", "params": {"field": "risk_score"}, "schema": "metric"},
            {
                "id": "2",
                "enabled": True,
                "type": "terms",
                "params": {
                    "field": "source_host.keyword",
                    "orderBy": "1",
                    "order": "desc",
                    "size": 10,
                    "otherBucket": False,
                    "missingBucket": False
                },
                "schema": "segment"
            }
        ],
        "params": {
            "type": "histogram",
            "grid": {"categoryLines": False},
            "categoryAxes": [{
                "id": "CategoryAxis-1",
                "type": "category",
                "position": "left",
                "show": True,
                "style": {},
                "scale": {"type": "linear"},
                "labels": {"show": True, "filter": True, "truncate": 100},
                "title": {}
            }],
            "valueAxes": [{
                "id": "ValueAxis-1",
                "name": "BottomAxis-1",
                "type": "value",
                "position": "bottom",
                "show": True,
                "style": {},
                "scale": {"type": "linear", "mode": "normal"},
                "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                "title": {"text": "Max risk_score"}
            }],
            "seriesParams": [{
                "show": True,
                "type": "histogram",
                "mode": "stacked",
                "data": {"label": "Max risk_score", "id": "1"},
                "valueAxis": "ValueAxis-1",
                "drawLinesBetweenPoints": True,
                "lineWidth": 2,
                "showCircles": True
            }],
            "addTooltip": True,
            "addLegend": True,
            "legendPosition": "right",
            "times": [],
            "addTimeMarker": False,
            "labels": {"show": False},
            "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"}
        }
    }
    create_saved_object("visualization", VIS_IDS[3], {
        "title": "Top Risky Source Hosts",
        "visState": json.dumps(vis_4_state),
        "uiStateJSON": "{}",
        "description": "",
        "version": 1,
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({
                "query": {"language": "kuery", "query": ""},
                "filter": [],
                "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"
            })
        }
    }, [
        {"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": INDEX_PATTERN_ID}
    ])

    # 5. Top Destination Ports (Vertical Bar Chart)
    vis_5_state = {
        "title": "Top Destination Ports",
        "type": "histogram",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
            {
                "id": "2",
                "enabled": True,
                "type": "terms",
                "params": {
                    "field": "destination_port",
                    "orderBy": "1",
                    "order": "desc",
                    "size": 10,
                    "otherBucket": False,
                    "missingBucket": False
                },
                "schema": "segment"
            }
        ],
        "params": {
            "type": "histogram",
            "grid": {"categoryLines": False},
            "categoryAxes": [{
                "id": "CategoryAxis-1",
                "type": "category",
                "position": "bottom",
                "show": True,
                "style": {},
                "scale": {"type": "linear"},
                "labels": {"show": True, "filter": True, "truncate": 100},
                "title": {}
            }],
            "valueAxes": [{
                "id": "ValueAxis-1",
                "name": "LeftAxis-1",
                "type": "value",
                "position": "left",
                "show": True,
                "style": {},
                "scale": {"type": "linear", "mode": "normal"},
                "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                "title": {"text": "Count"}
            }],
            "seriesParams": [{
                "show": True,
                "type": "histogram",
                "mode": "stacked",
                "data": {"label": "Count", "id": "1"},
                "valueAxis": "ValueAxis-1",
                "drawLinesBetweenPoints": True,
                "lineWidth": 2,
                "showCircles": True
            }],
            "addTooltip": True,
            "addLegend": True,
            "legendPosition": "right",
            "times": [],
            "addTimeMarker": False,
            "labels": {"show": False},
            "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"}
        }
    }
    create_saved_object("visualization", VIS_IDS[4], {
        "title": "Top Destination Ports",
        "visState": json.dumps(vis_5_state),
        "uiStateJSON": "{}",
        "description": "",
        "version": 1,
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({
                "query": {"language": "kuery", "query": ""},
                "filter": [],
                "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"
            })
        }
    }, [
        {"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": INDEX_PATTERN_ID}
    ])

    # 6. High Risk Event Details (Data Table)
    fields_vis_6 = [
        ("@timestamp", "@timestamp"),
        ("classification.keyword", "classification"),
        ("risk_score", "risk_score"),
        ("detection_type.keyword", "detection_type"),
        ("source_host.keyword", "source_host"),
        ("source_ip.keyword", "source_ip"),
        ("source_role.keyword", "source_role"),
        ("destination_ip.keyword", "destination_ip"),
        ("destination_role.keyword", "destination_role"),
        ("destination_port", "destination_port"),
        ("service.keyword", "service"),
        ("description.keyword", "description"),
        ("reasons.keyword", "reasons")
    ]
    aggs_vis_6 = [{"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"}]
    for idx, (field_name, label) in enumerate(fields_vis_6, start=2):
        aggs_vis_6.append({
            "id": str(idx),
            "enabled": True,
            "type": "terms",
            "params": {
                "field": field_name,
                "orderBy": "1",
                "order": "desc",
                "size": 100,
                "customLabel": label,
                "missingBucket": False
            },
            "schema": "bucket"
        })
    vis_6_state = {
        "title": "High Risk Event Details",
        "type": "table",
        "aggs": aggs_vis_6,
        "params": {
            "perPage": 10,
            "showPartialRows": True,
            "showMetricsAtAllLevels": False,
            "sort": {"columnIndex": None, "direction": None},
            "showTotal": False,
            "totalFunc": "sum"
        }
    }
    create_saved_object("visualization", VIS_IDS[5], {
        "title": "High Risk Event Details",
        "visState": json.dumps(vis_6_state),
        "uiStateJSON": "{}",
        "description": "",
        "version": 1,
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({
                "query": {
                    "language": "kuery",
                    "query": 'classification.keyword : "Suspicious" OR classification.keyword : "Likely Malicious"'
                },
                "filter": [],
                "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"
            })
        }
    }, [
        {"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": INDEX_PATTERN_ID}
    ])

    # 7. Correlated Host Network Events (Data Table)
    fields_vis_7 = [
        ("@timestamp", "@timestamp"),
        ("source_host.keyword", "source_host"),
        ("source_ip.keyword", "source_ip"),
        ("source_role.keyword", "source_role"),
        ("destination_ip.keyword", "destination_ip"),
        ("destination_role.keyword", "destination_role"),
        ("destination_port", "destination_port"),
        ("service.keyword", "service"),
        ("wazuh_score", "wazuh_score"),
        ("zeek_score", "zeek_score"),
        ("correlation_score", "correlation_score"),
        ("risk_score", "risk_score"),
        ("classification.keyword", "classification"),
        ("time_difference_minutes", "time_difference_minutes"),
        ("reasons.keyword", "reasons")
    ]
    aggs_vis_7 = [{"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"}]
    for idx, (field_name, label) in enumerate(fields_vis_7, start=2):
        aggs_vis_7.append({
            "id": str(idx),
            "enabled": True,
            "type": "terms",
            "params": {
                "field": field_name,
                "orderBy": "1",
                "order": "desc",
                "size": 100,
                "customLabel": label,
                "missingBucket": False
            },
            "schema": "bucket"
        })
    vis_7_state = {
        "title": "Correlated Host Network Events",
        "type": "table",
        "aggs": aggs_vis_7,
        "params": {
            "perPage": 10,
            "showPartialRows": True,
            "showMetricsAtAllLevels": False,
            "sort": {"columnIndex": None, "direction": None},
            "showTotal": False,
            "totalFunc": "sum"
        }
    }
    create_saved_object("visualization", VIS_IDS[6], {
        "title": "Correlated Host Network Events",
        "visState": json.dumps(vis_7_state),
        "uiStateJSON": "{}",
        "description": "",
        "version": 1,
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({
                "query": {
                    "language": "kuery",
                    "query": 'detection_type.keyword : "correlated_host_network_event"'
                },
                "filter": [],
                "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"
            })
        }
    }, [
        {"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": INDEX_PATTERN_ID}
    ])

    print("\nStep 4: Building the new Dashboard...")
    vis_panel_layout = [
        ("0", VIS_IDS[0], 0, 0, 16, 12),     # Risk Classification Count
        ("1", VIS_IDS[1], 16, 0, 16, 12),    # Detection Type Count
        ("2", VIS_IDS[4], 32, 0, 16, 12),    # Top Destination Ports
        ("3", VIS_IDS[2], 0, 12, 48, 12),    # Risk Score Over Time
        ("4", VIS_IDS[3], 0, 24, 16, 15),    # Top Risky Source Hosts
        ("5", VIS_IDS[5], 16, 24, 16, 15),   # High Risk Event Details
        ("6", VIS_IDS[6], 32, 24, 16, 15)    # Correlated Host Network Events
    ]

    panels = []
    references = []

    for panel_idx, vis_id, x, y, w, h in vis_panel_layout:
        ref_name = f"panel_{panel_idx}"
        panels.append({
            "version": "2.11.0",
            "gridData": {"x": x, "y": y, "w": w, "h": h, "i": panel_idx},
            "panelIndex": panel_idx,
            "embeddableConfig": {},
            "panelRefName": ref_name
        })
        references.append({
            "name": ref_name,
            "type": "visualization",
            "id": vis_id
        })

    dashboard_attributes = {
        "title": DASHBOARD_TITLE,
        "description": "Healthcare Contextual Risk Engine Analytics Dashboard",
        "hits": 0,
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({
                "query": {"query": "", "language": "kuery"},
                "filter": []
            })
        },
        "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
        "panelsJSON": json.dumps(panels),
        "timeRestore": False,
        "version": 1
    }

    create_saved_object("dashboard", DASHBOARD_ID, dashboard_attributes, references)
    print("\nDashboard deletion and recreation complete!")


if __name__ == "__main__":
    main()
