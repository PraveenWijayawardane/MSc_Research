import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(
    __file__
).resolve().parents[1]

SRC_ROOT = (
    PROJECT_ROOT
    / "src"
)

if str(SRC_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(
            SRC_ROOT
        ),
    )


from risk_engine import ContextualRiskEngine  # noqa: E402


@pytest.fixture(scope="module")
def engine():
    return ContextualRiskEngine.from_environment(
        environment_id="healthcare-lab",
        config_root=PROJECT_ROOT / "config",
    )


def make_wazuh(
    event_id: str,
    description: str,
    timestamp: str = "2026-08-16T08:00:00Z",
    host_ip: str = "192.168.100.20",
    rule_level: int = 7,
    rule_id: str = "5503",
):
    return {
        "_id": event_id,
        "_source": {
            "timestamp": timestamp,
            "environment_id": "healthcare-lab",
            "agent": {
                "ip": host_ip,
                "name": "user-pc-01",
            },
            "rule": {
                "id": rule_id,
                "level": rule_level,
                "description": description,
            },
            "full_log": description,
        },
    }


def make_zeek(
    uid: str,
    destination_port: int,
    service: str = "",
    timestamp: str = "2026-08-16T08:01:00Z",
    source_ip: str = "192.168.100.20",
    destination_ip: str = "192.168.100.30",
):
    return {
        "uid": uid,
        "ts": timestamp,
        "id.orig_h": source_ip,
        "id.orig_p": 50000,
        "id.resp_h": destination_ip,
        "id.resp_p": destination_port,
        "proto": "tcp",
        "service": service,
        "conn_state": "SF",
        "duration": 1.0,
        "orig_bytes": 100,
        "resp_bytes": 100,
        "environment_id": "healthcare-lab",
    }


def test_generic_temporal_match_does_not_correlate(
    engine,
):
    output = engine.build_output(
        wazuh_data=[
            make_wazuh(
                "generic-1",
                "service restarted",
            )
        ],
        zeek_data=[
            make_zeek(
                "normal-ehr-1",
                destination_port=5000,
                service="http",
            )
        ],
    )

    assert (
        output[
            "summary"
        ][
            "correlated_result_count"
        ]
        == 0
    )


def test_privilege_activity_does_not_correlate_with_normal_ehr(
    engine,
):
    output = engine.build_output(
        wazuh_data=[
            make_wazuh(
                "sudo-normal-ehr",
                "sudo root session",
            )
        ],
        zeek_data=[
            make_zeek(
                "normal-ehr-2",
                destination_port=5000,
                service="http",
            )
        ],
    )

    assert (
        output[
            "correlated_results"
        ]
        == []
    )


def test_failed_authentication_correlates_with_ssh(
    engine,
):
    output = engine.build_output(
        wazuh_data=[
            make_wazuh(
                "failed-auth-ssh",
                "failed password authentication failure",
            )
        ],
        zeek_data=[
            make_zeek(
                "ssh-1",
                destination_port=22,
                service="ssh",
            )
        ],
    )

    assert len(
        output[
            "correlated_results"
        ]
    ) == 1

    result = (
        output[
            "correlated_results"
        ][0]
    )

    assert (
        result[
            "semantic_correlation"
        ]
        is True
    )

    assert (
        result[
            "correlation_strength"
        ]
        == "strong"
    )

    assert (
        "failed_authentication_remote_service"
        in result[
            "correlation_types"
        ]
    )


def test_privilege_activity_correlates_with_database_access(
    engine,
):
    output = engine.build_output(
        wazuh_data=[
            make_wazuh(
                "sudo-db",
                "sudo root session",
            )
        ],
        zeek_data=[
            make_zeek(
                "db-1",
                destination_port=5432,
                service="postgresql",
            )
        ],
    )

    assert len(
        output[
            "correlated_results"
        ]
    ) == 1

    result = (
        output[
            "correlated_results"
        ][0]
    )

    assert (
        "privilege_database_access"
        in result[
            "correlation_types"
        ]
    )


def test_privilege_activity_correlates_with_smb(
    engine,
):
    output = engine.build_output(
        wazuh_data=[
            make_wazuh(
                "sudo-smb",
                "sudo root session",
            )
        ],
        zeek_data=[
            make_zeek(
                "smb-1",
                destination_port=445,
                service="smb",
            )
        ],
    )

    assert len(
        output[
            "correlated_results"
        ]
    ) == 1

    assert (
        "privilege_smb_activity"
        in output[
            "correlated_results"
        ][0][
            "correlation_types"
        ]
    )


def test_malware_correlates_with_smb(
    engine,
):
    output = engine.build_output(
        wazuh_data=[
            make_wazuh(
                "malware-smb",
                "malware malicious file detected",
                rule_level=12,
            )
        ],
        zeek_data=[
            make_zeek(
                "smb-2",
                destination_port=445,
                service="smb",
            )
        ],
    )

    assert len(
        output[
            "correlated_results"
        ]
    ) == 1

    assert (
        "malware_smb_activity"
        in output[
            "correlated_results"
        ][0][
            "correlation_types"
        ]
    )


def test_semantic_match_outside_window_does_not_correlate(
    engine,
):
    output = engine.build_output(
        wazuh_data=[
            make_wazuh(
                "old-auth",
                "authentication failure",
                timestamp="2026-08-16T07:50:00Z",
            )
        ],
        zeek_data=[
            make_zeek(
                "late-ssh",
                destination_port=22,
                service="ssh",
                timestamp="2026-08-16T08:01:00Z",
            )
        ],
    )

    assert (
        output[
            "correlated_results"
        ]
        == []
    )


def test_generic_temporal_match_is_discarded_when_semantic_match_exists(
    engine,
):
    output = engine.build_output(
        wazuh_data=[
            make_wazuh(
                "nearby-service-change",
                "service restarted",
                timestamp="2026-08-16T08:00:10Z",
            ),
            make_wazuh(
                "real-failed-auth",
                "authentication failure failed password",
                timestamp="2026-08-16T08:00:20Z",
            ),
        ],
        zeek_data=[
            make_zeek(
                "mixed-ssh",
                destination_port=22,
                service="ssh",
                timestamp="2026-08-16T08:01:00Z",
            )
        ],
    )

    assert len(
        output[
            "correlated_results"
        ]
    ) == 1

    result = (
        output[
            "correlated_results"
        ][0]
    )

    assert (
        result[
            "temporal_wazuh_count"
        ]
        == 2
    )

    assert (
        result[
            "matched_wazuh_count"
        ]
        == 1
    )

    assert (
        result[
            "discarded_temporal_match_count"
        ]
        == 1
    )

    assert (
        result[
            "matched_wazuh_event_ids"
        ]
        == [
            "wazuh:real-failed-auth"
        ]
    )


def test_priority3_mdns_exclusion_is_preserved(
    engine,
):
    mdns_event = {
        "uid": "mdns-priority3-check",
        "ts": "2026-08-16T08:01:00Z",
        "id.orig_h": "192.168.100.20",
        "id.orig_p": 5353,
        "id.resp_h": "224.0.0.251",
        "id.resp_p": 5353,
        "proto": "udp",
        "service": "dns",
        "conn_state": "SF",
        "duration": 0.1,
        "orig_bytes": 50,
        "resp_bytes": 50,
        "environment_id": "healthcare-lab",
    }

    output = engine.build_output(
        wazuh_data=[
            make_wazuh(
                "auth-near-mdns",
                "authentication failure",
            )
        ],
        zeek_data=[
            mdns_event
        ],
    )

    assert (
        output[
            "summary"
        ][
            "risk_eligible_zeek_event_count"
        ]
        == 0
    )

    assert (
        output[
            "summary"
        ][
            "excluded_zeek_event_count"
        ]
        == 1
    )

    assert (
        output[
            "zeek_results"
        ]
        == []
    )

    assert (
        output[
            "correlated_results"
        ]
        == []
    )