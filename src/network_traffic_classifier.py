#!/usr/bin/env python3
"""
Classify routine Zeek discovery/network-control traffic.

The classifier does not delete telemetry. It adds metadata that allows the
risk engine to exclude routine discovery/control traffic from behavioural
analysis, contextual scoring, correlation, and investigation publishing.
"""

from __future__ import annotations

import ipaddress
from typing import Any


IPV6_SOLICITED_NODE_NETWORK = ipaddress.ip_network(
    "ff02::1:ff00:0/104"
)

ICMP_CONTROL_PROTOCOLS = {
    "icmp",
    "icmp6",
    "icmpv6",
    "ipv6-icmp",
}


def _normalise_text(value: Any) -> str:
    """Return a lower-case trimmed string."""
    return str(value or "").strip().lower()


def _destination_port(event: dict[str, Any]) -> int:
    """Return the destination port safely."""
    value = (
        event.get("id.resp_p")
        or event.get("destination_port")
        or 0
    )

    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def classify_zeek_traffic(
    event: dict[str, Any],
) -> dict[str, Any]:
    """
    Return traffic-classification metadata for a Zeek connection event.

    Only narrow, well-known routine discovery/control flows are excluded.
    Unknown traffic, ordinary unicast traffic, unusual multicast usage, and
    IPv6 link-local unicast remain risk eligible by default.
    """
    destination_ip = _normalise_text(
        event.get("id.resp_h")
        or event.get("destination_ip")
    )
    destination_port = _destination_port(event)
    protocol = _normalise_text(
        event.get("proto")
        or event.get("protocol")
    )

    default_result = {
        "traffic_class": "network_connection",
        "risk_eligible": True,
        "risk_exclusion_reason": None,
    }

    # Multicast DNS (mDNS)
    if (
        destination_ip in {"224.0.0.251", "ff02::fb"}
        and destination_port == 5353
        and protocol == "udp"
    ):
        return {
            "traffic_class": "service_discovery",
            "risk_eligible": False,
            "risk_exclusion_reason": "mdns",
        }

    # Link-Local Multicast Name Resolution (LLMNR)
    if (
        destination_ip in {"224.0.0.252", "ff02::1:3"}
        and destination_port == 5355
        and protocol in {"udp", "tcp"}
    ):
        return {
            "traffic_class": "service_discovery",
            "risk_eligible": False,
            "risk_exclusion_reason": "llmnr",
        }

    # Simple Service Discovery Protocol (SSDP)
    if (
        destination_ip in {"239.255.255.250", "ff02::c"}
        and destination_port == 1900
        and protocol == "udp"
    ):
        return {
            "traffic_class": "service_discovery",
            "risk_eligible": False,
            "risk_exclusion_reason": "ssdp",
        }

    # IPv6 all-nodes multicast. Restrict the exclusion to ICMP control
    # traffic so unusual TCP/UDP use is not silently hidden.
    if (
        destination_ip == "ff02::1"
        and protocol in ICMP_CONTROL_PROTOCOLS
    ):
        return {
            "traffic_class": "network_control",
            "risk_eligible": False,
            "risk_exclusion_reason": "ipv6_all_nodes_multicast",
        }

    # IPv6 all-routers multicast.
    if (
        destination_ip == "ff02::2"
        and protocol in ICMP_CONTROL_PROTOCOLS
    ):
        return {
            "traffic_class": "network_control",
            "risk_eligible": False,
            "risk_exclusion_reason": "ipv6_all_routers_multicast",
        }

    # IPv6 solicited-node multicast ff02::1:ff00:0/104.
    if protocol in ICMP_CONTROL_PROTOCOLS:
        try:
            parsed_destination = ipaddress.ip_address(
                destination_ip
            )

            if (
                parsed_destination.version == 6
                and parsed_destination in IPV6_SOLICITED_NODE_NETWORK
            ):
                return {
                    "traffic_class": "network_control",
                    "risk_eligible": False,
                    "risk_exclusion_reason": (
                        "ipv6_solicited_node_multicast"
                    ),
                }
        except ValueError:
            pass

    # Do not broadly suppress fe80::/10 or other IPv6/unclassified traffic.
    return default_result