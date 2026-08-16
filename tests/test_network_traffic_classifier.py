import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(
    0,
    str(PROJECT_ROOT / "src"),
)


from network_traffic_classifier import (  # noqa: E402
    classify_zeek_traffic,
)


class NetworkTrafficClassifierTests(unittest.TestCase):
    def test_ipv4_mdns_is_excluded(self):
        result = classify_zeek_traffic(
            {
                "id.resp_h": "224.0.0.251",
                "id.resp_p": 5353,
                "proto": "udp",
            }
        )

        self.assertFalse(result["risk_eligible"])
        self.assertEqual(
            result["traffic_class"],
            "service_discovery",
        )
        self.assertEqual(
            result["risk_exclusion_reason"],
            "mdns",
        )

    def test_ipv6_mdns_is_excluded(self):
        result = classify_zeek_traffic(
            {
                "id.resp_h": "ff02::fb",
                "id.resp_p": 5353,
                "proto": "udp",
            }
        )

        self.assertFalse(result["risk_eligible"])
        self.assertEqual(
            result["risk_exclusion_reason"],
            "mdns",
        )

    def test_ipv4_llmnr_is_excluded(self):
        result = classify_zeek_traffic(
            {
                "id.resp_h": "224.0.0.252",
                "id.resp_p": 5355,
                "proto": "udp",
            }
        )

        self.assertFalse(result["risk_eligible"])
        self.assertEqual(
            result["risk_exclusion_reason"],
            "llmnr",
        )

    def test_ssdp_is_excluded(self):
        result = classify_zeek_traffic(
            {
                "id.resp_h": "239.255.255.250",
                "id.resp_p": 1900,
                "proto": "udp",
            }
        )

        self.assertFalse(result["risk_eligible"])
        self.assertEqual(
            result["risk_exclusion_reason"],
            "ssdp",
        )

    def test_ipv6_all_routers_icmp_is_excluded(self):
        result = classify_zeek_traffic(
            {
                "id.resp_h": "ff02::2",
                "id.resp_p": 0,
                "proto": "icmp",
            }
        )

        self.assertFalse(result["risk_eligible"])
        self.assertEqual(
            result["traffic_class"],
            "network_control",
        )
        self.assertEqual(
            result["risk_exclusion_reason"],
            "ipv6_all_routers_multicast",
        )

    def test_ipv6_solicited_node_icmp_is_excluded(self):
        result = classify_zeek_traffic(
            {
                "id.resp_h": "ff02::1:ff12:3456",
                "id.resp_p": 0,
                "proto": "icmp",
            }
        )

        self.assertFalse(result["risk_eligible"])
        self.assertEqual(
            result["risk_exclusion_reason"],
            "ipv6_solicited_node_multicast",
        )

    def test_normal_ipv4_connection_is_eligible(self):
        result = classify_zeek_traffic(
            {
                "id.resp_h": "192.168.100.30",
                "id.resp_p": 5000,
                "proto": "tcp",
            }
        )

        self.assertTrue(result["risk_eligible"])
        self.assertEqual(
            result["traffic_class"],
            "network_connection",
        )

    def test_ipv6_link_local_unicast_is_eligible(self):
        result = classify_zeek_traffic(
            {
                "id.resp_h": "fe80::1234",
                "id.resp_p": 22,
                "proto": "tcp",
            }
        )

        self.assertTrue(result["risk_eligible"])

    def test_unusual_tcp_to_solicited_node_address_is_not_hidden(self):
        result = classify_zeek_traffic(
            {
                "id.resp_h": "ff02::1:ff12:3456",
                "id.resp_p": 4444,
                "proto": "tcp",
            }
        )

        self.assertTrue(result["risk_eligible"])


if __name__ == "__main__":
    unittest.main()