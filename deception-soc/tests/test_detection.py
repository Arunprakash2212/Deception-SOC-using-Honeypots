"""
Tests for the Detection Engine (Suricata rules and log watcher).
"""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock, AsyncMock

# Add parent path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'detection-engine', 'log-watcher'))

from watcher import EveLogParser, SIGNATURE_MAP


class TestEveLogParser(unittest.TestCase):
    """Test Suricata EVE JSON log parsing."""

    def test_parse_valid_alert(self):
        """Test parsing a valid Suricata alert."""
        eve_line = json.dumps({
            "event_type": "alert",
            "timestamp": "2024-11-15T10:30:00.000000+0000",
            "src_ip": "192.168.1.100",
            "dest_ip": "10.0.1.15",
            "dest_port": 22,
            "proto": "TCP",
            "alert": {
                "signature_id": 1000003,
                "signature": "DECEPTION - SSH Brute Force Detected",
                "severity": 2,
            }
        })

        threat = EveLogParser.parse_alert(eve_line)
        self.assertIsNotNone(threat)
        self.assertEqual(threat.source_ip, "192.168.1.100")
        self.assertEqual(threat.attack_type, "ssh_bruteforce")
        self.assertEqual(threat.severity, "high")
        self.assertEqual(threat.signature_id, 1000003)

    def test_parse_non_alert_event(self):
        """Test that non-alert events are ignored."""
        eve_line = json.dumps({
            "event_type": "flow",
            "src_ip": "192.168.1.100",
        })
        threat = EveLogParser.parse_alert(eve_line)
        self.assertIsNone(threat)

    def test_parse_unknown_signature(self):
        """Test that unknown signature IDs are skipped."""
        eve_line = json.dumps({
            "event_type": "alert",
            "src_ip": "192.168.1.100",
            "dest_ip": "10.0.1.15",
            "dest_port": 80,
            "alert": {"signature_id": 9999999, "signature": "Unknown"},
        })
        threat = EveLogParser.parse_alert(eve_line)
        self.assertIsNone(threat)

    def test_parse_invalid_json(self):
        """Test handling of invalid JSON."""
        threat = EveLogParser.parse_alert("not valid json{{{")
        self.assertIsNone(threat)

    def test_parse_sql_injection_alert(self):
        """Test parsing SQL injection alert."""
        eve_line = json.dumps({
            "event_type": "alert",
            "timestamp": "2024-11-15T10:30:00.000000+0000",
            "src_ip": "203.0.113.50",
            "dest_ip": "10.0.1.15",
            "dest_port": 80,
            "proto": "TCP",
            "alert": {
                "signature_id": 1000005,
                "signature": "DECEPTION - SQL Injection Attempt Detected",
            }
        })
        threat = EveLogParser.parse_alert(eve_line)
        self.assertIsNotNone(threat)
        self.assertEqual(threat.attack_type, "sql_injection")
        self.assertEqual(threat.severity, "critical")

    def test_signature_map_completeness(self):
        """Test that all expected signatures are mapped."""
        expected_sids = [1000001, 1000002, 1000003, 1000004, 1000005]
        for sid in expected_sids:
            self.assertIn(sid, SIGNATURE_MAP, f"SID {sid} missing from signature map")


if __name__ == "__main__":
    unittest.main()
