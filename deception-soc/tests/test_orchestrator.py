"""
Tests for the Orchestrator (Decision Engine, Models).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'orchestrator'))

from app.models import ThreatEvent, DeceptionSession, ActionType, SessionStatus
from app.decision_engine import DeceptionDecisionEngine


class TestDecisionEngine(unittest.TestCase):
    """Test the deception decision engine."""

    def setUp(self):
        self.engine = DeceptionDecisionEngine()
        self.engine.clear_cooldown()

    def _make_threat(self, src_ip="203.0.113.50", attack_type="nmap_scan",
                     severity="medium", dest_port=22):
        return ThreatEvent(
            timestamp="2024-11-15T10:30:00Z",
            source_ip=src_ip,
            destination_ip="10.0.1.15",
            destination_port=dest_port,
            attack_type=attack_type,
            severity=severity,
            signature_id=1000001,
            signature_text="Test alert",
            protocol="TCP",
        )

    def test_critical_severity_traps(self):
        """Critical severity should result in TRAP."""
        threat = self._make_threat(severity="critical", attack_type="sql_injection")
        decision = self.engine.evaluate(threat)
        self.assertEqual(decision.action, ActionType.TRAP)
        self.assertEqual(decision.honeypot_type, "http")

    def test_high_severity_traps(self):
        """High severity should result in TRAP."""
        threat = self._make_threat(severity="high", attack_type="ssh_bruteforce")
        decision = self.engine.evaluate(threat)
        self.assertEqual(decision.action, ActionType.TRAP)
        self.assertEqual(decision.honeypot_type, "ssh")

    def test_medium_severity_traps(self):
        """Medium severity should result in TRAP."""
        threat = self._make_threat(severity="medium", attack_type="nmap_scan")
        decision = self.engine.evaluate(threat)
        self.assertEqual(decision.action, ActionType.TRAP)
        self.assertEqual(decision.honeypot_type, "multi")

    def test_low_severity_monitors(self):
        """Low severity should result in MONITOR."""
        threat = self._make_threat(severity="low")
        decision = self.engine.evaluate(threat)
        self.assertEqual(decision.action, ActionType.MONITOR)

    def test_whitelist_monitors(self):
        """Whitelisted IPs should result in MONITOR."""
        for ip in ["10.0.0.1", "172.16.5.10", "192.168.1.100"]:
            threat = self._make_threat(src_ip=ip, severity="critical")
            decision = self.engine.evaluate(threat)
            self.assertEqual(decision.action, ActionType.MONITOR,
                           f"IP {ip} should be whitelisted")

    def test_cooldown(self):
        """Same IP within cooldown should result in MONITOR."""
        threat = self._make_threat(src_ip="203.0.113.99", severity="high")
        decision1 = self.engine.evaluate(threat)
        self.assertEqual(decision1.action, ActionType.TRAP)

        decision2 = self.engine.evaluate(threat)
        self.assertEqual(decision2.action, ActionType.MONITOR)

    def test_attack_type_mapping(self):
        """Attack types should map to correct honeypot types."""
        mappings = {
            "nmap_scan": "multi",
            "ssh_bruteforce": "ssh",
            "http_enumeration": "http",
            "sql_injection": "http",
            "ftp_bruteforce": "ftp",
        }
        for attack_type, expected_hp in mappings.items():
            self.engine.clear_cooldown()
            threat = self._make_threat(
                src_ip=f"203.0.113.{hash(attack_type) % 200 + 1}",
                attack_type=attack_type,
                severity="high",
            )
            decision = self.engine.evaluate(threat)
            self.assertEqual(decision.honeypot_type, expected_hp,
                           f"{attack_type} should map to {expected_hp}")


class TestModels(unittest.TestCase):
    """Test Pydantic models."""

    def test_threat_event_creation(self):
        event = ThreatEvent(
            timestamp="2024-11-15T10:30:00Z",
            source_ip="203.0.113.50",
            destination_ip="10.0.1.15",
            destination_port=22,
            attack_type="ssh_bruteforce",
            severity="high",
            signature_id=1000003,
        )
        self.assertEqual(event.source_ip, "203.0.113.50")

    def test_deception_session_defaults(self):
        session = DeceptionSession(
            attacker_ip="203.0.113.50",
            honeypot_ip="172.20.0.10",
            honeypot_port=22,
            honeypot_type="ssh",
            attack_type="ssh_bruteforce",
        )
        self.assertEqual(session.status, SessionStatus.ACTIVE)
        self.assertIsNotNone(session.session_id)
        self.assertEqual(session.commands_executed, [])


if __name__ == "__main__":
    unittest.main()
