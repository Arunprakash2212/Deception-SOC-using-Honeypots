"""
=============================================================================
Deception Decision Engine
=============================================================================
Rule-based engine that decides how to handle detected threats:
  - TRAP: Deploy honeypot and redirect attacker
  - BLOCK: Block the attacker's IP entirely
  - MONITOR: Just log and observe
=============================================================================
"""

import ipaddress
import logging
import time
from typing import Dict, Optional

from .models import ThreatEvent, Decision, ActionType
from .config import config

logger = logging.getLogger("orchestrator.decision_engine")


class DeceptionDecisionEngine:
    """
    Rule-based decision engine for determining how to handle attacker traffic.
    NOT AI-based — uses deterministic rules for reliability.
    """

    # Map attack types to appropriate honeypot types
    ATTACK_TO_HONEYPOT: Dict[str, str] = {
        "nmap_scan": "multi",
        "service_probe": "multi",
        "ssh_bruteforce": "ssh",
        "http_enumeration": "http",
        "sql_injection": "http",
        "ftp_bruteforce": "ftp",
        "http_bruteforce": "http",
        "command_injection": "http",
        "path_traversal": "http",
        "reverse_shell": "ssh",
        "dns_tunneling": "multi",
    }

    def __init__(self):
        self._whitelist_networks = [
            ipaddress.ip_network(cidr) for cidr in config.WHITELIST_CIDRS
        ]
        self._cooldown_tracker: Dict[str, float] = {}  # ip → last_decision_time
        self._cooldown_seconds = config.COOLDOWN_SECONDS

    def _is_whitelisted(self, ip: str) -> bool:
        """Check if an IP falls within whitelisted private network ranges."""
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in network for network in self._whitelist_networks)
        except ValueError:
            logger.warning(f"Invalid IP address: {ip}")
            return False

    def _is_in_cooldown(self, ip: str) -> bool:
        """Check if an IP was recently evaluated (within cooldown window)."""
        last_time = self._cooldown_tracker.get(ip)
        if last_time is None:
            return False
        return (time.time() - last_time) < self._cooldown_seconds

    def _update_cooldown(self, ip: str) -> None:
        """Record the current time for cooldown tracking."""
        self._cooldown_tracker[ip] = time.time()

    def _get_honeypot_type(self, attack_type: str) -> str:
        """Map an attack type to the appropriate honeypot type."""
        return self.ATTACK_TO_HONEYPOT.get(attack_type, "multi")

    def evaluate(self, threat: ThreatEvent) -> Decision:
        """
        Evaluate a threat event and decide on the appropriate action.

        Decision flow:
        1. Whitelisted IP → MONITOR
        2. Same IP in cooldown → MONITOR
        3. Critical severity → TRAP
        4. High/Medium severity → TRAP
        5. Low severity → MONITOR
        6. Default → TRAP
        """
        source_ip = threat.source_ip
        severity = threat.severity.lower()
        attack_type = threat.attack_type

        logger.info(
            f"Evaluating threat: ip={source_ip}, "
            f"type={attack_type}, severity={severity}"
        )

        # Rule 1: Whitelist check
        if self._is_whitelisted(source_ip):
            logger.info(f"IP {source_ip} is whitelisted (private network) → MONITOR")
            return Decision(
                action=ActionType.MONITOR,
                reason=f"Source IP {source_ip} is in a whitelisted private network range",
                confidence=1.0,
                honeypot_type=None,
            )

        # Rule 2: Cooldown check
        if self._is_in_cooldown(source_ip):
            logger.info(
                f"IP {source_ip} is in cooldown period "
                f"({self._cooldown_seconds}s) → MONITOR"
            )
            return Decision(
                action=ActionType.MONITOR,
                reason=f"Source IP {source_ip} was recently evaluated, in cooldown",
                confidence=0.9,
                honeypot_type=None,
            )

        # Update cooldown tracker
        self._update_cooldown(source_ip)

        # Rule 3: Critical severity → TRAP
        if severity == "critical":
            honeypot_type = self._get_honeypot_type(attack_type)
            logger.info(
                f"Critical severity attack ({attack_type}) "
                f"from {source_ip} → TRAP ({honeypot_type})"
            )
            return Decision(
                action=ActionType.TRAP,
                reason=f"Critical severity {attack_type} attack detected",
                confidence=0.95,
                honeypot_type=honeypot_type,
            )

        # Rule 4: High severity → TRAP
        if severity == "high":
            honeypot_type = self._get_honeypot_type(attack_type)
            logger.info(
                f"High severity attack ({attack_type}) "
                f"from {source_ip} → TRAP ({honeypot_type})"
            )
            return Decision(
                action=ActionType.TRAP,
                reason=f"High severity {attack_type} attack detected",
                confidence=0.85,
                honeypot_type=honeypot_type,
            )

        # Rule 5: Medium severity → TRAP
        if severity == "medium":
            honeypot_type = self._get_honeypot_type(attack_type)
            logger.info(
                f"Medium severity attack ({attack_type}) "
                f"from {source_ip} → TRAP ({honeypot_type})"
            )
            return Decision(
                action=ActionType.TRAP,
                reason=f"Medium severity {attack_type} attack detected",
                confidence=0.75,
                honeypot_type=honeypot_type,
            )

        # Rule 6: Low severity → MONITOR
        if severity == "low":
            logger.info(
                f"Low severity attack ({attack_type}) "
                f"from {source_ip} → MONITOR"
            )
            return Decision(
                action=ActionType.MONITOR,
                reason=f"Low severity {attack_type} — monitoring only",
                confidence=0.65,
                honeypot_type=None,
            )

        # Default: TRAP
        honeypot_type = self._get_honeypot_type(attack_type)
        logger.info(
            f"Default decision for {attack_type} "
            f"from {source_ip} → TRAP ({honeypot_type})"
        )
        return Decision(
            action=ActionType.TRAP,
            reason=f"Default action for {attack_type} attack",
            confidence=0.7,
            honeypot_type=honeypot_type,
        )

    def clear_cooldown(self, ip: Optional[str] = None) -> None:
        """Clear cooldown for a specific IP or all IPs."""
        if ip:
            self._cooldown_tracker.pop(ip, None)
        else:
            self._cooldown_tracker.clear()
