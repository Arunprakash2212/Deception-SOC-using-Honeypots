"""
=============================================================================
Traffic Redirector
=============================================================================
Manipulates iptables to redirect attacker traffic from real systems
to honeypot containers. Uses DNAT rules in a custom chain.
=============================================================================
"""

import logging
import shlex
import subprocess
from typing import Dict, List, Tuple

logger = logging.getLogger("orchestrator.traffic_redirector")


class TrafficRedirector:
    """
    Manages iptables rules to redirect attacker traffic to honeypots.
    Creates a custom DECEPTION_REDIRECT chain in the nat table.
    """

    CHAIN_NAME = "DECEPTION_REDIRECT"

    def __init__(self):
        self._active_rules: Dict[str, List[str]] = {}  # source_ip → list of rules
        self._initialized = False
        self._initialize_chain()

    def _run_iptables(self, cmd: str) -> bool:
        """Execute an iptables command safely."""
        full_cmd = f"iptables {cmd}"
        logger.debug(f"Executing: {full_cmd}")
        try:
            result = subprocess.run(
                shlex.split(full_cmd),
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                stderr = result.stderr.strip()
                # Ignore "already exists" or "no such chain" errors during init
                if "already exists" in stderr or "No chain" in stderr:
                    logger.debug(f"iptables notice: {stderr}")
                    return True
                logger.error(f"iptables error (rc={result.returncode}): {stderr}")
                return False
            return True
        except subprocess.TimeoutExpired:
            logger.error(f"iptables command timed out: {full_cmd}")
            return False
        except FileNotFoundError:
            logger.error("iptables not found. Ensure iptables is installed.")
            return False
        except Exception as e:
            logger.error(f"Error executing iptables command: {e}")
            return False

    def _initialize_chain(self):
        """Create the custom DECEPTION_REDIRECT chain in the nat table."""
        # Create the custom chain
        if self._run_iptables(f"-t nat -N {self.CHAIN_NAME}"):
            logger.info(f"Created iptables chain: {self.CHAIN_NAME}")
        else:
            logger.info(f"Chain {self.CHAIN_NAME} may already exist")

        # Insert jump rule to our chain from PREROUTING
        self._run_iptables(
            f"-t nat -C PREROUTING -j {self.CHAIN_NAME}"
        ) or self._run_iptables(
            f"-t nat -I PREROUTING -j {self.CHAIN_NAME}"
        )

        self._initialized = True
        logger.info("Traffic redirector initialized with custom chain")

    def redirect(
        self,
        source_ip: str,
        original_dest_ip: str,
        original_port: int,
        honeypot_ip: str,
        honeypot_port: int,
    ) -> bool:
        """
        Create iptables rules to redirect traffic from source_ip
        to the honeypot instead of the real destination.

        Args:
            source_ip: Attacker's IP address
            original_dest_ip: The IP the attacker was targeting
            original_port: The port the attacker was targeting
            honeypot_ip: The honeypot's IP address
            honeypot_port: The honeypot's service port

        Returns:
            True if rules were successfully created
        """
        logger.info(
            f"Creating redirect: {source_ip} → {original_dest_ip}:{original_port} "
            f"⇒ {honeypot_ip}:{honeypot_port}"
        )

        rules = []

        # DNAT rule: redirect incoming traffic to honeypot
        dnat_rule = (
            f"-t nat -A {self.CHAIN_NAME} "
            f"-s {source_ip} -d {original_dest_ip} -p tcp "
            f"--dport {original_port} -j DNAT "
            f"--to-destination {honeypot_ip}:{honeypot_port}"
        )

        if not self._run_iptables(dnat_rule):
            logger.error(f"Failed to create DNAT rule for {source_ip}")
            return False
        rules.append(dnat_rule)

        # MASQUERADE rule for return traffic
        masq_rule = (
            f"-t nat -A POSTROUTING "
            f"-s {honeypot_ip} -d {source_ip} -p tcp "
            f"-j MASQUERADE"
        )

        if not self._run_iptables(masq_rule):
            logger.warning(f"Failed to create MASQUERADE rule for {source_ip}")
            # Continue anyway — DNAT might still work
        rules.append(masq_rule)

        # FORWARD rule to allow traffic to honeypot
        forward_rule = (
            f"-A FORWARD "
            f"-s {source_ip} -d {honeypot_ip} -p tcp "
            f"--dport {honeypot_port} -j ACCEPT"
        )
        self._run_iptables(forward_rule)
        rules.append(forward_rule)

        # Store rules for cleanup
        if source_ip not in self._active_rules:
            self._active_rules[source_ip] = []
        self._active_rules[source_ip].extend(rules)

        logger.info(
            f"Traffic redirect active: {source_ip} → {honeypot_ip}:{honeypot_port} "
            f"({len(rules)} rules created)"
        )
        return True

    def remove_redirect(self, source_ip: str) -> bool:
        """
        Remove all redirect rules for a specific source IP.

        Args:
            source_ip: The attacker's IP to remove redirect for

        Returns:
            True if all rules were successfully removed
        """
        rules = self._active_rules.get(source_ip)
        if not rules:
            logger.warning(f"No active redirect rules found for {source_ip}")
            return False

        logger.info(f"Removing {len(rules)} redirect rules for {source_ip}")

        success = True
        for rule in rules:
            # Change -A (append) to -D (delete)
            delete_rule = rule.replace(" -A ", " -D ", 1)
            if not self._run_iptables(delete_rule):
                logger.warning(f"Failed to remove rule: {delete_rule}")
                success = False

        # Clean up tracking
        del self._active_rules[source_ip]
        logger.info(f"Redirect rules removed for {source_ip}")
        return success

    def block_ip(self, source_ip: str) -> bool:
        """
        Block all traffic from a source IP using iptables DROP.

        Args:
            source_ip: The IP address to block

        Returns:
            True if the block rule was successfully created
        """
        logger.info(f"Blocking IP: {source_ip}")

        rule = f"-A INPUT -s {source_ip} -j DROP"
        if self._run_iptables(rule):
            if source_ip not in self._active_rules:
                self._active_rules[source_ip] = []
            self._active_rules[source_ip].append(rule)
            logger.info(f"IP blocked: {source_ip}")
            return True
        return False

    def unblock_ip(self, source_ip: str) -> bool:
        """Remove a block rule for a source IP."""
        logger.info(f"Unblocking IP: {source_ip}")
        rule = f"-D INPUT -s {source_ip} -j DROP"
        return self._run_iptables(rule)

    def get_active_redirects(self) -> Dict[str, List[str]]:
        """Return all active redirect rules."""
        return dict(self._active_rules)

    def cleanup_all(self) -> int:
        """Remove all redirect and block rules. Returns count of IPs cleaned."""
        ips = list(self._active_rules.keys())
        for ip in ips:
            self.remove_redirect(ip)
        logger.info(f"Cleaned up rules for {len(ips)} IPs")

        # Flush our custom chain
        self._run_iptables(f"-t nat -F {self.CHAIN_NAME}")
        return len(ips)
