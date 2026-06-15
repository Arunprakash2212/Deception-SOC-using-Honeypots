#!/bin/bash
# =============================================================================
# iptables Rules for Deception-SOC Network
# =============================================================================
# This script sets up the network infrastructure for traffic redirection.
# Must be run with root privileges on the host.
# =============================================================================

set -e

echo "[*] Setting up Deception-SOC iptables rules..."

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
echo "[+] IP forwarding enabled"

# Create custom chain for deception redirects
iptables -t nat -N DECEPTION_REDIRECT 2>/dev/null || true
echo "[+] DECEPTION_REDIRECT chain created"

# Insert jump rule to our chain from PREROUTING
iptables -t nat -C PREROUTING -j DECEPTION_REDIRECT 2>/dev/null || \
    iptables -t nat -I PREROUTING -j DECEPTION_REDIRECT
echo "[+] PREROUTING jump rule added"

# Allow forwarding to/from deception network
iptables -C FORWARD -s 172.20.0.0/16 -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -s 172.20.0.0/16 -j ACCEPT
iptables -C FORWARD -d 172.20.0.0/16 -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -d 172.20.0.0/16 -j ACCEPT
echo "[+] FORWARD rules for deception network added"

# Enable masquerading for return traffic from honeypots
iptables -t nat -C POSTROUTING -s 172.20.0.0/16 -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s 172.20.0.0/16 -j MASQUERADE
echo "[+] MASQUERADE rule for honeypot return traffic added"

# Log all traffic to deception network (for auditing)
iptables -C FORWARD -d 172.20.0.0/16 -j LOG --log-prefix "DECEPTION-FWD: " --log-level 4 2>/dev/null || \
    iptables -A FORWARD -d 172.20.0.0/16 -j LOG --log-prefix "DECEPTION-FWD: " --log-level 4
echo "[+] Logging rules added"

echo ""
echo "[*] Current DECEPTION_REDIRECT chain:"
iptables -t nat -L DECEPTION_REDIRECT -n -v 2>/dev/null || echo "  (empty — rules added dynamically by orchestrator)"

echo ""
echo "[✓] Deception-SOC network setup complete!"
echo "    Redirects will be added dynamically by the orchestrator."
