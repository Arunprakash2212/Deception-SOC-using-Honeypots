"""
=============================================================================
FTP Honeypot — Fake FTP Server
=============================================================================
A fake FTP server that serves bait files and logs all interactions.
Uses pyftpdlib for the FTP protocol implementation.
=============================================================================
"""

import json
import logging
import os
import sys
import time
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List

import requests
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SERVICE_PORT = int(os.getenv("SERVICE_PORT", "21"))
ATTACKER_IP = os.getenv("ATTACKER_IP", "unknown")
LOGGER_URL = os.getenv("LOGGER_URL", "http://logger:9000")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("ftp-honeypot")

# ---------------------------------------------------------------------------
# Session State
# ---------------------------------------------------------------------------
login_attempts: List[dict] = []
commands_executed: List[dict] = []
file_downloads: List[dict] = []

# ---------------------------------------------------------------------------
# Accepted Credentials
# ---------------------------------------------------------------------------
USERS = {
    "admin": "admin",
    "admin123": "admin123",
    "root": "root",
    "test": "test",
    "anonymous": "",
    "ftp": "ftp",
}

# ---------------------------------------------------------------------------
# Bait Files Setup
# ---------------------------------------------------------------------------
def create_bait_files(base_dir: str):
    """Create realistic bait files in the FTP root directory."""
    os.makedirs(base_dir, exist_ok=True)

    # backup.zip placeholder (small file with header bytes)
    backup_path = os.path.join(base_dir, "backup.zip")
    with open(backup_path, "wb") as f:
        # Write PK zip header followed by fake content
        f.write(b"PK\x03\x04")
        f.write(b"\x00" * 26)
        f.write(b"FAKE_BACKUP_ARCHIVE_CONTENTS_DO_NOT_USE\n" * 100)

    # passwords.xlsx placeholder
    passwords_path = os.path.join(base_dir, "passwords.xlsx")
    with open(passwords_path, "w") as f:
        f.write("Username,Password,Service,Notes\n")
        f.write("admin,Adm1n_FAKE_P@ss!,Portal,Main admin account\n")
        f.write("root,R00t_FAKE_MySQL_2024,MySQL,Database root\n")
        f.write("deploy,D3pl0y_FAKE_K3y!,Jenkins,CI/CD deploy user\n")
        f.write("backup,B@ckup_FAKE_Acc3ss,S3,AWS backup user\n")
        f.write("api_user,AP1_FAKE_s3cr3t_k3y,API,REST API access\n")
        f.write("sa,SA_FAKE_SqlS3rv3r!,MSSQL,SQL Server admin\n")
        f.write("postgres,PG_FAKE_Sup3rUs3r,PostgreSQL,PG admin\n")

    # db_dump.sql
    dump_path = os.path.join(base_dir, "db_dump.sql")
    with open(dump_path, "w") as f:
        f.write("-- MySQL dump - FAKE HONEYPOT DATA\n")
        f.write("-- Host: db-prod-01.internal.corp\n")
        f.write("-- Database: production_db\n")
        f.write(f"-- Dump date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("CREATE DATABASE IF NOT EXISTS production_db;\n")
        f.write("USE production_db;\n\n")
        f.write("CREATE TABLE users (\n")
        f.write("  id INT AUTO_INCREMENT PRIMARY KEY,\n")
        f.write("  username VARCHAR(255) NOT NULL,\n")
        f.write("  email VARCHAR(255) NOT NULL,\n")
        f.write("  password_hash VARCHAR(255) NOT NULL,\n")
        f.write("  api_key VARCHAR(255),\n")
        f.write("  role ENUM('admin','user','manager') DEFAULT 'user',\n")
        f.write("  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n")
        f.write(");\n\n")
        f.write("INSERT INTO users (username, email, password_hash, api_key, role) VALUES\n")
        f.write("('admin', 'admin@company.com', '$2b$12$FAKE_HASH_admin', 'ak_FAKE_admin_key', 'admin'),\n")
        f.write("('john', 'john@company.com', '$2b$12$FAKE_HASH_john', 'ak_FAKE_john_key', 'manager'),\n")
        f.write("('sarah', 'sarah@company.com', '$2b$12$FAKE_HASH_sarah', 'ak_FAKE_sarah_key', 'user');\n\n")
        f.write("CREATE TABLE api_keys (\n")
        f.write("  id INT AUTO_INCREMENT PRIMARY KEY,\n")
        f.write("  key_value VARCHAR(255) NOT NULL,\n")
        f.write("  service VARCHAR(100),\n")
        f.write("  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n")
        f.write(");\n\n")
        f.write("INSERT INTO api_keys (key_value, service) VALUES\n")
        f.write("('sk_live_FAKE_stripe_key_123', 'stripe'),\n")
        f.write("('SG.FAKE_sendgrid_key_456', 'sendgrid'),\n")
        f.write("('AKIAIOSFODNN7FAKEAWS', 'aws');\n")

    # id_rsa (fake private key)
    rsa_path = os.path.join(base_dir, "id_rsa")
    with open(rsa_path, "w") as f:
        f.write("-----BEGIN OPENSSH PRIVATE KEY-----\n")
        f.write("FAKE_PRIVATE_KEY_DO_NOT_USE_b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAE\n")
        f.write("bm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQAAACBmFAKE_KEY_DATA\n")
        f.write("xyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789FAKE_KEY_CONTENT_HERE\n")
        f.write("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345\n")
        f.write("FAKE_DO_NOT_USE_THIS_IS_A_HONEYPOT_PRIVATE_KEY_FOR_DECEPTION\n")
        f.write("-----END OPENSSH PRIVATE KEY-----\n")

    # Create subdirectories with more bait
    config_dir = os.path.join(base_dir, "config")
    os.makedirs(config_dir, exist_ok=True)

    with open(os.path.join(config_dir, "app.env"), "w") as f:
        f.write("DB_PASSWORD=Pr0d_DB_FAKE_P@ssw0rd_2024!\n")
        f.write("AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCFAKESECRETKEY\n")
        f.write("JWT_SECRET=FAKE_jwt_secr3t_hS512_kM4nP6qR8s\n")

    logger.info(f"Bait files created in {base_dir}")
    return base_dir


# ---------------------------------------------------------------------------
# Custom FTP Handler
# ---------------------------------------------------------------------------
class HoneypotFTPHandler(FTPHandler):
    """Custom FTP handler that logs all activity."""

    def on_connect(self):
        logger.info(f"FTP connection from {self.remote_ip}:{self.remote_port}")

    def on_disconnect(self):
        logger.info(f"FTP disconnect from {self.remote_ip}:{self.remote_port}")
        # Send logs on disconnect
        send_logs()

    def on_login(self, username):
        login_attempts.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "username": username,
            "success": True,
            "remote_ip": self.remote_ip,
        })
        logger.info(f"FTP login SUCCESS: {username} from {self.remote_ip}")

    def on_login_failed(self, username, password):
        login_attempts.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "username": username,
            "password": password,
            "success": False,
            "remote_ip": self.remote_ip,
        })
        logger.info(
            f"FTP login FAILED: {username}:{password} from {self.remote_ip}"
        )

    def on_file_sent(self, file):
        file_downloads.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "file": file,
            "remote_ip": self.remote_ip,
        })
        logger.warning(f"File downloaded: {file} by {self.remote_ip}")

    def on_file_received(self, file):
        commands_executed.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "command": f"STOR {file}",
            "remote_ip": self.remote_ip,
        })
        logger.warning(f"File uploaded: {file} by {self.remote_ip}")

    def ftp_LIST(self, path):
        commands_executed.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "command": f"LIST {path}",
            "remote_ip": self.remote_ip,
        })
        super().ftp_LIST(path)

    def ftp_RETR(self, file):
        commands_executed.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "command": f"RETR {file}",
            "remote_ip": self.remote_ip,
        })
        super().ftp_RETR(file)

    def ftp_CWD(self, path):
        commands_executed.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "command": f"CWD {path}",
            "remote_ip": self.remote_ip,
        })
        super().ftp_CWD(path)

    def ftp_PWD(self, line):
        commands_executed.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "command": "PWD",
            "remote_ip": self.remote_ip,
        })
        super().ftp_PWD(line)


def send_logs():
    """Send all FTP session logs to the Logger service."""
    if not login_attempts and not commands_executed and not file_downloads:
        return

    payload = {
        "attacker_ip": ATTACKER_IP,
        "service": "ftp",
        "session_start": login_attempts[0]["timestamp"] if login_attempts else datetime.now(timezone.utc).isoformat(),
        "session_end": datetime.now(timezone.utc).isoformat(),
        "credentials_tried": login_attempts,
        "commands": commands_executed,
        "files_accessed": file_downloads,
        "download_attempts": file_downloads,
    }

    try:
        resp = requests.post(
            f"{LOGGER_URL}/api/v1/session/log",
            json=payload,
            timeout=10,
        )
        logger.info(f"FTP logs sent to logger: status={resp.status_code}")
    except Exception as e:
        logger.warning(f"Could not send FTP logs: {e}")
        try:
            fallback = f"/tmp/ftp_log_{int(time.time())}.json"
            with open(fallback, "w") as f:
                json.dump(payload, f, indent=2)
            logger.info(f"FTP logs saved to fallback: {fallback}")
        except IOError:
            pass


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------
def main():
    logger.info(f"Starting FTP honeypot on port {SERVICE_PORT}")
    logger.info(f"Attacker IP: {ATTACKER_IP}")
    logger.info(f"Logger URL: {LOGGER_URL}")

    # Create bait files directory
    ftp_root = "/tmp/ftp-honeypot-root"
    create_bait_files(ftp_root)

    # Set up authorizer with accepted credentials
    authorizer = DummyAuthorizer()

    for username, password in USERS.items():
        try:
            if username == "anonymous":
                authorizer.add_anonymous(ftp_root)
            else:
                authorizer.add_user(
                    username, password, ftp_root,
                    perm="elradfmwMT"  # Full permissions (to log everything)
                )
        except Exception as e:
            logger.warning(f"Could not add user {username}: {e}")

    # Configure handler
    handler = HoneypotFTPHandler
    handler.authorizer = authorizer
    handler.banner = "220 ProFTPD 1.3.5 Server (Production FTP) [10.0.1.15]"
    handler.passive_ports = range(60000, 60100)

    # Start server
    server = FTPServer(("0.0.0.0", SERVICE_PORT), handler)
    server.max_cons = 50
    server.max_cons_per_ip = 10

    logger.info(f"FTP honeypot listening on port {SERVICE_PORT}")

    try:
        server.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        logger.info("FTP honeypot shutting down...")
        send_logs()
        server.close_all()


if __name__ == "__main__":
    main()
