"""
=============================================================================
HTTP Honeypot — Fake Web Application
=============================================================================
A realistic-looking web application portal that logs every interaction.
Includes login pages, admin dashboards, API endpoints, and bait files.

Features:
- Realistic login page with HTML comment bait
- Fake admin dashboard with stats and user data
- API endpoints returning fake credentials
- SQL injection detection and logging
- robots.txt revealing "hidden" paths
- .env file with fake secrets
=============================================================================
"""

import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from functools import wraps
from typing import List

import requests
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    jsonify,
    session,
    make_response,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SERVICE_PORT = int(os.getenv("SERVICE_PORT", "80"))
ATTACKER_IP = os.getenv("ATTACKER_IP", "unknown")
LOGGER_URL = os.getenv("LOGGER_URL", "http://logger:9000")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("http-honeypot")

# ---------------------------------------------------------------------------
# Flask Application
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = "FAKE_flask_s3cret_key_honeypot_xY9zW2"

# ---------------------------------------------------------------------------
# Accepted Credentials
# ---------------------------------------------------------------------------
ACCEPTED_CREDENTIALS = {
    ("admin", "admin"),
    ("admin", "admin123"),
    ("admin", "password"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
}

# ---------------------------------------------------------------------------
# Session Tracking
# ---------------------------------------------------------------------------
request_log: List[dict] = []
login_attempts: List[dict] = []
sqli_attempts: List[dict] = []
file_access_log: List[dict] = []
auth_failure_count = {}  # ip → count

# ---------------------------------------------------------------------------
# SQL Injection Patterns
# ---------------------------------------------------------------------------
SQLI_PATTERNS = [
    r"union\s+select",
    r"select\s+.*\s+from",
    r"insert\s+into",
    r"drop\s+table",
    r"delete\s+from",
    r"1\s*=\s*1",
    r"'\s*or\s+",
    r'"\s*or\s+',
    r"--\s*$",
    r";--",
    r"/\*",
    r"'\s*;\s*drop",
    r"union\s+all\s+select",
    r"or\s+1\s*=\s*1",
    r"'\s*or\s+'1'\s*=\s*'1",
]

# ---------------------------------------------------------------------------
# Fake Data
# ---------------------------------------------------------------------------
FAKE_USERS = [
    {
        "id": 1,
        "username": "admin",
        "email": "admin@company.com",
        "role": "admin",
        "api_key": "ak_live_FAKE_xQ9wR7tY5uI3oP1aS2dF4gH6",
        "last_login": "2024-11-15T08:30:00Z",
    },
    {
        "id": 2,
        "username": "john.smith",
        "email": "john.smith@company.com",
        "role": "manager",
        "password_hash": "$2b$12$FAKE_LM7H3kZ9vN1mQ4sW6eR8tY0uI2oP3aS5dF7gH9jK1lZ3xC",
        "last_login": "2024-11-14T14:22:00Z",
    },
    {
        "id": 3,
        "username": "db_admin",
        "email": "dba@company.com",
        "role": "dba",
        "db_password": "DBA_Master_FAKE_2024!",
        "last_login": "2024-11-15T06:15:00Z",
    },
    {
        "id": 4,
        "username": "deploy_bot",
        "email": "deploy@company.com",
        "role": "service",
        "ssh_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ_FAKE_KEY deploy@ci",
        "last_login": "2024-11-15T09:00:00Z",
    },
    {
        "id": 5,
        "username": "sarah.jones",
        "email": "sarah.jones@company.com",
        "role": "developer",
        "github_token": "ghp_FAKE_1234567890abcdefghijklmnopqrstuvwx",
        "last_login": "2024-11-14T16:45:00Z",
    },
]

FAKE_CONFIG = {
    "database": {
        "host": "db-prod-01.internal.corp",
        "port": 3306,
        "name": "production_db",
        "username": "app_rw",
        "password": "Pr0d_DB_FAKE_P@ssw0rd_2024!",
        "max_connections": 100,
    },
    "redis": {
        "host": "10.0.1.55",
        "port": 6379,
        "password": "R3d1s_FAKE_C@ch3_P@ss!",
        "db": 0,
    },
    "aws": {
        "access_key_id": "AKIAIOSFODNN7FAKEAWS",
        "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCFAKESECRETKEY",
        "region": "us-east-1",
        "s3_bucket": "company-assets-prod",
    },
    "jwt": {
        "secret": "FAKE_jwt_secr3t_hS512_kM4nP6qR8sT0uV2wX4yZ",
        "algorithm": "HS512",
        "expiry_hours": 24,
    },
    "encryption": {
        "key": "FAKE_enc_k3y_aEs256_xB7yC9zD1eF3gH5iJ7kL9",
        "algorithm": "AES-256-GCM",
    },
}

FAKE_DATABASE = {
    "tables": [
        {"name": "users", "rows": 12847, "size_mb": 45.2},
        {"name": "orders", "rows": 89234, "size_mb": 234.7},
        {"name": "payments", "rows": 67891, "size_mb": 178.3},
        {"name": "sessions", "rows": 234567, "size_mb": 89.1},
        {"name": "api_keys", "rows": 1523, "size_mb": 2.4},
        {"name": "audit_log", "rows": 1567890, "size_mb": 567.8},
    ],
    "connection": {
        "host": "db-prod-01.internal.corp",
        "port": 3306,
        "user": "app_rw",
        "password": "Pr0d_DB_FAKE_P@ssw0rd_2024!",
        "database": "production_db",
    },
    "status": "connected",
    "version": "MySQL 8.0.35",
    "uptime_hours": 768,
}

FAKE_ENV_FILE = """# Application Environment Configuration
# WARNING: Do not commit this file to version control!

APP_ENV=production
APP_DEBUG=false
APP_SECRET=FAKE_app_s3cret_key_dJ8kL2mN4pQ6rS8tU0vW2xY4z

# Database
DB_HOST=db-prod-01.internal.corp
DB_PORT=3306
DB_NAME=production_db
DB_USER=app_rw
DB_PASSWORD=Pr0d_DB_FAKE_P@ssw0rd_2024!

# Redis
REDIS_URL=redis://:R3d1s_FAKE_C@ch3_P@ss!@10.0.1.55:6379/0

# JWT
JWT_SECRET=FAKE_jwt_secr3t_hS512_kM4nP6qR8sT0uV2wX4yZ

# AWS
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7FAKEAWS
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCFAKESECRETKEY
AWS_REGION=us-east-1
S3_BUCKET=company-assets-prod

# Stripe
STRIPE_SECRET_KEY=sk_live_FAKE_4eC39HqLyjWDarjtT1zdp7dc
STRIPE_PUBLIC_KEY=pk_live_FAKE_TYooMQauvdEDq54NiTphI7jx

# SendGrid
SENDGRID_API_KEY=SG.FAKE_nW4Jd0RhR-OGY0olMEQ.FAKE_key_xyz

# Slack
SLACK_BOT_TOKEN=xoxb-FAKE-1234567890-AbCdEfGhIjKlMnOpQrStUv
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/TFAKE/BFAKE/FAKE_webhook_key
"""


# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------
def log_request():
    """Log every HTTP request."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "method": request.method,
        "path": request.path,
        "query_string": request.query_string.decode("utf-8", errors="replace"),
        "headers": dict(request.headers),
        "body": request.get_data(as_text=True)[:2048],
        "user_agent": request.user_agent.string,
        "remote_addr": request.remote_addr or ATTACKER_IP,
    }
    request_log.append(entry)
    logger.info(
        f"HTTP {request.method} {request.path} from "
        f"{request.remote_addr} (UA: {request.user_agent.string[:60]})"
    )


def check_sqli(text: str) -> bool:
    """Check for SQL injection patterns in request data."""
    if not text:
        return False
    text_lower = text.lower()
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, text_lower):
            sqli_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "payload": text[:500],
                "pattern_matched": pattern,
                "path": request.path,
                "method": request.method,
                "remote_addr": request.remote_addr or ATTACKER_IP,
            }
            sqli_attempts.append(sqli_entry)
            logger.warning(f"SQLi detected: {text[:100]} (pattern: {pattern})")
            return True
    return False


def send_logs_to_logger():
    """Send all collected logs to the Logger service."""
    payload = {
        "attacker_ip": ATTACKER_IP,
        "requests": request_log[-500:],  # Last 500 requests
        "login_attempts": login_attempts,
        "sql_injection_attempts": sqli_attempts,
        "file_access": file_access_log,
    }
    try:
        resp = requests.post(
            f"{LOGGER_URL}/api/v1/http/log",
            json=payload,
            timeout=10,
        )
        logger.info(f"Logs sent to logger: status={resp.status_code}")
    except Exception as e:
        logger.warning(f"Could not send logs to logger: {e}")
        # Save locally as fallback
        try:
            fallback = f"/tmp/http_log_{int(time.time())}.json"
            with open(fallback, "w") as f:
                json.dump(payload, f, indent=2)
            logger.info(f"Logs saved to fallback: {fallback}")
        except IOError:
            pass


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------
@app.before_request
def before_request_handler():
    """Run before every request: log and check for SQLi."""
    log_request()
    # Check URL and body for SQL injection
    check_sqli(request.url)
    check_sqli(request.get_data(as_text=True))


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return redirect(url_for("login_page"))


@app.route("/login", methods=["GET"])
def login_page():
    error = request.args.get("error")
    return render_template("login.html", error=error)


@app.route("/login", methods=["POST"])
def login_submit():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    remote_ip = request.remote_addr or ATTACKER_IP

    login_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "username": username,
        "password": password,
        "remote_addr": remote_ip,
        "user_agent": request.user_agent.string,
    }
    login_attempts.append(login_entry)
    logger.info(f"Login attempt: {username}:{password} from {remote_ip}")

    # Check credentials
    is_accepted = (username, password) in ACCEPTED_CREDENTIALS

    # Track failures per IP for "accept any after 3" logic
    if remote_ip not in auth_failure_count:
        auth_failure_count[remote_ip] = 0

    accept_any = auth_failure_count[remote_ip] >= 3

    if is_accepted or accept_any:
        login_entry["success"] = True
        session["logged_in"] = True
        session["username"] = username
        logger.info(f"Login SUCCESS: {username} from {remote_ip}")
        return redirect(url_for("admin_dashboard"))
    else:
        auth_failure_count[remote_ip] += 1
        login_entry["success"] = False
        logger.info(
            f"Login FAILED ({auth_failure_count[remote_ip]}): "
            f"{username} from {remote_ip}"
        )
        return redirect(url_for("login_page", error="Invalid credentials"))


@app.route("/admin")
def admin_dashboard():
    return render_template("admin.html", username=session.get("username", "admin"))


@app.route("/admin/users")
def admin_users():
    file_access_log.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "path": "/admin/users",
        "remote_addr": request.remote_addr or ATTACKER_IP,
    })
    return jsonify(FAKE_USERS)


@app.route("/admin/config")
def admin_config():
    file_access_log.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "path": "/admin/config",
        "remote_addr": request.remote_addr or ATTACKER_IP,
    })
    return jsonify(FAKE_CONFIG)


@app.route("/admin/database")
def admin_database():
    file_access_log.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "path": "/admin/database",
        "remote_addr": request.remote_addr or ATTACKER_IP,
    })
    return jsonify(FAKE_DATABASE)


@app.route("/api/v1/users")
def api_users():
    file_access_log.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "path": "/api/v1/users",
        "remote_addr": request.remote_addr or ATTACKER_IP,
    })
    return jsonify(FAKE_USERS)


@app.route("/api/v1/config")
def api_config():
    file_access_log.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "path": "/api/v1/config",
        "remote_addr": request.remote_addr or ATTACKER_IP,
    })
    return jsonify(FAKE_CONFIG)


@app.route("/robots.txt")
def robots_txt():
    content = (
        "User-agent: *\n"
        "Disallow: /admin/\n"
        "Disallow: /api/\n"
        "Disallow: /backup/\n"
        "Disallow: /.env\n"
        "Disallow: /wp-admin/\n"
        "Disallow: /config/\n"
        "Disallow: /.git/\n"
        "Disallow: /phpmyadmin/\n"
    )
    response = make_response(content, 200)
    response.headers["Content-Type"] = "text/plain"
    return response


@app.route("/.env")
def env_file():
    file_access_log.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "path": "/.env",
        "remote_addr": request.remote_addr or ATTACKER_IP,
    })
    logger.warning(f".env file accessed by {request.remote_addr}")
    response = make_response(FAKE_ENV_FILE, 200)
    response.headers["Content-Type"] = "text/plain"
    return response


@app.route("/wp-login.php")
@app.route("/wp-admin")
@app.route("/wp-admin/")
def wordpress_redirect():
    return redirect(url_for("login_page"))


@app.route("/phpmyadmin")
@app.route("/phpmyadmin/")
def phpmyadmin_redirect():
    return redirect(url_for("login_page"))


@app.route("/health")
def health():
    return jsonify({
        "status": "healthy",
        "service": "http-honeypot",
        "requests_logged": len(request_log),
        "login_attempts": len(login_attempts),
        "sqli_detected": len(sqli_attempts),
    })


@app.errorhandler(404)
def not_found(error):
    file_access_log.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "path": request.path,
        "status": 404,
        "remote_addr": request.remote_addr or ATTACKER_IP,
    })
    return jsonify({
        "error": "Not Found",
        "path": request.path,
        "message": f"The requested URL {request.path} was not found on this server.",
    }), 404


# ---------------------------------------------------------------------------
# Shutdown Hook
# ---------------------------------------------------------------------------
import atexit
atexit.register(send_logs_to_logger)


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logger.info(f"Starting HTTP honeypot on port {SERVICE_PORT}")
    logger.info(f"Attacker IP: {ATTACKER_IP}")
    logger.info(f"Logger URL: {LOGGER_URL}")
    app.run(host="0.0.0.0", port=SERVICE_PORT, debug=False)
