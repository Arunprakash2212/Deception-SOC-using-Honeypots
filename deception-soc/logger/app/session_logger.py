"""
=============================================================================
Central Session Logger Service
=============================================================================
FastAPI application that receives logs from all honeypots and stores them
in Elasticsearch. Provides query APIs for the dashboard.
Port: 9000
=============================================================================
"""

import logging
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .elasticsearch_sink import ElasticsearchSink

# ---------------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("session-logger")

# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Deception-SOC Session Logger",
    description="Central logging service for all honeypot sessions",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

es = ElasticsearchSink()


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------
class CommandEntry(BaseModel):
    command: str = ""
    cwd: str = ""
    timestamp: str = ""


class CredentialEntry(BaseModel):
    username: str = ""
    password: str = ""
    success: bool = False
    timestamp: str = ""


class FileAccessEntry(BaseModel):
    path: str = ""
    found: bool = False
    timestamp: str = ""


class DownloadEntry(BaseModel):
    url: str = ""
    timestamp: str = ""


class SessionLogRequest(BaseModel):
    attacker_ip: str
    username: str = ""
    session_start: str = ""
    session_end: str = ""
    credentials_tried: List[dict] = Field(default_factory=list)
    commands: List[dict] = Field(default_factory=list)
    files_accessed: List[dict] = Field(default_factory=list)
    download_attempts: List[dict] = Field(default_factory=list)
    service: str = "ssh"
    # Allow extra fields from orchestrator sessions
    session_id: Optional[str] = None
    honeypot_ip: Optional[str] = None
    honeypot_port: Optional[int] = None
    honeypot_type: Optional[str] = None
    attack_type: Optional[str] = None
    status: Optional[str] = None
    container_id: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    commands_executed: List[str] = Field(default_factory=list)


class HTTPLogRequest(BaseModel):
    attacker_ip: str
    requests: List[dict] = Field(default_factory=list)
    login_attempts: List[dict] = Field(default_factory=list)
    sql_injection_attempts: List[dict] = Field(default_factory=list)
    file_access: List[dict] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Startup / Shutdown
# ---------------------------------------------------------------------------
@app.on_event("startup")
async def startup():
    logger.info("Session Logger starting up...")
    await es.connect()
    logger.info("Session Logger ready on port 9000")


@app.on_event("shutdown")
async def shutdown():
    logger.info("Session Logger shutting down...")
    await es.close()


# ---------------------------------------------------------------------------
# Background Tasks
# ---------------------------------------------------------------------------
async def index_individual_commands(
    session_id: str, attacker_ip: str, commands: List[dict]
):
    """Index each command as a separate document for granular querying."""
    docs = []
    for cmd in commands:
        docs.append({
            "session_id": session_id,
            "attacker_ip": attacker_ip,
            "command": cmd.get("command", ""),
            "cwd": cmd.get("cwd", ""),
            "timestamp": cmd.get("timestamp", datetime.now(timezone.utc).isoformat()),
        })

    if docs:
        count = await es.bulk_index("deception-commands", docs)
        logger.info(f"Indexed {count} commands for session {session_id}")


async def index_credentials(
    session_id: str, attacker_ip: str, credentials: List[dict]
):
    """Index each credential attempt as a separate document."""
    docs = []
    for cred in credentials:
        docs.append({
            "session_id": session_id,
            "attacker_ip": attacker_ip,
            "username": cred.get("username", ""),
            "password": cred.get("password", ""),
            "success": cred.get("success", False),
            "timestamp": cred.get("timestamp", datetime.now(timezone.utc).isoformat()),
        })

    if docs:
        count = await es.bulk_index("deception-credentials", docs)
        logger.info(f"Indexed {count} credentials for session {session_id}")


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------
@app.post("/api/v1/session/log")
async def receive_session_log(
    data: SessionLogRequest, background_tasks: BackgroundTasks
):
    """Receive and store SSH/FTP honeypot session log."""
    session_id = data.session_id or str(uuid.uuid4())

    # Handle alternate field names from orchestrator
    commands = data.commands
    session_start = data.session_start or data.start_time or datetime.now(timezone.utc).isoformat()
    session_end = data.session_end or data.end_time or datetime.now(timezone.utc).isoformat()

    # Calculate duration
    try:
        start_dt = datetime.fromisoformat(session_start.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(session_end.replace("Z", "+00:00"))
        duration = (end_dt - start_dt).total_seconds()
    except (ValueError, TypeError):
        duration = 0.0

    logger.info(
        f"Received session log: attacker={data.attacker_ip}, "
        f"commands={len(commands)}, "
        f"credentials={len(data.credentials_tried)}, "
        f"duration={duration:.1f}s"
    )

    # Build session document
    session_doc = {
        "session_id": session_id,
        "attacker_ip": data.attacker_ip,
        "username": data.username,
        "session_start": session_start,
        "session_end": session_end,
        "duration_seconds": duration,
        "commands": commands,
        "credentials_tried": data.credentials_tried,
        "files_accessed": data.files_accessed,
        "download_attempts": data.download_attempts,
        "service": data.service or data.honeypot_type or "ssh",
        "honeypot_type": data.honeypot_type,
        "attack_type": data.attack_type,
        "indexed_at": datetime.now(timezone.utc).isoformat(),
    }

    # Index session document
    doc_id = await es.index_document("deception-sessions", session_doc, session_id)

    # Background: index individual commands and credentials
    if commands:
        background_tasks.add_task(
            index_individual_commands, session_id, data.attacker_ip, commands
        )

    if data.credentials_tried:
        background_tasks.add_task(
            index_credentials, session_id, data.attacker_ip, data.credentials_tried
        )

    return {
        "status": "success",
        "session_id": session_id,
        "commands_recorded": len(commands),
        "credentials_recorded": len(data.credentials_tried),
        "duration_seconds": duration,
    }


@app.post("/api/v1/http/log")
async def receive_http_log(data: HTTPLogRequest):
    """Receive and store HTTP honeypot log."""
    logger.info(
        f"Received HTTP log: attacker={data.attacker_ip}, "
        f"requests={len(data.requests)}, "
        f"logins={len(data.login_attempts)}, "
        f"sqli={len(data.sql_injection_attempts)}"
    )

    http_doc = {
        "attacker_ip": data.attacker_ip,
        "requests": data.requests[-500:],  # Cap at 500
        "login_attempts": data.login_attempts,
        "sql_injection_attempts": data.sql_injection_attempts,
        "file_access": data.file_access,
        "request_count": len(data.requests),
        "indexed_at": datetime.now(timezone.utc).isoformat(),
    }

    doc_id = await es.index_document("deception-http", http_doc)

    # Also index credentials from HTTP login attempts
    if data.login_attempts:
        cred_docs = []
        for attempt in data.login_attempts:
            cred_docs.append({
                "attacker_ip": data.attacker_ip,
                "username": attempt.get("username", ""),
                "password": attempt.get("password", ""),
                "success": attempt.get("success", False),
                "timestamp": attempt.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "session_id": "http",
            })
        await es.bulk_index("deception-credentials", cred_docs)

    return {
        "status": "success",
        "requests_recorded": len(data.requests),
        "login_attempts_recorded": len(data.login_attempts),
        "sqli_attempts_recorded": len(data.sql_injection_attempts),
    }


@app.get("/api/v1/sessions")
async def get_sessions(limit: int = 50):
    """Query all sessions, sorted by start time descending."""
    sessions = await es.search(
        index="deception-sessions",
        sort=[{"session_start": {"order": "desc"}}],
        size=limit,
    )
    return sessions


@app.get("/api/v1/sessions/{attacker_ip}")
async def get_sessions_by_ip(attacker_ip: str):
    """Query sessions for a specific attacker IP."""
    sessions = await es.search(
        index="deception-sessions",
        query={"term": {"attacker_ip": attacker_ip}},
        sort=[{"session_start": {"order": "desc"}}],
        size=100,
    )
    return sessions


@app.get("/api/v1/commands/{attacker_ip}")
async def get_commands_by_ip(attacker_ip: str):
    """Query all commands from a specific attacker, chronological order."""
    commands = await es.search(
        index="deception-commands",
        query={"term": {"attacker_ip": attacker_ip}},
        sort=[{"timestamp": {"order": "asc"}}],
        size=500,
    )
    return commands


@app.get("/api/v1/credentials/top")
async def get_top_credentials():
    """Get top 20 usernames and top 20 passwords."""
    aggs = {
        "top_usernames": {
            "terms": {"field": "username", "size": 20}
        },
        "top_passwords": {
            "terms": {"field": "password", "size": 20}
        },
    }
    result = await es.aggregate("deception-credentials", aggs)

    top_usernames = [
        {"username": bucket["key"], "count": bucket["doc_count"]}
        for bucket in result.get("top_usernames", {}).get("buckets", [])
    ]
    top_passwords = [
        {"password": bucket["key"], "count": bucket["doc_count"]}
        for bucket in result.get("top_passwords", {}).get("buckets", [])
    ]

    return {
        "top_usernames": top_usernames,
        "top_passwords": top_passwords,
    }


@app.get("/api/v1/stats")
async def get_stats():
    """Return total counts across all indices."""
    sessions = await es.count("deception-sessions")
    commands = await es.count("deception-commands")
    credentials = await es.count("deception-credentials")
    http_logs = await es.count("deception-http")

    return {
        "total_sessions": sessions,
        "total_commands": commands,
        "total_credentials": credentials,
        "total_http_logs": http_logs,
    }


@app.get("/api/v1/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "session-logger",
    }


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.session_logger:app",
        host="0.0.0.0",
        port=9000,
        reload=False,
        log_level="info",
    )
