"""
=============================================================================
Dashboard Backend — API Proxy/Aggregator
=============================================================================
FastAPI application that aggregates data from all deception-SOC services
and provides a unified API for the frontend dashboard.
Port: 3001
=============================================================================
"""

import logging
import os
import sys
from typing import Any, Dict, List, Optional

import aiohttp
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ORCHESTRATOR_URL = os.getenv("ORCHESTRATOR_URL", "http://orchestrator:8000")
LOGGER_URL = os.getenv("LOGGER_URL", "http://logger:9000")
AI_URL = os.getenv("AI_URL", "http://ai-module:8500")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("dashboard-backend")

# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Deception-SOC Dashboard Backend",
    description="Aggregation API for the analyst dashboard",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# HTTP Client Helper
# ---------------------------------------------------------------------------
async def fetch(url: str, method: str = "GET", json_data: dict = None) -> Any:
    """Make an async HTTP request to an internal service."""
    timeout = aiohttp.ClientTimeout(total=10)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            if method == "GET":
                async with session.get(url) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    else:
                        logger.warning(f"GET {url} returned {resp.status}")
                        return None
            elif method == "POST":
                async with session.post(url, json=json_data) as resp:
                    if resp.status in (200, 201):
                        return await resp.json()
                    else:
                        logger.warning(f"POST {url} returned {resp.status}")
                        return None
    except aiohttp.ClientError as e:
        logger.warning(f"Request to {url} failed: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error fetching {url}: {e}")
        return None


# ---------------------------------------------------------------------------
# Dashboard Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/dashboard/overview")
async def dashboard_overview():
    """
    Aggregated overview combining data from all services.
    """
    # Fetch from all services in parallel-ish fashion
    orchestrator_health = await fetch(f"{ORCHESTRATOR_URL}/api/v1/health")
    orchestrator_sessions = await fetch(f"{ORCHESTRATOR_URL}/api/v1/sessions")
    logger_stats = await fetch(f"{LOGGER_URL}/api/v1/stats")
    ai_status = await fetch(f"{AI_URL}/api/v1/ai/status")

    # Count active sessions
    active_sessions = []
    completed_sessions = []
    if orchestrator_sessions and isinstance(orchestrator_sessions, list):
        for s in orchestrator_sessions:
            if s.get("status") == "active":
                active_sessions.append(s)
            else:
                completed_sessions.append(s)

    return {
        "active_traps": len(active_sessions),
        "total_sessions": (logger_stats or {}).get("total_sessions", 0),
        "total_commands": (logger_stats or {}).get("total_commands", 0),
        "total_credentials": (logger_stats or {}).get("total_credentials", 0),
        "tracked_attackers": (orchestrator_health or {}).get("tracked_attackers", 0),
        "active_sessions": active_sessions,
        "completed_sessions": completed_sessions[:20],
        "ai_model_trained": (ai_status or {}).get("model_trained", False),
        "system_health": {
            "orchestrator": orchestrator_health is not None,
            "logger": logger_stats is not None,
            "ai_module": ai_status is not None,
        },
    }


@app.get("/api/dashboard/sessions")
async def dashboard_sessions():
    """
    Get all sessions from the logger service.
    """
    # Try logger first (has ES-stored sessions)
    logger_sessions = await fetch(f"{LOGGER_URL}/api/v1/sessions?limit=100")

    # Also get orchestrator sessions (in-memory active ones)
    orch_sessions = await fetch(f"{ORCHESTRATOR_URL}/api/v1/sessions")

    all_sessions = []
    if logger_sessions and isinstance(logger_sessions, list):
        all_sessions.extend(logger_sessions)
    if orch_sessions and isinstance(orch_sessions, list):
        # Add orchestrator sessions that aren't in logger yet
        logger_ips = {s.get("attacker_ip") for s in all_sessions}
        for s in orch_sessions:
            if s.get("attacker_ip") not in logger_ips:
                all_sessions.append(s)

    return all_sessions


@app.get("/api/dashboard/session/{attacker_ip}")
async def dashboard_session_detail(attacker_ip: str):
    """
    Get detailed session info for a specific attacker IP.
    Combines session data, commands, and AI classification.
    """
    # Fetch session data
    sessions = await fetch(f"{LOGGER_URL}/api/v1/sessions/{attacker_ip}")

    # Fetch commands
    commands = await fetch(f"{LOGGER_URL}/api/v1/commands/{attacker_ip}")

    # Build session data for AI classification
    session_for_ai = {}
    if sessions and isinstance(sessions, list) and len(sessions) > 0:
        latest = sessions[0]
        session_for_ai = {
            "attacker_ip": attacker_ip,
            "session_start": latest.get("session_start", ""),
            "session_end": latest.get("session_end", ""),
            "duration_seconds": latest.get("duration_seconds", 0),
            "commands": latest.get("commands", []),
            "credentials_tried": latest.get("credentials_tried", []),
            "files_accessed": latest.get("files_accessed", []),
            "download_attempts": latest.get("download_attempts", []),
        }

    # Get AI classification
    ai_result = None
    if session_for_ai:
        ai_result = await fetch(
            f"{AI_URL}/api/v1/ai/classify",
            method="POST",
            json_data=session_for_ai,
        )

    return {
        "attacker_ip": attacker_ip,
        "sessions": sessions or [],
        "commands": commands or [],
        "ai_classification": ai_result,
        "total_sessions": len(sessions) if sessions else 0,
        "total_commands": len(commands) if commands else 0,
    }


@app.get("/api/dashboard/credentials")
async def dashboard_credentials():
    """
    Get top credentials from the logger.
    """
    result = await fetch(f"{LOGGER_URL}/api/v1/credentials/top")
    return result or {"top_usernames": [], "top_passwords": []}


@app.get("/api/dashboard/attackers")
async def dashboard_attackers():
    """
    Get all tracked attacker profiles from the orchestrator.
    """
    result = await fetch(f"{ORCHESTRATOR_URL}/api/v1/attackers")
    return result or []


@app.get("/api/dashboard/ai/status")
async def dashboard_ai_status():
    """
    Get AI module status.
    """
    result = await fetch(f"{AI_URL}/api/v1/ai/status")
    return result or {"model_trained": False}


@app.get("/api/health")
async def health():
    return {"status": "healthy", "service": "dashboard-backend"}


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=3001,
        reload=False,
        log_level="info",
    )
