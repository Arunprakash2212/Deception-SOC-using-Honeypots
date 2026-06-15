"""
=============================================================================
Orchestrator Main Application
=============================================================================
FastAPI application that serves as the central brain of the deception system.
Receives threats, makes decisions, deploys honeypots, and redirects traffic.
=============================================================================
"""

import asyncio
import logging
import sys
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

import aiohttp
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware

from .models import (
    ThreatEvent,
    DeceptionSession,
    AttackerProfile,
    ThreatResponse,
    HealthResponse,
    ActionType,
    SessionStatus,
)
from .decision_engine import DeceptionDecisionEngine
from .honeypot_manager import HoneypotManager
from .traffic_redirector import TrafficRedirector
from .config import config

# ---------------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("orchestrator")

# ---------------------------------------------------------------------------
# Application Initialization
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Deception-SOC Orchestrator",
    description="Central orchestration service for the deception-driven SOC",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Core components
decision_engine = DeceptionDecisionEngine()
honeypot_manager = HoneypotManager()
traffic_redirector = TrafficRedirector()

# In-memory state stores
active_sessions: Dict[str, DeceptionSession] = {}  # session_id → session
attacker_profiles: Dict[str, AttackerProfile] = {}  # ip → profile
startup_time = time.time()


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------
def get_or_create_attacker_profile(ip: str) -> AttackerProfile:
    """Get existing attacker profile or create a new one."""
    if ip not in attacker_profiles:
        now = datetime.now(timezone.utc).isoformat()
        attacker_profiles[ip] = AttackerProfile(
            ip=ip, first_seen=now, last_seen=now
        )
    return attacker_profiles[ip]


def get_session_by_attacker_ip(ip: str) -> Optional[DeceptionSession]:
    """Find an active session for a given attacker IP."""
    for session in active_sessions.values():
        if session.attacker_ip == ip and session.status == SessionStatus.ACTIVE:
            return session
    return None


async def notify_logger(session: DeceptionSession) -> None:
    """Notify the logger service about a new or updated session."""
    try:
        async with aiohttp.ClientSession() as http:
            async with http.post(
                f"{config.LOGGER_URL}/api/v1/session/log",
                json=session.model_dump(),
                timeout=aiohttp.ClientTimeout(total=5),
            ) as resp:
                if resp.status in (200, 201):
                    logger.info(f"Logger notified for session {session.session_id}")
                else:
                    logger.warning(f"Logger returned status {resp.status}")
    except Exception as e:
        logger.warning(f"Could not notify logger: {e}")


async def monitor_session(session_id: str) -> None:
    """
    Background task that monitors a deception session.
    Checks every 30 seconds and auto-cleans up after MAX_SESSION_DURATION.
    """
    logger.info(f"Monitoring started for session {session_id}")
    max_duration = config.MAX_SESSION_DURATION

    while True:
        await asyncio.sleep(30)

        session = active_sessions.get(session_id)
        if session is None or session.status != SessionStatus.ACTIVE:
            logger.info(f"Session {session_id} no longer active, stopping monitor")
            break

        # Check if session has exceeded maximum duration
        start = datetime.fromisoformat(session.start_time)
        elapsed = (datetime.now(timezone.utc) - start).total_seconds()

        if elapsed >= max_duration:
            logger.info(
                f"Session {session_id} expired after {elapsed:.0f}s "
                f"(max: {max_duration}s)"
            )
            await cleanup_session(session_id, SessionStatus.EXPIRED)
            break

        logger.debug(
            f"Session {session_id} still active "
            f"({elapsed:.0f}s / {max_duration}s)"
        )


async def cleanup_session(
    session_id: str, status: SessionStatus = SessionStatus.COMPLETED
) -> None:
    """Clean up a deception session: remove iptables rules, destroy container."""
    session = active_sessions.get(session_id)
    if session is None:
        logger.warning(f"Cannot cleanup session {session_id}: not found")
        return

    logger.info(f"Cleaning up session {session_id} (status: {status})")

    # Remove iptables redirect
    traffic_redirector.remove_redirect(session.attacker_ip)

    # Destroy honeypot container
    honeypot_manager.destroy_honeypot(session.honeypot_ip)

    # Update session status
    session.status = status
    session.end_time = datetime.now(timezone.utc).isoformat()

    # Notify logger about completed session
    await notify_logger(session)

    logger.info(f"Session {session_id} cleaned up successfully")


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------
@app.post("/api/v1/threat/detected", response_model=ThreatResponse)
async def handle_threat_detected(
    threat: ThreatEvent, background_tasks: BackgroundTasks
):
    """
    Receive a threat alert from the detection engine.
    Evaluate and take action: TRAP, BLOCK, or MONITOR.
    """
    logger.info(
        f"Threat received: type={threat.attack_type}, "
        f"src={threat.source_ip}, severity={threat.severity}"
    )

    # Check if attacker already has an active session
    existing_session = get_session_by_attacker_ip(threat.source_ip)
    if existing_session is not None:
        logger.info(
            f"Attacker {threat.source_ip} already has active session "
            f"{existing_session.session_id}, skipping duplicate"
        )
        return ThreatResponse(
            session_id=existing_session.session_id,
            action="monitor",
            reason="Attacker already has an active deception session",
            honeypot_ip=existing_session.honeypot_ip,
            honeypot_port=existing_session.honeypot_port,
            honeypot_type=existing_session.honeypot_type,
        )

    # Update attacker profile
    profile = get_or_create_attacker_profile(threat.source_ip)
    profile.last_seen = datetime.now(timezone.utc).isoformat()
    if threat.attack_type not in profile.attack_types:
        profile.attack_types.append(threat.attack_type)

    # Make decision
    decision = decision_engine.evaluate(threat)
    logger.info(
        f"Decision: action={decision.action}, "
        f"reason={decision.reason}, confidence={decision.confidence}"
    )

    if decision.action == ActionType.TRAP:
        # Deploy honeypot
        honeypot = honeypot_manager.deploy_honeypot(
            attack_type=decision.honeypot_type or "multi",
            target_port=threat.destination_port,
            attacker_ip=threat.source_ip,
        )

        if honeypot is None:
            logger.error("Failed to deploy honeypot, falling back to MONITOR")
            return ThreatResponse(
                action="monitor",
                reason="Honeypot deployment failed, falling back to monitoring",
            )

        # Set up traffic redirect
        traffic_redirector.redirect(
            source_ip=threat.source_ip,
            original_dest_ip=threat.destination_ip,
            original_port=threat.destination_port,
            honeypot_ip=honeypot.ip,
            honeypot_port=honeypot.port,
        )

        # Create deception session
        session = DeceptionSession(
            attacker_ip=threat.source_ip,
            honeypot_ip=honeypot.ip,
            honeypot_port=honeypot.port,
            honeypot_type=honeypot.service_type,
            attack_type=threat.attack_type,
            container_id=honeypot.container_id,
        )

        active_sessions[session.session_id] = session
        profile.sessions.append(session.session_id)

        # Start background monitoring task
        background_tasks.add_task(monitor_session, session.session_id)

        logger.info(
            f"TRAP deployed: session={session.session_id}, "
            f"honeypot={honeypot.ip}:{honeypot.port}"
        )

        return ThreatResponse(
            session_id=session.session_id,
            action="trap",
            reason=decision.reason,
            honeypot_ip=honeypot.ip,
            honeypot_port=honeypot.port,
            honeypot_type=honeypot.service_type,
        )

    elif decision.action == ActionType.BLOCK:
        traffic_redirector.block_ip(threat.source_ip)
        logger.info(f"IP BLOCKED: {threat.source_ip}")

        return ThreatResponse(
            action="block",
            reason=decision.reason,
        )

    else:  # MONITOR
        logger.info(f"MONITORING: {threat.source_ip} ({decision.reason})")

        return ThreatResponse(
            action="monitor",
            reason=decision.reason,
        )


@app.get("/api/v1/sessions")
async def get_sessions() -> List[dict]:
    """Return all deception sessions (active and completed)."""
    return [session.model_dump() for session in active_sessions.values()]


@app.get("/api/v1/sessions/{session_id}")
async def get_session(session_id: str):
    """Return a specific deception session by ID."""
    session = active_sessions.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return session.model_dump()


@app.delete("/api/v1/sessions/{attacker_ip}")
async def end_session(attacker_ip: str):
    """Manually end a deception session for a given attacker IP."""
    session = get_session_by_attacker_ip(attacker_ip)
    if session is None:
        raise HTTPException(
            status_code=404,
            detail=f"No active session found for attacker IP {attacker_ip}",
        )

    await cleanup_session(session.session_id, SessionStatus.MANUALLY_STOPPED)
    return {
        "status": "success",
        "message": f"Session {session.session_id} terminated",
        "attacker_ip": attacker_ip,
    }


@app.get("/api/v1/attackers")
async def get_attackers() -> List[dict]:
    """Return all tracked attacker profiles."""
    return [profile.model_dump() for profile in attacker_profiles.values()]


@app.get("/api/v1/health", response_model=HealthResponse)
async def health_check():
    """Return system health status."""
    active_count = sum(
        1
        for s in active_sessions.values()
        if s.status == SessionStatus.ACTIVE
    )
    return HealthResponse(
        status="healthy",
        active_traps=active_count,
        tracked_attackers=len(attacker_profiles),
        uptime_seconds=time.time() - startup_time,
    )


@app.on_event("shutdown")
async def shutdown_event():
    """Clean up all resources on shutdown."""
    logger.info("Orchestrator shutting down — cleaning up resources...")
    traffic_redirector.cleanup_all()
    honeypot_manager.cleanup_all()
    logger.info("Cleanup complete. Goodbye!")


# ---------------------------------------------------------------------------
# Uvicorn Entry Point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info",
    )
