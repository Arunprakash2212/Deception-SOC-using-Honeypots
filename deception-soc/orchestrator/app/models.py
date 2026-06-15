"""
=============================================================================
Orchestrator Data Models
=============================================================================
Pydantic models for all data structures used in the orchestrator.
=============================================================================
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field
import uuid


class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionType(str, Enum):
    TRAP = "trap"
    BLOCK = "block"
    MONITOR = "monitor"


class SessionStatus(str, Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    EXPIRED = "expired"
    MANUALLY_STOPPED = "manually_stopped"


class ThreatEvent(BaseModel):
    """Incoming threat event from the detection engine."""
    timestamp: str
    source_ip: str
    destination_ip: str
    destination_port: int
    attack_type: str
    severity: str
    signature_id: int
    signature_text: str = ""
    protocol: str = "TCP"
    raw_alert: dict = Field(default_factory=dict)


class Decision(BaseModel):
    """Decision made by the decision engine."""
    action: ActionType
    reason: str
    confidence: float = Field(ge=0.0, le=1.0)
    honeypot_type: Optional[str] = None


class HoneypotInstance(BaseModel):
    """Represents a deployed honeypot container."""
    container_id: str
    ip: str
    port: int
    service_type: str
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class DeceptionSession(BaseModel):
    """Represents an active deception (trap) session."""
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    attacker_ip: str
    honeypot_ip: str
    honeypot_port: int
    honeypot_type: str
    attack_type: str
    start_time: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    end_time: Optional[str] = None
    status: SessionStatus = SessionStatus.ACTIVE
    container_id: Optional[str] = None
    commands_executed: List[str] = Field(default_factory=list)
    files_accessed: List[str] = Field(default_factory=list)
    credentials_tried: List[dict] = Field(default_factory=list)


class AttackerProfile(BaseModel):
    """Profile of a tracked attacker."""
    ip: str
    first_seen: str
    last_seen: str
    attack_types: List[str] = Field(default_factory=list)
    sessions: List[str] = Field(default_factory=list)  # session IDs
    threat_score: float = 0.0
    cluster_id: Optional[int] = None
    country: Optional[str] = None
    isp: Optional[str] = None


class ThreatResponse(BaseModel):
    """Response after processing a threat event."""
    session_id: Optional[str] = None
    action: str
    reason: str
    honeypot_ip: Optional[str] = None
    honeypot_port: Optional[int] = None
    honeypot_type: Optional[str] = None


class HealthResponse(BaseModel):
    """System health status."""
    status: str = "healthy"
    active_traps: int = 0
    tracked_attackers: int = 0
    uptime_seconds: float = 0.0
