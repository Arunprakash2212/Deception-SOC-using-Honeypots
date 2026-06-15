"""
=============================================================================
AI Module API
=============================================================================
FastAPI application providing AI-powered attacker classification,
clustering, and threat scoring endpoints.
Port: 8500
=============================================================================
"""

import logging
import sys
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .clustering import AttackerClusterer
from .threat_scorer import ThreatScorer

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("ai-module")

# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Deception-SOC AI Module",
    description="AI-powered attacker classification and threat scoring",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Core AI components
clusterer = AttackerClusterer()
scorer = ThreatScorer()


# ---------------------------------------------------------------------------
# Request/Response Models
# ---------------------------------------------------------------------------
class SessionData(BaseModel):
    """Session data for classification/scoring."""
    attacker_ip: str = ""
    username: str = ""
    session_start: str = ""
    session_end: str = ""
    duration_seconds: float = 0.0
    commands: List[dict] = Field(default_factory=list)
    credentials_tried: List[dict] = Field(default_factory=list)
    files_accessed: List[dict] = Field(default_factory=list)
    download_attempts: List[dict] = Field(default_factory=list)
    service: str = ""
    honeypot_type: str = ""
    attack_type: str = ""


class TrainRequest(BaseModel):
    """Request body for training the clustering model."""
    sessions: List[dict] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.post("/api/v1/ai/classify")
async def classify_session(data: SessionData):
    """
    Classify a session: returns both cluster result and threat score.
    """
    session_dict = data.model_dump()

    # Get threat score (always works, rule-based)
    threat_result = scorer.score(session_dict)

    # Get cluster prediction (only if model is trained)
    cluster_result = clusterer.predict(session_dict)

    return {
        "threat_score": threat_result,
        "cluster": cluster_result,
    }


@app.post("/api/v1/ai/train")
async def train_model(data: TrainRequest):
    """
    Train or retrain the clustering model on provided sessions.
    """
    if not data.sessions:
        raise HTTPException(
            status_code=400,
            detail="No sessions provided for training",
        )

    logger.info(f"Training request: {len(data.sessions)} sessions")
    result = clusterer.train(data.sessions)
    return result


@app.post("/api/v1/ai/score")
async def score_session(data: SessionData):
    """
    Score a session (threat score only, no clustering).
    """
    session_dict = data.model_dump()
    result = scorer.score(session_dict)
    return result


@app.get("/api/v1/ai/status")
async def model_status():
    """
    Return current model status and cluster information.
    """
    stats = clusterer.get_cluster_stats()
    return {
        "model_trained": stats["is_trained"],
        "n_clusters": stats["n_clusters"],
        "cluster_labels": stats["cluster_labels"],
        "cluster_stats": stats.get("cluster_stats", {}),
    }


@app.get("/api/v1/ai/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "ai-module",
        "model_trained": clusterer.is_trained,
    }


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.api:app",
        host="0.0.0.0",
        port=8500,
        reload=False,
        log_level="info",
    )
