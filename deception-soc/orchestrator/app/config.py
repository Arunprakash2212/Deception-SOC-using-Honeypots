"""
=============================================================================
Orchestrator Configuration
=============================================================================
Central configuration loaded from environment variables.
=============================================================================
"""

import os


class Config:
    """Application configuration from environment variables."""

    # Elasticsearch
    ELASTICSEARCH_HOST = os.getenv("ELASTICSEARCH_HOST", "http://elasticsearch:9200")

    # Service URLs
    LOGGER_URL = os.getenv("LOGGER_URL", "http://logger:9000")
    AI_URL = os.getenv("AI_URL", "http://ai-module:8500")
    ORCHESTRATOR_URL = os.getenv("ORCHESTRATOR_URL", "http://orchestrator:8000")

    # Honeypot configuration
    HONEYPOT_NETWORK = os.getenv("HONEYPOT_NETWORK", "deception-net")
    HONEYPOT_SUBNET = os.getenv("HONEYPOT_SUBNET", "172.20.0")
    MAX_HONEYPOTS = int(os.getenv("MAX_HONEYPOTS", "20"))
    MAX_SESSION_DURATION = int(os.getenv("MAX_SESSION_DURATION", "3600"))  # 1 hour

    # Resource limits for honeypots
    HONEYPOT_MEM_LIMIT = "256m"
    HONEYPOT_CPU_PERIOD = 100000
    HONEYPOT_CPU_QUOTA = 50000  # 50% CPU

    # Docker images
    HONEYPOT_IMAGES = {
        "ssh": "deception-soc/ssh-honeypot:latest",
        "http": "deception-soc/http-honeypot:latest",
        "ftp": "deception-soc/ftp-honeypot:latest",
        "multi": "deception-soc/multi-honeypot:latest",
    }

    # Decision engine
    COOLDOWN_SECONDS = 30

    # Whitelist — private networks that should never be trapped
    WHITELIST_CIDRS = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
    ]


config = Config()
