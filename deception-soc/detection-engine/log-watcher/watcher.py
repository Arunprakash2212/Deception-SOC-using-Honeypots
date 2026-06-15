"""
=============================================================================
Suricata EVE Log Watcher
=============================================================================
Monitors Suricata EVE JSON log file for alerts and forwards detected threats
to the Orchestrator service via REST API.

Uses watchdog for file monitoring and aiohttp for async HTTP requests.
Implements tail -f behavior to only process new log lines.
=============================================================================
"""

import asyncio
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import aiohttp
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ORCHESTRATOR_URL = os.getenv("ORCHESTRATOR_URL", "http://orchestrator:8000")
THREAT_ENDPOINT = f"{ORCHESTRATOR_URL}/api/v1/threat/detected"
SURICATA_LOG_DIR = os.getenv("SURICATA_LOG_DIR", "/var/log/suricata/")
EVE_LOG_FILE = os.path.join(SURICATA_LOG_DIR, "eve.json")
RETRY_DELAY = 5  # seconds between retry attempts
MAX_RETRIES = 3
FALLBACK_LOG_DIR = "/tmp/deception-watcher-fallback/"

# ---------------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("log-watcher")

# ---------------------------------------------------------------------------
# Signature ID to Attack Type Mapping
# ---------------------------------------------------------------------------
SIGNATURE_MAP = {
    1000001: {"attack_type": "nmap_scan", "severity": "medium"},
    1000002: {"attack_type": "service_probe", "severity": "medium"},
    1000003: {"attack_type": "ssh_bruteforce", "severity": "high"},
    1000004: {"attack_type": "http_enumeration", "severity": "medium"},
    1000005: {"attack_type": "sql_injection", "severity": "critical"},
    1000010: {"attack_type": "ssh_bruteforce", "severity": "high"},
    1000011: {"attack_type": "ftp_bruteforce", "severity": "high"},
    1000012: {"attack_type": "http_bruteforce", "severity": "high"},
    1000013: {"attack_type": "http_bruteforce", "severity": "high"},
    1000020: {"attack_type": "command_injection", "severity": "critical"},
    1000021: {"attack_type": "path_traversal", "severity": "high"},
    1000022: {"attack_type": "http_enumeration", "severity": "medium"},
    1000023: {"attack_type": "http_enumeration", "severity": "medium"},
    1000024: {"attack_type": "reverse_shell", "severity": "critical"},
    1000025: {"attack_type": "dns_tunneling", "severity": "high"},
}


@dataclass
class ThreatEvent:
    """Represents a detected threat event from Suricata."""
    timestamp: str
    source_ip: str
    destination_ip: str
    destination_port: int
    attack_type: str
    severity: str
    signature_id: int
    signature_text: str
    protocol: str
    raw_alert: dict


class EveLogParser:
    """Parses Suricata EVE JSON log entries and extracts threat events."""

    @staticmethod
    def parse_alert(line: str) -> Optional[ThreatEvent]:
        """Parse a single EVE JSON line and return ThreatEvent if it's an alert."""
        try:
            event = json.loads(line.strip())
        except (json.JSONDecodeError, ValueError):
            return None

        # Only process alert events
        if event.get("event_type") != "alert":
            return None

        alert = event.get("alert", {})
        signature_id = alert.get("signature_id", 0)

        # Look up attack mapping
        mapping = SIGNATURE_MAP.get(signature_id)
        if mapping is None:
            logger.debug(f"Unknown signature ID: {signature_id}, skipping")
            return None

        return ThreatEvent(
            timestamp=event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            source_ip=event.get("src_ip", "0.0.0.0"),
            destination_ip=event.get("dest_ip", "0.0.0.0"),
            destination_port=event.get("dest_port", 0),
            attack_type=mapping["attack_type"],
            severity=mapping["severity"],
            signature_id=signature_id,
            signature_text=alert.get("signature", "Unknown"),
            protocol=event.get("proto", "TCP").upper(),
            raw_alert=alert,
        )


class ThreatForwarder:
    """Forwards detected threats to the Orchestrator via async HTTP POST."""

    def __init__(self):
        self._session: Optional[aiohttp.ClientSession] = None
        self._fallback_dir = Path(FALLBACK_LOG_DIR)
        self._fallback_dir.mkdir(parents=True, exist_ok=True)

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create an aiohttp session."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=10)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def send_threat(self, threat: ThreatEvent) -> bool:
        """Send a threat event to the orchestrator with retries."""
        payload = asdict(threat)
        logger.info(
            f"Sending threat: {threat.attack_type} from {threat.source_ip} "
            f"(SID:{threat.signature_id}, severity:{threat.severity})"
        )

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                session = await self._get_session()
                async with session.post(THREAT_ENDPOINT, json=payload) as response:
                    if response.status in (200, 201):
                        result = await response.json()
                        logger.info(
                            f"Threat forwarded successfully: "
                            f"action={result.get('action', 'unknown')}, "
                            f"session_id={result.get('session_id', 'N/A')}"
                        )
                        return True
                    else:
                        body = await response.text()
                        logger.warning(
                            f"Orchestrator returned {response.status}: {body} "
                            f"(attempt {attempt}/{MAX_RETRIES})"
                        )
            except aiohttp.ClientError as e:
                logger.warning(
                    f"Connection error to orchestrator: {e} "
                    f"(attempt {attempt}/{MAX_RETRIES})"
                )
            except Exception as e:
                logger.error(
                    f"Unexpected error sending threat: {e} "
                    f"(attempt {attempt}/{MAX_RETRIES})"
                )

            if attempt < MAX_RETRIES:
                await asyncio.sleep(RETRY_DELAY)

        # All retries exhausted — fallback to local file
        logger.error(
            f"Failed to send threat after {MAX_RETRIES} attempts. "
            f"Saving to fallback log."
        )
        self._save_fallback(payload)
        return False

    def _save_fallback(self, payload: dict) -> None:
        """Save threat event to a local fallback JSON file."""
        fallback_file = self._fallback_dir / "unsent_threats.jsonl"
        try:
            with open(fallback_file, "a") as f:
                f.write(json.dumps(payload) + "\n")
            logger.info(f"Threat saved to fallback: {fallback_file}")
        except IOError as e:
            logger.error(f"Failed to write fallback log: {e}")

    async def close(self):
        """Close the HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()


class EveFileWatcher(FileSystemEventHandler):
    """
    Watches the Suricata EVE JSON log file for new entries.
    Implements tail -f behavior by tracking file position.
    """

    def __init__(self, loop: asyncio.AbstractEventLoop, forwarder: ThreatForwarder):
        super().__init__()
        self.loop = loop
        self.forwarder = forwarder
        self.parser = EveLogParser()
        self._file_position = 0
        self._log_path = EVE_LOG_FILE
        self._initialize_position()

    def _initialize_position(self):
        """Set initial file position to end of file (only read new lines)."""
        try:
            if os.path.exists(self._log_path):
                self._file_position = os.path.getsize(self._log_path)
                logger.info(
                    f"Initialized file position to {self._file_position} "
                    f"(end of file: {self._log_path})"
                )
            else:
                self._file_position = 0
                logger.info(f"Log file does not exist yet: {self._log_path}")
        except OSError as e:
            logger.error(f"Error initializing file position: {e}")
            self._file_position = 0

    def on_modified(self, event):
        """Called when the watched file is modified."""
        if event.is_directory:
            return
        if not event.src_path.endswith("eve.json"):
            return
        self._process_new_lines()

    def on_created(self, event):
        """Called when a new file is created (log rotation)."""
        if event.is_directory:
            return
        if event.src_path.endswith("eve.json"):
            logger.info("EVE log file created (possible log rotation)")
            self._file_position = 0
            self._process_new_lines()

    def _process_new_lines(self):
        """Read and process new lines from the EVE log file."""
        try:
            current_size = os.path.getsize(self._log_path)

            # Handle log rotation (file got smaller)
            if current_size < self._file_position:
                logger.info("Log rotation detected, resetting position to 0")
                self._file_position = 0

            if current_size == self._file_position:
                return  # No new data

            with open(self._log_path, "r") as f:
                f.seek(self._file_position)
                new_lines = f.readlines()
                self._file_position = f.tell()

            for line in new_lines:
                line = line.strip()
                if not line:
                    continue

                threat = self.parser.parse_alert(line)
                if threat is not None:
                    # Schedule async send in the event loop
                    asyncio.run_coroutine_threadsafe(
                        self.forwarder.send_threat(threat), self.loop
                    )

        except FileNotFoundError:
            logger.debug(f"Log file not found: {self._log_path}")
        except PermissionError:
            logger.error(f"Permission denied reading: {self._log_path}")
        except Exception as e:
            logger.error(f"Error processing log lines: {e}")


async def periodic_health_check():
    """Periodically log health status."""
    while True:
        logger.info(
            f"Health check: watching {EVE_LOG_FILE}, "
            f"forwarding to {THREAT_ENDPOINT}"
        )
        await asyncio.sleep(60)


async def main():
    """Main entry point for the log watcher."""
    logger.info("=" * 60)
    logger.info("Deception-SOC Log Watcher Starting")
    logger.info(f"  EVE log file:    {EVE_LOG_FILE}")
    logger.info(f"  Orchestrator:    {THREAT_ENDPOINT}")
    logger.info(f"  Retry delay:     {RETRY_DELAY}s")
    logger.info(f"  Max retries:     {MAX_RETRIES}")
    logger.info("=" * 60)

    # Ensure log directory exists
    os.makedirs(SURICATA_LOG_DIR, exist_ok=True)

    # Create an empty eve.json if it doesn't exist yet
    if not os.path.exists(EVE_LOG_FILE):
        Path(EVE_LOG_FILE).touch()
        logger.info(f"Created empty log file: {EVE_LOG_FILE}")

    loop = asyncio.get_event_loop()
    forwarder = ThreatForwarder()

    # Set up watchdog observer
    event_handler = EveFileWatcher(loop, forwarder)
    observer = Observer()
    observer.schedule(event_handler, SURICATA_LOG_DIR, recursive=False)
    observer.start()
    logger.info(f"File observer started on directory: {SURICATA_LOG_DIR}")

    # Run health check in background
    health_task = asyncio.create_task(periodic_health_check())

    try:
        # Keep the main coroutine alive
        while True:
            await asyncio.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        logger.info("Shutting down log watcher...")
    finally:
        observer.stop()
        observer.join()
        health_task.cancel()
        await forwarder.close()
        logger.info("Log watcher stopped.")


if __name__ == "__main__":
    asyncio.run(main())
