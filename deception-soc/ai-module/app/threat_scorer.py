"""
=============================================================================
Threat Scorer
=============================================================================
Calculates a threat score from 0-100 based on session behavior.
Uses rule-based scoring (NOT ML) for reliability and explainability.
=============================================================================
"""

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger("ai.threat_scorer")

# ---------------------------------------------------------------------------
# Dangerous Command Sets
# ---------------------------------------------------------------------------
DANGEROUS_COMMANDS: Set[str] = {
    "wget", "curl", "nc", "ncat", "python", "python3", "perl",
    "ruby", "gcc", "make", "chmod", "chown", "bash", "base64",
    "openssl", "netcat",
}

LATERAL_COMMANDS: Set[str] = {
    "ssh", "scp", "rsync", "ping", "nmap", "telnet", "ftp",
    "rdesktop", "xfreerdp",
}

EXFIL_COMMANDS: Set[str] = {
    "tar", "zip", "gzip", "base64", "xxd", "scp", "nc", "ncat",
    "curl", "wget",
}

SENSITIVE_FILE_KEYWORDS: Set[str] = {
    "passwd", "shadow", ".env", "config", "credential", "key",
    "secret", "token", "password", "id_rsa", "authorized_keys",
    "htpasswd",
}

# ---------------------------------------------------------------------------
# Severity Levels
# ---------------------------------------------------------------------------
SEVERITY_THRESHOLDS = [
    (75, "critical"),
    (50, "high"),
    (25, "medium"),
    (0, "low"),
]


class ThreatScorer:
    """
    Calculates a threat score (0-100) based on observed attacker behavior.

    Scoring Factors:
        Factor 1 - Session Duration (max 10 pts)
        Factor 2 - Dangerous Commands (max 25 pts)
        Factor 3 - Credential Attempts (max 15 pts)
        Factor 4 - Sensitive File Access (max 20 pts)
        Factor 5 - Lateral Movement (max 15 pts)
        Factor 6 - Data Exfiltration (max 15 pts)
    """

    MAX_SCORE = 100

    def _extract_base_command(self, full_command: str) -> str:
        """Extract the base command from a full command string."""
        cmd = full_command.strip().split()[0] if full_command.strip() else ""
        if "/" in cmd:
            cmd = cmd.split("/")[-1]
        return cmd.lower()

    def _is_sensitive_file(self, path: str) -> bool:
        """Check if a file path references a sensitive file."""
        path_lower = path.lower()
        return any(kw in path_lower for kw in SENSITIVE_FILE_KEYWORDS)

    def score(self, session_data: dict) -> dict:
        """
        Calculate threat score for a session.

        Args:
            session_data: Session data dictionary

        Returns:
            Scoring result with score, severity, and detailed reasons
        """
        reasons: List[str] = []
        total_score = 0

        # ---------------------------------------------------------------
        # Factor 1: Session Duration (max 10 points)
        # ---------------------------------------------------------------
        duration = session_data.get("duration_seconds", 0.0)
        if duration == 0.0:
            start = session_data.get("session_start", "")
            end = session_data.get("session_end", "")
            if start and end:
                try:
                    start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
                    end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
                    duration = max(0, (end_dt - start_dt).total_seconds())
                except (ValueError, TypeError):
                    pass

        duration_score = 0
        if duration > 600:  # > 10 minutes
            duration_score = 10
            reasons.append(f"Long session duration ({duration:.0f}s > 600s): +10")
        elif duration > 120:  # > 2 minutes
            duration_score = 5
            reasons.append(f"Moderate session duration ({duration:.0f}s > 120s): +5")

        total_score += duration_score

        # ---------------------------------------------------------------
        # Factor 2: Dangerous Commands (max 25 points)
        # ---------------------------------------------------------------
        commands_raw = session_data.get("commands", [])
        command_strings = []
        for cmd in commands_raw:
            if isinstance(cmd, dict):
                command_strings.append(cmd.get("command", ""))
            elif isinstance(cmd, str):
                command_strings.append(cmd)

        base_commands = [self._extract_base_command(c) for c in command_strings]
        dangerous_found = set()
        for cmd in base_commands:
            if cmd in DANGEROUS_COMMANDS:
                dangerous_found.add(cmd)

        danger_score = min(25, len(dangerous_found) * 5)
        if dangerous_found:
            reasons.append(
                f"Dangerous commands ({', '.join(sorted(dangerous_found))}): "
                f"+{danger_score}"
            )
        total_score += danger_score

        # ---------------------------------------------------------------
        # Factor 3: Credential Attempts (max 15 points)
        # ---------------------------------------------------------------
        credentials = session_data.get("credentials_tried", [])
        cred_count = len(credentials)

        cred_score = 0
        if cred_count > 20:
            cred_score = 15
            reasons.append(f"High credential attempts ({cred_count} > 20): +15")
        elif cred_count > 5:
            cred_score = 8
            reasons.append(f"Moderate credential attempts ({cred_count} > 5): +8")

        total_score += cred_score

        # ---------------------------------------------------------------
        # Factor 4: Sensitive File Access (max 20 points)
        # ---------------------------------------------------------------
        files_accessed = session_data.get("files_accessed", [])
        sensitive_files = []
        for fa in files_accessed:
            path = fa.get("path", "") if isinstance(fa, dict) else str(fa)
            if self._is_sensitive_file(path):
                sensitive_files.append(path)

        file_score = min(20, len(sensitive_files) * 5)
        if sensitive_files:
            reasons.append(
                f"Sensitive files accessed ({len(sensitive_files)}): "
                f"+{file_score}"
            )
        total_score += file_score

        # ---------------------------------------------------------------
        # Factor 5: Lateral Movement (max 15 points)
        # ---------------------------------------------------------------
        lateral_found = set()
        for cmd in base_commands:
            if cmd in LATERAL_COMMANDS:
                lateral_found.add(cmd)

        lateral_score = min(15, len(lateral_found) * 5)
        if lateral_found:
            reasons.append(
                f"Lateral movement commands ({', '.join(sorted(lateral_found))}): "
                f"+{lateral_score}"
            )
        total_score += lateral_score

        # ---------------------------------------------------------------
        # Factor 6: Data Exfiltration (max 15 points)
        # ---------------------------------------------------------------
        exfil_found = set()
        for cmd in base_commands:
            if cmd in EXFIL_COMMANDS:
                exfil_found.add(cmd)

        exfil_score = min(15, len(exfil_found) * 5)
        if exfil_found:
            reasons.append(
                f"Data exfiltration indicators ({', '.join(sorted(exfil_found))}): "
                f"+{exfil_score}"
            )
        total_score += exfil_score

        # ---------------------------------------------------------------
        # Final Score & Severity
        # ---------------------------------------------------------------
        total_score = min(self.MAX_SCORE, total_score)

        severity = "low"
        for threshold, level in SEVERITY_THRESHOLDS:
            if total_score >= threshold:
                severity = level
                break

        attacker_ip = session_data.get("attacker_ip", "unknown")

        result = {
            "threat_score": total_score,
            "severity": severity,
            "reasons": reasons,
            "attacker_ip": attacker_ip,
            "scored_at": datetime.now(timezone.utc).isoformat(),
            "breakdown": {
                "duration": duration_score,
                "dangerous_commands": danger_score,
                "credentials": cred_score,
                "sensitive_files": file_score,
                "lateral_movement": lateral_score,
                "data_exfiltration": exfil_score,
            },
            "session_summary": {
                "duration_seconds": duration,
                "total_commands": len(command_strings),
                "total_credentials": cred_count,
                "files_accessed": len(files_accessed),
                "sensitive_files": len(sensitive_files),
            },
        }

        logger.info(
            f"Threat score for {attacker_ip}: "
            f"{total_score}/100 ({severity})"
        )

        return result
