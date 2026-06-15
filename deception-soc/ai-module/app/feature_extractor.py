"""
=============================================================================
Attacker Feature Extractor
=============================================================================
Converts raw session data into numerical feature vectors (15-dimensional)
for use in clustering and threat analysis.
=============================================================================
"""

import logging
from typing import Dict, List, Set

import numpy as np

logger = logging.getLogger("ai.feature_extractor")

# ---------------------------------------------------------------------------
# Command Category Sets
# ---------------------------------------------------------------------------
RECON_COMMANDS: Set[str] = {
    "ls", "cat", "find", "grep", "locate", "which", "whereis",
    "file", "head", "tail", "less", "more", "dir", "tree",
}

EXPLOIT_COMMANDS: Set[str] = {
    "wget", "curl", "nc", "ncat", "python", "python3", "perl",
    "ruby", "gcc", "make", "chmod", "chown", "bash",
}

PERSISTENCE_COMMANDS: Set[str] = {
    "crontab", "at", "systemctl", "service", "useradd", "adduser",
    "passwd", "ssh-keygen", "chkconfig", "update-rc.d",
}

LATERAL_COMMANDS: Set[str] = {
    "ssh", "scp", "rsync", "ping", "nmap", "telnet", "ftp",
    "rdesktop", "xfreerdp",
}

DATA_COMMANDS: Set[str] = {
    "mysql", "psql", "mongo", "redis-cli", "tar", "zip", "gzip",
    "base64", "xxd", "mysqldump", "pg_dump",
}

SENSITIVE_FILE_KEYWORDS: Set[str] = {
    "passwd", "shadow", ".env", "config", "credential", "key",
    "secret", "token", "password", "id_rsa", "authorized_keys",
    "htpasswd", "wp-config", "database",
}


class AttackerFeatureExtractor:
    """
    Converts raw session data into a 15-dimensional numerical feature vector.

    Feature vector layout:
        [0]  session_duration (seconds)
        [1]  total_commands executed
        [2]  unique_commands used
        [3]  recon_command_ratio
        [4]  exploit_command_ratio
        [5]  persistence_command_ratio
        [6]  lateral_movement_ratio
        [7]  data_exfil_ratio
        [8]  avg_time_between_commands (seconds)
        [9]  total_credentials_tried
        [10] unique_usernames
        [11] unique_passwords
        [12] files_accessed_count
        [13] sensitive_files_ratio
        [14] download_attempts
    """

    FEATURE_NAMES = [
        "session_duration",
        "total_commands",
        "unique_commands",
        "recon_ratio",
        "exploit_ratio",
        "persistence_ratio",
        "lateral_ratio",
        "data_exfil_ratio",
        "avg_cmd_interval",
        "total_creds",
        "unique_usernames",
        "unique_passwords",
        "files_accessed",
        "sensitive_files_ratio",
        "download_attempts",
    ]

    def _extract_base_command(self, full_command: str) -> str:
        """Extract the base command from a full command string."""
        cmd = full_command.strip().split()[0] if full_command.strip() else ""
        # Remove path prefix if present (e.g., /usr/bin/python → python)
        if "/" in cmd:
            cmd = cmd.split("/")[-1]
        return cmd.lower()

    def _compute_command_ratio(
        self, commands: List[str], category: Set[str]
    ) -> float:
        """Compute the ratio of commands belonging to a category."""
        if not commands:
            return 0.0
        base_commands = [self._extract_base_command(c) for c in commands]
        matches = sum(1 for c in base_commands if c in category)
        return matches / len(commands)

    def _compute_avg_interval(self, commands: List[dict]) -> float:
        """Compute average time between commands in seconds."""
        if len(commands) < 2:
            return 0.0

        timestamps = []
        for cmd in commands:
            ts = cmd.get("timestamp", "")
            if ts:
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    timestamps.append(dt.timestamp())
                except (ValueError, TypeError):
                    continue

        if len(timestamps) < 2:
            return 0.0

        timestamps.sort()
        intervals = [
            timestamps[i + 1] - timestamps[i]
            for i in range(len(timestamps) - 1)
        ]
        return sum(intervals) / len(intervals)

    def _is_sensitive_file(self, path: str) -> bool:
        """Check if a file path contains sensitive keywords."""
        path_lower = path.lower()
        return any(kw in path_lower for kw in SENSITIVE_FILE_KEYWORDS)

    def extract(self, session_data: dict) -> np.ndarray:
        """
        Extract a 15-dimensional feature vector from session data.

        Args:
            session_data: Dictionary containing session information with keys:
                - commands: list of command dicts with 'command' and 'timestamp'
                - credentials_tried: list of credential dicts
                - files_accessed: list of file access dicts
                - download_attempts: list of download dicts
                - session_start, session_end: ISO timestamps
                - duration_seconds: float (optional, computed if missing)

        Returns:
            numpy array of shape (15,)
        """
        # --- Duration ---
        duration = session_data.get("duration_seconds", 0.0)
        if duration == 0.0:
            start = session_data.get("session_start", "")
            end = session_data.get("session_end", "")
            if start and end:
                try:
                    from datetime import datetime
                    start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
                    end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
                    duration = max(0, (end_dt - start_dt).total_seconds())
                except (ValueError, TypeError):
                    duration = 0.0

        # --- Commands ---
        commands_raw = session_data.get("commands", [])
        command_strings = []
        for cmd in commands_raw:
            if isinstance(cmd, dict):
                command_strings.append(cmd.get("command", ""))
            elif isinstance(cmd, str):
                command_strings.append(cmd)

        total_commands = len(command_strings)
        unique_commands = len(set(
            self._extract_base_command(c) for c in command_strings
        )) if command_strings else 0

        # Command category ratios
        recon_ratio = self._compute_command_ratio(command_strings, RECON_COMMANDS)
        exploit_ratio = self._compute_command_ratio(command_strings, EXPLOIT_COMMANDS)
        persistence_ratio = self._compute_command_ratio(command_strings, PERSISTENCE_COMMANDS)
        lateral_ratio = self._compute_command_ratio(command_strings, LATERAL_COMMANDS)
        data_ratio = self._compute_command_ratio(command_strings, DATA_COMMANDS)

        # Average time between commands
        avg_interval = self._compute_avg_interval(commands_raw)

        # --- Credentials ---
        credentials = session_data.get("credentials_tried", [])
        total_creds = len(credentials)
        unique_usernames = len(set(
            c.get("username", "") for c in credentials if isinstance(c, dict)
        ))
        unique_passwords = len(set(
            c.get("password", "") for c in credentials if isinstance(c, dict)
        ))

        # --- Files ---
        files_accessed = session_data.get("files_accessed", [])
        files_count = len(files_accessed)
        sensitive_count = sum(
            1 for f in files_accessed
            if isinstance(f, dict) and self._is_sensitive_file(f.get("path", ""))
        )
        sensitive_ratio = sensitive_count / files_count if files_count > 0 else 0.0

        # --- Downloads ---
        downloads = session_data.get("download_attempts", [])
        download_count = len(downloads)

        # Build feature vector
        features = np.array([
            duration,           # [0]
            total_commands,     # [1]
            unique_commands,    # [2]
            recon_ratio,        # [3]
            exploit_ratio,      # [4]
            persistence_ratio,  # [5]
            lateral_ratio,      # [6]
            data_ratio,         # [7]
            avg_interval,       # [8]
            total_creds,        # [9]
            unique_usernames,   # [10]
            unique_passwords,   # [11]
            files_count,        # [12]
            sensitive_ratio,    # [13]
            download_count,     # [14]
        ], dtype=np.float64)

        logger.debug(f"Extracted features: {features}")
        return features

    def extract_with_names(self, session_data: dict) -> Dict[str, float]:
        """Extract features and return as named dictionary."""
        features = self.extract(session_data)
        return dict(zip(self.FEATURE_NAMES, features.tolist()))
