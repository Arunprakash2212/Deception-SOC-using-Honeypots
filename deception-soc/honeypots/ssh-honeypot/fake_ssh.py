"""
=============================================================================
SSH Honeypot — Fake SSH Server
=============================================================================
A realistic-looking SSH server that accepts attacker connections, simulates
a real Ubuntu system, and logs everything the attacker does.

Features:
- Accepts weak credentials (and any credential after 3 failures)
- Full fake filesystem with bait files containing fake secrets
- Command simulation (ls, cat, cd, ps, netstat, etc.)
- Complete session logging → forwarded to Logger service
=============================================================================
"""

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import asyncssh
import aiohttp

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SERVICE_PORT = int(os.getenv("SERVICE_PORT", "22"))
ATTACKER_IP = os.getenv("ATTACKER_IP", "unknown")
LOGGER_URL = os.getenv("LOGGER_URL", "http://logger:9000")
HOST_KEY_PATH = "/app/ssh_host_key"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("ssh-honeypot")

# ---------------------------------------------------------------------------
# Accepted Credentials (weak/common pairs)
# ---------------------------------------------------------------------------
ACCEPTED_CREDENTIALS = {
    ("admin", "admin"),
    ("admin", "admin123"),
    ("admin", "password"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
}

MAX_FAILURES_BEFORE_ACCEPT_ANY = 3

# ---------------------------------------------------------------------------
# Fake Filesystem
# ---------------------------------------------------------------------------
FAKE_FS: Dict[str, str] = {
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
        "sync:x:4:65534:sync:/bin:/bin/sync\n"
        "games:x:5:60:games:/usr/games:/usr/sbin/nologin\n"
        "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n"
        "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n"
        "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n"
        "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
        "sshd:x:105:65534::/run/sshd:/usr/sbin/nologin\n"
        "mysql:x:106:113:MySQL Server,,,:/nonexistent:/bin/false\n"
        "admin:x:1000:1000:System Administrator,,,:/home/admin:/bin/bash\n"
        "deploy:x:1001:1001:Deploy User,,,:/home/deploy:/bin/bash\n"
        "jenkins:x:1002:1002:Jenkins CI,,,:/home/jenkins:/bin/bash\n"
    ),
    "/etc/shadow": (
        "root:$6$rounds=656000$rANdOmSaLt$FAKE_HASH_DO_NOT_USE_aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ:19750:0:99999:7:::\n"
        "daemon:*:19750:0:99999:7:::\n"
        "admin:$6$rounds=656000$F4k3SaLt$FAKE_HASH_admin_password_aB3cD4eF5gH6:19750:0:99999:7:::\n"
        "deploy:$6$rounds=656000$d3pL0Y$FAKE_HASH_deploy_key_xY9wV8uT7sR6:19750:0:99999:7:::\n"
        "jenkins:$6$rounds=656000$j3nK1n5$FAKE_HASH_jenkins_aQ2bR3cS4dT5eU6:19750:0:99999:7:::\n"
    ),
    "/home/admin/credentials.txt": (
        "=== INTERNAL CREDENTIALS - DO NOT SHARE ===\n"
        "\n"
        "Database (Production):\n"
        "  Host: db-prod-01.internal.corp\n"
        "  Port: 3306\n"
        "  User: app_rw\n"
        "  Pass: Pr0d_DB_FAKE_P@ssw0rd_2024!\n"
        "\n"
        "Database (Staging):\n"
        "  Host: db-staging.internal.corp\n"
        "  Port: 3306\n"
        "  User: staging_admin\n"
        "  Pass: St@g1ng_FAKE_db_Pass!\n"
        "\n"
        "AWS Access Keys:\n"
        "  Access Key ID:     AKIAIOSFODNN7FAKEAWS\n"
        "  Secret Access Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCFAKESECRETKEY\n"
        "  Region: us-east-1\n"
        "\n"
        "API Keys:\n"
        "  Stripe Live: sk_live_FAKE_4eC39HqLyjWDarjtT1zdp7dc\n"
        "  SendGrid:    SG.FAKE_nW4Jd0RhR-OGY0olMEQ.FAKE_key_xyz\n"
        "  Slack Bot:   xoxb-FAKE-1234567890-AbCdEfGhIjKlMnOpQrStUv\n"
        "\n"
        "Last updated: 2024-11-15 by admin\n"
    ),
    "/home/admin/.bash_history": (
        "mysql -u root -p'FAKE_r00t_MySQL_2024' -h db-prod-01.internal.corp\n"
        "ssh deploy@10.0.1.50\n"
        "scp backup.tar.gz admin@10.0.1.100:/backups/\n"
        "curl -H 'Authorization: Bearer FAKE_eyJhbGciOiJIUzI1NiJ9' https://api.internal.corp/v1/users\n"
        "systemctl restart nginx\n"
        "tail -f /var/log/nginx/access.log\n"
        "docker ps\n"
        "kubectl get pods -n production\n"
        "aws s3 ls s3://company-backups-prod/\n"
        "mysql -u app_rw -p'Pr0d_DB_FAKE_P@ssw0rd_2024!' production_db\n"
        "vim /etc/nginx/sites-enabled/api.conf\n"
        "certbot renew --dry-run\n"
        "cat /home/admin/credentials.txt\n"
        "ssh-keygen -t rsa -b 4096 -C 'admin@prod-web-01'\n"
        "git pull origin main\n"
        "pip install -r requirements.txt\n"
        "python manage.py migrate\n"
        "supervisorctl restart all\n"
    ),
    "/home/admin/notes.txt": (
        "=== Server Notes ===\n"
        "\n"
        "Production Servers:\n"
        "  Web:    10.0.1.15 (this server)\n"
        "  App:    10.0.1.20\n"
        "  DB:     10.0.1.50 (MySQL 8.0)\n"
        "  Cache:  10.0.1.55 (Redis 7)\n"
        "  CI/CD:  10.0.1.100 (Jenkins)\n"
        "\n"
        "VPN Access:\n"
        "  Server: vpn.company-FAKE.com\n"
        "  User:   admin_vpn\n"
        "  Pass:   VPN_FAKE_Acc3ss_2024!\n"
        "  Secret: JBSWY3DPEHPK3FAKE\n"
        "\n"
        "Jenkins:\n"
        "  URL:  http://10.0.1.100:8080\n"
        "  User: admin\n"
        "  Pass: J3nk1ns_FAKE_Adm1n_2024!\n"
        "\n"
        "TODO:\n"
        "  - Rotate AWS keys (overdue)\n"
        "  - Update SSL cert on api.company.com\n"
        "  - Patch OpenSSH vulnerability\n"
    ),
    "/var/www/config.php": (
        "<?php\n"
        "// Application Configuration - FAKE HONEYPOT FILE\n"
        "return [\n"
        "    'database' => [\n"
        "        'host'     => 'db-prod-01.internal.corp',\n"
        "        'port'     => 3306,\n"
        "        'name'     => 'production_db',\n"
        "        'username' => 'app_rw',\n"
        "        'password' => 'Pr0d_DB_FAKE_P@ssw0rd_2024!',\n"
        "    ],\n"
        "    'stripe' => [\n"
        "        'secret_key' => 'sk_live_FAKE_4eC39HqLyjWDarjtT1zdp7dc',\n"
        "        'public_key' => 'pk_live_FAKE_TYooMQauvdEDq54NiTphI7jx',\n"
        "    ],\n"
        "    'sendgrid' => [\n"
        "        'api_key' => 'SG.FAKE_nW4Jd0RhR-OGY0olMEQ.FAKE_key_xyz',\n"
        "    ],\n"
        "    'app' => [\n"
        "        'secret'         => 'FAKE_app_s3cret_key_dJ8kL2mN4pQ6r',\n"
        "        'encryption_key' => 'FAKE_enc_k3y_aEs256_xB7yC9zD1eF3g',\n"
        "        'jwt_secret'     => 'FAKE_jwt_secr3t_hS512_kM4nP6qR8s',\n"
        "    ],\n"
        "];\n"
    ),
}

# Directory structure for ls command
FAKE_DIRS: Dict[str, List[Tuple[str, str, str, str, str, int]]] = {
    # (permissions, links, owner, group, size, name)
    "/": [
        ("drwxr-xr-x", "2", "root", "root", 4096, "bin"),
        ("drwxr-xr-x", "3", "root", "root", 4096, "boot"),
        ("drwxr-xr-x", "5", "root", "root", 4096, "dev"),
        ("drwxr-xr-x", "85", "root", "root", 4096, "etc"),
        ("drwxr-xr-x", "5", "root", "root", 4096, "home"),
        ("drwxr-xr-x", "2", "root", "root", 4096, "lib"),
        ("drwxr-xr-x", "2", "root", "root", 4096, "opt"),
        ("dr-xr-xr-x", "1", "root", "root", 0, "proc"),
        ("drwx------", "4", "root", "root", 4096, "root"),
        ("drwxr-xr-x", "2", "root", "root", 4096, "sbin"),
        ("drwxrwxrwt", "2", "root", "root", 4096, "tmp"),
        ("drwxr-xr-x", "10", "root", "root", 4096, "usr"),
        ("drwxr-xr-x", "11", "root", "root", 4096, "var"),
    ],
    "/etc": [
        ("-rw-r--r--", "1", "root", "root", 1748, "passwd"),
        ("-rw-r-----", "1", "root", "shadow", 1156, "shadow"),
        ("-rw-r--r--", "1", "root", "root", 367, "hosts"),
        ("-rw-r--r--", "1", "root", "root", 92, "hostname"),
        ("drwxr-xr-x", "2", "root", "root", 4096, "nginx"),
        ("drwxr-xr-x", "2", "root", "root", 4096, "ssh"),
        ("drwxr-xr-x", "2", "root", "root", 4096, "mysql"),
    ],
    "/home": [
        ("drwxr-xr-x", "5", "admin", "admin", 4096, "admin"),
        ("drwxr-xr-x", "3", "deploy", "deploy", 4096, "deploy"),
        ("drwxr-xr-x", "3", "jenkins", "jenkins", 4096, "jenkins"),
    ],
    "/home/admin": [
        ("-rw-------", "1", "admin", "admin", 1846, ".bash_history"),
        ("-rw-r--r--", "1", "admin", "admin", 220, ".bash_logout"),
        ("-rw-r--r--", "1", "admin", "admin", 3771, ".bashrc"),
        ("-rw-r--r--", "1", "admin", "admin", 807, ".profile"),
        ("-rw-r--r--", "1", "admin", "admin", 1523, "credentials.txt"),
        ("-rw-r--r--", "1", "admin", "admin", 856, "notes.txt"),
        ("drwx------", "2", "admin", "admin", 4096, ".ssh"),
    ],
    "/var": [
        ("drwxr-xr-x", "2", "root", "root", 4096, "backups"),
        ("drwxr-xr-x", "8", "root", "root", 4096, "cache"),
        ("drwxr-xr-x", "2", "root", "root", 4096, "lib"),
        ("drwxr-xr-x", "2", "root", "root", 4096, "log"),
        ("drwxr-xr-x", "2", "root", "root", 4096, "mail"),
        ("drwxr-xr-x", "3", "root", "root", 4096, "www"),
    ],
    "/var/www": [
        ("-rw-r--r--", "1", "www-data", "www-data", 2048, "config.php"),
        ("drwxr-xr-x", "5", "www-data", "www-data", 4096, "html"),
        ("-rw-r--r--", "1", "www-data", "www-data", 1024, "index.php"),
    ],
    "/root": [
        ("-rw-------", "1", "root", "root", 3106, ".bashrc"),
        ("-rw-------", "1", "root", "root", 148, ".profile"),
    ],
}


# ---------------------------------------------------------------------------
# Session Logger
# ---------------------------------------------------------------------------
class SessionLog:
    """Records everything an attacker does during a session."""

    def __init__(self, attacker_ip: str, username: str):
        self.attacker_ip = attacker_ip
        self.username = username
        self.session_start = datetime.now(timezone.utc).isoformat()
        self.session_end: Optional[str] = None
        self.credentials_tried: List[dict] = []
        self.commands_executed: List[dict] = []
        self.files_accessed: List[dict] = []
        self.download_attempts: List[dict] = []

    def log_credential(self, username: str, password: str, success: bool):
        self.credentials_tried.append({
            "username": username,
            "password": password,
            "success": success,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def log_command(self, command: str, cwd: str):
        self.commands_executed.append({
            "command": command,
            "cwd": cwd,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def log_file_access(self, path: str, found: bool):
        self.files_accessed.append({
            "path": path,
            "found": found,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def log_download(self, url: str):
        self.download_attempts.append({
            "url": url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def to_dict(self) -> dict:
        self.session_end = datetime.now(timezone.utc).isoformat()
        return {
            "attacker_ip": self.attacker_ip,
            "username": self.username,
            "session_start": self.session_start,
            "session_end": self.session_end,
            "credentials_tried": self.credentials_tried,
            "commands": self.commands_executed,
            "files_accessed": self.files_accessed,
            "download_attempts": self.download_attempts,
        }


async def send_session_log(session_log: SessionLog):
    """POST session log to the Logger service."""
    payload = session_log.to_dict()
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{LOGGER_URL}/api/v1/session/log",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status in (200, 201):
                    logger.info(
                        f"Session log sent to logger: "
                        f"{len(session_log.commands_executed)} commands, "
                        f"{len(session_log.credentials_tried)} credentials"
                    )
                else:
                    raise Exception(f"Logger returned {resp.status}")
    except Exception as e:
        logger.warning(f"Could not send to logger: {e}. Saving locally.")
        fallback_path = f"/tmp/session_log_{int(time.time())}.json"
        try:
            with open(fallback_path, "w") as f:
                json.dump(payload, f, indent=2)
            logger.info(f"Session log saved to {fallback_path}")
        except IOError as io_err:
            logger.error(f"Failed to save fallback log: {io_err}")


# ---------------------------------------------------------------------------
# Command Simulator
# ---------------------------------------------------------------------------
class CommandSimulator:
    """Simulates Linux commands with realistic fake output."""

    def __init__(self, username: str, session_log: SessionLog):
        self.username = username
        self.cwd = f"/home/{username}" if username != "root" else "/root"
        self.hostname = "prod-web-01"
        self.session_log = session_log

    def get_prompt(self) -> str:
        """Return a realistic-looking bash prompt."""
        symbol = "#" if self.username == "root" else "$"
        return f"{self.username}@{self.hostname}:{self.cwd}{symbol} "

    def _resolve_path(self, path: str) -> str:
        """Resolve a relative path to absolute."""
        if path.startswith("/"):
            return path
        if path == "~":
            return f"/home/{self.username}"
        if path.startswith("~/"):
            return f"/home/{self.username}/{path[2:]}"
        parts = self.cwd.rstrip("/").split("/") + path.split("/")
        resolved = []
        for part in parts:
            if part == "..":
                if resolved:
                    resolved.pop()
            elif part and part != ".":
                resolved.append(part)
        return "/" + "/".join(resolved) if resolved else "/"

    def execute(self, raw_command: str) -> str:
        """Execute a simulated command and return output."""
        raw_command = raw_command.strip()
        if not raw_command:
            return ""

        self.session_log.log_command(raw_command, self.cwd)

        parts = raw_command.split()
        cmd = parts[0]
        args = parts[1:] if len(parts) > 1 else []

        command_handlers = {
            "ls": self._cmd_ls,
            "cat": self._cmd_cat,
            "cd": self._cmd_cd,
            "pwd": self._cmd_pwd,
            "whoami": self._cmd_whoami,
            "id": self._cmd_id,
            "uname": self._cmd_uname,
            "hostname": self._cmd_hostname,
            "ifconfig": self._cmd_ifconfig,
            "ip": self._cmd_ip,
            "ps": self._cmd_ps,
            "netstat": self._cmd_netstat,
            "ss": self._cmd_netstat,
            "w": self._cmd_w,
            "env": self._cmd_env,
            "history": self._cmd_history,
            "wget": self._cmd_wget,
            "curl": self._cmd_curl,
            "sudo": self._cmd_sudo,
            "exit": self._cmd_exit,
            "head": self._cmd_head,
            "tail": self._cmd_tail,
            "echo": self._cmd_echo,
            "find": self._cmd_find,
            "grep": self._cmd_grep,
            "which": self._cmd_which,
            "file": self._cmd_file,
            "date": self._cmd_date,
            "uptime": self._cmd_uptime,
            "df": self._cmd_df,
            "free": self._cmd_free,
            "mount": self._cmd_mount,
            "lsb_release": self._cmd_lsb_release,
        }

        handler = command_handlers.get(cmd)
        if handler:
            return handler(args)
        else:
            return f"-bash: {cmd}: command not found\n"

    def _cmd_ls(self, args: List[str]) -> str:
        long_format = "-l" in args or "-la" in args or "-al" in args
        show_hidden = "-a" in args or "-la" in args or "-al" in args

        target = self.cwd
        for a in args:
            if not a.startswith("-"):
                target = self._resolve_path(a)
                break

        entries = FAKE_DIRS.get(target)
        if entries is None:
            return f"ls: cannot access '{target}': No such file or directory\n"

        self.session_log.log_file_access(target, True)
        lines = []
        if long_format:
            lines.append(f"total {len(entries) * 4}")
            if show_hidden:
                lines.append("drwxr-xr-x  2 root root 4096 Nov 15 10:30 .")
                lines.append("drwxr-xr-x  2 root root 4096 Nov 15 10:30 ..")
            for perms, links, owner, group, size, name in entries:
                if name.startswith(".") and not show_hidden:
                    continue
                lines.append(
                    f"{perms} {links:>3} {owner:<8} {group:<8} "
                    f"{size:>5} Nov 15 10:30 {name}"
                )
        else:
            names = [n for *_, n in entries]
            if not show_hidden:
                names = [n for n in names if not n.startswith(".")]
            lines.append("  ".join(names))

        return "\n".join(lines) + "\n"

    def _cmd_cat(self, args: List[str]) -> str:
        if not args:
            return ""
        path = self._resolve_path(args[0])
        content = FAKE_FS.get(path)
        if content:
            self.session_log.log_file_access(path, True)
            return content
        else:
            self.session_log.log_file_access(path, False)
            return f"cat: {args[0]}: No such file or directory\n"

    def _cmd_cd(self, args: List[str]) -> str:
        if not args:
            self.cwd = f"/home/{self.username}"
            return ""
        target = self._resolve_path(args[0])
        if target in FAKE_DIRS or target in ("/root",):
            if target == "/root" and self.username != "root":
                return "-bash: cd: /root: Permission denied\n"
            self.cwd = target
            return ""
        return f"-bash: cd: {args[0]}: No such file or directory\n"

    def _cmd_pwd(self, args: List[str]) -> str:
        return self.cwd + "\n"

    def _cmd_whoami(self, args: List[str]) -> str:
        return self.username + "\n"

    def _cmd_id(self, args: List[str]) -> str:
        if self.username == "root":
            return "uid=0(root) gid=0(root) groups=0(root)\n"
        return (
            f"uid=1000({self.username}) gid=1000({self.username}) "
            f"groups=1000({self.username}),4(adm),24(cdrom),27(sudo),"
            f"30(dip),46(plugdev),116(lxd)\n"
        )

    def _cmd_uname(self, args: List[str]) -> str:
        if "-a" in args:
            return (
                "Linux prod-web-01 5.15.0-89-generic #99-Ubuntu SMP "
                "Mon Oct 30 20:42:41 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n"
            )
        return "Linux\n"

    def _cmd_hostname(self, args: List[str]) -> str:
        return "prod-web-01\n"

    def _cmd_ifconfig(self, args: List[str]) -> str:
        return (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            "        inet 10.0.1.15  netmask 255.255.255.0  broadcast 10.0.1.255\n"
            "        inet6 fe80::42:acff:fe11:1  prefixlen 64  scopeid 0x20<link>\n"
            "        ether 02:42:ac:11:00:01  txqueuelen 0  (Ethernet)\n"
            "        RX packets 15234  bytes 12847326 (12.8 MB)\n"
            "        TX packets 11892  bytes 9126453 (9.1 MB)\n"
            "\n"
            "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
            "        inet 127.0.0.1  netmask 255.0.0.0\n"
            "        inet6 ::1  prefixlen 128  scopeid 0x10<host>\n"
            "        loop  txqueuelen 1000  (Local Loopback)\n"
            "        RX packets 4521  bytes 567890 (567.8 KB)\n"
            "        TX packets 4521  bytes 567890 (567.8 KB)\n"
        )

    def _cmd_ip(self, args: List[str]) -> str:
        if args and args[0] == "addr":
            return (
                "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n"
                "    inet 127.0.0.1/8 scope host lo\n"
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
                "    inet 10.0.1.15/24 brd 10.0.1.255 scope global eth0\n"
            )
        return self._cmd_ifconfig(args)

    def _cmd_ps(self, args: List[str]) -> str:
        return (
            "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
            "root         1  0.0  0.1 169372 11824 ?        Ss   Oct15   0:12 /sbin/init\n"
            "root       487  0.0  0.1  72304  6012 ?        Ss   Oct15   1:23 /usr/sbin/sshd -D\n"
            "www-data   892  0.1  0.3 141120 28416 ?        S    Oct15   8:45 nginx: worker process\n"
            "www-data   893  0.1  0.3 141120 27392 ?        S    Oct15   8:42 nginx: worker process\n"
            "mysql     1204  1.2  5.4 1894564 442368 ?      Sl   Oct15  52:13 /usr/sbin/mysqld\n"
            "root      1567  0.0  0.2 112876 16384 ?        Ss   Oct15   0:08 /usr/sbin/cron -f\n"
            "admin     2341  0.3  1.1 584320 92160 ?        Sl   Nov14   2:15 python3 /var/www/app.py\n"
            "admin     2456  0.0  0.1  21564  4892 ?        S    Nov14   0:03 python3 /var/www/worker.py\n"
            f"{self.username:8} {os.getpid():>5}  0.0  0.0  10068  3240 pts/0    Ss   {datetime.now().strftime('%H:%M')}   0:00 -bash\n"
            f"{self.username:8} {os.getpid()+1:>5}  0.0  0.0  10068  1648 pts/0    R+   {datetime.now().strftime('%H:%M')}   0:00 ps aux\n"
        )

    def _cmd_netstat(self, args: List[str]) -> str:
        return (
            "Active Internet connections (only servers)\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      487/sshd\n"
            "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      891/nginx\n"
            "tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      891/nginx\n"
            "tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      1204/mysqld\n"
            "tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      2341/python3\n"
            "tcp6       0      0 :::22                   :::*                    LISTEN      487/sshd\n"
        )

    def _cmd_w(self, args: List[str]) -> str:
        now = datetime.now()
        return (
            f" {now.strftime('%H:%M:%S')} up 32 days, 14:23,  2 users,  load average: 0.42, 0.38, 0.35\n"
            "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
            f"{self.username:<8} pts/0    {ATTACKER_IP:<16} {now.strftime('%H:%M')}    0.00s  0.04s  0.00s w\n"
            "deploy   pts/1    10.0.1.100       09:15    3:22m  0.02s  0.02s -bash\n"
        )

    def _cmd_env(self, args: List[str]) -> str:
        return (
            f"USER={self.username}\n"
            "HOME=/home/admin\n"
            "HOSTNAME=prod-web-01\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
            "SHELL=/bin/bash\n"
            "LANG=en_US.UTF-8\n"
            "TERM=xterm-256color\n"
            "DB_HOST=db-prod-01.internal.corp\n"
            "DB_USER=app_rw\n"
            "DB_PASSWORD=Pr0d_DB_FAKE_P@ssw0rd_2024!\n"
            "API_SECRET=FAKE_api_s3cret_key_vX8wY0zA2bC4d\n"
            "REDIS_URL=redis://10.0.1.55:6379/0\n"
            "JWT_SECRET=FAKE_jwt_secr3t_hS512_kM4nP6qR8s\n"
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7FAKEAWS\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCFAKESECRETKEY\n"
            "AWS_DEFAULT_REGION=us-east-1\n"
            "STRIPE_SECRET_KEY=sk_live_FAKE_4eC39HqLyjWDarjtT1zdp7dc\n"
        )

    def _cmd_history(self, args: List[str]) -> str:
        content = FAKE_FS.get("/home/admin/.bash_history", "")
        lines = content.strip().split("\n")
        result = ""
        for i, line in enumerate(lines, 1):
            result += f"  {i:>4}  {line}\n"
        return result

    def _cmd_wget(self, args: List[str]) -> str:
        url = args[0] if args else "unknown"
        self.session_log.log_download(url)
        return (
            f"--{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}--  {url}\n"
            f"Resolving {url.split('/')[2] if '/' in url else url}... failed: "
            "Temporary failure in name resolution.\n"
            f"wget: unable to resolve host address '{url.split('/')[2] if '/' in url else url}'\n"
        )

    def _cmd_curl(self, args: List[str]) -> str:
        url = args[-1] if args else "unknown"
        self.session_log.log_download(url)
        host = url.split("/")[2] if "/" in url and len(url.split("/")) > 2 else url
        return (
            f"curl: (6) Could not resolve host: {host}\n"
        )

    def _cmd_sudo(self, args: List[str]) -> str:
        return (
            f"[sudo] password for {self.username}: \n"
            f"{self.username} is not in the sudoers file. "
            "This incident will be reported.\n"
        )

    def _cmd_exit(self, args: List[str]) -> str:
        return "__EXIT__"

    def _cmd_head(self, args: List[str]) -> str:
        if not args:
            return ""
        path = self._resolve_path(args[-1])
        content = FAKE_FS.get(path)
        if content:
            self.session_log.log_file_access(path, True)
            lines = content.split("\n")[:10]
            return "\n".join(lines) + "\n"
        self.session_log.log_file_access(path, False)
        return f"head: cannot open '{args[-1]}' for reading: No such file or directory\n"

    def _cmd_tail(self, args: List[str]) -> str:
        if not args:
            return ""
        path = self._resolve_path(args[-1])
        content = FAKE_FS.get(path)
        if content:
            self.session_log.log_file_access(path, True)
            lines = content.split("\n")[-10:]
            return "\n".join(lines) + "\n"
        self.session_log.log_file_access(path, False)
        return f"tail: cannot open '{args[-1]}' for reading: No such file or directory\n"

    def _cmd_echo(self, args: List[str]) -> str:
        return " ".join(args) + "\n"

    def _cmd_find(self, args: List[str]) -> str:
        return (
            "/home/admin/credentials.txt\n"
            "/home/admin/notes.txt\n"
            "/var/www/config.php\n"
        )

    def _cmd_grep(self, args: List[str]) -> str:
        return ""

    def _cmd_which(self, args: List[str]) -> str:
        common = {
            "python": "/usr/bin/python3",
            "python3": "/usr/bin/python3",
            "gcc": "/usr/bin/gcc",
            "mysql": "/usr/bin/mysql",
            "ssh": "/usr/bin/ssh",
            "scp": "/usr/bin/scp",
            "nmap": "/usr/bin/nmap",
            "wget": "/usr/bin/wget",
            "curl": "/usr/bin/curl",
        }
        if args:
            path = common.get(args[0])
            if path:
                return path + "\n"
            return f"{args[0]} not found\n"
        return ""

    def _cmd_file(self, args: List[str]) -> str:
        if args:
            return f"{args[0]}: ASCII text\n"
        return ""

    def _cmd_date(self, args: List[str]) -> str:
        return datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y") + "\n"

    def _cmd_uptime(self, args: List[str]) -> str:
        return (
            f" {datetime.now().strftime('%H:%M:%S')} up 32 days, 14:23,  "
            "2 users,  load average: 0.42, 0.38, 0.35\n"
        )

    def _cmd_df(self, args: List[str]) -> str:
        return (
            "Filesystem     1K-blocks    Used Available Use% Mounted on\n"
            "/dev/sda1       51475068 18294632  30540764  38% /\n"
            "tmpfs            2024892        0   2024892   0% /dev/shm\n"
            "/dev/sda2       10190100  2345678   7303850  25% /var\n"
        )

    def _cmd_free(self, args: List[str]) -> str:
        return (
            "              total        used        free      shared  buff/cache   available\n"
            "Mem:        4049784     1832456      412328       45672     1805000     1978656\n"
            "Swap:       2097148      234568     1862580\n"
        )

    def _cmd_mount(self, args: List[str]) -> str:
        return (
            "/dev/sda1 on / type ext4 (rw,relatime)\n"
            "proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n"
            "tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)\n"
        )

    def _cmd_lsb_release(self, args: List[str]) -> str:
        return (
            "Distributor ID: Ubuntu\n"
            "Description:    Ubuntu 22.04.3 LTS\n"
            "Release:        22.04\n"
            "Codename:       jammy\n"
        )


# ---------------------------------------------------------------------------
# SSH Server Implementation
# ---------------------------------------------------------------------------
class HoneypotSSHServer(asyncssh.SSHServer):
    """Custom SSH server that logs all authentication attempts."""

    def __init__(self):
        self._auth_failures = 0
        self._session_log: Optional[SessionLog] = None
        self._conn = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self._conn = conn
        peername = conn.get_extra_info("peername")
        client_ip = peername[0] if peername else "unknown"
        logger.info(f"SSH connection from {client_ip}")

    def connection_lost(self, exc: Optional[Exception]) -> None:
        peername = self._conn.get_extra_info("peername") if self._conn else None
        client_ip = peername[0] if peername else "unknown"
        logger.info(f"SSH connection lost from {client_ip}: {exc}")

    def begin_auth(self, username: str) -> bool:
        """Called when authentication begins. Return True to require auth."""
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        """Validate password — accept weak creds or any after 3 failures."""
        peername = self._conn.get_extra_info("peername") if self._conn else None
        client_ip = peername[0] if peername else "unknown"

        # Initialize session log on first auth attempt
        if self._session_log is None:
            self._session_log = SessionLog(client_ip, username)

        is_accepted = (username, password) in ACCEPTED_CREDENTIALS
        accept_any = self._auth_failures >= MAX_FAILURES_BEFORE_ACCEPT_ANY

        if is_accepted or accept_any:
            self._session_log.log_credential(username, password, True)
            logger.info(
                f"Auth SUCCESS: {username}:{password} from {client_ip} "
                f"({'known creds' if is_accepted else 'accepted after failures'})"
            )
            return True
        else:
            self._auth_failures += 1
            self._session_log.log_credential(username, password, False)
            logger.info(
                f"Auth FAILED ({self._auth_failures}): "
                f"{username}:{password} from {client_ip}"
            )
            return False


class HoneypotShellSession:
    """Handles an interactive shell session inside the honeypot."""

    def __init__(self, process: asyncssh.SSHServerProcess, session_log: SessionLog):
        self.process = process
        self.session_log = session_log
        self.simulator = CommandSimulator(
            username=process.get_extra_info("username") or "admin",
            session_log=session_log,
        )

    async def run(self):
        """Run the interactive shell session."""
        username = self.process.get_extra_info("username") or "admin"
        now = datetime.now()

        # Login banner
        banner = (
            f"\n"
            f"Last login: {now.strftime('%a %b %d %H:%M:%S %Y')} from 10.0.1.100\n"
            f"Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)\n"
            f"\n"
            f" * Documentation:  https://help.ubuntu.com\n"
            f" * Management:     https://landscape.canonical.com\n"
            f" * Support:        https://ubuntu.com/advantage\n"
            f"\n"
            f"  System information as of {now.strftime('%a %b %d %H:%M:%S UTC %Y')}\n"
            f"\n"
            f"  System load:  0.42               Processes:             187\n"
            f"  Usage of /:   37.8% of 49.09GB   Users logged in:       1\n"
            f"  Memory usage: 45%                IPv4 address for eth0: 10.0.1.15\n"
            f"  Swap usage:   11%\n"
            f"\n"
            f" * 3 security updates available.\n"
            f"\n"
        )

        self.process.stdout.write(banner)

        try:
            while True:
                prompt = self.simulator.get_prompt()
                self.process.stdout.write(prompt)

                # Read input line
                try:
                    line = await asyncio.wait_for(
                        self.process.stdin.readline(), timeout=300
                    )
                except asyncio.TimeoutError:
                    self.process.stdout.write("\nSession timed out.\n")
                    break

                if not line:
                    break

                command = line.strip()
                if not command:
                    continue

                output = self.simulator.execute(command)

                if output == "__EXIT__":
                    self.process.stdout.write("logout\n")
                    break

                self.process.stdout.write(output)

        except (asyncssh.BreakReceived, asyncssh.TerminalSizeChanged):
            pass
        except Exception as e:
            logger.error(f"Shell session error: {e}")
        finally:
            # Send session log
            await send_session_log(self.session_log)
            self.process.exit(0)


async def handle_ssh_session(process: asyncssh.SSHServerProcess) -> None:
    """Handle a new SSH session by creating a shell."""
    server = process.channel.get_connection().get_owner()
    session_log = getattr(server, "_session_log", None)
    if session_log is None:
        peername = process.get_extra_info("peername")
        client_ip = peername[0] if peername else "unknown"
        session_log = SessionLog(client_ip, process.get_extra_info("username") or "admin")

    shell = HoneypotShellSession(process, session_log)
    await shell.run()


async def start_ssh_server():
    """Start the SSH honeypot server."""
    # Generate host key if it doesn't exist
    if not os.path.exists(HOST_KEY_PATH):
        logger.info("Generating SSH host key...")
        import subprocess
        subprocess.run(
            ["ssh-keygen", "-t", "rsa", "-b", "2048", "-f", HOST_KEY_PATH, "-N", "", "-q"],
            check=True,
        )
        logger.info(f"Host key generated: {HOST_KEY_PATH}")

    logger.info(f"Starting SSH honeypot on port {SERVICE_PORT}")
    logger.info(f"Attacker IP: {ATTACKER_IP}")
    logger.info(f"Logger URL: {LOGGER_URL}")

    await asyncssh.create_server(
        HoneypotSSHServer,
        "",
        SERVICE_PORT,
        server_host_keys=[HOST_KEY_PATH],
        process_factory=handle_ssh_session,
    )

    logger.info(f"SSH honeypot listening on port {SERVICE_PORT}")

    # Keep running
    while True:
        await asyncio.sleep(3600)


if __name__ == "__main__":
    try:
        asyncio.run(start_ssh_server())
    except (KeyboardInterrupt, SystemExit):
        logger.info("SSH honeypot shutdown.")
