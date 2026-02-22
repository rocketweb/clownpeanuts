"""TCP-based SSH-style honeypot emulator with credential capture."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import PurePosixPath
import socket
import socketserver
import threading
from typing import Any
from uuid import uuid4
from collections import OrderedDict

from clownpeanuts.config.schema import ServiceConfig
from clownpeanuts.core.logging import get_logger
from clownpeanuts.services.base import ServiceEmulator
from clownpeanuts.tarpit.throttle import AdaptiveThrottle


class _ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, *args: Any, max_concurrent_connections: int = 256, **kwargs: Any) -> None:
        self._connection_slots = threading.BoundedSemaphore(max(1, int(max_concurrent_connections)))
        super().__init__(*args, **kwargs)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._connection_slots.acquire(blocking=False):
            try:
                request.close()
            except OSError:
                pass
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._connection_slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()


class Emulator(ServiceEmulator):
    _MAX_SHELL_STATES = 10_000

    def __init__(self) -> None:
        super().__init__()
        self.logger = get_logger("clownpeanuts.services.ssh")
        self._config: ServiceConfig | None = None
        self._server: _ThreadingTCPServer | None = None
        self._thread: threading.Thread | None = None
        self._bound_host: str | None = None
        self._bound_port: int | None = None
        self._auth_failures_before_success = 1
        self._banner = "SSH-2.0-OpenSSH_8.4p1 Debian-5"
        self._hostname = "ip-172-31-44-9"
        self._socket_timeout = 45.0
        self._max_concurrent_connections = 256
        self._tarpit = AdaptiveThrottle(service_name=self.name)
        self._shell_state: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._shell_state_lock = threading.RLock()

    @property
    def name(self) -> str:
        return "ssh"

    @property
    def default_ports(self) -> list[int]:
        return [22, 2222]

    @property
    def config_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "banner": {"type": "string"},
                "hostname": {"type": "string"},
                "auth_failures_before_success": {"type": "integer", "minimum": 0, "maximum": 5},
                "socket_timeout_seconds": {"type": "number", "minimum": 1},
                "max_concurrent_connections": {"type": "integer", "minimum": 1, "maximum": 5000},
                "adaptive_tarpit_enabled": {"type": "boolean"},
                "tarpit_min_delay_ms": {"type": "integer", "minimum": 0, "maximum": 10000},
                "tarpit_max_delay_ms": {"type": "integer", "minimum": 0, "maximum": 20000},
                "tarpit_ramp_events": {"type": "integer", "minimum": 1, "maximum": 1000},
                "tarpit_jitter_ratio": {"type": "number", "minimum": 0.0, "maximum": 1.0},
            },
        }

    def apply_runtime_config(self, config: ServiceConfig) -> None:
        self._banner = str(config.config.get("banner", self._banner))
        self._hostname = str(config.config.get("hostname", self._hostname))
        self._socket_timeout = float(config.config.get("socket_timeout_seconds", self._socket_timeout))
        self._max_concurrent_connections = max(
            1,
            int(config.config.get("max_concurrent_connections", self._max_concurrent_connections)),
        )
        self._auth_failures_before_success = max(
            0, int(config.config.get("auth_failures_before_success", self._auth_failures_before_success))
        )
        self._tarpit.configure(config=config.config)

    async def start(self, config: ServiceConfig) -> None:
        self._config = config
        self.apply_runtime_config(config)

        listen_host = config.listen_host
        listen_port = config.ports[0] if config.ports else self.default_ports[0]
        self._server = _ThreadingTCPServer(
            (listen_host, listen_port),
            self._build_handler(),
            max_concurrent_connections=self._max_concurrent_connections,
        )
        self._bound_host = listen_host
        self._bound_port = int(self._server.server_address[1])
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.running = True

        self.logger.info(
            "service started",
            extra={"service": self.name, "payload": {"host": self._bound_host, "port": self._bound_port}},
        )
        if self.runtime:
            self.runtime.event_logger.emit(
                message="ssh service started",
                service=self.name,
                action="service_start",
                event_type="start",
                payload={"host": self._bound_host, "port": self._bound_port},
            )

    async def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
        self._thread = None
        with self._shell_state_lock:
            self._shell_state.clear()
        self.running = False
        self.logger.info("service stopped", extra={"service": self.name})
        if self.runtime:
            self.runtime.event_logger.emit(
                message="ssh service stopped",
                service=self.name,
                action="service_stop",
                event_type="end",
            )

    async def handle_connection(self, conn: dict[str, Any]) -> dict[str, Any]:
        username = str(conn.get("username", "root"))
        password = str(conn.get("password", "toor"))
        source_ip = str(conn.get("source_ip", "127.0.0.1"))
        source_port = int(conn.get("source_port", 0))
        session_id = str(conn.get("session_id", f"ssh-{uuid4().hex}"))
        attempts = conn.get("attempts")
        if not isinstance(attempts, list):
            attempts = [(username, password)]

        if self.runtime:
            self.runtime.session_manager.get_or_create(session_id=session_id, source_ip=source_ip)

        accepted_username = ""
        accepted_password = ""
        auth_log: list[dict[str, str]] = []
        for index, attempt in enumerate(attempts):
            attempt_user = str(attempt[0])
            attempt_password = str(attempt[1])
            outcome = "failure" if index < self._auth_failures_before_success else "success"
            auth_log.append({"username": attempt_user, "password": attempt_password, "outcome": outcome})
            self._record_auth_attempt(
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                username=attempt_user,
                password=attempt_password,
                outcome=outcome,
            )
            if outcome == "success":
                accepted_username = attempt_user
                accepted_password = attempt_password
                break

        commands = [str(item) for item in conn.get("commands", [])]
        command_outputs: list[dict[str, str]] = []
        for command in commands:
            output = self._render_command(
                command,
                accepted_username or username,
                session_id=session_id,
                source_ip=source_ip,
            )
            command_outputs.append({"command": command, "output": output})
            self._record_command(
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                username=accepted_username or username,
                command=command,
            )

        return {
            "service": self.name,
            "session_id": session_id,
            "auth_attempts": auth_log,
            "accepted": bool(accepted_username),
            "username": accepted_username or username,
            "password": accepted_password or password,
            "commands": command_outputs,
        }

    def inject_activity(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.runtime is None:
            return {
                "accepted": False,
                "service": self.name,
                "reason": "runtime not initialized",
            }
        activity_type = str(payload.get("type", "ssh_session")).strip().lower()
        if activity_type not in {"ssh_session", "command_session", "command"}:
            return {
                "accepted": False,
                "service": self.name,
                "reason": f"unsupported activity type '{activity_type}'",
            }
        source_ip = str(payload.get("source_ip", "127.0.0.1")).strip() or "127.0.0.1"
        try:
            source_port = int(payload.get("source_port", 0) or 0)
        except (TypeError, ValueError):
            source_port = 0
        username = str(payload.get("username", "ops-bot")).strip() or "ops-bot"
        session_id = str(payload.get("session_id", f"ssh-injected-{uuid4().hex[:12]}")).strip()
        if not session_id:
            session_id = f"ssh-injected-{uuid4().hex[:12]}"

        commands_raw = payload.get("commands")
        commands: list[str] = []
        if isinstance(commands_raw, list):
            commands.extend([str(item).strip() for item in commands_raw if str(item).strip()])
        command_value = str(payload.get("command", "")).strip()
        if command_value:
            commands.append(command_value)
        details = payload.get("payload")
        if isinstance(details, dict):
            nested_commands = details.get("commands")
            if isinstance(nested_commands, list):
                commands.extend([str(item).strip() for item in nested_commands if str(item).strip()])
            nested_command = str(details.get("command", "")).strip()
            if nested_command:
                commands.append(nested_command)
        if not commands:
            commands = ["whoami", "id"]

        self.runtime.session_manager.get_or_create(session_id=session_id, source_ip=source_ip)
        password = str(payload.get("password", "injected-password")).strip() or "injected-password"
        self._record_auth_attempt(
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            username=username,
            password=password,
            outcome="success",
        )

        emitted = 0
        for command in commands[:120]:
            self._record_command(
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                username=username,
                command=command,
            )
            emitted += 1
        return {
            "accepted": True,
            "service": self.name,
            "activity_type": activity_type,
            "session_id": session_id,
            "username": username,
            "command_count": emitted,
        }

    @property
    def bound_endpoint(self) -> tuple[str, int] | None:
        if self._bound_host is None or self._bound_port is None:
            return None
        return (self._bound_host, self._bound_port)

    def _build_handler(self) -> type[socketserver.BaseRequestHandler]:
        emulator = self

        class SSHHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                emulator._handle_client(self.request, self.client_address)

        return SSHHandler

    def _handle_client(self, conn: socket.socket, client_address: tuple[str, int]) -> None:
        conn.settimeout(self._socket_timeout)
        source_ip, source_port = client_address
        session_id = f"ssh-{source_ip}-{uuid4().hex[:12]}"

        if self.runtime:
            self.runtime.session_manager.get_or_create(session_id=session_id, source_ip=source_ip)

        self._send_line(conn, self._banner)
        client_banner = self._recvline(conn)
        if client_banner:
            self._record_event(
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                action="client_banner",
                event_type="info",
                payload={"banner": client_banner},
            )

        username = "root"
        auth_attempt = 0
        while True:
            typed_username = self._prompt(conn, "login as: ")
            if typed_username is None:
                return
            username = typed_username or username
            typed_password = self._prompt(conn, "password: ")
            if typed_password is None:
                return

            auth_attempt += 1
            outcome = "failure" if auth_attempt <= self._auth_failures_before_success else "success"
            self._record_auth_attempt(
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                username=username,
                password=typed_password,
                outcome=outcome,
            )

            if outcome == "failure":
                self._tarpit.maybe_delay(
                    runtime=self.runtime,
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    trigger="ssh_auth_failure",
                )
                self._send_line(conn, "Permission denied, please try again.")
                continue
            break

        self._send_line(conn, f"Last login: {datetime.now(UTC).strftime('%a %b %d %H:%M:%S %Y')} from {source_ip}")
        prompt = f"{username}@{self._hostname}:~$ "

        while True:
            command = self._prompt(conn, prompt)
            if command is None:
                return
            command = command.strip()
            if not command:
                continue
            if command in {"exit", "logout", "quit"}:
                self._send_line(conn, "logout")
                self._record_command(
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    username=username,
                    command=command,
                )
                return

            output = self._render_command(
                command,
                username,
                session_id=session_id,
                source_ip=source_ip,
            )
            self._tarpit.maybe_delay(
                runtime=self.runtime,
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                trigger="ssh_command_response",
            )
            if output:
                self._send_block(conn, output)
            self._record_command(
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                username=username,
                command=command,
            )

    def _prompt(self, conn: socket.socket, text: str) -> str | None:
        self._send_raw(conn, text)
        line = self._recvline(conn)
        return line

    def _recvline(self, conn: socket.socket, limit: int = 2048) -> str | None:
        data = bytearray()
        try:
            while len(data) < limit:
                chunk = conn.recv(1)
                if not chunk:
                    break
                if chunk in b"\r\n":
                    if chunk == b"\r":
                        try:
                            conn.recv(1)
                        except socket.timeout:
                            pass
                    break
                data.extend(chunk)
        except (TimeoutError, OSError):
            return None

        if not data:
            return None
        return data.decode("utf-8", errors="replace").strip()

    @staticmethod
    def _send_raw(conn: socket.socket, text: str) -> None:
        try:
            conn.sendall(text.encode("utf-8", errors="replace"))
        except OSError:
            return

    def _send_line(self, conn: socket.socket, text: str) -> None:
        self._send_raw(conn, f"{text}\r\n")

    def _send_block(self, conn: socket.socket, text: str) -> None:
        self._send_raw(conn, text.replace("\n", "\r\n"))
        if not text.endswith("\n"):
            self._send_raw(conn, "\r\n")

    def _record_event(
        self,
        *,
        session_id: str,
        source_ip: str,
        source_port: int,
        action: str,
        event_type: str,
        payload: dict[str, Any],
        outcome: str | None = None,
    ) -> None:
        if not self.runtime:
            return
        event_payload = {"source_ip": source_ip, **payload}
        self.runtime.session_manager.record_event(
            session_id=session_id,
            service=self.name,
            action=action,
            payload=event_payload,
        )
        self.runtime.event_logger.emit(
            message=f"ssh {action}",
            service=self.name,
            action=action,
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            outcome=outcome,
            event_type=event_type,
            payload=event_payload,
        )

    def _record_auth_attempt(
        self,
        *,
        session_id: str,
        source_ip: str,
        source_port: int,
        username: str,
        password: str,
        outcome: str,
    ) -> None:
        self._record_event(
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            action="auth_attempt",
            event_type="authentication",
            outcome=outcome,
            payload={"username": username, "password": password, "outcome": outcome},
        )

    def _record_command(
        self,
        *,
        session_id: str,
        source_ip: str,
        source_port: int,
        username: str,
        command: str,
    ) -> None:
        self._record_event(
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            action="command",
            event_type="info",
            outcome="success",
            payload={"username": username, "command": command},
        )

    def _render_command(
        self,
        command: str,
        username: str,
        *,
        session_id: str | None = None,
        source_ip: str | None = None,
    ) -> str:
        command = command.strip()
        if not command:
            return ""
        state = self._session_shell_state(session_id=session_id, username=username)
        cwd = str(state.get("cwd", f"/home/{username}"))
        history = state.get("history", [])
        if isinstance(history, list):
            history.append(command)
            state["history"] = history[-60:]
        narrative = self._resolve_narrative_context(
            session_id=session_id,
            source_ip=source_ip,
            command=command,
        )
        selected_lure_arm = self._select_lure_arm(
            session_id=session_id,
            source_ip=source_ip,
            command=command,
        )
        narrative_host = self._narrative_focus_label(narrative, kind="host", default=self._hostname)
        narrative_service = self._narrative_focus_label(narrative, kind="service", default="control-plane")
        narrative_ticket = self._narrative_focus_label(narrative, kind="ticket", default="OPS-1042")

        lowered = command.lower()
        if command == "whoami":
            return username
        if command in {"pwd", "cwd"}:
            return cwd
        if command in {"hostname", "hostname -f"}:
            return narrative_host
        if command == "hostnamectl":
            return (
                f" Static hostname: {narrative_host}\n"
                "       Icon name: computer-vm\n"
                "         Chassis: vm\n"
                "      Machine ID: e7f0d4c6dd1a43cb8f7b6c8f67f1c999\n"
                "         Boot ID: 22f459cf74d64f6ab6c6324a24dbdc12\n"
                "  Operating System: Ubuntu 22.04.4 LTS\n"
                "            Kernel: Linux 5.15.0-1033-aws\n"
                "      Architecture: x86-64"
            )
        if command in {"id", "/usr/bin/id"}:
            return f"uid=1000({username}) gid=1000({username}) groups=1000({username}),27(sudo)"
        if command == "uname -a":
            return f"Linux {narrative_host} 5.15.0-1033-aws x86_64 GNU/Linux"
        if command == "uname -r":
            return "5.15.0-1033-aws"
        if command in {"cat /etc/os-release", "cat /usr/lib/os-release"}:
            return (
                'NAME="Ubuntu"\n'
                'VERSION="22.04.4 LTS (Jammy Jellyfish)"\n'
                "ID=ubuntu\n"
                "ID_LIKE=debian\n"
                'PRETTY_NAME="Ubuntu 22.04.4 LTS"\n'
                'VERSION_ID="22.04"\n'
                "HOME_URL=\"https://www.ubuntu.com/\"\n"
            )
        if command in {"ps aux", "ps -ef"}:
            return (
                "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
                "root         1  0.0  0.1 169612 11248 ?        Ss   00:01   0:01 /sbin/init\n"
                "root       412  0.0  0.3 118764 21440 ?        Ssl  00:02   0:02 /usr/sbin/sshd -D\n"
                "www-data   873  0.2  1.8 413212 74288 ?        S    00:04   0:11 php-fpm: pool www\n"
                "mysql      940  0.1  2.0 1523800 82448 ?       Ssl  00:05   0:08 /usr/sbin/mysqld\n"
            )
        if command in {"netstat -plnt", "ss -tulpn", "ss -lntp"}:
            return (
                "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n"
                "tcp   LISTEN 0      128    0.0.0.0:22          0.0.0.0:*         users:((\"sshd\",pid=412,fd=3))\n"
                "tcp   LISTEN 0      80     0.0.0.0:80          0.0.0.0:*         users:((\"nginx\",pid=702,fd=6))\n"
                "tcp   LISTEN 0      151    127.0.0.1:3306      0.0.0.0:*         users:((\"mysqld\",pid=940,fd=22))\n"
            )
        if command == "df -h":
            return (
                "Filesystem      Size  Used Avail Use% Mounted on\n"
                "/dev/nvme0n1p1   40G   18G   21G  47% /\n"
                "tmpfs           990M  2.1M  988M   1% /run\n"
                "tmpfs           2.0G     0  2.0G   0% /dev/shm\n"
            )
        if lowered in {"ip a", "ip addr", "ip addr show", "/sbin/ip a"}:
            return (
                "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default\n"
                "    inet 127.0.0.1/8 scope host lo\n"
                "       valid_lft forever preferred_lft forever\n"
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc mq state UP group default\n"
                "    inet 172.31.44.9/20 brd 172.31.47.255 scope global dynamic eth0\n"
                "       valid_lft 3123sec preferred_lft 3123sec\n"
                "3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default\n"
                "    inet 172.17.0.1/16 scope global docker0\n"
                "       valid_lft forever preferred_lft forever\n"
            )
        if lowered in {"ifconfig", "/sbin/ifconfig"}:
            return (
                "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001\n"
                "        inet 172.31.44.9  netmask 255.255.240.0  broadcast 172.31.47.255\n"
                "        RX packets 134273  bytes 154908332 (154.9 MB)\n"
                "        TX packets 98210  bytes 120334719 (120.3 MB)\n"
                "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
                "        inet 127.0.0.1  netmask 255.0.0.0\n"
            )
        if command == "free -m":
            return (
                "               total        used        free      shared  buff/cache   available\n"
                "Mem:            3952        1678         812         101        1461        1912\n"
                "Swap:           1023         121         902\n"
            )
        if lowered in {"lsblk", "lsblk -f"}:
            return (
                "NAME         FSTYPE LABEL UUID                                 FSAVAIL FSUSE% MOUNTPOINTS\n"
                "nvme0n1\n"
                "├─nvme0n1p1  ext4         3d8f2d2a-1f19-4d0e-bf0a-6e97f55ac001   21.0G    47% /\n"
                "└─nvme0n1p14 vfat         4A1C-A2D1\n"
            )
        if lowered == "mount":
            return (
                "/dev/nvme0n1p1 on / type ext4 (rw,relatime,discard)\n"
                "proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n"
                "tmpfs on /run type tmpfs (rw,nosuid,nodev,mode=755)\n"
                "overlay on /var/lib/docker/overlay2 type overlay (rw,relatime)\n"
            )
        if lowered in {"systemctl status nginx", "service nginx status"}:
            return (
                "nginx.service - A high performance web server\n"
                "   Loaded: loaded (/lib/systemd/system/nginx.service; enabled)\n"
                "   Active: active (running) since Tue 2026-02-17 00:02:11 UTC; 1 day ago\n"
                " Main PID: 702 (nginx)\n"
                "    Tasks: 3 (limit: 4704)\n"
            )
        if lowered in {"systemctl status ssh", "systemctl status sshd", "service ssh status", "service sshd status"}:
            return (
                "ssh.service - OpenBSD Secure Shell server\n"
                "   Loaded: loaded (/lib/systemd/system/ssh.service; enabled)\n"
                "   Active: active (running) since Tue 2026-02-17 00:02:09 UTC; 1 day ago\n"
                " Main PID: 412 (sshd)\n"
                "    Tasks: 1 (limit: 4704)\n"
            )
        if lowered.startswith("journalctl -u ssh"):
            return (
                "Feb 18 00:12:14 ip-172-31-44-9 sshd[3112]: Failed password for invalid user ubuntu from 185.220.101.9 port 55970 ssh2\n"
                "Feb 18 00:12:17 ip-172-31-44-9 sshd[3112]: Received disconnect from 185.220.101.9 port 55970:11: Bye Bye\n"
                "Feb 18 00:13:48 ip-172-31-44-9 sshd[3220]: Accepted password for root from 203.0.113.9 port 43116 ssh2\n"
                "Feb 18 00:14:01 ip-172-31-44-9 sshd[3220]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)\n"
            )
        if command == "sudo -l":
            return (
                "Matching Defaults entries for root on ip-172-31-44-9:\n"
                "    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
                "\n"
                "User root may run the following commands on ip-172-31-44-9:\n"
                "    (ALL : ALL) ALL\n"
            )
        if command == "crontab -l":
            return "0 2 * * * /usr/local/bin/backup.sh\n*/15 * * * * /usr/local/bin/cache-warm.sh\n"
        if command in {"last", "last -n 5"}:
            return (
                "root     pts/0        203.0.113.9      Tue Feb 18 00:13   still logged in\n"
                "admin    pts/1        198.51.100.44    Mon Feb 17 21:09 - 21:11  (00:02)\n"
                "reboot   system boot  5.15.0-1033-aws  Mon Feb 17 20:58   still running\n"
            )
        if command in {"ip route", "route -n"}:
            return (
                "default via 172.31.0.1 dev eth0 proto dhcp src 172.31.44.9 metric 100\n"
                "10.10.2.0/24 via 172.31.44.1 dev eth0\n"
                "10.10.3.0/24 via 172.31.44.1 dev eth0\n"
                "172.31.0.0/20 dev eth0 proto kernel scope link src 172.31.44.9\n"
            )
        if command in {"history", "history 10"}:
            recent = [str(item) for item in state.get("history", [])][-10:]
            return "\n".join(f"{index + 1}  {item}" for index, item in enumerate(recent))
        if lowered.startswith("echo $"):
            key = lowered.removeprefix("echo $").strip().upper()
            environment = {
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "HOME": f"/home/{username}",
                "SHELL": "/bin/bash",
                "USER": username,
            }
            return environment.get(key, "")
        if command.startswith("ls"):
            target, long_format = self._parse_ls_command(command=command, cwd=cwd, username=username)
            return self._render_directory_listing(path=target, username=username, long_format=long_format)
        if command == "cat .env":
            return "DB_USER=wp_admin\nDB_PASSWORD=cp_fake_db_password\nAWS_ACCESS_KEY_ID=CP_FAKE_AWS_ACCESS_KEY"
        if command == "cat /etc/passwd":
            return (
                "root:x:0:0:root:/root:/bin/bash\n"
                f"{username}:x:1000:1000:{username}:/home/{username}:/bin/bash\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
            )
        if command == "cat /etc/hosts":
            return (
                "127.0.0.1 localhost\n"
                f"127.0.1.1 {narrative_host}\n"
                "10.10.2.14 db01.internal\n"
                "10.10.2.21 cache01.internal\n"
                "10.10.3.7 ci01.internal\n"
            )
        if command == "cat /etc/ssh/sshd_config":
            return (
                "Port 22\n"
                "Protocol 2\n"
                "PermitRootLogin yes\n"
                "PasswordAuthentication yes\n"
                "PubkeyAuthentication yes\n"
                "ChallengeResponseAuthentication no\n"
                "UsePAM yes\n"
                "X11Forwarding no\n"
                "PrintMotd no\n"
                "AcceptEnv LANG LC_*\n"
                "Subsystem sftp /usr/lib/openssh/sftp-server\n"
            )
        if lowered in {
            "grep -n passwordauthentication /etc/ssh/sshd_config",
            "grep -n \"passwordauthentication\" /etc/ssh/sshd_config",
        }:
            return "4:PasswordAuthentication yes"
        if command == "cat /var/log/auth.log":
            return (
                "Feb 18 00:12:14 ip-172-31-44-9 sshd[3112]: Failed password for invalid user ubuntu from 185.220.101.9 port 55970 ssh2\n"
                "Feb 18 00:12:19 ip-172-31-44-9 sshd[3112]: Accepted password for root from 185.220.101.9 port 55970 ssh2\n"
            )
        if lowered.startswith("tail ") and "/var/log/auth.log" in lowered:
            return (
                "Feb 18 00:12:14 ip-172-31-44-9 sshd[3112]: Failed password for invalid user ubuntu from 185.220.101.9 port 55970 ssh2\n"
                "Feb 18 00:12:17 ip-172-31-44-9 sshd[3112]: Received disconnect from 185.220.101.9 port 55970:11: Bye Bye\n"
                "Feb 18 00:13:48 ip-172-31-44-9 sshd[3220]: Accepted password for root from 203.0.113.9 port 43116 ssh2\n"
                "Feb 18 00:14:01 ip-172-31-44-9 sshd[3220]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)\n"
            )
        if command == "cat notes.txt":
            lure_line = f"lure profile: {selected_lure_arm}\n" if selected_lure_arm else ""
            return (
                f"TODO: rotate {narrative_service} credentials before release\n"
                f"ticket: {narrative_ticket}\n"
                f"{lure_line}"
                "remember to disable debug endpoints in nginx\n"
            )
        if command == "cd":
            state["cwd"] = f"/home/{username}"
            return ""
        if command.startswith("cd "):
            target_raw = command.split(" ", 1)[1].strip() or f"/home/{username}"
            target = self._normalize_shell_path(raw=target_raw, cwd=cwd, username=username)
            if not self._is_known_directory(path=target, username=username):
                return f"bash: cd: {target_raw}: No such file or directory"
            state["cwd"] = target
            return ""
        if command.startswith("cat "):
            target_raw = command.split(" ", 1)[1].strip()
            target = self._normalize_shell_path(raw=target_raw, cwd=cwd, username=username)
            if target == "/etc/shadow":
                return "cat: /etc/shadow: Permission denied"
            static_file = self._static_file_content(path=target, username=username)
            if static_file is not None:
                return static_file
            if self.runtime and self.runtime.rabbit_hole and session_id and source_ip:
                response = self.runtime.rabbit_hole.respond_shell(
                    session_id=session_id,
                    source_ip=source_ip,
                    username=username,
                    command=command,
                    tenant_id=self.runtime.tenant_id,
                )
                if response:
                    return response
            return f"cat: {target_raw}: No such file or directory"
        if self.runtime and self.runtime.rabbit_hole and session_id and source_ip:
            response = self.runtime.rabbit_hole.respond_shell(
                session_id=session_id,
                source_ip=source_ip,
                username=username,
                command=command,
                tenant_id=self.runtime.tenant_id,
            )
            if response:
                return response
        return f"bash: {command}: command not found"

    def _resolve_narrative_context(
        self,
        *,
        session_id: str | None,
        source_ip: str | None,
        command: str,
    ) -> dict[str, Any]:
        if (
            not self.runtime
            or not self.runtime.rabbit_hole
            or not session_id
            or not source_ip
        ):
            return {}
        return self.runtime.rabbit_hole.resolve_narrative_context(
            session_id=session_id,
            source_ip=source_ip,
            tenant_id=self.runtime.tenant_id,
            service=self.name,
            action="command",
            hints={"command": command},
        )

    def _select_lure_arm(
        self,
        *,
        session_id: str | None,
        source_ip: str | None,
        command: str,
    ) -> str:
        if (
            not self.runtime
            or not callable(self.runtime.bandit_select)
            or not session_id
            or not source_ip
        ):
            return ""
        context_key = f"ssh:{self._command_category(command)}"
        candidates = ["ssh-baseline", "ssh-credential-bait", "ssh-lateral-bait"]
        try:
            decision = self.runtime.bandit_select(context_key=context_key, candidates=candidates)
        except Exception:
            return ""
        if not isinstance(decision, dict):
            return ""
        selected_raw = decision.get("selected_arm")
        selected_arm = str(selected_raw).strip() if selected_raw is not None else ""
        event_payload = {
            "source_ip": source_ip,
            "context_key": context_key,
            "command": command,
            "selected_arm": selected_arm,
            "candidates": candidates,
        }
        self.runtime.session_manager.record_event(
            session_id=session_id,
            service=self.name,
            action="lure_arm_selection",
            payload=event_payload,
        )
        self.runtime.event_logger.emit(
            message="ssh lure arm selection",
            service=self.name,
            action="lure_arm_selection",
            session_id=session_id,
            source_ip=source_ip,
            event_type="info",
            outcome="success" if selected_arm else "partial",
            payload=event_payload,
        )
        return selected_arm

    @staticmethod
    def _command_category(command: str) -> str:
        lowered = command.strip().lower()
        if lowered.startswith("cat "):
            return "artifact"
        if lowered.startswith(("pivot ", "ssh ", "hosts", "ip a", "ifconfig")):
            return "lateral"
        if lowered in {"show credentials", "cat creds.txt"}:
            return "credentials"
        return "generic"

    @staticmethod
    def _narrative_focus_label(narrative: dict[str, Any], *, kind: str, default: str) -> str:
        focus = narrative.get("focus", {})
        if not isinstance(focus, dict):
            return default
        item = focus.get(kind, {})
        if not isinstance(item, dict):
            return default
        label = str(item.get("label", "")).strip()
        return label or default

    def _session_shell_state(self, *, session_id: str | None, username: str) -> dict[str, Any]:
        if not session_id:
            return {"cwd": f"/home/{username}", "history": []}
        with self._shell_state_lock:
            state = self._shell_state.get(session_id)
            if state is None:
                if len(self._shell_state) >= self._MAX_SHELL_STATES:
                    self._shell_state.popitem(last=False)
                state = {"cwd": f"/home/{username}", "history": []}
                self._shell_state[session_id] = state
            else:
                self._shell_state.move_to_end(session_id)
            return state

    def _normalize_shell_path(self, *, raw: str, cwd: str, username: str) -> str:
        value = raw.strip() or f"/home/{username}"
        if value == "~":
            value = f"/home/{username}"
        if value.startswith("~/"):
            value = f"/home/{username}/{value[2:]}"
        if not value.startswith("/"):
            value = f"{cwd.rstrip('/')}/{value}"
        path = PurePosixPath(value)
        resolved: list[str] = []
        for part in path.parts:
            if part in {"", "/"}:
                continue
            if part == ".":
                continue
            if part == "..":
                if resolved:
                    resolved.pop()
                continue
            resolved.append(part)
        return "/" + "/".join(resolved)

    def _is_known_directory(self, *, path: str, username: str) -> bool:
        known_paths = {
            f"/home/{username}",
            f"/home/{username}/.backups",
            f"/home/{username}/www",
            "/var",
            "/var/www",
            "/var/www/html",
            "/var/log",
            "/var/log/nginx",
            "/etc",
            "/etc/ssh",
            "/tmp",
        }
        return path in known_paths

    def _parse_ls_command(self, *, command: str, cwd: str, username: str) -> tuple[str, bool]:
        parts = command.split()
        if len(parts) == 1:
            return (cwd, False)
        long_format = False
        target = cwd
        for item in parts[1:]:
            if item.startswith("-"):
                if "l" in item:
                    long_format = True
                continue
            target = self._normalize_shell_path(raw=item, cwd=cwd, username=username)
        return (target, long_format)

    def _render_directory_listing(self, *, path: str, username: str, long_format: bool) -> str:
        listings: dict[str, list[str]] = {
            f"/home/{username}": [".bash_history", ".backups", ".env", "notes.txt", "www"],
            f"/home/{username}/www": ["index.php", "wp-config.php", "uploads"],
            f"/home/{username}/.backups": ["db-2026-02-11.sql.gz", "db-2026-02-12.sql.gz", "db-2026-02-13.sql.gz"],
            "/var/www/html": ["index.php", "wp-admin", "wp-content", "wp-includes", ".maintenance"],
            "/etc": ["hosts", "passwd", "os-release", "ssh", "mysql", "nginx"],
            "/etc/ssh": ["sshd_config", "ssh_config", "ssh_host_rsa_key.pub"],
            "/var/log": ["auth.log", "nginx", "mysql", "syslog"],
            "/var/log/nginx": ["access.log", "error.log"],
            "/tmp": ["cache.tmp", ".X11-unix", "deploy.lock"],
            "/var/www": ["html"],
            "/var": ["log", "www", "tmp"],
        }
        entries = listings.get(path)
        if entries is None:
            return f"ls: cannot access '{path}': No such file or directory"
        if not long_format:
            return "\n".join(entries)

        rendered: list[str] = []
        timestamp = "Feb 18 00:14"
        for name in entries:
            is_dir = name in {
                ".backups",
                "www",
                "uploads",
                "wp-admin",
                "wp-content",
                "wp-includes",
                "html",
                "log",
                "tmp",
                "ssh",
                "mysql",
                "nginx",
                "docker0",
            }
            perms = "drwxr-xr-x" if is_dir else "-rw-r--r--"
            owner = "root" if path in {"/etc", "/var/log", "/var/www/html", "/var/www", "/var"} else username
            group = "root" if owner == "root" else username
            size = "4096" if is_dir else "1024"
            rendered.append(f"{perms} 1 {owner:8} {group:8} {size:>5} {timestamp} {name}")
        return "\n".join(rendered)

    def _static_file_content(self, *, path: str, username: str) -> str | None:
        static_files = {
            f"/home/{username}/.env": "DB_USER=wp_admin\nDB_PASSWORD=cp_fake_db_password\nAWS_ACCESS_KEY_ID=CP_FAKE_AWS_ACCESS_KEY",
            f"/home/{username}/notes.txt": "TODO: rotate DB credentials before release\nremember to disable debug endpoints in nginx\n",
            "/etc/hosts": (
                "127.0.0.1 localhost\n"
                "127.0.1.1 ip-172-31-44-9\n"
                "10.10.2.14 db01.internal\n"
                "10.10.2.21 cache01.internal\n"
                "10.10.3.7 ci01.internal\n"
            ),
            "/etc/os-release": (
                'NAME="Ubuntu"\n'
                'VERSION="22.04.4 LTS (Jammy Jellyfish)"\n'
                "ID=ubuntu\n"
                "ID_LIKE=debian\n"
                'PRETTY_NAME="Ubuntu 22.04.4 LTS"\n'
            ),
            "/etc/ssh/sshd_config": (
                "Port 22\n"
                "Protocol 2\n"
                "PermitRootLogin yes\n"
                "PasswordAuthentication yes\n"
                "PubkeyAuthentication yes\n"
                "ChallengeResponseAuthentication no\n"
                "UsePAM yes\n"
            ),
            "/var/log/auth.log": (
                "Feb 18 00:12:14 ip-172-31-44-9 sshd[3112]: Failed password for invalid user ubuntu from 185.220.101.9 port 55970 ssh2\n"
                "Feb 18 00:12:19 ip-172-31-44-9 sshd[3112]: Accepted password for root from 185.220.101.9 port 55970 ssh2\n"
            ),
        }
        return static_files.get(path)
