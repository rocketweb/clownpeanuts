"""Session world model and context state."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
import hashlib
import random
from typing import Any


@dataclass(slots=True)
class HostContext:
    hostname: str
    role: str
    ip: str
    users: list[str]
    files: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class SessionWorld:
    session_id: str
    source_ip: str
    tenant_id: str
    seed: str
    current_host: str
    hosts: dict[str, HostContext]
    discovered_credentials: list[dict[str, str]] = field(default_factory=list)
    pivots: list[dict[str, str]] = field(default_factory=list)
    hydrated: bool = False


class WorldModel:
    def __init__(self, *, seed: str = "clownpeanuts", max_worlds: int = 10_000) -> None:
        self.seed = seed
        self._max_worlds = max(1, int(max_worlds))
        self._worlds: OrderedDict[str, SessionWorld] = OrderedDict()

    def get_or_create(self, *, session_id: str, source_ip: str, tenant_id: str = "default") -> SessionWorld:
        world = self._worlds.get(session_id)
        if world is not None:
            self._worlds.move_to_end(session_id)
            return world
        if len(self._worlds) >= self._max_worlds:
            self._worlds.popitem(last=False)
        world = self._build_world(session_id=session_id, source_ip=source_ip, tenant_id=tenant_id)
        self._worlds[session_id] = world
        return world

    def all_worlds(self) -> list[SessionWorld]:
        return list(self._worlds.values())

    def set_current_host(self, *, session_id: str, source_ip: str, host: str, tenant_id: str = "default") -> str:
        world = self.get_or_create(session_id=session_id, source_ip=source_ip, tenant_id=tenant_id)
        if host in world.hosts:
            world.current_host = host
        return world.current_host

    def current_host(self, *, session_id: str, source_ip: str, tenant_id: str = "default") -> HostContext:
        world = self.get_or_create(session_id=session_id, source_ip=source_ip, tenant_id=tenant_id)
        return world.hosts[world.current_host]

    def get_file(
        self,
        *,
        session_id: str,
        source_ip: str,
        path: str,
        tenant_id: str = "default",
    ) -> str | None:
        host = self.current_host(session_id=session_id, source_ip=source_ip, tenant_id=tenant_id)
        return host.files.get(path)

    def update_file(
        self,
        *,
        session_id: str,
        source_ip: str,
        path: str,
        contents: str,
        tenant_id: str = "default",
    ) -> None:
        host = self.current_host(session_id=session_id, source_ip=source_ip, tenant_id=tenant_id)
        host.files[path] = contents

    def _build_world(self, *, session_id: str, source_ip: str, tenant_id: str) -> SessionWorld:
        derived = hashlib.sha1(f"{self.seed}:{tenant_id}:{session_id}".encode("utf-8"), usedforsecurity=False).hexdigest()
        rng = random.Random(int(derived[:8], 16))
        suffix = derived[:6]

        hosts = {
            "web01": HostContext(
                hostname=f"web01-{suffix}",
                role="web",
                ip=f"10.40.{rng.randint(1, 30)}.{rng.randint(10, 240)}",
                users=["ubuntu", "www-data", "deploy"],
                files={},
            ),
            "db01": HostContext(
                hostname=f"db01-{suffix}",
                role="database",
                ip=f"10.41.{rng.randint(1, 30)}.{rng.randint(10, 240)}",
                users=["postgres", "mysql", "backup"],
                files={},
            ),
            "cache01": HostContext(
                hostname=f"cache01-{suffix}",
                role="cache",
                ip=f"10.42.{rng.randint(1, 30)}.{rng.randint(10, 240)}",
                users=["redis", "memcache", "ops"],
                files={},
            ),
            "api01": HostContext(
                hostname=f"api01-{suffix}",
                role="api",
                ip=f"10.43.{rng.randint(1, 30)}.{rng.randint(10, 240)}",
                users=["svc-api", "deploy", "ubuntu"],
                files={},
            ),
            "worker01": HostContext(
                hostname=f"worker01-{suffix}",
                role="worker",
                ip=f"10.44.{rng.randint(1, 30)}.{rng.randint(10, 240)}",
                users=["queue", "svc-worker", "ubuntu"],
                files={},
            ),
            "backup01": HostContext(
                hostname=f"backup01-{suffix}",
                role="backup",
                ip=f"10.45.{rng.randint(1, 30)}.{rng.randint(10, 240)}",
                users=["backup", "root", "ops"],
                files={},
            ),
            "bastion01": HostContext(
                hostname=f"bastion01-{suffix}",
                role="bastion",
                ip=f"10.46.{rng.randint(1, 30)}.{rng.randint(10, 240)}",
                users=["ops", "secops", "ubuntu"],
                files={},
            ),
            "ci01": HostContext(
                hostname=f"ci01-{suffix}",
                role="ci",
                ip=f"10.47.{rng.randint(1, 30)}.{rng.randint(10, 240)}",
                users=["jenkins", "runner", "git"],
                files={},
            ),
        }
        hosts_lines = "\n".join(f"{host.ip} {host.hostname}" for host in hosts.values())
        hosts["web01"].files = {
            "/home/ubuntu/.bash_history": "sudo su\ncat /var/www/.env\npsql -h db01 -U app_user app\n",
            "/var/www/.env": f"DB_HOST={hosts['db01'].hostname}\nDB_USER=app_user\nDB_PASS={derived[0:10]}\n",
            "/etc/hosts": f"127.0.0.1 localhost\n{hosts_lines}\n",
        }
        hosts["db01"].files = {
            "/var/lib/postgresql/backups/README": "nightly dumps sync to s3://acme-prod-backups/",
            "/home/postgres/.pgpass": f"{hosts['db01'].hostname}:5432:app:app_user:{derived[0:10]}\n",
            "/etc/hosts": f"127.0.0.1 localhost\n{hosts_lines}\n",
        }
        hosts["cache01"].files = {
            "/etc/memcached.conf": "-m 2048\n-p 11211\n-U 0\n-l 0.0.0.0\n",
            "/etc/redis/redis.conf": "protected-mode no\nbind 0.0.0.0\nrequirepass stagingpass\n",
        }
        hosts["api01"].files = {
            "/srv/api/.env": f"JWT_SECRET={derived[26:40]}\nREDIS_HOST={hosts['cache01'].hostname}\n",
            "/etc/hosts": f"127.0.0.1 localhost\n{hosts_lines}\n",
        }
        hosts["worker01"].files = {
            "/opt/worker/.env": f"QUEUE_URL=redis://{hosts['cache01'].hostname}:6379/0\n",
            "/home/queue/.bash_history": "cat /opt/worker/.env\npython replay_jobs.py --tenant default\n",
        }
        hosts["backup01"].files = {
            "/etc/backup/targets.txt": f"{hosts['db01'].hostname}\n{hosts['api01'].hostname}\n",
            "/var/backups/README": "full backups every 6h, encrypted with ops key",
        }
        hosts["bastion01"].files = {
            "/home/ops/.ssh/config": (
                f"Host db\n  HostName {hosts['db01'].hostname}\n  User ops\n"
                f"Host backup\n  HostName {hosts['backup01'].hostname}\n  User backup\n"
            ),
        }
        hosts["ci01"].files = {
            "/var/lib/jenkins/secrets/master.key": derived[40:56],
            "/etc/hosts": f"127.0.0.1 localhost\n{hosts_lines}\n",
        }

        return SessionWorld(
            session_id=session_id,
            source_ip=source_ip,
            tenant_id=tenant_id,
            seed=derived,
            current_host="web01",
            hosts=hosts,
        )

    def snapshot(self) -> list[dict[str, Any]]:
        payload: list[dict[str, Any]] = []
        for world in self._worlds.values():
            payload.append(
                {
                    "session_id": world.session_id,
                    "source_ip": world.source_ip,
                    "tenant_id": world.tenant_id,
                    "current_host": world.current_host,
                    "credential_count": len(world.discovered_credentials),
                    "pivot_count": len(world.pivots),
                    "hosts": [
                        {
                            "name": key,
                            "hostname": value.hostname,
                            "role": value.role,
                            "ip": value.ip,
                            "users": value.users,
                        }
                        for key, value in world.hosts.items()
                    ],
                }
            )
        return payload
