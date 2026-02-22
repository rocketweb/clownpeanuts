"""Realistic operator-mistake artifact library."""

from __future__ import annotations

from typing import Any


class OopsArtifactLibrary:
    def artifacts_for_role(self, role: str, *, seed: str) -> dict[str, str]:
        seed3 = (seed * 3)[:96]
        if role == "web":
            return {
                "/home/ubuntu/.bash_history": (
                    "aws s3 cp /tmp/customer-export.csv s3://acme-prod-backups/customer-export.csv\n"
                    "vim /var/www/.env\n"
                    "ssh postgres@db01\n"
                ),
                "/var/www/.env": f"APP_KEY=base64:{seed3[:16]}\nDB_PASSWORD={seed3[0:10]}\n",
                "/var/www/html/.env.bak": f"MAIL_PASSWORD={seed3[16:28]}\nS3_SECRET={seed3[28:40]}\n",
                "/tmp/deploy-debug.log": (
                    "2026-02-01T04:11:22Z INFO loaded env from /var/www/.env\n"
                    "2026-02-01T04:11:23Z WARN fallback credential used for db bootstrap\n"
                ),
                "/opt/scripts/db-smoke.sh": "psql -h db01 -U app_user app -c 'select 1;'\n",
                "/home/www-data/.aws/credentials": (
                    "[default]\naws_access_key_id=CP_FAKE_AWS_WEB_KEY\naws_secret_access_key=CP_FAKE_AWS_WEB_SECRET\n"
                ),
            }
        if role == "database":
            return {
                "/home/postgres/.psql_history": "SELECT * FROM users LIMIT 20;\n\\i /tmp/debug.sql\n",
                "/tmp/debug.sql": "copy (select * from payment_methods) to '/tmp/payment_methods.csv' csv header;\n",
                "/var/lib/postgresql/.pg_service.conf": f"[analytics]\nhost=db01\nuser=analytics\npassword={seed3[40:52]}\n",
                "/root/.my.cnf": f"[client]\nuser=root\npassword={seed3[52:64]}\n",
                "/etc/mysql/conf.d/backup.cnf": (
                    f"[clientbackup]\nuser=backup\npassword={seed3[64:74]}\nhost=backup01\n"
                ),
                "/var/backups/last-failed.txt": "rsync to backup01 failed: Permission denied (publickey,password)\n",
            }
        if role == "cache":
            return {
                "/var/tmp/cache-notes.txt": "rotate redis password every 90d (still TODO)\n",
                "/etc/redis/redis.conf.bak": "requirepass stagingpass\nrename-command FLUSHALL \"\"\n",
                "/home/ops/.config/cache-admin.yml": f"token: {seed3[74:90]}\n",
                "/tmp/cache_warmup.py": "print('warming cache from db snapshots')\n",
                "/etc/memcached/sasl2/memcached.conf": "mech_list: plain\npwcheck_method: auxprop\n",
                "/var/log/redis/redis-server.log.1": "Possible SECURITY ATTACK detected. benign in staging.\n",
            }
        if role == "api":
            return {
                "/srv/api/config/debug.json": '{"trace": true, "db": "db01", "cache": "cache01"}\n',
                "/srv/api/.env.local": f"STRIPE_KEY=CP_FAKE_STRIPE_TEST_{seed3[20:28]}\nSENTRY_DSN=https://{seed3[36:44]}@sentry.local/2\n",
                "/home/deploy/.npmrc": "//registry.npmjs.org/:_authToken=CP_FAKE_NPM_TOKEN\n",
                "/tmp/request-dump.txt": "Authorization: Bearer eyJhbGciOi...\n",
            }
        if role == "worker":
            return {
                "/opt/worker/.env": f"RABBITMQ_PASS={seed3[44:56]}\nWORKER_POOL=12\n",
                "/home/queue/.bash_history": "redis-cli -h cache01 keys '*'\ncat /opt/worker/.env\n",
                "/tmp/replay-jobs.sh": "python manage.py replay_failed --limit 5000\n",
                "/var/log/worker/failures.log": "2026-02-15 payment.sync timeout after 60s\n",
            }
        if role == "backup":
            return {
                "/etc/backup/targets.yml": "targets:\n  - db01\n  - api01\n  - ci01\n",
                "/root/.s3cfg": f"access_key=CP_FAKE_AWS_BACKUP_KEY\nsecret_key=CP_FAKE_AWS_BACKUP_SECRET_{seed3[56:64]}\n",
                "/var/backups/rotation.txt": "retain_daily=14\nretain_weekly=8\nretain_monthly=6\n",
                "/home/backup/.ssh/id_rsa.pub": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCfake backup@backup01\n",
            }
        if role == "bastion":
            return {
                "/home/ops/.ssh/config": "Host *\n  ServerAliveInterval 30\n  StrictHostKeyChecking no\n",
                "/home/secops/todo.txt": "remove temp sudo from ci_runner (forgot after incident drill)\n",
                "/etc/sudoers.d/ops": "ops ALL=(ALL) NOPASSWD:/usr/bin/systemctl restart api\n",
                "/var/log/auth.log.1": "Accepted password for ops from 10.0.2.44 port 52911 ssh2\n",
            }
        if role == "ci":
            return {
                "/var/lib/jenkins/credentials.xml": "<credentials><secret>fake-secret</secret></credentials>\n",
                "/var/lib/jenkins/secrets/master.key": seed3[72:88],
                "/home/git/.git-credentials": f"https://ci-bot:{seed3[12:24]}@git.internal\n",
                "/opt/runner/config.toml": "concurrent = 8\ncheck_interval = 0\n",
            }
        return {}

    def merge_into_host_files(self, *, files: dict[str, str], role: str, seed: str) -> dict[str, str]:
        merged = dict(files)
        merged.update(self.artifacts_for_role(role, seed=seed))
        return merged

    def render_listing(self, *, files: dict[str, str]) -> str:
        entries = sorted(path.split("/")[-1] for path in files if path.count("/") >= 1)
        return "\n".join(entries[:12]) if entries else "notes.txt\n.tmp\n"

    def snapshot(self, *, role: str, seed: str) -> dict[str, Any]:
        artifacts = self.artifacts_for_role(role, seed=seed)
        return {"role": role, "count": len(artifacts), "paths": sorted(artifacts.keys())}
