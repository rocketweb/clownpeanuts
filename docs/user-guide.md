# ClownPeanuts User Guide

Last updated: **February 21, 2026** (optional enhancement-lane continuation: Redis `LINSERT` realism, Theater multi-session triage filters, Theater syslog interoperability, and stricter production token-hardening/performance updates)

This is the complete operator guide for deploying and running ClownPeanuts. It covers everything from initial setup through ongoing operations, with detailed explanations of every configuration option, CLI command, and operational workflow.

If you're looking for a quick overview of the project, start with the [README](../README.md). If you want to understand how the internals fit together, read the [Architecture](architecture.md) doc. This guide is for the person who's actually going to run the thing.

---

## 1. Before You Start

ClownPeanuts is a **defensive deception platform**. It intentionally presents convincing weak points -- services that look misconfigured, credentials that look leaked, data that looks valuable -- to attract adversary activity and capture their behavior in detail.

A few things to keep in mind before deploying:

- **Defensive use only.** ClownPeanuts does not deliver exploits, send offensive payloads, or reach out to external systems. It sits, waits, and records.
- **Isolation is non-negotiable.** Your honeypot infrastructure must be on a network segment that has no path to your production environment. ClownPeanuts validates network isolation at startup, but you're responsible for the underlying architecture.
- **Insecure behavior is by design.** Services that accept weak passwords, files with leaked credentials, admin panels with poor authentication -- these are deliberate trap mechanics. Don't "fix" them unless you specifically intend to change the deception posture.
- **Operational surfaces need their own protection.** The API server and dashboard are meant for your team, not for attackers. Firewall them to operator IPs. The bait services are the things you expose to the internet.

---

## 2. Choosing a Deployment Mode

ClownPeanuts supports several deployment configurations depending on what you're doing. Pick the one that fits your situation:

| Mode | When to Use It | What Runs | How to Start |
| --- | --- | --- | --- |
| **Local CLI** | Protocol development, testing, quick smoke checks | Core runtime in a single shell process | `clownpeanuts up --config ...` |
| **Local API + Dashboard** | Operator workflow development, UI/API testing, demo environments | API server + optionally emulators + dashboard in separate processes | `clownpeanuts api ... --start-services` + `npm run dev` |
| **Shared Control Plane (SquirrelOps)** | Cross-product operator workflows (ClownPeanuts + PingTing + orchestration actions) | SquirrelOps control-plane dashboard/API + ClownPeanuts API backend | In `squirrelops`: `./scripts/controlplane/start_dev.sh` (with ClownPeanuts API running) |
| **Docker Compose `core`** | Containerized core runtime without the operations UI | Core emulator container + Redis | `docker compose --profile core up --build` |
| **Docker Compose `ops`** | Full operator stack, closest to production deployment | API (with emulators) + dashboard + Redis, all containerized | `docker compose --profile ops up --build` |

**If you just want to get the whole thing running with one command**, use the Docker Compose `ops` profile. It brings up everything in containers with sensible defaults.

**If you're developing or debugging**, the local CLI mode gives you the fastest feedback loop -- no containers, no build steps, just Python running in your terminal.

---

## 3. Prerequisites

### Required (All Deployment Modes)

- **Git** -- to clone the repository
- **Python 3.12 or later** -- ClownPeanuts uses modern Python features (slots dataclasses, `X | Y` union types) that require 3.12+
- **pip** -- for installing the Python package and its dependencies

### Required for Docker Compose Modes

- **Docker** -- container runtime
- **Docker Compose v2** -- the `docker compose` command (not the older `docker-compose` binary)

### Required for Dashboard Development

- **Node.js** -- the dashboard is a Next.js application
- **npm** -- for installing frontend dependencies

### Port Planning

ClownPeanuts binds to several ports. Make sure nothing else is using them, or adjust the configuration before starting.

**Bait service ports** (these are what attackers connect to):

| Service | Default Port | Notes |
| --- | --- | --- |
| SSH emulator | 2222 | Configurable in the service config |
| HTTP admin emulator | 8080 | Configurable in the service config |
| Redis emulator | 6380 | Configurable; uses a non-standard port to avoid conflicting with a real Redis instance |
| MySQL emulator | 13306 | Configurable; non-standard port to avoid conflicts |
| PostgreSQL emulator | 15432 | Configurable |
| MongoDB emulator | 27018 | Disabled by default |
| Memcached emulator | 11212 | Disabled by default |

**Operations ports** (these are for your team):

| Service | Default Port | Notes |
| --- | --- | --- |
| API server | 8099 | FastAPI backend |
| Dashboard | 3000 | Next.js frontend (dev mode) |
| Redis (infrastructure) | 6379 | Used by session/event backends in Docker Compose; this is ClownPeanuts's own Redis, separate from the Redis emulator |

---

## 4. Initial Setup

### 4.1 Clone and Install

```bash
git clone git@github.com:rocketweb/clownpeanuts.git
cd clownpeanuts
python3 -m venv .venv
source .venv/bin/activate

# Full install (core + API + dev tools)
pip install -e .[dev,api]
```

If you only need the core CLI and don't plan to run the API server:

```bash
pip install -e .[dev]
```

### 4.2 Create a Configuration File

You have two options:

**Option A: Generate a starter config.** This creates a new YAML file with all sections populated with sensible defaults and comments:

```bash
clownpeanuts init --config ./config/clownpeanuts.yml
```

**Option B: Use the bundled defaults directly.** The file at `clownpeanuts/config/defaults.yml` contains the same defaults the system uses internally. You can point commands at it directly or copy it as a starting point:

```bash
cp clownpeanuts/config/defaults.yml ./config/clownpeanuts.yml
```

**Option C: Start from the hardened production baseline.** The file at `config/production-hardened.yml` enables stricter operator/API posture controls by default (API token auth on, docs off, trusted host/CORS pinning, Redis AUTH URLs, Redis backends required):

```bash
cp config/production-hardened.yml ./config/clownpeanuts.yml
```

**Option D: Start from the reverse-proxy hardened profile.** The file at `config/production-reverse-proxy.yml` is tuned for loopback API exposure behind an authenticated reverse proxy or mTLS boundary (auth on, docs off, strict host/origin allowlists, Redis AUTH URLs):

```bash
cp config/production-reverse-proxy.yml ./config/clownpeanuts.yml
```

Either way, you'll end up with a YAML file that you can edit to match your deployment.

---

## 5. Configuration Reference

This section covers every configuration block in detail. The configuration file is YAML, and every value supports environment variable interpolation using `${VAR}` (required -- fails if unset) or `${VAR:-default}` (falls back to the default value if unset).

### 5.1 Top-Level Structure

```yaml
environment: development       # Freeform label (development, staging, production, etc.)
network: { ... }
session: { ... }
event_bus: { ... }
api: { ... }
logging: { ... }
engine: { ... }
narrative: { ... }
bandit: { ... }
theater: { ... }
alerts: { ... }
threat_intel: { ... }
multi_tenant: { ... }
templates: { ... }
red_team: { ... }
services: [ ... ]
```

### 5.2 Network Isolation (`network`)

This block controls how ClownPeanuts validates and enforces network isolation between the honeypot and your real infrastructure. Getting this right is critical -- the whole point of a honeypot is that it's disconnected from production.

```yaml
network:
  segmentation_mode: vxlan
  require_segmentation: true
  enforce_runtime: true
  verify_host_firewall: false
  verify_docker_network: false
  required_docker_network: clownpeanuts
  apply_firewall_rules: false
  firewall_dry_run: true
  allow_outbound: false
  allowed_egress:
    - redis
```

| Field | Type | Default | What It Does |
| --- | --- | --- | --- |
| `segmentation_mode` | string | `vxlan` | The network segmentation technology you're using. Valid values: `vxlan`, `wireguard`, `none`. This tells ClownPeanuts what kind of isolation to expect and validate. Use `none` during local development when you don't have segmentation set up. |
| `require_segmentation` | bool | `true` | If `true`, ClownPeanuts will refuse to start if segmentation validation fails. Set to `false` during development or if you're managing isolation outside of ClownPeanuts. |
| `enforce_runtime` | bool | `true` | If `true`, isolation policy is enforced (violations block startup). If `false`, violations produce warnings but don't prevent startup. |
| `verify_host_firewall` | bool | `false` | Check for the presence of a host-level firewall (`iptables`, `nft`, or `pfctl`) at startup. Useful in production to verify that the host has firewall rules in place. |
| `verify_docker_network` | bool | `false` | Check that a specific Docker network exists at startup. Useful when you're running in Docker and want to verify the network topology. |
| `required_docker_network` | string | `clownpeanuts` | The name of the Docker network to check for when `verify_docker_network` is `true`. |
| `apply_firewall_rules` | bool | `false` | Actually apply egress control rules using the host's firewall backend. **Be careful with this** -- it modifies your host's firewall configuration. Always test with `firewall_dry_run: true` first. |
| `firewall_dry_run` | bool | `true` | When `apply_firewall_rules` is `true`, this flag controls whether rules are actually applied (`false`) or just previewed (`true`). Leave this on until you've reviewed the rule preview and are confident. |
| `allow_outbound` | bool | `false` | Whether honeypot services are allowed to make outbound connections. Should almost always be `false` -- you don't want attackers using your honeypot as a relay. |
| `allowed_egress` | list | `[redis]` | Exceptions to the outbound block. The special value `redis` allows connections to the configured Redis instance. You can also specify IP ranges (CIDR notation) or hostnames for other exceptions. |

**Recommended rollout for firewall rules:**

1. Start with `apply_firewall_rules: true` and `firewall_dry_run: true`.
2. Run `clownpeanuts doctor` and `clownpeanuts up --once` to see the rule preview.
3. Review the rules to make sure they match your expectations.
4. Set `firewall_dry_run: false` only after you're satisfied.

### 5.3 Session Backend (`session`)

Controls how attacker session state is stored and correlated.

```yaml
session:
  backend: redis
  redis_url: redis://:change-me@redis:6379/0
  key_prefix: clownpeanuts
  ttl_seconds: 86400
  connect_timeout_seconds: 1.0
  max_events_per_session: 2000
  required: false
```

| Field | Type | Default | What It Does |
| --- | --- | --- | --- |
| `backend` | string | `memory` | Where session state is stored. `memory` keeps everything in-process (fast, but lost on restart). `redis` persists sessions in Redis (survives restarts, required for multi-process setups). |
| `redis_url` | string | `redis://:${CP_REDIS_PASSWORD:-clownpeanuts-dev-redis}@redis:6379/0` | The Redis connection URL. Default config now requires a password and reads it from `CP_REDIS_PASSWORD` (falls back to a local-dev value). For production-style deployments, override with a strong secret and keep Redis network-isolated. The hostname `redis` works in Docker Compose (it resolves to the Redis container). For local development without Compose, change this to `redis://:password@127.0.0.1:6379/0`. |
| `key_prefix` | string | `clownpeanuts` | Prefix for all Redis keys. Useful if you're sharing a Redis instance with other applications. |
| `ttl_seconds` | int | `86400` | How long session data is retained in Redis (in seconds). Default is 24 hours. Increase this if you want to correlate attacker activity over longer periods. |
| `connect_timeout_seconds` | float | `1.0` | How long to wait when connecting to Redis before giving up. |
| `max_events_per_session` | int | `2000` | Cap on retained event payloads per session (memory and Redis). Total per-session event counters still track full activity, but replay payloads keep the most recent `N` events for predictable memory/storage use at high volume. |
| `required` | bool | `false` | If `true`, ClownPeanuts will refuse to start if Redis is unreachable. If `false` (default), it falls back to in-memory sessions when Redis isn't available. This is convenient for local development where you might not have Redis running. |

**When to use which backend:**

- Use `memory` for quick local testing. Sessions are fast but ephemeral.
- Use `redis` for anything resembling a real deployment. You need Redis if you want sessions to survive process restarts, or if you're running the API server and emulators in separate processes (they need shared state).

### 5.4 Event Bus (`event_bus`)

The event bus distributes real-time events (new connections, commands, alerts) to downstream consumers like the dashboard's WebSocket stream and the alert routing system.

```yaml
event_bus:
  backend: redis
  redis_url: redis://:change-me@redis:6379/1
  channel_prefix: clownpeanuts
  connect_timeout_seconds: 1.0
  required: false
```

| Field | Type | Default | What It Does |
| --- | --- | --- | --- |
| `backend` | string | `memory` | `memory` for in-process event distribution, `redis` for cross-process pub/sub. |
| `redis_url` | string | `redis://:${CP_REDIS_PASSWORD:-clownpeanuts-dev-redis}@redis:6379/1` | Redis URL for the event bus. Default config now requires a password and reads it from `CP_REDIS_PASSWORD`. For production-style deployments, use a strong secret (`redis://:strong-password@redis:6379/1` or `rediss://...`). Note this uses database `1` by default (separate from session state on database `0`). |
| `channel_prefix` | string | `clownpeanuts` | Prefix for Redis pub/sub channels. |
| `connect_timeout_seconds` | float | `1.0` | Redis connection timeout. |
| `required` | bool | `false` | Same behavior as the session backend -- if `false`, falls back to in-memory when Redis is unavailable. |

If you're running the API server separately from the emulators (not using `--start-services`), both processes need to use the `redis` backend so events from the emulators reach the API's WebSocket stream.

### 5.4A API Hardening (`api`)

Controls operator-surface hardening for the FastAPI backend.

```yaml
api:
  docs_enabled: false
  cors_allow_origins:
    - "http://127.0.0.1:3000"
    - "http://localhost:3000"
    - "http://127.0.0.1:3001"
    - "http://localhost:3001"
  cors_allow_credentials: false
  intel_report_cache_ttl_seconds: 1.5
  trusted_hosts: ["*"]
  auth_enabled: false
  auth_operator_tokens:
    - "${CP_API_OPERATOR_TOKEN:-}"
  auth_viewer_tokens:
    - "${CP_API_VIEWER_TOKEN:-}"
  allow_unauthenticated_health: true
  rate_limit_enabled: false
  rate_limit_requests_per_minute: 240
  rate_limit_burst: 60
  rate_limit_exempt_paths:
    - "/health"
  max_request_body_bytes: 262144
```

| Field | Type | Default | What It Does |
| --- | --- | --- | --- |
| `docs_enabled` | bool | `false` | Enables `/docs`, `/redoc`, and `/openapi.json`. Defaults to `false` so schema/doc surfaces are not exposed unless explicitly enabled. |
| `cors_allow_origins` | list | `["http://127.0.0.1:3000", "http://localhost:3000", "http://127.0.0.1:3001", "http://localhost:3001"]` | Allowed browser origins for API access. Use explicit origins (for example `https://soc.example`) for production-style deployments. |
| `cors_allow_credentials` | bool | `false` | Whether browser credentials are allowed on CORS requests. Cannot be `true` when origins include `*`. |
| `intel_report_cache_ttl_seconds` | float | `1.5` | Shared cache TTL (seconds) for live `/intel/*` report-derived endpoints. Use `0` to disable caching; increase slightly for high-polling multi-operator deployments. |
| `trusted_hosts` | list | `["*"]` | Allowed HTTP host headers. Restrict this to known operator hostnames/domains to block host-header abuse (`["api.soc.example"]`, `["*.soc.example"]`, etc.). |
| `auth_enabled` | bool | `false` | Enables API token authentication for HTTP and websocket endpoints. |
| `auth_operator_tokens` | list | `[]` | Operator tokens. Required for mutating requests (`POST`, `PUT`, `PATCH`, `DELETE`) when auth is enabled; production `doctor` checks also require at least one non-empty entry when `api.auth_enabled=true`, require token length `>=24`, reject placeholder values like `replace-with-*`, and enforce separation from `auth_viewer_tokens` values. |
| `auth_viewer_tokens` | list | `[]` | Viewer tokens. Allowed for read-only HTTP/websocket access when auth is enabled; production `doctor` checks require non-placeholder values and minimum length `>=24` when viewer tokens are configured. |
| `allow_unauthenticated_health` | bool | `true` | Keeps `/health` open without a token. Set `false` to require auth on health checks too; production `doctor` hardening checks require this to be `false`. |
| `rate_limit_enabled` | bool | `false` | Enables built-in API + websocket client rate limiting. Returns HTTP `429` with `Retry-After` when exceeded and rejects new websocket connections with rate-limit close codes. |
| `rate_limit_requests_per_minute` | int | `240` | Sustained refill rate per client identity (IP or `X-Forwarded-For` first-hop value). Production hardening diagnostics require this to remain `<= 5000`. |
| `rate_limit_burst` | int | `60` | Extra burst bucket capacity on top of the sustained per-minute rate. In production posture checks, keep this at or below `rate_limit_requests_per_minute`. |
| `rate_limit_exempt_paths` | list | `["/health"]` | Paths excluded from API/websocket rate limiting. Use this sparingly (health/liveness endpoints only in most deployments). Wildcard entries are rejected and the list is capped at 16 entries. |
| `max_request_body_bytes` | int | `262144` | Maximum allowed HTTP request body size for mutating API methods (`POST`, `PUT`, `PATCH`, `DELETE`). Requests above the limit return HTTP `413`. |

When API auth is enabled, set `NEXT_PUBLIC_CLOWNPEANUTS_API_TOKEN` in the dashboard environment so browser fetch/websocket requests include the token automatically.
The CLI also refuses non-loopback API binds (for example `--host 0.0.0.0`) unless `api.auth_enabled` is set to `true`.

### 5.5 Logging (`logging`)

```yaml
logging:
  level: INFO
  format: ecs_json
  sink: stdout
  service_name: clownpeanuts
  siem:
    enabled: false
    transport: http
    endpoint: ""
    timeout_seconds: 2.0
    headers: {}
    batch_size: 50
    flush_interval_seconds: 1.0
    max_retries: 3
    retry_backoff_seconds: 0.5
    max_queue_size: 5000
    dead_letter_path: logs/siem-dead-letter.ndjson
```

| Field | Type | Default | What It Does |
| --- | --- | --- | --- |
| `level` | string | `INFO` | Minimum log level. Valid: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. Use `DEBUG` during development to see every event. Use `INFO` or `WARNING` in production to reduce noise. |
| `format` | string | `ecs_json` | Log output format. `ecs_json` produces Elastic Common Schema-compatible JSON (good for SIEM ingestion). `json` produces simpler JSON. |
| `sink` | string | `stdout` | Where logs go. `stdout` writes to the console (Docker captures this). `file` writes to the path specified in `file_path`. |
| `file_path` | string | null | Path for file-based logging when `sink` is `file`. |
| `service_name` | string | `clownpeanuts` | The `service.name` field in ECS JSON logs. Useful for filtering in a SIEM that ingests logs from multiple services. |

**SIEM Shipping** (`logging.siem`):

The SIEM subsection controls real-time log shipping to an external SIEM platform (Elastic, Splunk, etc.).

| Field | Type | Default | What It Does |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Master switch for SIEM shipping. |
| `transport` | string | `http` | Delivery transport. `http` sends JSON over HTTP POST. `udp` sends over UDP (for syslog-style ingestion). |
| `endpoint` | string | `""` | The URL or address to ship logs to. |
| `timeout_seconds` | float | `2.0` | HTTP timeout for each delivery attempt. |
| `headers` | dict | `{}` | Extra HTTP headers (e.g., authentication tokens). |
| `batch_size` | int | `50` | Number of log entries to batch into each delivery. |
| `flush_interval_seconds` | float | `1.0` | How often to flush the log buffer, even if the batch isn't full. |
| `max_retries` | int | `3` | Number of retry attempts for failed deliveries. |
| `retry_backoff_seconds` | float | `0.5` | Wait time between retries (multiplied by attempt number). |
| `max_queue_size` | int | `5000` | Maximum number of log entries to buffer in memory. If the queue fills up (because the SIEM endpoint is unreachable), new entries are dropped. |
| `dead_letter_path` | string | `logs/siem-dead-letter.ndjson` | File path where undeliverable log entries are written for later recovery. |

### 5.6 Engine (`engine`)

The Rabbit Hole Engine generates contextual responses for attacker interactions. It maintains a per-session world model and produces output that's consistent with what the attacker has already seen.

```yaml
engine:
  enabled: true
  backend: rule-based
  model: rule-based
  template_fast_path: true
  context_seed: clownpeanuts
  local_llm:
    enabled: false
    provider: lmstudio
    endpoint: http://masoc:1234/v1/chat/completions
    model: llama3.2:3b
    api_key: ""
    timeout_seconds: 1.2
    max_response_chars: 700
    temperature: 0.2
    failure_threshold: 3
    cooldown_seconds: 15.0
```

| Field | Type | Default | What It Does |
| --- | --- | --- | --- |
| `enabled` | bool | `true` | Master switch for the engine. If disabled, services use static responses only. |
| `backend` | string | `rule-based` | Response generation strategy. `rule-based` uses template matching and procedural generation (no external dependencies, very fast). `local-llm` uses a locally hosted language model for dynamic responses. |
| `template_fast_path` | bool | `true` | When `true`, common commands (`ls`, `cat`, `pwd`, etc.) are handled by fast template matching instead of going through the full engine pipeline. This keeps interactive latency low. |
| `context_seed` | string | `clownpeanuts` | Seed value for procedural world generation. Changing this produces a different set of fake hostnames, users, and file contents. |

**Local LLM Configuration** (`engine.local_llm`):

| Field | Type | Default | What It Does |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Whether to use the LLM backend. Auto-set to `true` when `backend` is `local-llm`. |
| `provider` | string | `lmstudio` | Which LLM hosting platform you're using. `lmstudio` expects an OpenAI-compatible chat completions endpoint. `ollama` expects the Ollama generate endpoint. |
| `endpoint` | string | varies | The HTTP endpoint for the LLM API. Defaults to `http://masoc:1234/v1/chat/completions` for LM Studio or `http://127.0.0.1:11434/api/generate` for Ollama. |
| `model` | string | `llama3.2:3b` | The model name to request from the LLM provider. |
| `api_key` | string | `""` | API key for the LLM endpoint (if required). LM Studio and Ollama typically don't need one for local use. |
| `timeout_seconds` | float | `1.2` | Maximum time to wait for an LLM response. Honeypot interactions need to feel responsive -- if the LLM is too slow, the deception becomes unconvincing. Keep this low. |
| `max_response_chars` | int | `700` | Truncate LLM responses beyond this length. Prevents the model from generating unrealistically verbose output. |
| `temperature` | float | `0.2` | Controls randomness in LLM output. Low values (0.1-0.3) produce more consistent, predictable responses. Higher values make output more varied but potentially less coherent. For deception purposes, consistency matters more than creativity. |
| `failure_threshold` | int | `3` | Number of consecutive LLM failures (timeouts, errors) before the engine enters cooldown and falls back to rule-based responses. |
| `cooldown_seconds` | float | `15.0` | How long to wait after hitting the failure threshold before trying the LLM again. During cooldown, all responses use the rule-based fallback. |

### 5.7 Narrative (`narrative`)

The narrative engine keeps attacker-visible context coherent across services. The same session should see matching users, hosts, projects, and datasets in SSH, HTTP, and database interactions.

```yaml
narrative:
  enabled: false
  world_seed: clownpeanuts
  entity_count: 120
  per_tenant_worlds: true
```

| Field | Type | Default | What It Does |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Master switch for the narrative engine. |
| `world_seed` | string | `clownpeanuts` | Seed used to generate deterministic narrative worlds. Same seed + tenant yields stable output. |
| `entity_count` | int | `120` | Number of generated entities in the world graph. Higher values increase variety and memory pressure. |
| `per_tenant_worlds` | bool | `true` | Whether each tenant receives a distinct narrative world namespace. |

Related APIs:

- `GET /engine/narrative/world`
- `GET /engine/narrative/session/{session_id}`

### 5.8 Adaptive Lure Bandit (`bandit`)

Bandit policy selects lure variants per context and tracks reward outcomes for continuous optimization.

```yaml
bandit:
  enabled: false
  algorithm: thompson
  exploration_floor: 0.1
  reward_weights:
    dwell_time: 1.0
    cross_protocol_pivot: 1.2
    technique_novelty: 1.3
    alert_quality: 0.8
    analyst_feedback: 1.0
  safety_caps:
    max_arm_exposure_percent: 0.7
    cooldown_seconds: 30.0
    denylist: []
```

| Field | Type | Default | What It Does |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Master switch for live bandit selection. |
| `algorithm` | string | `thompson` | Selection strategy. Valid: `thompson`, `ucb`. |
| `exploration_floor` | float | `0.1` | Minimum exploration rate (`0.0` to `1.0`). |
| `reward_weights.*` | float | varies | Relative weight for each reward signal dimension. |
| `safety_caps.max_arm_exposure_percent` | float | `0.7` | Exposure ceiling for any single arm (`>0` and `<=1`). |
| `safety_caps.cooldown_seconds` | float | `30.0` | Cooldown window before an arm can be re-applied in the same selection context. |
| `safety_caps.denylist` | list[str] | `[]` | Explicitly blocked arms. |

Related CLI and APIs:

- `clownpeanuts simulate-bandit --config ...`
- `GET /intel/bandit/arms`
- `GET /intel/bandit/performance`
- `GET /intel/bandit/observability`
- `POST /intel/bandit/override`
- `POST /intel/bandit/reset`

### 5.9 Adversary Theater (`theater`)

Theater is the operator control plane for live adversary sessions and recommendations.

```yaml
theater:
  enabled: false
  rollout_mode: observe-only
  max_live_sessions: 75
  recommendation_cooldown_seconds: 8.0
```

| Field | Type | Default | What It Does |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Master switch for theater aggregation and action endpoints. |
| `rollout_mode` | string | `observe-only` | Valid: `observe-only`, `recommend-only`, `apply-enabled`. |
| `max_live_sessions` | int | `75` | Max active sessions included in theater live payloads. |
| `recommendation_cooldown_seconds` | float | `8.0` | Cooldown for repeat recommendation emission. |

Rollout mode behavior:

- `observe-only`: telemetry only.
- `recommend-only`: recommendations shown, action endpoints can still audit labels but live lure apply should be operationally withheld.
- `apply-enabled`: one-click apply-lure workflows enabled for operators.

Related APIs and stream:

- `GET /theater/live`
- `GET /theater/sessions/{session_id}`
- `GET /theater/recommendations` (supports filtering/sizing params: `min_confidence`, `min_prediction_confidence`, `predicted_stage`, `lure_arm`, `context_key_prefix`, `apply_allowed_only`, `include_explanation`, `compact`, `sort_by`, `sort_order`)
- `GET /theater/actions` (short-TTL cached by full filter/sort query shape; supports `session_id`, `session_ids`, `actor`, `actor_prefix`, `session_prefix`, `query`, `recommendation_id`, `created_after`, `created_before`, `action_types`, `compact`, `sort_by`, `sort_order` for high-frequency triage polling)
- `GET /theater/actions/export` (`json|csv|tsv|ndjson|jsonl|logfmt|cef|leef|syslog` action history adapters for automation/reporting, with the same filter/sort/query surface as `/theater/actions`)
- `POST /theater/actions/apply-lure`
- `POST /theater/actions/label`
- WebSocket: `/ws/theater/live`

Related dashboard routes:

- `/theater` -- live Theater queue, explainability, action controls, session replay analyzer, and bookmark triage filter.
- `/theater/replay/{session_id}` -- full replay drilldown with replay + Theater session context, filtered event timeline, and quick apply/label actions.

### 5.10 Alerts (`alerts`)

The alert system evaluates events from the event bus and dispatches notifications to configured destinations.

```yaml
alerts:
  enabled: false
  min_severity: medium
  throttle_seconds: 60
  destinations: [ ... ]
```

| Field | Type | Default | What It Does |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Master switch for the entire alert system. Nothing fires unless this is `true`. |
| `min_severity` | string | `medium` | Global minimum severity filter. Events below this severity level are dropped before destination evaluation. Valid: `low`, `medium`, `high`, `critical`. |
| `throttle_seconds` | int | `60` | Minimum time (in seconds) between alerts from the same source/event combination. Prevents alert storms during active scanning. |

**Alert Destinations** (`alerts.destinations`):

Each destination is an independent delivery target with its own filters.

```yaml
destinations:
  - name: slack-soc              # Human-readable name (used in logs and route previews)
    type: slack                  # Destination type (see below)
    enabled: true                # Per-destination on/off switch
    endpoint: https://hooks.slack.com/services/...  # Delivery endpoint
    token: ""                    # Auth token (for PagerDuty, etc.)
    channel: ""                  # Channel override (for Slack/Discord)
    min_severity: high           # Per-destination severity floor
    include_services: [ssh]      # Only alerts from these services (empty = all)
    include_actions: []          # Only alerts for these action types (empty = all)
    exclude_actions: [scan]      # Suppress alerts for these action types
    metadata:                    # Extra key-value pairs passed to the adapter
      source: clownpeanuts
```

**Supported destination types:**

| Type | Endpoint Format | Required Fields |
| --- | --- | --- |
| `webhook` | Any HTTP(S) URL | `endpoint` |
| `slack` | Slack incoming webhook URL | `endpoint` |
| `discord` | Discord webhook URL | `endpoint` |
| `pagerduty` | PagerDuty Events API v2 URL | `endpoint`, `token` (routing key) |
| `email` | SMTP URL (e.g., `smtp://localhost:25`) | `endpoint`, `metadata.from`, `metadata.to` |
| `syslog` | Syslog address | `endpoint` |

**How routing works**: When an event occurs, the alert router evaluates each enabled destination in order. For each destination, it checks:

1. Is the event severity >= the destination's `min_severity` (or the global `min_severity` if the destination doesn't set one)?
2. If `include_services` is non-empty, is the event's service in the list?
3. If `include_actions` is non-empty, is the event's action in the list?
4. If `exclude_actions` is non-empty, is the event's action *not* in the list?
5. Has enough time passed since the last alert from this source (throttle check)?

If all checks pass, the alert is dispatched to that destination.

### 5.11 Threat Intelligence Rotation (`threat_intel`)

ClownPeanuts can rotate its bait content based on external threat intelligence feeds. This means the fake credentials, file names, and service configurations evolve to match what attackers are currently scanning for.

```yaml
threat_intel:
  enabled: false
  strategy: balanced
  seasonal_month_override: null
  rotation_interval_seconds: 3600
  feed_urls: []
```

| Field | Type | Default | What It Does |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Master switch for threat intel integration. |
| `strategy` | string | `balanced` | Rotation strategy. `balanced` mixes current trends with evergreen bait. `aggressive` heavily weights current scanning trends. `conservative` changes slowly and prioritizes stability. `seasonal` adjusts based on time-of-year attack patterns. |
| `seasonal_month_override` | int/null | `null` | Force a specific month (1-12) for the seasonal strategy. Useful for testing December-themed bait in July. |
| `rotation_interval_seconds` | int | `3600` | How often the background scheduler evaluates whether to rotate bait content. Default is one hour. |
| `feed_urls` | list | `[]` | HTTPS threat-intel URLs used during rotation. Non-HTTPS URLs, local file paths, and URLs resolving to private/link-local/loopback addresses are rejected. |

### 5.12 Multi-Tenant Configuration (`multi_tenant`)

Multi-tenancy lets you run separate deception configurations for different environments, clients, or network segments from a single ClownPeanuts instance.

```yaml
multi_tenant:
  enabled: false
  default_tenant: default
  tenants:
    - id: default
      display_name: Default Tenant
      enabled: true
      tags: [production]
      service_overrides: {}
```

| Field | Type | Default | What It Does |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Master switch for multi-tenancy. |
| `default_tenant` | string | `default` | The tenant used when no `--tenant` flag is provided to CLI commands. |
| `tenants[].id` | string | required | Unique identifier for this tenant. |
| `tenants[].display_name` | string | same as `id` | Human-readable name shown in the dashboard and reports. |
| `tenants[].enabled` | bool | `true` | Whether this tenant is active. |
| `tenants[].tags` | list | `[]` | Freeform tags for filtering and organization. |
| `tenants[].service_overrides` | dict | `{}` | Per-service configuration overrides for this tenant. Keys are service names, values are config dicts that merge with (and override) the base service config. |

Example with overrides:

```yaml
tenants:
  - id: dmz
    display_name: DMZ Honeypot
    tags: [external, dmz]
    service_overrides:
      ssh:
        auth_failures_before_success: 3   # Harder to brute-force in the DMZ
      http-admin:
        tarpit_enabled: false             # No tarpit for this tenant
```

### 5.13 Deception Templates (`templates`)

Templates let you define reusable deception configurations as code -- version-controlled playbooks that describe what bait to present and how services should behave.

```yaml
templates:
  enabled: false
  paths: []
```

| Field | Type | Default | What It Does |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Master switch for the template system. |
| `paths` | list | `[]` | File paths to template definition files. Templates are loaded, validated, and merged with the base configuration. |

### 5.14 Red Team Mode (`red_team`)

When your internal red team is running exercises against the honeypot, you probably don't want their activity generating alerts that go to your SOC. Red team mode lets you suppress alerts for traffic from known internal CIDR ranges.

```yaml
red_team:
  enabled: false
  label: red_team
  suppress_external_alerts: true
  internal_cidrs:
    - 10.0.0.0/8
    - 192.168.0.0/16
```

| Field | Type | Default | What It Does |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Master switch for red team detection. |
| `label` | string | `red_team` | Label applied to sessions that match internal CIDRs. Shows up in intelligence reports and the dashboard. |
| `suppress_external_alerts` | bool | `false` | If `true`, alerts are suppressed for sessions originating from `internal_cidrs`. The activity is still logged and appears in intelligence reports -- it just doesn't page anyone. |
| `internal_cidrs` | list | `[]` | CIDR ranges that identify red team traffic. Any source IP matching these ranges gets the red team label. |

### 5.15 Service Definitions (`services`)

Each service emulator is defined as an entry in the `services` list. Services that are disabled are loaded but not started.

```yaml
services:
  - name: ssh
    module: clownpeanuts.services.ssh.emulator
    enabled: true
    listen_host: 0.0.0.0
    ports: [2222]
    config:
      banner: "SSH-2.0-OpenSSH_8.4p1 Debian-5"
      hostname: "ip-172-31-44-9"
      auth_failures_before_success: 1
      adaptive_tarpit_enabled: true
      tarpit_min_delay_ms: 20
      tarpit_max_delay_ms: 180
      tarpit_ramp_events: 10
```

**Common fields** (all services):

| Field | Type | What It Does |
| --- | --- | --- |
| `name` | string | Unique service identifier. Used in logs, alerts, and CLI output. |
| `module` | string | Python module path for the emulator class. Must be in the built-in allowlist, or explicitly allowed via `CLOWNPEANUTS_EXTRA_ALLOWED_MODULES`. |
| `enabled` | bool | Whether to start this service. |
| `listen_host` | string | Bind address. `0.0.0.0` listens on all interfaces. |
| `ports` | list[int] | Port numbers to bind. |
| `config` | dict | Service-specific configuration (varies by emulator). |

**SSH emulator config:**

| Field | Default | What It Does |
| --- | --- | --- |
| `banner` | `SSH-2.0-OpenSSH_8.4p1 Debian-5` | The SSH version string presented to connecting clients. Change this to match the OS you're impersonating. |
| `hostname` | `ip-172-31-44-9` | The hostname shown in the fake shell prompt. An AWS-style hostname makes the honeypot look like a cloud instance. |
| `auth_failures_before_success` | `1` | How many failed login attempts before the next attempt succeeds. Set to `1` to let brute-force tools think they cracked the password quickly. Higher values make it feel more realistic but reduce engagement rate. |
| `max_concurrent_connections` | `256` | Hard cap on concurrent live client connections for this service. New sockets above the cap are dropped to prevent thread-exhaustion attacks. |
| `adaptive_tarpit_enabled` | `true` | Gradually increase response latency as the session progresses. |
| `tarpit_min_delay_ms` | `20` | Starting delay in milliseconds (barely noticeable). |
| `tarpit_max_delay_ms` | `180` | Maximum delay the tarpit ramps up to. |
| `tarpit_ramp_events` | `10` | Number of events over which the delay ramps from min to max. |

**HTTP admin emulator config:**

| Field | Default | What It Does |
| --- | --- | --- |
| `tarpit_enabled` | `true` | Enable tarpit behavior on HTTP responses. |
| `max_concurrent_connections` | `256` | Hard cap on concurrent live client connections for this service. New sockets above the cap are dropped to prevent thread-exhaustion attacks. |
| `backup_stream_chunks` | `40` | Number of chunks in the slow-drip backup download (`/backup.sql.gz`). |
| `backup_chunk_size_bytes` | `512` | Size of each chunk in the backup download. |
| `slowdrip_min_delay_ms` | `80` | Minimum delay between backup download chunks. |
| `slowdrip_max_delay_ms` | `250` | Maximum delay between chunks. |
| `slowdrip_jitter_ratio` | `0.0` | Random variation added to chunk delays (0.0 = none, 1.0 = +/-100%). |
| `infinite_exfil_enabled` | `true` | Enable the infinite exfiltration endpoint. |
| `infinite_exfil_path` | `/backup/live.sql.gz` | URL path for the infinite download stream. |
| `infinite_exfil_chunk_size_bytes` | `768` | Size of each chunk in the infinite stream. |
| `infinite_exfil_max_chunks` | `0` | Maximum chunks before ending the stream. `0` means truly infinite. |
| `auth_failures_before_success` | `1` | Login attempts before success (same concept as SSH). |
| `auth_delay_pattern_ms` | `[120, 450, 900]` | Delays applied to successive login attempts, in milliseconds. Each failed login feels progressively slower. |
| `auth_delay_jitter_ratio` | `0.15` | Random variation on auth delays. |
| `query_tarpit_enabled` | `true` | Enable the query tarpit endpoint (`/api/internal/search`). |
| `query_tarpit_min_delay_ms` | `120` | Starting delay for query tarpit pagination. |
| `query_tarpit_max_delay_ms` | `700` | Maximum delay for query tarpit pages. |
| `query_tarpit_jitter_ratio` | `0.2` | Random variation on query delays. |
| `query_tarpit_max_page_size` | `50` | Results per page in tarpit pagination. |
| `query_tarpit_estimated_total` | `4200` | Total result count shown in pagination headers (fake). |

**Database emulator config** (Redis, MySQL, PostgreSQL, MongoDB, Memcached):

| Field | Default | What It Does |
| --- | --- | --- |
| `server_version` | varies | Version string returned to connecting clients. |
| `max_concurrent_connections` | `256` | Hard cap on concurrent live client connections for each emulator instance. New sockets above the cap are dropped. |
| `adaptive_tarpit_enabled` | `true` | Gradually increase response latency. |
| `tarpit_min_delay_ms` | varies | Starting delay. |
| `tarpit_max_delay_ms` | varies | Maximum delay. |
| `tarpit_ramp_events` | varies | Events over which delay ramps up. |

### 5.16 Redis Behavior in Local vs. Docker Compose

The default configuration assumes Redis is available at `redis://:${CP_REDIS_PASSWORD:-clownpeanuts-dev-redis}@redis:6379/...` -- the hostname `redis` resolves automatically in Docker Compose because it's the name of the Redis service container.

For production, do not run Redis without authentication. Use credentialed `redis://:password@...` (or `rediss://...`) URLs and network-isolate Redis so only ClownPeanuts components can reach it.

When running locally without Docker Compose:

- If Redis is unreachable and `required: false` (the default for both session and event_bus), ClownPeanuts falls back to in-memory backends automatically. You'll see a warning in the logs but everything works.
- If you want Redis-backed state locally, either start a local Redis instance and change the URLs to `redis://:password@127.0.0.1:6379/...`, or add a hosts file entry mapping `redis` to `127.0.0.1`.

---

## 6. First-Time Validation

Before running ClownPeanuts continuously, verify that everything is set up correctly. Run these steps in order.

### 6.1 Run the Test Suite

```bash
.venv/bin/pytest
```

This runs unit and integration tests against the codebase. All tests should pass. If they don't, something is wrong with your Python environment or dependencies.

### 6.2 Run Diagnostic Checks

```bash
.venv/bin/clownpeanuts doctor --config ./config/clownpeanuts.yml
```

The `doctor` command validates your configuration, checks network isolation settings, and reports any issues. It doesn't start any services -- it just checks that everything *would* work.

To also probe a configured local LLM endpoint:

```bash
.venv/bin/clownpeanuts doctor --config ./config/clownpeanuts.yml --check-llm
```

### 6.3 Smoke Test the Runtime

```bash
.venv/bin/clownpeanuts up --once --config ./config/clownpeanuts.yml
```

The `--once` flag starts all enabled services, prints the orchestrator status as JSON, and then shuts everything down cleanly. This confirms that services can bind their ports, the engine initializes, and there are no configuration errors that only surface at runtime.

If that smoke test fails with `Address already in use` on your workstation, rerun smoke on the demo-safe config (alternate bait ports):

```bash
.venv/bin/clownpeanuts up --once --config ./config/local-theater-demo.yml
```

---

## 7. Running ClownPeanuts

### 7.1 CLI Mode (Continuous)

```bash
.venv/bin/clownpeanuts up --config ./config/clownpeanuts.yml
```

What happens when you run this:

1. The configuration file is loaded and validated.
2. Network isolation checks run (depending on your `network` settings).
3. All enabled service emulators start and bind their ports.
4. The orchestrator prints a status summary.
5. ClownPeanuts runs until you press `Ctrl+C`.
6. On interrupt, the orchestrator stops all services cleanly.

For multi-tenant mode, specify which tenant's configuration to use:

```bash
.venv/bin/clownpeanuts up --config ./config/clownpeanuts.yml --tenant dmz
```

### 7.2 API + Dashboard (Local)

**Start the API server:**

If you want the API server without in-process emulators (you're running emulators separately or via Docker):

```bash
.venv/bin/clownpeanuts api --config ./config/clownpeanuts.yml --host 127.0.0.1 --port 8099
```

If you want the API server *and* emulators in the same process (simpler for development):

```bash
.venv/bin/clownpeanuts api --config ./config/clownpeanuts.yml --host 127.0.0.1 --port 8099 --start-services
```

**Start the dashboard** (in a separate terminal):

```bash
cd dashboard
npm install
npm run dev
```

The dashboard connects to:
- API: `http://127.0.0.1:8099` (override with `NEXT_PUBLIC_CLOWNPEANUTS_API`)
- WebSocket events: `ws://127.0.0.1:8099/ws/events` (override with `NEXT_PUBLIC_CLOWNPEANUTS_WS`)
- Theater live stream: `ws://127.0.0.1:8099/ws/theater/live` (requested by the Theater page via the configured API base URL)
- Optional API token: set `NEXT_PUBLIC_CLOWNPEANUTS_API_TOKEN` when `api.auth_enabled: true`

Primary dashboard routes after startup:
- `http://127.0.0.1:3000/` -- main operations dashboard
- `http://127.0.0.1:3000/theater` -- Theater live queue and action console
- `http://127.0.0.1:3000/theater/replay/<session-id>` -- session drilldown (open from Theater "drilldown" links or direct URL)

Current dashboard layout behavior to expect:

- High-contrast Swiss-style visual language with strong typographic hierarchy.
- Responsive breakpoints that collapse complex multi-column panels as viewport narrows.
- Desktop max-width containment to prevent very-wide screens from introducing visual drift.
- Invisible alignment grid strategy (layout structure is grid-based, but no visible grid overlay is rendered).

**Shared control-plane alternative (SquirrelOps):**

If you are operating multiple runtime repos (for example ClownPeanuts + PingTing), run the shared control-plane from the SquirrelOps repository instead of this local dashboard:

```bash
# from the squirrelops repository root
./scripts/controlplane/start_dev.sh
```

In that topology, ClownPeanuts remains the deception runtime/API source, and SquirrelOps provides the aggregated operator UI/API tabs (Overview, Deception, Sentry, Orchestration).

**Quick validation:**

```bash
curl -s http://127.0.0.1:8099/health    # Should return {"status":"ok"}
curl -s http://127.0.0.1:8099/status    # Orchestrator status
curl -s http://127.0.0.1:8099/intel/report  # Intelligence snapshot
curl -s http://127.0.0.1:8099/theater/live  # Theater aggregation payload
curl -s http://127.0.0.1:8099/sessions  # Recent sessions list
curl -s http://127.0.0.1:8099/intel/bandit/performance  # Bandit performance metrics
```

If API auth is enabled, add `-H "Authorization: Bearer <token>"` to non-health requests.

Then open `http://127.0.0.1:3000` in your browser.

### 7.3 Docker Compose

**Full stack** (API with emulators + dashboard + Redis):

```bash
docker compose --profile ops up --build
```

The `ops` profile enables API auth and Redis AUTH by default. Set `CP_API_OPERATOR_TOKEN` and `CP_REDIS_PASSWORD` before startup if you want custom secrets:

```bash
CP_API_OPERATOR_TOKEN="replace-with-long-random-token" \
CP_REDIS_PASSWORD="replace-with-strong-redis-password" \
docker compose --profile ops up --build
```

**Core only** (emulators + Redis, no dashboard):

```bash
docker compose --profile core up --build
```

**Run detached and manage the lifecycle:**

```bash
docker compose --profile ops up -d --build     # Start in background
docker compose --profile ops ps                # Check container status
docker compose --profile ops logs -f api       # Follow API logs
docker compose --profile ops logs -f dashboard  # Follow dashboard logs
docker compose --profile ops down              # Stop everything
```

**Resource limit overrides:**

The Docker Compose file includes default memory and CPU limits for each container. Override them with environment variables:

```bash
CP_CORE_MEM_LIMIT=1536m \
CP_CORE_CPUS=1.5 \
CP_API_MEM_LIMIT=1024m \
CP_DASHBOARD_MEM_LIMIT=768m \
docker compose --profile ops up --build
```

### 7.4 One-Command Demo Harness

If you want a repeatable local test environment with Theater features pre-enabled and immediate seed data, use the included demo scripts:

```bash
./scripts/dev-up-demo.sh
```

What this script does:

1. Generates `config/local-theater-demo.yml` from defaults.
2. Enables `narrative`, `bandit`, and `theater` (`apply-enabled` rollout mode).
3. Uses local-safe settings (`network.segmentation_mode: none`, in-memory session/event backends).
4. Starts API on `127.0.0.1:8109` and dashboard on `127.0.0.1:3001`.
5. Seeds HTTP traffic so Theater/replay views have immediate sessions.
6. Writes PID/log/state files under `/tmp/clownpeanuts-demo`.

Stop the demo stack:

```bash
./scripts/dev-down-demo.sh
```

Optional environment overrides:

- `DEMO_API_HOST`, `DEMO_API_PORT`
- `DEMO_DASH_HOST`, `DEMO_DASH_PORT`
- `DEMO_SSH_PORT`, `DEMO_HTTP_PORT`
- `DEMO_STATE_DIR`
- `DEMO_CONFIG_PATH`

---

## 8. Day-2 Operations

This section covers the workflows you'll use once ClownPeanuts is running.

### 8.1 Startup Checklist (Every Deploy/Restart)

Every time you deploy or restart ClownPeanuts, walk through these steps:

1. **Validate configuration and isolation:**
   ```bash
   .venv/bin/clownpeanuts doctor --config ./config/clownpeanuts.yml
   ```

2. **Validate template overlays** (if you're using templates):
   ```bash
   .venv/bin/clownpeanuts templates-validate --config ./config/clownpeanuts.yml
   ```

3. **Start the runtime** (CLI, API, or Compose -- whichever mode you're using).

4. **Verify API health** (if the API is running):
   ```bash
   curl -s http://127.0.0.1:8099/health
   curl -s http://127.0.0.1:8099/status
   ```

5. **Check the dashboard** -- open it in a browser and confirm stream status:
   - Main dashboard badge should show `EVENT STREAM LIVE` (or reconnect countdown if transiently disconnected).
   - Theater badge should show `THEATER STREAM LIVE`.
   - Freshness pills should show recent snapshot/event ages (not stale).

### 8.2 Health Monitoring

Commands you should run regularly to make sure things are healthy:

```bash
# Configuration and runtime state
.venv/bin/clownpeanuts status --config ./config/clownpeanuts.yml

# Full diagnostic check
.venv/bin/clownpeanuts doctor --config ./config/clownpeanuts.yml

# API health (if API is running)
curl -s http://127.0.0.1:8099/health
curl -s http://127.0.0.1:8099/doctor
```

### 8.3 Intelligence Extraction

The intelligence pipeline transforms raw session data into structured threat reports. Here's the typical workflow:

**Generate a current intelligence snapshot:**

```bash
.venv/bin/clownpeanuts intel --config ./config/clownpeanuts.yml
```

This builds a report from current session data, maps observed behavior to ATT&CK techniques, scores engagement levels, and outputs a structured summary.

**Review ATT&CK coverage:**

```bash
.venv/bin/clownpeanuts intel-coverage --config ./config/clownpeanuts.yml
```

This shows which ATT&CK techniques your honeypot is currently detecting and where the coverage gaps are. Use this to decide which emulators or deception patterns to add next.

**Browse historical reports:**

```bash
.venv/bin/clownpeanuts intel-history --config ./config/clownpeanuts.yml --limit 20
```

**Generate SOC handoff markdown for shift-change/reporting:**

```bash
.venv/bin/clownpeanuts intel-handoff --config ./config/clownpeanuts.yml --format markdown --output ./exports/soc-handoff.md
```

**Generate SOC handoff CSV for SIEM/SOC spreadsheet ingestion:**

```bash
.venv/bin/clownpeanuts intel-handoff --config ./config/clownpeanuts.yml --format csv --output ./exports/soc-handoff.csv
```

**Generate SOC handoff TSV for tab-delimited spreadsheet/SIEM ingestion:**

```bash
.venv/bin/clownpeanuts intel-handoff --config ./config/clownpeanuts.yml --format tsv --output ./exports/soc-handoff.tsv
```

**Generate SOC handoff NDJSON for streaming/SIEM pipelines:**

```bash
.venv/bin/clownpeanuts intel-handoff --config ./config/clownpeanuts.yml --format ndjson --output ./exports/soc-handoff.ndjson
```

**Generate SOC handoff JSONL for tools that expect `.jsonl` naming:**

```bash
.venv/bin/clownpeanuts intel-handoff --config ./config/clownpeanuts.yml --format jsonl --output ./exports/soc-handoff.jsonl
```

**Generate SOC handoff CEF for ArcSight/CEF-compatible SIEM pipelines:**

```bash
.venv/bin/clownpeanuts intel-handoff --config ./config/clownpeanuts.yml --format cef --output ./exports/soc-handoff.cef
```

**Generate SOC handoff LEEF for QRadar/LEEF-compatible SIEM pipelines:**

```bash
.venv/bin/clownpeanuts intel-handoff --config ./config/clownpeanuts.yml --format leef --output ./exports/soc-handoff.leef
```

**Generate SOC handoff syslog lines for RFC 5424-compatible log ingestion:**

```bash
.venv/bin/clownpeanuts intel-handoff --config ./config/clownpeanuts.yml --format syslog --output ./exports/soc-handoff.syslog
```

**Generate SOC handoff logfmt key/value lines for log-pipeline ingestion:**

```bash
.venv/bin/clownpeanuts intel-handoff --config ./config/clownpeanuts.yml --format logfmt --output ./exports/soc-handoff.logfmt
```

**Compare two session replays:**

```bash
.venv/bin/clownpeanuts replay-compare \
  --config ./config/clownpeanuts.yml \
  --left-session-id <session-a> \
  --right-session-id <session-b> \
  --events-limit 500 \
  --bootstrap
```

**Export for downstream platforms:**

```bash
# STIX 2.1 bundle
.venv/bin/clownpeanuts stix-export --config ./config/clownpeanuts.yml --output ./exports/stix-latest.json

# TAXII manifest
.venv/bin/clownpeanuts taxii-export --config ./config/clownpeanuts.yml --manifest --output ./exports/taxii-manifest.json

# ATT&CK Navigator layer
.venv/bin/clownpeanuts navigator-export --config ./config/clownpeanuts.yml --output ./exports/attack-navigator.json
```

### 8.4 Bandit Policy Simulation and Tuning

Use the simulator before changing live policy behavior:

```bash
.venv/bin/clownpeanuts simulate-bandit \
  --config ./config/clownpeanuts.yml \
  --window-hours 24 \
  --history-limit 200 \
  --candidate-algorithm ucb
```

Inspect live performance and drift:

```bash
curl -s http://127.0.0.1:8099/intel/bandit/performance
curl -s http://127.0.0.1:8099/intel/bandit/observability
```

Apply temporary override during active investigation:

```bash
curl -s -X POST http://127.0.0.1:8099/intel/bandit/override \
  -H 'content-type: application/json' \
  -d '{"context_key":"ssh:generic","arm":"ssh-credential-bait","duration_seconds":300}'
```

Reset policy state if a test cycle contaminated production metrics:

```bash
curl -s -X POST http://127.0.0.1:8099/intel/bandit/reset \
  -H 'content-type: application/json' \
  -d '{"reason":"post-exercise cleanup"}'
```

### 8.5 Alert Operations

**Preview how alerts would route** for a given event:

```bash
.venv/bin/clownpeanuts alerts-routes --config ./config/clownpeanuts.yml --severity high --service ssh --action command
```

This shows you which destinations would fire (and which would be filtered out, and why) without actually sending anything. Very useful for debugging routing rules.

**Send a test alert** through all configured destinations:

```bash
.venv/bin/clownpeanuts alerts-test --config ./config/clownpeanuts.yml --severity high --title "route_test" --summary "synthetic delivery check"
```

If this returns a non-zero exit code, check that `alerts.enabled` is `true` and at least one destination has `enabled: true` with valid endpoint configuration.

### 8.6 Canary Token Operations

**List available canary types:**

```bash
.venv/bin/clownpeanuts canary-types
```

**Generate a new canary token:**

```bash
.venv/bin/clownpeanuts canary-generate --config ./config/clownpeanuts.yml --namespace cp --token-type http
```

The `--namespace` groups related tokens together. The `--token-type` determines the format (dns, http, email, aws, code).

**Record a canary hit** (for testing or external webhook integration):

```bash
.venv/bin/clownpeanuts canary-hit --config ./config/clownpeanuts.yml --token "<token>" --source-ip "203.0.113.10"
```

**Review token inventory and hit history:**

```bash
.venv/bin/clownpeanuts canary-tokens --config ./config/clownpeanuts.yml   # List all tokens
.venv/bin/clownpeanuts canary-hits --config ./config/clownpeanuts.yml     # List all hits
```

### 8.7 Threat Intel Rotation

**Preview what the next rotation would select:**

```bash
.venv/bin/clownpeanuts rotate-preview --config ./config/clownpeanuts.yml
```

**Trigger an immediate rotation:**

```bash
.venv/bin/clownpeanuts rotate --config ./config/clownpeanuts.yml
```

The background scheduler handles automatic rotation at the interval configured in `threat_intel.rotation_interval_seconds`. Use the manual `rotate` command when you want to force a refresh (e.g., after updating feed URLs or changing the rotation strategy).

### 8.8 Theater Triage and Operator Actions

Theater is where analysts move from passive observation to active deception control. It combines kill-chain timeline, narrative context, recommendation ranking, replay visibility, and action controls.

#### API-first workflow (scriptable/SOC automation)

Use these endpoints to fetch the live queue and recommendation set:

```bash
curl -s "http://127.0.0.1:8099/theater/live?limit=50&events_per_session=200"
curl -s "http://127.0.0.1:8099/theater/recommendations?limit=20&session_limit=100"
curl -s "http://127.0.0.1:8099/theater/recommendations?limit=20&session_limit=100&min_confidence=0.7&predicted_stage=credential_access&apply_allowed_only=true&include_explanation=false"
curl -s "http://127.0.0.1:8099/theater/recommendations?limit=20&session_limit=100&min_prediction_confidence=0.75"
curl -s "http://127.0.0.1:8099/theater/recommendations?limit=20&session_limit=100&lure_arm=ssh-credential-bait&context_key_prefix=ssh:"
curl -s "http://127.0.0.1:8099/theater/recommendations?limit=20&session_limit=100&compact=true&sort_by=session_id&sort_order=asc"
curl -s "http://127.0.0.1:8099/theater/actions?limit=100&actor=soc-analyst-1&session_ids=<session-a>,<session-b>&recommendation_id=<recommendation-id>&created_after=2026-02-21T00:00:00Z&created_before=2026-02-21T23:59:59Z&action_types=apply_lure,label&compact=true&sort_by=created_at&sort_order=desc"
```

Apply a lure recommendation and attach operator attribution:

```bash
curl -s -X POST http://127.0.0.1:8099/theater/actions/apply-lure \
  -H 'content-type: application/json' \
  -d '{"session_id":"<session-id>","lure_arm":"ssh-credential-bait","context_key":"ssh:discovery","duration_seconds":180,"actor":"soc-analyst-1"}'
```

Label a session for downstream triage pipelines:

```bash
curl -s -X POST http://127.0.0.1:8099/theater/actions/label \
  -H 'content-type: application/json' \
  -d '{"session_id":"<session-id>","label":"high_value_actor","confidence":0.9,"actor":"soc-analyst-1"}'
```

Export action history from CLI for post-incident review:

```bash
.venv/bin/clownpeanuts theater-history --config ./config/clownpeanuts.yml --limit 200 --output ./exports/theater-actions.json
.venv/bin/clownpeanuts theater-history --config ./config/clownpeanuts.yml --limit 200 --format csv --output ./exports/theater-actions.csv
.venv/bin/clownpeanuts theater-history --config ./config/clownpeanuts.yml --limit 200 --format tsv --output ./exports/theater-actions.tsv
.venv/bin/clownpeanuts theater-history --config ./config/clownpeanuts.yml --limit 200 --format ndjson --output ./exports/theater-actions.ndjson
.venv/bin/clownpeanuts theater-history --config ./config/clownpeanuts.yml --limit 200 --format jsonl --output ./exports/theater-actions.jsonl
.venv/bin/clownpeanuts theater-history --config ./config/clownpeanuts.yml --limit 200 --format logfmt --output ./exports/theater-actions.logfmt
.venv/bin/clownpeanuts theater-history --config ./config/clownpeanuts.yml --limit 200 --format cef --output ./exports/theater-actions.cef
.venv/bin/clownpeanuts theater-history --config ./config/clownpeanuts.yml --limit 200 --format leef --output ./exports/theater-actions.leef
.venv/bin/clownpeanuts theater-history --config ./config/clownpeanuts.yml --limit 200 --format syslog --output ./exports/theater-actions.syslog
.venv/bin/clownpeanuts theater-history --config ./config/clownpeanuts.yml --limit 200 --session-ids <session-a>,<session-b> --output ./exports/theater-actions-selected.json
```

#### Dashboard workflow (interactive analyst mode)

Open `http://127.0.0.1:3000/theater` and use this sequence:

1. Watch stream health first:
   - `THEATER STREAM LIVE` means socket is healthy.
   - `THEATER RECONNECT n (Xs)` means transient reconnect backoff is in progress.
   - Freshness pills show how old live payload and action snapshots are.
2. Work the recommendation queue:
   - Use `inspect` to focus the selected session.
   - Use `drilldown` to open full replay workflow on `/theater/replay/<session-id>`.
   - Use `apply` and `label` for direct actioning when rollout mode allows.
3. Use bookmarks to keep analyst focus:
   - `bookmark` any queue row or selected session.
   - Switch `Bookmark Filter` to `bookmarked only` to run high-priority triage sweeps.
4. Review replay analyzer in-place:
   - Classification, engagement score, coherence score, and recent replay events are shown directly in Theater.
   - Use `refresh replay` to force a fresh session replay snapshot.

### 8.9 Session Replay and Triage

**List recent sessions** (via the API):

```bash
curl -s "http://127.0.0.1:8099/sessions?limit=50&events_per_session=20"
```

**Replay a specific session** via API to review full event sequence and scoring:

```bash
curl -s "http://127.0.0.1:8099/sessions/<session-id>/replay?events_limit=500"
```

The replay payload includes:
- `classification` (attacker profile label/confidence)
- `engagement_score` (numeric score + severity band)
- `coherence_score` and `coherence_violations` (narrative consistency checks)
- derived ATT&CK `techniques` and summarized `canaries`

**Replay from CLI** (useful for terminal-driven triage and export pipelines):

```bash
.venv/bin/clownpeanuts replay --config ./config/clownpeanuts.yml --session-id "<session-id>" --events-limit 500 --bootstrap
```

The `--bootstrap` flag includes the session's initial connection metadata. The `--events-limit` controls how many events to include (useful for very long sessions).

**Replay from dashboard** (recommended for deep operator investigation):

1. Start at `/theater`.
2. Select a session and click `drilldown` or `open full replay`.
3. Work in `/theater/replay/<session-id>`:
   - Compare replay events against Theater timeline and kill-chain path.
   - Filter events by service and text search to reduce noise.
   - Run quick actions (`apply recommended lure`, `label high value`, `label false positive`) without leaving replay view.
4. Return to `/theater` for queue-level flow control.

### 8.10 Template and Tenant Management

**View the current effective template plan:**

```bash
.venv/bin/clownpeanuts templates --config ./config/clownpeanuts.yml
```

**Validate templates across all tenants:**

```bash
.venv/bin/clownpeanuts templates-validate --config ./config/clownpeanuts.yml --all-tenants
```

**Compare plans between tenants:**

```bash
.venv/bin/clownpeanuts templates-diff --config ./config/clownpeanuts.yml --left-tenant default --right-tenant dmz
```

---

## 9. Hardening and Isolation

ClownPeanuts includes intentional bait behavior at the service level -- that's the point. But you still need to isolate the deployment itself from your production infrastructure, and you need to protect the operational surfaces (API, dashboard) from unauthorized access.

### 9.1 Network Isolation Rollout

If you're using ClownPeanuts's built-in firewall management:

1. **Start in dry-run mode:**
   ```yaml
   network:
     apply_firewall_rules: true
     firewall_dry_run: true
   ```

2. **Run diagnostics** to see what rules would be applied:
   ```bash
   clownpeanuts doctor --config ./config/clownpeanuts.yml
   clownpeanuts up --once --config ./config/clownpeanuts.yml
   ```

3. **Review the rule preview** in the output. Make sure the rules match your expectations.

4. **Enable enforcement** once you're confident:
   ```yaml
   network:
     firewall_dry_run: false
   ```

ClownPeanuts supports three firewall backends: `iptables`, `nft` (nftables), and `pfctl` (macOS/BSD). It auto-detects which is available on your host.

### 9.2 Operational Surface Protection

The API server and dashboard are operator tools -- they should never be exposed to the same network as the bait services. At minimum:

- Bind the API to a management interface or localhost (`--host 127.0.0.1`)
- Use a reverse proxy with authentication in front of the dashboard
- Firewall API/dashboard ports to your operator IP ranges

---

## 10. Persistence and Data Retention

### 10.1 Session and Event State

Session and event data can be stored in memory (ephemeral) or Redis (persistent). In-memory state is lost when the process exits. Redis state persists across restarts and is controlled by `session.ttl_seconds`.

### 10.2 Intelligence and Canary History

Intelligence reports and canary hit records are stored in a SQLite database managed by `IntelligenceStore`. By default, the database is created in your system's temporary directory as `clownpeanuts-intel.sqlite3`.

**For any deployment where you care about keeping historical data**, override the default path to a persistent location:

```bash
export CLOWNPEANUTS_INTEL_DB=/var/lib/clownpeanuts/intel.sqlite3
```

This is important. The default temporary directory path means your intelligence history can be lost on reboot. Set this environment variable in your deployment configuration (systemd unit, Docker Compose environment, etc.).

---

## 11. Logging and Monitoring

### 11.1 Check Logging Configuration

```bash
.venv/bin/clownpeanuts logs --config ./config/clownpeanuts.yml
```

This prints the current log format, sink, and SIEM shipping configuration without starting any services.

### 11.2 Log Collection Patterns

**Direct shell capture:**

```bash
.venv/bin/clownpeanuts up --config ./config/clownpeanuts.yml | tee /var/log/clownpeanuts/runtime.log
```

**Docker Compose logs:**

```bash
docker compose --profile ops logs -f api
docker compose --profile core logs -f clownpeanuts
```

### 11.3 API Endpoints to Monitor

If you're running the API server, these endpoints are useful for monitoring:

| Endpoint | What It Returns |
| --- | --- |
| `/health` | Simple health check (`{"status":"ok"}`). Good for load balancer health probes. |
| `/status` | Full orchestrator status including service states and configuration. |
| `/doctor` | Diagnostic check results (same as the CLI `doctor` command). |
| `/templates/plan` | Effective template-driven service plan for one tenant or all tenants. |
| `/templates/diff/matrix` | Cross-tenant service-plan difference matrix for drift detection. |
| `/sessions/{session_id}/replay` | Full replay payload for one session, including classification, engagement, coherence, and derived technique/canary summaries. |
| `/sessions/replay/compare` | Side-by-side replay comparison for two session IDs, including overlap/delta/similarity metrics. |
| `/alerts/recent` | Recent alert deliveries and their status. |
| `/intel/history` | Stored intelligence report summaries. |
| `/intel/handoff` | SOC handoff output as structured JSON or rendered markdown/csv/tsv/ndjson/jsonl/cef/leef/syslog/logfmt (`?format=markdown|csv|tsv|ndjson|jsonl|cef|leef|syslog|logfmt`), from live intel or history (`report_id`). |
| `/intel/coverage` | Current ATT&CK coverage and gap payload. |
| `/intel/attack-navigator` | ATT&CK Navigator layer JSON export for direct import into ATT&CK Navigator. |
| `/intel/attack-navigator/history/{report_id}` | ATT&CK Navigator layer generated from a persisted intelligence report. |
| `/intel/bandit/performance` | Live arm-level selection/reward performance and trend metrics. |
| `/intel/stix` | Current STIX 2.1 bundle generation endpoint. |
| `/taxii2/` | TAXII 2.1 discovery endpoint for external integration checks. |
| `/engine/narrative/world` | Deterministic narrative world snapshot for the selected tenant. |
| `/theater/live` | Aggregated live Theater payload including recommendations and latency budget status. |
| `/theater/actions/export` | Filtered/sorted Theater action history export in `json`, `csv`, `tsv`, `ndjson`, `jsonl`, `logfmt`, `cef`, `leef`, or `syslog` format (`?format=...`). |
| `/ws/events` | WebSocket stream of real-time events (for the dashboard and custom integrations). Optional query params: `cursor` (last received event id), `batch_limit` (`1-1000`, default `200`), `interval_ms` (`50-5000`, default `250`), `format` (`event` default, or `batch` for aggregated frames), `topic`, `service`, `action`, `session_id` (server-side stream filters), and `include_payload` (`true` default, `false` to trim nested payload bodies). |
| `/ws/theater/live` | WebSocket stream of Theater live payloads. |

---

## 12. Running as a System Service

If you're running ClownPeanuts in CLI mode outside of Docker and want automatic restart on failure, set up a systemd service.

Example `/etc/systemd/system/clownpeanuts.service`:

```ini
[Unit]
Description=ClownPeanuts Core Runtime
After=network.target

[Service]
Type=simple
User=clownpeanuts
WorkingDirectory=/opt/clownpeanuts
Environment=CLOWNPEANUTS_INTEL_DB=/var/lib/clownpeanuts/intel.sqlite3
ExecStart=/opt/clownpeanuts/.venv/bin/clownpeanuts up --config /opt/clownpeanuts/config/clownpeanuts.yml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Then enable and start it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now clownpeanuts
sudo systemctl status clownpeanuts
```

---

## 13. Upgrading

1. **Pull the latest code:**
   ```bash
   git pull
   ```

2. **Update Python dependencies:**
   ```bash
   source .venv/bin/activate
   pip install -e .[dev,api]
   ```

3. **Run the validation suite:**
   ```bash
   .venv/bin/pytest
   cd dashboard && npm install && npm run build && cd ..
   .venv/bin/clownpeanuts up --once --config ./config/clownpeanuts.yml
   ```

4. **Restart the runtime** (via systemd, Docker Compose, or manual restart).

---

## 14. Troubleshooting

### `doctor` fails on network checks

**Symptoms**: Violations mentioning segmentation mode or firewall backend.

**What's happening**: ClownPeanuts can't verify your network isolation configuration. This is common during local development where you don't have VXLAN or WireGuard set up.

**Fix**: For development, set `network.segmentation_mode: none` and `network.require_segmentation: false`. For production, make sure your segmentation infrastructure matches what's configured. If you're not using host-level firewall validation, set `verify_host_firewall: false`.

### Redis connection warnings in local mode

**Symptoms**: Warning logs about Redis fallback.

**What's happening**: The default config points at `redis://:${CP_REDIS_PASSWORD:-clownpeanuts-dev-redis}@redis:6379/...`, which only resolves in Docker Compose. When running locally without Redis, ClownPeanuts falls back to in-memory backends.

**Fix**: This is expected behavior. If the warnings bother you, either run a local Redis and change the URLs to `redis://:password@127.0.0.1:6379/...`, or set `session.backend: memory` and `event_bus.backend: memory` explicitly. In production-style environments, require Redis AUTH and use `redis://:password@host:6379/...` (or `rediss://...`).

### API starts but no live events appear

**What's happening**: The API server is running, but the WebSocket stream and event-driven endpoints show no activity.

**Fix**: Make sure you started the API with `--start-services` if you want emulators to run in the same process. Without that flag, the API server is just an operations frontend with no event source. Alternatively, if you're running emulators separately, make sure both the emulators and the API are using Redis-backed event bus (not in-memory -- in-memory events don't cross process boundaries).

### Dashboard shows stale or empty data

**What's happening**: The dashboard can't connect to the API or WebSocket endpoint.

**Fix**:
1. Check that the environment variables `NEXT_PUBLIC_CLOWNPEANUTS_API` and `NEXT_PUBLIC_CLOWNPEANUTS_WS` point to the correct addresses. In local development, the defaults (`http://127.0.0.1:8099` and `ws://127.0.0.1:8099/ws/events`) should work.
2. If API auth is enabled (`api.auth_enabled: true`), set `NEXT_PUBLIC_CLOWNPEANUTS_API_TOKEN` to a valid operator/viewer token.
3. Watch the stream badges:
   - `EVENT STREAM LIVE` / `THEATER STREAM LIVE` means websocket is connected.
   - `RECONNECT n (Xs)` means client backoff is active and automatic reconnect is in progress.
   - `OFFLINE` means no socket and no reconnect attempt currently active.
4. Check freshness pills:
   - If they show `snapshot stale` or `payload stale`, force a manual refresh and confirm API latency/health.
5. Check browser console for API or WebSocket errors.
6. Verify API health directly:
   ```bash
   curl -s http://127.0.0.1:8099/health
   curl -s http://127.0.0.1:8099/theater/live
   ```

### Dashboard layout looks outdated after a frontend change

**Symptoms**: You made CSS/layout updates but still see old spacing, old hero proportions, or old visual accents.

**What's happening**: Most commonly, you're looking at a different running instance/port than expected (for example demo harness on `3001` vs regular dev on `3000`), or the browser is holding stale frontend artifacts.

**Fix**:
1. Confirm the active URL:
   - regular dev: `http://127.0.0.1:3000`
   - one-command demo: `http://127.0.0.1:3001`
2. Hard-refresh (`Cmd+Shift+R`).
3. If still stale, restart dashboard dev server:
   ```bash
   cd dashboard
   npm run dev
   ```
4. If running demo harness, restart it cleanly:
   ```bash
   ./scripts/dev-down-demo.sh
   ./scripts/dev-up-demo.sh
   ```
5. Re-open `/` and `/theater` and verify both picked up current styles.

### Replay drilldown route shows "session not found" or degraded state

**What's happening**: `/theater/replay/<session-id>` is up, but data panels are empty or marked degraded.

**Fix**:
1. Confirm the session exists:
   ```bash
   curl -s "http://127.0.0.1:8099/sessions?limit=50&events_per_session=1"
   ```
2. Confirm replay payload is available:
   ```bash
   curl -s "http://127.0.0.1:8099/sessions/<session-id>/replay?events_limit=200"
   ```
3. Confirm Theater session payload is available:
   ```bash
   curl -s "http://127.0.0.1:8099/theater/sessions/<session-id>?events_limit=200"
   ```
4. If API works but UI still shows degraded:
   - use `refresh now` in replay page,
   - then hard-refresh the browser tab,
   - then verify `NEXT_PUBLIC_CLOWNPEANUTS_API` points to the intended API instance.

### Theater apply-lure requests return validation errors

**What's happening**: Theater action API calls are rejected with `400` responses.

**Fix**: Verify required fields are present and valid:
1. `session_id` must be non-empty.
2. `lure_arm` must be non-empty for apply-lure actions.
3. `duration_seconds` must be greater than zero.
4. `confidence` for labels must be between `0` and `1`.
5. `metadata` (if provided) must be a JSON object.

If validation still fails, inspect the API response body and confirm the request shape matches `/theater/actions/apply-lure` or `/theater/actions/label`.

### Alert tests not delivering

**What's happening**: `alerts-test` runs but no notifications arrive at your destinations.

**Fix**: Walk through this checklist:
1. Is `alerts.enabled` set to `true`?
2. Does at least one destination have `enabled: true`?
3. Does the test severity meet the destination's `min_severity` threshold?
4. Are the endpoint URLs, tokens, and credentials correct?
5. Run `alerts-routes --severity <level>` to see the routing decision -- it'll tell you exactly which destinations would fire and which are filtered out, and why.

### LLM responses are slow or failing

**What's happening**: The local LLM is timing out or returning errors, causing the engine to fall back to rule-based responses.

**Fix**: Check that `engine.local_llm.timeout_seconds` is realistic for your hardware. A 3B parameter model on a modern GPU should respond in under a second. If it's consistently slow, increase the timeout slightly. If the LLM is completely unavailable, ClownPeanuts will enter cooldown after `failure_threshold` consecutive failures and use rule-based responses for `cooldown_seconds`. The rule-based fallback is perfectly functional -- the LLM just adds more variety to responses.

---

## 15. Suggested Operator Cadence

### Daily

1. Run `doctor` to verify configuration and isolation.
2. Check the dashboard for live events and recent alert activity.
3. Run `intel` to review engagement trends and new attacker profiles.
4. Review `theater/live`, work high-confidence recommendations in `/theater`, and use bookmark filtering to maintain analyst focus queues.
5. Drill into at least one priority session via `/theater/replay/<session-id>` to validate recommendation quality against full replay context.
6. Run `alerts-routes` to verify routing rules are working as expected.
7. Periodically run `alerts-test` to confirm delivery endpoints are still reachable.

### Weekly

1. Run `templates-validate --all-tenants` to catch any template drift.
2. Review canary hit trends with `canary-hits`.
3. Run `simulate-bandit` and compare baseline vs. candidate reward deltas before changing live policy posture.
4. Export `theater-history` and review operator action quality and consistency.
5. If the threat intel rotation scheduler is disabled or needs manual intervention, run `rotate` or `rotate-preview`.
6. Export STIX/TAXII/ATT&CK Navigator payloads for downstream sharing and analyst tooling.

### Monthly

1. Verify the `CLOWNPEANUTS_INTEL_DB` path is on persistent storage and the database is healthy.
2. Run the full test/build validation suite before applying any upgrades.
3. Review the isolation policy (`network.*` settings) against your current risk posture.
4. Review and adjust tarpit parameters based on observed attacker behavior patterns.
5. Revisit `theater.rollout_mode` and bandit safety caps against current SOC operating maturity.

---

## 16. Further Reading

| Document | What It Covers |
| --- | --- |
| [README](../README.md) | Project overview and quick start. |
| [Architecture](architecture.md) | Component boundaries, runtime data flow, and trust boundaries. |
| [Current State](current-state.md) | What's implemented at the current repo head. |
| [Public Extension Boundary](public-extension-boundary.md) | Public integration contracts and standalone compatibility boundaries for optional modules. |
