# ClownPeanuts

An adaptive deception framework that turns your honeypot infrastructure into a procedurally generated funhouse for attackers.

ClownPeanuts emulates commonly attacked services (SSH, HTTP admin panels, databases), keeps attackers engaged with believable fake environments that respond dynamically to their behavior, and transforms every interaction into structured threat intelligence you can actually use for triage, detection engineering, and reporting.

ClownPeanuts is a unified multi-protocol framework with its own stateful deception engine, tarpit layer, and full intelligence pipeline -- all in one codebase. The credential cascade graph, phantom lateral movement, and oops artifact library don't really have equivalents in the open-source space. Comparable capabilities are generally found in closed-source, enterprise-priced commercial platforms.

Last documentation refresh: **February 21, 2026** (optional enhancement-lane continuation: Redis list insertion realism, Theater multi-session triage filters, Theater syslog interoperability, and stricter production token hardening checks).

---

## Why ClownPeanuts Exists

Traditional honeypots are passive. They capture a port scan, maybe a login attempt, and that's it. The attacker pokes, gets nothing interesting back, and moves on in seconds. You end up with a pile of scanner noise and very little insight into what a real adversary would do after gaining access.

ClownPeanuts is built to capture the full attack progression, not just the first touch:

- **Initial access attempts** -- credential stuffing, brute-force, service enumeration. The bread and butter of honeypot capture, but with the added twist that ClownPeanuts will *let attackers in* after a realistic number of failures, making them believe they've succeeded.
- **Post-compromise behavior** -- once inside, attackers interact with a stateful fake environment. The commands they run, the files they look for, the credentials they try to reuse, the lateral movement they attempt -- all of it is captured and correlated.
- **Tooling fingerprints** -- automated tools leave distinct behavioral signatures. ClownPeanuts identifies scanners, exploit frameworks, and custom tooling by analyzing command patterns, timing cadence, and protocol-level artifacts.
- **Cross-session patterns** -- when the same attacker (or the same tool) comes back days later, ClownPeanuts correlates credential reuse, source clustering, and behavioral similarity to connect sessions into campaign-level intelligence.

The design principle is simple: every attacker "success" is a trapdoor into more fake terrain. Every door leads to another hallway. Every hallway has more doors.

## Ground Rules

ClownPeanuts is a **defensive-only** tool. There is no exploit delivery, no offensive payload generation, no active engagement beyond deception.

- **Isolation-first design.** Honeypot services must be deployed on infrastructure that has no network path to your production environment. ClownPeanuts validates this at startup and can enforce firewall policies to guarantee it.
- **Deception realism is intentional.** Some things in ClownPeanuts look insecure on purpose -- weak authentication, leaked credentials, misconfigured services. These are deliberate trap mechanics, not accidental defects. If you're auditing the codebase and something looks like a vulnerability, check whether it's part of the deception layer before filing a bug.
- **Licensed under PolyForm Noncommercial 1.0.0** for source code and documentation.

---

## What's In The Box

ClownPeanuts ships as a complete platform. Here's what you get:

### Service Emulators (The Bait Surface)

Seven protocol emulators that present convincing attack targets:

| Service | Default Port | What It Does |
| --- | --- | --- |
| **SSH** | 2222 | Fake OpenSSH server. Accepts credentials after a configurable number of failures. Drops attackers into a fake shell with command capture. Adaptive tarpit ramps up latency on repeated attempts. |
| **HTTP Admin** | 8080 | Fake admin panel with login baiting, slow-drip backup downloads, infinite exfiltration streams, and a query tarpit that serves paginated fake data forever. |
| **Redis** | 6380 | Unauthenticated Redis emulator. Returns fake cached data and responds to common Redis commands. |
| **MySQL** | 13306 | MySQL wire protocol emulator with fake query responses and adaptive delays. |
| **PostgreSQL** | 15432 | PostgreSQL emulator with believable connection handling and query responses. |
| **MongoDB** | 27018 | MongoDB emulator (disabled by default). Returns fake collections and documents. |
| **Memcached** | 11212 | Memcached emulator (disabled by default). Responds to cache inspection commands. |

### The Rabbit Hole Engine

The core of what makes ClownPeanuts different from a static honeypot. The Rabbit Hole Engine maintains a per-session world model -- a coherent fake environment that evolves based on what the attacker does:

- **World Model**: Each session gets a generated environment with fake hostnames, users, processes, and files. If an attacker runs `ls /home`, the engine generates plausible user directories. If they `cat /etc/passwd`, the same users appear. Consistency is maintained across the entire session.
- **Credential Cascade Graph**: A directed graph of fake credentials where each discovery leads to the next. Finding database credentials in a `.env` file leads to a database that contains API keys, which lead to another service, and so on. The graph can be 8+ levels deep.
- **Phantom Lateral Movement**: The fake environment includes network interfaces, `/etc/hosts` entries, and SSH keys that suggest other reachable hosts. When an attacker "pivots," ClownPeanuts spins up the next layer of the illusion.
- **Oops Artifacts**: Deliberately planted artifacts that look like operator mistakes -- `.bash_history` with sensitive commands, leaked git history, debug endpoints with stack traces, cron scripts with hardcoded passwords. These are bait designed to keep attackers digging.
- **LLM Backend (Optional)**: The engine can use a local LLM (via LM Studio or Ollama) for dynamic response generation. Without an LLM, it falls back to a rule-based template system that handles common interaction patterns with low latency.

### Tarpit Primitives

Techniques for wasting attacker time without making the deception obvious:

- **Adaptive Throttle**: Gradually increases response latency as an attacker sends more commands. Starts imperceptibly slow and ramps up over configurable thresholds.
- **Slow-Drip Downloads**: File downloads that fragment data into small chunks with randomized pauses between them. Looks like a congested server, not a deliberate slowdown.
- **Infinite Exfiltration**: Data streams that never end. Database dumps with infinite pagination, backup files that keep generating content. The attacker's download progress bar never quite reaches 100%.
- **Query Tarpit**: Search endpoints that return paginated results with increasing delays between pages. Each page suggests there's more data ahead.

### Intelligence Pipeline

Raw session data goes in, structured threat intelligence comes out:

- **ATT&CK Mapping**: Observed attacker behavior is automatically mapped to MITRE ATT&CK techniques. Coverage gaps are tracked so you know which techniques your honeypot isn't capturing.
- **Attacker Classification**: Sessions are scored and classified by sophistication level -- from automated scanners to advanced persistent threats.
- **Tool Fingerprinting**: Common tools (Nmap, Metasploit, custom scripts) are identified by their behavioral signatures.
- **Kill-Chain Analysis**: Tracks attacker progression through reconnaissance, initial access, privilege escalation, lateral movement, and exfiltration stages.
- **Source Enrichment**: IP addresses are enriched with ASN, geography, and ISP data for context.
- **Behavioral Biometrics**: Typing speed, command intervals, interaction cadence -- patterns that can help link sessions from the same operator.
- **Credential Reuse Detection**: Tracks when the same credentials appear across sessions, connecting potentially related attackers or campaigns.
- **STIX 2.1 / TAXII Export**: Intelligence output in industry-standard formats for integration with downstream platforms.

### Narrative, Bandit, and Theater Stack

The current enhancement wave is implemented and available behind config flags:

- **Adversary Narrative Engine**: Deterministic cross-protocol context so SSH, HTTP, and DB interactions stay coherent per session.
- **Adaptive Lure Bandit**: Contextual lure-arm selection (`thompson`/`ucb`) with exposure caps, cooldown, denylist, override, and reset controls.
- **Adversary Theater Mode**: Operator-focused live view with timeline, kill-chain progression, recommendation explainability, one-click lure application, labeling, persisted action audit history, bookmark-based queue filtering, and dedicated replay drilldown pages.
- **Counterfactual Simulation**: Offline `simulate-bandit` replay to compare baseline and candidate policies before enabling policy changes in production.

### Canary Tokens

Generate trackable tokens that reveal when data has been exfiltrated and used outside the honeypot:

- **DNS canaries**: Domain lookups that phone home when resolved.
- **HTTP canaries**: URLs that trigger alerts when visited.
- **Email canaries**: Addresses that alert on received mail.
- **AWS key canaries**: Fake credentials that alert when used against AWS APIs.
- **Code canaries**: Unique markers embedded in source files.

### Alert Routing

Notifications delivered where your team actually looks:

- **Webhook** -- generic HTTP POST to any endpoint.
- **Slack** -- channel messages with configurable formatting.
- **Discord** -- channel messages via Discord webhooks.
- **PagerDuty** -- incident creation for high-severity events.
- **Email** -- SMTP delivery to your SOC inbox.
- **Syslog** -- traditional syslog forwarding for SIEM ingestion.

Each destination supports severity filtering, service-specific routing, action include/exclude lists, and per-destination throttling.

### Operations Dashboard

A Next.js frontend backed by a FastAPI API server with WebSocket event streaming:

- Live engagement map showing active attacker sessions
- Attacker profile browser with classification and scoring
- Kill-chain visualization for individual sessions
- ATT&CK coverage heatmap
- Canary token status board
- Alert routing status and history
- Service health overview
- Template and tenant management views
- Resilient websocket reconnect loops for both `/ws/events` and `/ws/theater/live` streams
- Stream freshness telemetry badges (live/reconnect/offline plus stale snapshot indicators)
- Theater session replay analyzer and full drilldown route (`/theater/replay/<session_id>`)
- Swiss-style high-contrast visual system (Akzidenz/Helvetica/Univers fallback stack with strict hierarchy)
- Responsive asymmetrical layout with desktop max-width containment to prevent ultra-wide drift
- Invisible alignment grid methodology (structural grid retained, visible overlay removed from runtime UI)

### Shared Control Plane (SquirrelOps)

ClownPeanuts includes its own local dashboard/API workflow in this repository, and that path remains supported for runtime-focused development and compatibility.

For multi-product operations (ClownPeanuts + PingTing + orchestration actions), the shared control-plane now lives in SquirrelOps:

- Control-plane dashboard: `squirrelops/apps/controlplane-dashboard`
- Control-plane API: `squirrelops/apps/controlplane-api`
- Migration/current-state docs: [squirrelops/docs/controlplane-migration.md](https://github.com/mattmacrocket/squirrelops/blob/main/docs/controlplane-migration.md) and [squirrelops/docs/current-state.md](https://github.com/mattmacrocket/squirrelops/blob/main/docs/current-state.md)

In practice:

- Use this repository's dashboard when iterating directly on ClownPeanuts runtime/operator UX.
- Use the SquirrelOps control-plane for cross-repo operator workflows and shared tabs (Overview/Deception/Sentry/Orchestration).

### Optional Integration Policy

Optional integrations are additive by design. ClownPeanuts remains fully supported in standalone mode, and baseline ClownPeanuts + SquirrelOps + PingTing workflows must continue to operate when optional integrations are not enabled.

---

## Quick Start

### Local Development (CLI)

```bash
# Clone and set up the Python environment
git clone git@github.com:mattmacrocket/clownpeanuts.git
cd clownpeanuts
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]

# Generate a starter config file
clownpeanuts init --config ./config/clownpeanuts.yml

# Verify everything loads correctly
clownpeanuts status --config ./config/clownpeanuts.yml

# Run a one-shot smoke test (starts services, prints status, exits)
clownpeanuts up --once --config ./config/clownpeanuts.yml

# Run the test suite
.venv/bin/pytest
```

If default emulator ports on your machine are already occupied, run smoke against the demo-safe config:

```bash
.venv/bin/clownpeanuts up --once --config ./config/local-theater-demo.yml
```

To run continuously (services stay up until you hit Ctrl+C):

```bash
clownpeanuts up --config ./config/clownpeanuts.yml
```

### API + Dashboard (Local)

If you want the full operator experience with the web dashboard:

```bash
# Install API dependencies
pip install -e .[api]

# Start the API server (add --start-services to also run emulators in-process)
clownpeanuts api --config ./config/clownpeanuts.yml --host 127.0.0.1 --port 8099

# In another terminal, start the dashboard
cd dashboard
npm install
npm run dev
```

The dashboard opens at `http://127.0.0.1:3000` and connects to the API at `http://127.0.0.1:8099`.

Primary routes:

- `http://127.0.0.1:3000/` (Operations)
- `http://127.0.0.1:3000/theater` (Theater)
- `http://127.0.0.1:3000/theater/replay/<session_id>` (Replay drilldown)

### Docker Compose

The simplest way to run the full stack:

```bash
# Full stack: API (with emulators) + dashboard + Redis
docker compose --profile ops up --build

# Core runtime only: emulators + Redis (no dashboard)
docker compose --profile core up --build
```

Set custom auth secrets for API and Redis before startup:

```bash
CP_API_OPERATOR_TOKEN="replace-with-long-random-token" \
CP_REDIS_PASSWORD="replace-with-strong-redis-password" \
docker compose --profile ops up --build
```

Override container resource limits with environment variables:

```bash
CP_CORE_MEM_LIMIT=1536m CP_CORE_CPUS=1.5 CP_API_MEM_LIMIT=1024m docker compose --profile ops up --build
```

### One-Command Local Demo

For a fast local test harness (API + dashboard + seeded traffic + Theater-enabled config on safe alternate ports):

```bash
./scripts/dev-up-demo.sh
```

This brings up:
- API: `http://127.0.0.1:8109`
- Dashboard: `http://127.0.0.1:3001`
- Theater: `http://127.0.0.1:3001/theater`

It also:

- Generates `./config/local-theater-demo.yml` from defaults.
- Enables `narrative`, `bandit`, and `theater` (`apply-enabled`) so Theater workflows are immediately available.
- Uses safe alternate bait ports (`SSH 3222`, `HTTP 28080`) to avoid common local conflicts.
- Seeds initial HTTP traffic so sessions/replay views have immediate data.
- Writes logs and process state under `/tmp/clownpeanuts-demo`.

Stop the demo stack with:

```bash
./scripts/dev-down-demo.sh
```

---

## CLI Command Reference

### Runtime and Diagnostics

| Command | What It Does |
| --- | --- |
| `clownpeanuts init` | Generate a starter configuration file at the path you specify. |
| `clownpeanuts up` | Start all enabled service emulators and run until interrupted. Add `--once` to start, print status, and exit immediately. |
| `clownpeanuts status` | Print the current orchestrator state -- which services are configured, what ports they bind, and whether they're running. |
| `clownpeanuts logs` | Show the current logging configuration (format, sink, SIEM shipping settings). |
| `clownpeanuts api` | Start the FastAPI operations server. Add `--start-services` to also boot emulators in the same process. |
| `clownpeanuts doctor` | Run diagnostic checks against your config, network isolation, and optional dependencies. Add `--check-llm` to probe a configured local LLM endpoint. |

### Intelligence and Export

| Command | What It Does |
| --- | --- |
| `clownpeanuts intel` | Build and display an ATT&CK-mapped intelligence snapshot from current session data. |
| `clownpeanuts intel-history` | List stored intelligence reports from previous runs. Use `--limit` to control how many. |
| `clownpeanuts intel-coverage` | Show which ATT&CK techniques your honeypot is currently capturing and where the gaps are. |
| `clownpeanuts simulate-bandit` | Replay recent session traces against baseline and candidate lure-bandit policies and return counterfactual reward deltas. |
| `clownpeanuts replay` | Replay a specific session's events for triage. Requires `--session-id`. |
| `clownpeanuts stix-export` | Export intelligence data as a STIX 2.1 JSON bundle. |
| `clownpeanuts taxii-export` | Export a TAXII-style manifest for downstream threat-sharing platforms. |
| `clownpeanuts theater-history` | Export persisted theater operator actions (apply-lure/label) as script-friendly `json`, `csv`, `tsv`, `ndjson`, `jsonl`, `logfmt`, `cef`, `leef`, or `syslog` payloads (including multi-session slicing via `--session-ids`). |

### Canary Workflows

| Command | What It Does |
| --- | --- |
| `clownpeanuts canary-types` | List all available canary token types. |
| `clownpeanuts canary-generate` | Generate a new canary token. Specify `--namespace` and `--token-type`. |
| `clownpeanuts canary-hit` | Record a canary token hit manually (for testing or external integration). |
| `clownpeanuts canary-tokens` | List all generated canary tokens and their status. |
| `clownpeanuts canary-hits` | Show the full canary hit history. |

### Rotation, Templates, and Alerts

| Command | What It Does |
| --- | --- |
| `clownpeanuts rotate` | Trigger an immediate threat intelligence bait rotation. |
| `clownpeanuts rotate-preview` | Preview what the next rotation would select without applying it. |
| `clownpeanuts templates` | List loaded deception templates and the current effective plan. |
| `clownpeanuts templates-validate` | Validate template syntax and overlay consistency. Add `--all-tenants` to check every tenant. |
| `clownpeanuts templates-diff` | Compare effective plans between two tenants. |
| `clownpeanuts alerts-test` | Send a synthetic alert through all configured destinations to verify delivery. |
| `clownpeanuts alerts-routes` | Preview the routing decision for a synthetic event (which destinations would fire and why). |

Most runtime, intelligence, and template commands accept `--tenant` for multi-tenant scoping.

---

## API and WebSocket Surfaces

Core operational endpoints:

- `GET /health`, `GET /status`, `GET /doctor`
- `GET /sessions`, `GET /sessions/{session_id}/replay`
- `GET /templates/inventory`, `GET /templates/plan`, `GET /templates/validate`, `GET /templates/diff`, `GET /templates/diff/matrix`
- `GET /intel/report`, `GET /intel/history`, `GET /intel/history/sessions`, `GET /intel/coverage`, `GET /intel/map`
- `GET /intel/handoff` (structured JSON or rendered markdown/csv/tsv/ndjson/jsonl/cef/leef/syslog/logfmt via `?format=...`)
- `GET /intel/techniques`, `GET /intel/profiles`, `GET /intel/fingerprints`, `GET /intel/kill-chain`, `GET /intel/kill-chain/graph`
- `GET /intel/canaries`, `GET /intel/canary/tokens`, `GET /intel/canary/hits`, `GET /intel/canary/types`
- `GET /intel/bandit/arms`, `GET /intel/bandit/performance`, `GET /intel/bandit/observability`
- `POST /intel/bandit/override`, `POST /intel/bandit/reset`
- `GET /intel/stix`, `GET /intel/taxii/collections`, `GET /taxii2/`, `GET /taxii2/api/collections`
- `GET /engine/narrative/world`, `GET /engine/narrative/session/{session_id}`
- `GET /theater/live`, `GET /theater/sessions/{session_id}`, `GET /theater/recommendations` (supports `min_confidence`, `min_prediction_confidence`, `predicted_stage`, `lure_arm`, `context_key_prefix`, `apply_allowed_only`, `include_explanation`, `compact`, `sort_by`, `sort_order`; live payloads use short-TTL caching for high-frequency polling)
- `POST /theater/actions/apply-lure`, `POST /theater/actions/label`, `GET /theater/actions` (short-TTL cached by full filter/sort query shape; supports `session_id`, `session_ids`, `actor`, `actor_prefix`, `session_prefix`, `query`, `recommendation_id`, `created_after`, `created_before`, `action_types`, `compact`, `sort_by`, `sort_order` for triage filtering/ordering)
- `GET /theater/actions/export` (`json|csv|tsv|ndjson|jsonl|logfmt|cef|leef|syslog` export adapters for filtered/sorted action history, using the same filter/sort query surface as `/theater/actions`)

Live streams:

- `/ws/events` for global event flow (supports `cursor`, `batch_limit`, `interval_ms`, `format=batch`, filters: `topic`/`service`/`action`/`session_id`, and `include_payload=false` trim mode)
- `/ws/theater/live` for Theater live payloads (sessions, recommendations, bandit metrics)

---

## Configuration

ClownPeanuts uses YAML configuration with environment variable interpolation. You can generate a starter config with `clownpeanuts init`, start from the bundled defaults at `clownpeanuts/config/defaults.yml`, or use the stricter baseline at `config/production-hardened.yml`.

### Environment Variable Interpolation

Any YAML value can reference environment variables:

```yaml
engine:
  local_llm:
    api_key: ${LM_STUDIO_API_KEY}           # Required -- fails if unset
    endpoint: ${LLM_ENDPOINT:-http://localhost:1234/v1/chat/completions}  # With default
```

### Engine Configuration (Rabbit Hole Engine)

The engine has two backends:

**Rule-based (default)**: Uses template matching and procedural generation for responses. No external dependencies. Low latency.

```yaml
engine:
  backend: rule-based
  template_fast_path: true    # Use template shortcuts for common commands
  context_seed: clownpeanuts  # Seed for procedural world generation
```

**Local LLM**: Uses a locally hosted language model for dynamic response generation. Requires LM Studio or Ollama running separately.

```yaml
engine:
  backend: local-llm
  local_llm:
    enabled: true
    provider: lmstudio          # "lmstudio" or "ollama"
    endpoint: http://masoc:1234/v1/chat/completions
    model: llama3.2:3b
    api_key: ${LM_STUDIO_API_KEY}
    timeout_seconds: 1.2        # Max time to wait for LLM response
    max_response_chars: 700     # Truncate responses beyond this
    temperature: 0.2            # Low temperature for consistent output
    failure_threshold: 3        # Consecutive failures before cooldown
    cooldown_seconds: 15.0      # Wait this long after hitting failure threshold
```

If the LLM backend is enabled but unreachable, the engine automatically falls back to rule-based responses after hitting the failure threshold.

### Narrative, Bandit, and Theater Configuration

```yaml
narrative:
  enabled: true
  world_seed: clownpeanuts
  entity_count: 120
  per_tenant_worlds: true
```

```yaml
bandit:
  enabled: true
  algorithm: thompson          # "thompson" or "ucb"
  exploration_floor: 0.1       # 0.0-1.0
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

```yaml
theater:
  enabled: true
  rollout_mode: recommend-only # "observe-only", "recommend-only", "apply-enabled"
  max_live_sessions: 75
  recommendation_cooldown_seconds: 8.0
```

`rollout_mode` controls operator actioning posture:

- `observe-only`: theater telemetry only.
- `recommend-only`: recommendations visible, no lure apply action.
- `apply-enabled`: recommendations plus one-click lure application.

### Alert Configuration

```yaml
alerts:
  enabled: true               # Master switch for all alerting
  min_severity: medium         # Global minimum severity filter (low/medium/high/critical)
  throttle_seconds: 60         # Minimum time between alerts from the same source
  destinations:
    - name: slack-soc
      type: slack
      enabled: true
      endpoint: https://hooks.slack.com/services/T.../B.../xxx
      min_severity: high       # This destination only gets high and critical alerts
      include_services: [ssh, http-admin]  # Only alerts from these services
      exclude_actions: [scan]  # Suppress noisy scan alerts

    - name: pagerduty-critical
      type: pagerduty
      enabled: true
      endpoint: https://events.pagerduty.com/v2/enqueue
      token: ${PAGERDUTY_ROUTING_KEY}
      min_severity: critical   # Only pages for critical events
      metadata:
        source: clownpeanuts
```

### Network Isolation

```yaml
network:
  segmentation_mode: vxlan     # "vxlan", "wireguard", or "none"
  require_segmentation: true   # Fail startup if segmentation isn't verified
  enforce_runtime: true        # Enforce policy (vs. warn-only)
  allow_outbound: false        # Block all outbound traffic from honeypot services
  allowed_egress:
    - redis                    # Exceptions to the outbound block
  verify_host_firewall: false  # Check for iptables/nft/pfctl on the host
  apply_firewall_rules: false  # Actually apply firewall rules (careful!)
  firewall_dry_run: true       # Preview rules without applying
```

See the [User Guide](docs/user-guide.md) for the complete configuration reference.

---

## Intentional Insecure Behavior (By Design)

ClownPeanuts intentionally includes things that look like security weaknesses. This is the entire point -- convincing deception requires realistic-looking vulnerabilities.

Examples of intentional "insecure" behavior:

- Services that accept credentials after a small number of failures
- `.env` files with fake database passwords and API keys
- Admin panels with weak authentication
- Backup files available for download (via slow-drip tarpit)
- Debug endpoints that return fake stack traces with internal paths
- Redis and MongoDB instances with no authentication

These are trap mechanics, not bugs. Use caution when exposing operational surfaces (the API and dashboard) and deploy according to your risk posture -- those interfaces should be firewalled to operator IPs only.

---

## Testing and Validation

```bash
# Run the full test suite
.venv/bin/pytest -q

# Build the dashboard (catches frontend compilation errors)
cd dashboard && npm run build

# Runtime smoke test
.venv/bin/clownpeanuts up --once --config clownpeanuts/config/defaults.yml
```

If default bait ports are already in use (for example while another local stack is running), use:

```bash
.venv/bin/clownpeanuts up --once --config config/local-theater-demo.yml
```

---

## Repository Layout

```
clownpeanuts/
  clownpeanuts/        Python application code (services, engine, intel, alerts, config)
  dashboard/           Next.js operations UI
  tests/               Unit and integration tests
  docs/                Architecture, user guide, extension boundary, state snapshot
  config/              Generated/local configuration files (gitignored)
  scripts/             Local demo harness scripts (`dev-up-demo.sh`, `dev-down-demo.sh`)
  AGENTS.md            Operating guidance for AI coding agents working in this repo
```

---

## Documentation

Start with the user guide if you're setting up ClownPeanuts for the first time. The architecture doc is useful if you want to understand how the pieces fit together before diving into config.

| Document | What It Covers |
| --- | --- |
| **[User Guide](docs/user-guide.md)** | Complete setup and operations runbook. Deployment modes, configuration reference, day-2 operations, troubleshooting, and suggested operator cadence. |
| **[Architecture](docs/architecture.md)** | Component boundaries, runtime data flow, trust boundaries, and deployment topologies. |
| **[Current State](docs/current-state.md)** | Snapshot of what's implemented at the current repo head. |
| **[Public Extension Boundary](docs/public-extension-boundary.md)** | Public interface contracts and standalone compatibility guarantees for optional integrations. |
| **[Agent Handoff](docs/agent-handoff.md)** | Quick-start guide for new contributors or AI coding agents picking up work in this repo. |

---

## Contributing

1. Fork the repository and create a feature branch.
2. Run the test suite locally before submitting (`pytest` + `npm run build`).
3. Preserve isolation guarantees and defensive-only posture -- ClownPeanuts never reaches out to production systems or delivers exploits.
4. Keep deception realism intact. If you're changing service behavior, make sure it still looks convincing to an attacker.
5. Open a PR with implementation notes and validation evidence.

---

## License Choice

ClownPeanuts is source-available under `PolyForm Noncommercial 1.0.0`.

- Allowed: personal use, research, educational use, and other noncommercial use.
- Not allowed without separate permission: commercial use, resale, paid hosting, or repackaging for commercial advantage.

If you need commercial rights, open an issue in this repository to request a separate commercial license.

## License

This repository is licensed under `PolyForm Noncommercial 1.0.0`. See [LICENSE](LICENSE).

## Trademark Policy

Use of project names and logos is governed by [TRADEMARK_POLICY.md](TRADEMARK_POLICY.md).
