# Architecture Overview

This document describes how ClownPeanuts is structured internally -- what the major components are, how data flows through the system at runtime, where the trust boundaries lie, and how the different deployment topologies map onto these components.

If you're looking for setup instructions, start with the [User Guide](user-guide.md). If you want to understand what's implemented at the current repo head, see [Current State](current-state.md). This document is for understanding the design.

---

## Design Goals

ClownPeanuts is built around four objectives:

1. **Contain attacker interaction inside controlled deceptive surfaces.** Every service an attacker touches is fake. No real data, no real systems, no real credentials. The attacker is always inside the illusion, never outside it.

2. **Capture high-fidelity behavior telemetry with session correlation.** Individual events (a login attempt, a command, a file download) are linked together into sessions. Sessions are linked across reconnects by source identity and behavioral fingerprinting. This turns isolated data points into coherent narratives of attacker behavior.

3. **Convert raw telemetry into actionable threat intelligence.** Raw logs aren't useful by themselves. The intelligence pipeline classifies attackers, maps their behavior to ATT&CK techniques, scores engagement depth, and produces structured output (STIX 2.1, TAXII) that downstream platforms can consume.

4. **Preserve clear isolation boundaries from production infrastructure.** The honeypot stack must have no network path to production. This is validated at startup, can be enforced with firewall rules, and is architecturally baked into the deployment model.

---

## Component Map

The system is organized into three planes: control, runtime, and intelligence/operations. Each plane has distinct responsibilities and different trust characteristics.

### Control Plane

The control plane handles configuration, lifecycle management, and diagnostics. It's where the operator interacts with the system.

**`clownpeanuts/cli.py`** -- The CLI entry point. This is the `clownpeanuts` command you run in your terminal. It dispatches to subcommands for runtime startup (`up`, `api`), diagnostics (`doctor`, `status`, `logs`), intelligence extraction (`intel`, `intel-history`, `intel-handoff`, `intel-coverage`, `stix-export`, `taxii-export`, `navigator-export`), replay workflows (`replay`, `replay-compare`, `theater-history`), canary management (`canary-generate`, `canary-hit`, `canary-types`, `canary-tokens`, `canary-hits`), alert testing (`alerts-test`, `alerts-routes`), template management (`templates`, `templates-validate`, `templates-diff`), and threat intel/bandit controls (`rotate`, `rotate-preview`, `simulate-bandit`). Every subcommand loads configuration, validates it, and then delegates to the appropriate subsystem.

**`clownpeanuts/core/orchestrator.py`** -- The orchestrator is responsible for bootstrapping the entire runtime. It loads configuration, runs network isolation checks, initializes shared subsystems (session manager, event bus, engine), starts enabled service emulators, and coordinates graceful shutdown. When you run `clownpeanuts up`, the orchestrator is what's driving the process. It also handles multi-tenant configuration by merging tenant-specific overrides with the base service configs.

**`clownpeanuts/config/`** -- Configuration loading and validation. The `loader.py` module reads YAML files, performs environment variable interpolation (`${VAR}` and `${VAR:-default}`), and passes the result to `schema.py` for strict validation. The schema is implemented as Python dataclasses with explicit field-level validation -- every configuration value is type-checked, range-checked, and cross-validated against other settings.

### Runtime Plane

The runtime plane is where attacker interaction actually happens. These components are the ones that face adversary traffic.

**`clownpeanuts/services/`** -- Protocol emulators. Each emulator implements the `ServiceEmulator` abstract base class defined in `base.py`, which requires `start()`, `stop()`, and `handle_connection()` methods along with metadata properties (`name`, `default_ports`, `config_schema`). The emulators are:

- `ssh/emulator.py` -- Fake SSH server. Presents a configurable banner, accepts credentials after a configurable number of failures, and drops the attacker into a fake shell. Commands are captured and forwarded to the Rabbit Hole Engine for contextual response generation.
- `http/emulator.py` -- Fake HTTP admin panel. Serves login pages, handles authentication with configurable delay patterns, streams slow-drip backup files, runs an infinite exfiltration endpoint, and provides a query tarpit with paginated fake search results.
- `database/redis_emulator.py` -- Fake Redis. Responds to stateful Redis command workflows across string/hash/list/set operations (including TTL and key-lifecycle behavior) with coherent fake data.
- `database/mysql_emulator.py` -- Fake MySQL. Handles wire protocol handshake and responds to basic queries.
- `database/postgres_emulator.py` -- Fake PostgreSQL. Same pattern as MySQL, PostgreSQL wire protocol.
- `database/mongo_emulator.py` -- Fake MongoDB. Returns fake collections and documents.
- `database/memcached_emulator.py` -- Fake Memcached. Responds to cache inspection commands.
- `dummy/emulator.py` -- Generic placeholder emulator for development and testing.

**`clownpeanuts/engine/`** -- The Rabbit Hole Engine. This is the brain that makes ClownPeanuts's deception dynamic rather than static. It's composed of several subcomponents:

- `rabbit_hole.py` -- The core engine. Receives attacker input (a shell command, a query, a file request), builds context from the session's world model, generates a response (via rule-based templates or a local LLM), and returns it to the calling emulator. The engine maintains a consistent world across the entire session -- if a fake user appeared in `/etc/passwd`, they'll also appear in `/home/`.
- `context.py` -- The `WorldModel` class. Each session gets its own world model instance that tracks discovered hosts, users, credentials, processes, files, and network configuration. The world model is seeded procedurally from the engine's `context_seed` configuration and evolves as the attacker interacts.
- `credentials.py` -- The `CredentialCascade`. A directed graph of fake credentials where each node leads to another. Finding database credentials in a `.env` file leads to a database that contains API keys, which lead to another service. The graph is designed to keep attackers digging deeper.
- `lateral.py` -- `PhantomLateralMovement`. Generates network artifacts that suggest other reachable hosts -- multiple network interfaces, hostnames in `/etc/hosts`, SSH keys that appear to work. When an attacker tries to pivot, the engine generates the next hop's environment.
- `oops.py` -- `OopsArtifactLibrary`. A collection of deliberately planted "mistakes" that look like operator carelessness -- `.bash_history` with sensitive commands, git history with committed secrets, debug endpoints, cron scripts with hardcoded passwords. These are bait patterns designed to keep attackers engaged.

**`clownpeanuts/tarpit/`** -- Delay and friction primitives. These components make interactions slower without making them obviously artificial:

- `throttle.py` -- `AdaptiveThrottle`. Gradually increases response latency over a configurable ramp. Starts with imperceptible delays and slowly escalates. The ramp is controlled by `tarpit_min_delay_ms`, `tarpit_max_delay_ms`, and `tarpit_ramp_events` in the service config.
- `slowdrip.py` -- `SlowDripProfile`. Fragments file downloads into small chunks with randomized pauses between them. The result looks like a congested server, not a deliberate slowdown.
- `infinite_exfil.py` -- `InfiniteExfilStream`. Generates data streams that never end. Used for the infinite backup download endpoint -- the attacker's progress bar keeps moving but the download never completes.

**`clownpeanuts/core/session.py`** -- Session and event correlation. Tracks attacker sessions by source IP and behavioral fingerprint. Each session accumulates events (connections, commands, file accesses, credential attempts) into a correlated timeline. The backend can be in-memory (for development) or Redis (for persistence across restarts and cross-process visibility).

**`clownpeanuts/core/event_bus.py`** -- Event distribution. When something happens in the runtime (a new connection, a command executed, an alert triggered), the event bus publishes it to all subscribers. Subscribers include the alert router, the API's WebSocket stream, and the intelligence pipeline. Like the session backend, the event bus can be in-memory or Redis-backed.

### Intelligence and Operations Plane

This plane transforms raw telemetry into structured intelligence and exposes it through operator-facing interfaces.

**`clownpeanuts/intel/`** -- The intelligence pipeline. This is a collection of processors that each add a different dimension of analysis:

- `collector.py` -- Orchestrates the transformation from raw session data into intelligence report objects. Calls each downstream processor and assembles the final output.
- `classifier.py` -- Assigns an attacker profile to each session based on behavior patterns. Categories range from automated scanners to advanced persistent threats.
- `mitre.py` -- Maps observed behavior to MITRE ATT&CK techniques. Also tracks coverage -- which techniques your honeypot is currently detecting -- and identifies gaps.
- `scoring.py` -- Calculates engagement scores based on session depth, dwell time, techniques used, and interaction sophistication.
- `fingerprints.py` -- Identifies specific tools by their behavioral signatures (command patterns, timing, protocol-level artifacts).
- `behavior.py` -- Kill-chain analysis. Tracks attacker progression through reconnaissance, initial access, privilege escalation, lateral movement, and exfiltration stages. Also captures timing patterns between stages.
- `biometrics.py` -- Behavioral biometrics. Analyzes typing speed, command intervals, and interaction cadence to create profiles that can link sessions from the same human operator.
- `credentials.py` -- Cross-session credential reuse detection. When the same username/password combination appears in multiple sessions, it may indicate related attackers or a shared credential list.
- `canary.py` -- Canary token generation and hit tracking. Produces trackable tokens (DNS, HTTP, email, AWS key, code markers) and records when they're triggered.
- `source.py` -- Source IP enrichment. Adds ASN, geographic, and ISP context to source addresses.
- `rotation.py` -- Threat intelligence feed rotation scheduler. Pulls from external feeds and adjusts bait content based on current scanning trends.
- `export.py` -- STIX 2.1 and TAXII export formatting, ATT&CK Navigator layer export rendering, and Theater action-history export adapters (`json/csv/tsv/ndjson/jsonl/logfmt/cef/leef/syslog`).
- `store.py` -- SQLite-backed persistent storage for intelligence reports and canary history.

**`clownpeanuts/alerts/`** -- Alert routing and delivery:

- `router.py` -- Evaluates incoming events against configured routing rules (severity filters, service filters, action filters, throttling) and dispatches to matching destinations.
- `webhook.py`, `slack.py`, `discord.py`, `pagerduty.py`, `email.py`, `syslog.py` -- Delivery adapters for each notification channel.

**`clownpeanuts/dashboard/api.py`** -- FastAPI operations backend. Provides REST endpoints for intelligence reports, session data, session replay (`/sessions/{session_id}/replay`), kill-chain visualizations, ATT&CK coverage, alert status, canary management, diagnostics, and Theater action/recommendation workflows (including filtered action export adapters). Also serves WebSocket endpoints (`/ws/events`, `/ws/theater/live`) for real-time dashboard and Theater updates.

**`/dashboard` (Next.js)** -- The operator-facing web UI. Built with Next.js 14, React 18, and D3 charting. Provides views for live engagement monitoring, attacker profiles, kill-chain visualization, ATT&CK coverage heatmaps, canary status, template management, service health, Theater queue/action workflows (`/theater`), and replay drilldown workflows (`/theater/replay/{session_id}`). Dashboard websocket clients include reconnect/backoff handling and freshness telemetry indicators for degraded stream visibility. The current UI baseline also includes a Swiss-style high-contrast visual system and responsive max-width containment to preserve layout integrity on very wide viewports.

---

## Runtime Data Flow

Here's what happens when an attacker connects to a ClownPeanuts emulator, step by step:

1. **Connection arrives.** An attacker connects to one of the emulated service ports (e.g., SSH on 2222).

2. **Emulator handles the protocol.** The service emulator manages the protocol-level interaction -- SSH handshake, HTTP request parsing, database wire protocol, etc. It logs the connection metadata (source IP, client version, timing).

3. **Session is created or resumed.** The session manager checks whether this source IP already has an active session. If so, events are appended to the existing session. If not, a new session is created with a unique ID and the world model is initialized.

4. **Attacker input goes to the engine.** When the attacker does something meaningful (runs a command, submits a query, requests a file), the emulator sends the input to the Rabbit Hole Engine along with the session's current world model.

5. **Engine generates a response.** The engine looks up the appropriate response strategy -- template fast-path for common commands, full context generation for complex interactions, or LLM invocation for dynamic responses. The response is consistent with the session's world model (previously "discovered" files, users, and credentials remain consistent).

6. **Tarpit applies friction.** Before the response is sent back, the tarpit layer adds adaptive delay. Early in the session, delays are imperceptible. As the session progresses, they ramp up gradually.

7. **Event is published.** The event bus publishes a structured event envelope containing the session ID, timestamp, service name, action type, and relevant metadata.

8. **Downstream consumers react.** The alert router evaluates the event against routing rules and dispatches notifications. The API's WebSocket stream forwards the event to the dashboard. The intelligence pipeline updates its accumulators.

9. **Response goes to the attacker.** The emulator sends the generated response back through the protocol connection.

---

## Trust Boundaries

### Boundary 1: Internet to Honeypot Edge

Attacker-controlled input enters the system through protocol emulators. This traffic is intentionally allowed -- the whole point is to accept connections from adversaries. The emulators are designed to handle malformed, malicious, and unexpected input safely. They don't execute attacker commands on the real host; they generate fake responses that simulate execution.

### Boundary 2: Honeypot Runtime to Intelligence/Operations

Telemetry generated by the runtime plane crosses into the intelligence and operations plane. At this boundary, raw interaction data is transformed into structured reports, alert payloads, and API responses. The intelligence pipeline operates on event data -- it doesn't have access to the raw protocol streams.

### Boundary 3: Honeypot Stack to Production Infrastructure

This boundary must remain absolute. There should be no network path from any ClownPeanuts component (emulators, engine, API, dashboard) to your production infrastructure. ClownPeanuts validates this at startup through configurable isolation checks (network segmentation verification, firewall rule validation, Docker network verification), but the underlying network architecture is your responsibility.

---

## Isolation and Runtime Controls

ClownPeanuts provides several mechanisms for verifying and enforcing isolation:

- **Network validation at bootstrap.** The orchestrator checks segmentation mode, firewall presence, and Docker network configuration before starting services. Violations can be treated as warnings or hard failures depending on `enforce_runtime` and `require_segmentation` settings.

- **Firewall rule management.** ClownPeanuts can apply egress control rules using the host's firewall backend (`iptables`, `nft`, or `pfctl`). A dry-run mode lets you preview rules before applying them.

- **Docker Compose resource caps.** Container memory and CPU limits are set in the Compose file and can be overridden with environment variables. This prevents attackers from consuming excessive compute if they attempt resource abuse.

- **Outbound traffic control.** By default, `allow_outbound` is `false`, which means honeypot services cannot make outbound connections. Only specific exceptions listed in `allowed_egress` are permitted (typically just the Redis instance used for session/event state).

---

## Intentional Deception Characteristics

Some behavior that looks like a defect is intentional. This is important context for anyone reading the codebase or auditing the deployment:

- **Simulated misconfiguration.** Services present themselves as under-hardened or misconfigured. Weak authentication, missing TLS, overly permissive access -- these are deliberate design choices that make the honeypot look like a realistic target.

- **Fake secrets and artifacts.** Credentials, API keys, SSH keys, and configuration files scattered throughout the fake environment are bait. They look real but point to other parts of the deception layer.

- **Attractive decoy endpoints.** Paths like `/backup.sql.gz`, `/api/internal/search`, and `/.env` are designed to attract attacker interest and lead them deeper into the tarpit.

These are core deception mechanics, not accidental implementation drift. If you're contributing to the codebase, preserve these behaviors unless you're specifically redesigning the deception posture.

---

## Deployment Topologies

### Local Development

- **CLI mode**: Emulators run in a single Python process. Session/event state is in-memory. No containers, no Redis.
- **CLI + API + Dashboard**: API runs as a separate process (or with `--start-services` for co-located emulators). Dashboard runs in dev mode via `npm run dev`. Redis optional (falls back to in-memory).
- **One-command demo mode**: `scripts/dev-up-demo.sh` starts API + dashboard on alternate safe local ports, generates `config/local-theater-demo.yml`, seeds initial traffic, and enables narrative/bandit/theater for immediate operator workflow validation.

### Docker Compose: Core Profile

- `clownpeanuts` container: Core runtime with all enabled emulators.
- `redis` container: Session and event bus backend.
- No API or dashboard.

### Docker Compose: Ops Profile

- `api` container: FastAPI server with `--start-services` (co-located emulators).
- `dashboard` container: Next.js frontend in production build.
- `redis` container: Session and event bus backend.
- All services connected via a Docker bridge network with resource limits.

---

## Further Reading

- [User Guide](user-guide.md) -- Complete setup and operations reference.
- [Current State](current-state.md) -- What's implemented right now.
- [Public Extension Boundary](public-extension-boundary.md) -- Public integration contracts and standalone guarantees.
