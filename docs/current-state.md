# Current State Snapshot

Date: **February 22, 2026**

This document is the current capability and validation inventory for ClownPeanuts at repository head. It is intentionally concrete and operationally focused: if a feature is described here, it exists in code today. For deployment and operational procedure details, use `user-guide.md`.

---

## Executive Summary

ClownPeanuts is in a mature, fully functional state as a standalone deception platform.

At current head, the platform delivers:

- Seven protocol emulators (SSH, HTTP admin, Redis, MySQL, PostgreSQL, MongoDB, Memcached) with structured telemetry.
- Stateful Rabbit Hole deception (world model, credential cascades, lateral movement illusions, oops artifacts).
- Optional local-LLM response backend with cooldown/fallback controls (`lmstudio` and `ollama` providers).
- Narrative + contextual bandit + Theater workflows across CLI, API, and dashboard.
- Persistent intelligence/canary history (SQLite), plus STIX 2.1, TAXII 2.1, and ATT&CK Navigator export surfaces.
- Alert routing across six adapter types with filters and route-preview tooling.
- Responsive, high-contrast dashboard UX with resilient websocket reconnect behavior and replay drilldown workflows.

---

## Capability Inventory

### 1) Runtime Deception Surface

Implemented emulator modules:

- `clownpeanuts/services/ssh/emulator.py`
- `clownpeanuts/services/http/emulator.py`
- `clownpeanuts/services/database/redis_emulator.py`
- `clownpeanuts/services/database/mysql_emulator.py`
- `clownpeanuts/services/database/postgres_emulator.py`
- `clownpeanuts/services/database/mongo_emulator.py`
- `clownpeanuts/services/database/memcached_emulator.py`
- `clownpeanuts/services/dummy/emulator.py` (development placeholder)

Notable behavior currently implemented:

- SSH accepts after configurable failed attempts, captures commands, and feeds the deception engine.
- SSH shell realism includes common admin-enumeration command paths (`sudo -l`, `systemctl status ssh`, `journalctl -u ssh`, `last`, `ip route`) with coherent decoy output.
- SSH runtime realism additionally covers deeper host-enumeration workflows (`ip a`/`ifconfig`, `lsblk`, `mount`, `/etc/ssh/sshd_config` inspection, and `tail`/`grep` probes against auth logs and SSH config).
- HTTP admin includes login bait, slow-drip backup stream, infinite exfil stream, and query tarpit pagination.
- HTTP admin realism includes paginated internal operator-like APIs for user inventory and login-audit review (`/api/internal/users`, `/api/internal/login-audit`).
- Database emulators expose realistic-but-fake protocol interactions and tarpit delay controls.
- Redis emulator command realism now includes multi-key/stateful utility, hash, list, and set workflows (`MSET`, `MGET`, `SCAN`, `INCR`, `EXPIRE`, `PERSIST`, `TTL`, `PTTL`, `TYPE`, `HSET`, `HGET`, `HGETALL`, `HKEYS`, `HLEN`, `LPUSH`, `RPUSH`, `LPOP`, `RPOP`, `LLEN`, `LRANGE`, `LINDEX`, `LPOS`, `RPOPLPUSH`, `LMOVE`, `LINSERT`, `LSET`, `LTRIM`, `LREM`, `SADD`, `SREM`, `SMEMBERS`, `SISMEMBER`, `SMISMEMBER`, `SCARD`, `SRANDMEMBER`, `SPOP`, `SMOVE`, `SUNION`, `SINTER`, `SINTERCARD`, `SDIFF`, `SUNIONSTORE`, `SINTERSTORE`, `SDIFFSTORE`) with type-aware key handling.
- Protocol parser guards enforce maximum attacker-controlled payload sizes across HTTP/Redis/MongoDB/MySQL/PostgreSQL request reads and Memcached command-line parsing.
- MySQL/PostgreSQL prepared statement workflows enforce per-connection inventory caps (`1000`) with protocol-level rejection once caps are exceeded.
- SQL emulators now cover common enumeration paths (`information_schema`, `pg_catalog`, schema/table/column discovery, and `COUNT(*)` probes) with coherent fake datasets.
- MySQL emulator realism now includes index-enumeration/runtime metadata workflows (`SHOW INDEX`/`SHOW KEYS`, `SHOW CREATE TABLE`, `SHOW GRANTS`, `SHOW ENGINE INNODB STATUS`, `SHOW MASTER STATUS`, `SHOW BINARY LOGS`, `SHOW REPLICA STATUS`/`SHOW SLAVE STATUS`, and `information_schema.statistics`) with table-aware synthetic schema/index metadata.
- PostgreSQL emulator realism now includes `information_schema.columns`, `pg_indexes`, `pg_stat_activity`, `pg_locks`, `pg_stat_database`, `pg_stat_user_tables`, `pg_roles`, `pg_namespace`, `pg_extension`, `pg_settings`, `pg_stat_replication`, and replication-oriented `SHOW` introspection (`wal_level`, `max_wal_senders`) with table-aware synthetic metadata.
- MongoDB emulator now supports richer command realism (`listCollections`, `count`, `collStats`, `dbStats`, `serverStatus`, `getCmdLineOpts`, `replSetGetStatus`, `replSetGetConfig`, `connectionStatus`, `currentOp`, `getLog`, `whatsmyuri`, `hostInfo`, `usersInfo`, `rolesInfo`, `listIndexes`, `getParameter`, `listCommands`) plus non-empty `find`/`aggregate` sample batches.
- Memcached emulator supports richer mutation/audit command paths (`gets`, `cas`, `append`, `prepend`, `flush_all`, and segmented `stats` modes) with bounded object-size guards.
- Core emulators now implement protocol-aware synthetic activity injection hooks used by ecosystem APIs (`ssh_session`, `http_request`, SQL/NoSQL query injection, Redis command injection, Memcached cache-command injection) for ambient decoy-behavior workflows.
- MongoDB/Memcached are available but disabled by default in bundled defaults.

### 2) Rabbit Hole Engine

Implemented components:

- `clownpeanuts/engine/context.py` (world model)
- `clownpeanuts/engine/credentials.py` (credential cascade graph)
- `clownpeanuts/engine/lateral.py` (phantom lateral movement artifacts)
- `clownpeanuts/engine/oops.py` (operator-mistake artifact library)
- `clownpeanuts/engine/rabbit_hole.py` (response orchestration, backend switching, fallback logic)

Current behavior:

- Session-consistent world generation and discovery state.
- Cross-service deception continuity (commands/credentials/artifacts remain coherent inside session scope).
- Template fast-path for low-latency common interactions.
- Optional local LLM backend with:
  - timeout guardrails,
  - consecutive-failure threshold,
  - cooldown window,
  - automatic rule-based fallback.

### 3) Tarpit and Friction Controls

Implemented primitives:

- `clownpeanuts/tarpit/throttle.py`
- `clownpeanuts/tarpit/slowdrip.py`
- `clownpeanuts/tarpit/infinite_exfil.py`

Current behavior:

- Gradual latency ramps to increase attacker dwell time.
- Fragmented transfer patterns that mimic congestion.
- Endless exfil streams designed to occupy attacker tooling.
- Adaptive delay logic avoids blocking active async event loops while retaining delay telemetry metadata.

### 4) Intelligence and Analytics

Core processors and stores:

- `clownpeanuts/intel/collector.py`
- `clownpeanuts/intel/mitre.py`
- `clownpeanuts/intel/classifier.py`
- `clownpeanuts/intel/scoring.py`
- `clownpeanuts/intel/fingerprints.py`
- `clownpeanuts/intel/behavior.py`
- `clownpeanuts/intel/biometrics.py`
- `clownpeanuts/intel/credentials.py`
- `clownpeanuts/intel/source.py`
- `clownpeanuts/intel/export.py`
- `clownpeanuts/intel/store.py`

Current outputs:

- ATT&CK mapping + coverage/gap analysis.
- Session classification and engagement scoring.
- Tool fingerprinting.
- Kill-chain progression and graph summaries.
- Source geography and ASN rollups.
- Behavioral biometrics and credential reuse correlation.
- STIX/TAXII exports from live or historical report payloads.
- ATT&CK Navigator layer export for direct ATT&CK Navigator import workflows.
- Intelligence persistence now uses SQLite WAL-mode connections with concurrent-reader/single-writer lock behavior to improve multi-threaded event/report throughput.

### 5) Narrative, Bandit, Theater

Implemented modules:

- `clownpeanuts/engine/narrative.py`
- `clownpeanuts/intel/lure_bandit.py`
- `clownpeanuts/intel/simulator.py`
- `clownpeanuts/dashboard/theater.py`

Current behavior:

- Deterministic narrative world/session context.
- Bandit selection (`thompson`/`ucb`), safety caps, overrides, reset, observability.
- Counterfactual simulator via CLI (`simulate-bandit`) for policy A/B replay.
- Theater action flows:
  - recommendation inspection,
  - `apply_lure`,
  - `label`,
  - persisted action audit/history export.

### 6) Canary and Alerts

Canary:

- Token types: `dns`, `http`, `email`, `aws`, `code`.
- Hit ingestion API + CLI paths.
- Inventory and hit-history retrieval.

Alerts:

- Adapter types: webhook, slack, discord, syslog, email, pagerduty.
- Global and per-destination severity gating.
- Include/exclude filters for service/action fields.
- Throttle support plus routing preview without dispatch.

### 7) Operational Surfaces

CLI (verified command surface from `clownpeanuts/cli.py`):

- Runtime: `init`, `up`, `status`, `logs`, `doctor`, `api`
- Intel/reporting: `intel`, `intel-history`, `intel-handoff`, `intel-coverage`, `stix-export`, `taxii-export`, `navigator-export`
- Theater/bandit: `theater-history` (json/csv/tsv/ndjson/jsonl/logfmt/cef/leef/syslog export), `rotate`, `rotate-preview`, `simulate-bandit`, `replay`
- Replay comparison: `replay-compare`
- Replay comparison output now includes operator-facing summary + next-action guidance fields.
- Templates: `templates`, `templates-validate`, `templates-diff`
- Canary/alerts: `canary-generate`, `canary-hit`, `canary-types`, `canary-tokens`, `canary-hits`, `alerts-test`, `alerts-routes`

FastAPI (`clownpeanuts/dashboard/api.py`):

- Health/status/doctor endpoints.
- Optional ecosystem integration endpoints (all gated behind `ecosystem.enabled`):
  - Runtime lifecycle/orchestration: `/ecosystem/deployments*`, `/ecosystem/state`, `/ecosystem/activity/{deployment_id}*`, `/ecosystem/drift/*`, `/ecosystem/jit/*`, `/ecosystem/witchbait/*`.
  - Agent readiness/status: `/ecosystem/agents/status` (`disabled|blocked|ready` + `blockers`).
  - Public agent extension contracts: `/ecosystem/pripyatsprings/*`, `/ecosystem/adlibs/*`, `/ecosystem/dirtylaundry/*`.
  - ADLibs extensions include event-ingestion/correlation APIs (`/ecosystem/adlibs/events/catalog`, `/ecosystem/adlibs/events/ingest`, `/ecosystem/adlibs/events/ingest/batch`) for seeded-object trip generation from raw directory event feeds.
  - ADLibs and PripyatSprings now also expose aggregate trip/hit summary APIs (`/ecosystem/adlibs/trips/summary`, `/ecosystem/pripyatsprings/hits/summary`) for low-overhead operator triage and external orchestration polling.
  - DirtyLaundry extensions include policy-evaluation and session-reclassification APIs (`/ecosystem/dirtylaundry/sessions/evaluate`, `/ecosystem/dirtylaundry/sessions/reclassify`) alongside baseline ingestion/profile/share workflows.
  - DirtyLaundry now also exposes non-mutating attribution preview (`/ecosystem/dirtylaundry/sessions/preview`) for preflight profile-match checks.
  - Credential-trip registry now exposes non-mutating credential plan preview and trip summary endpoints (`/ecosystem/witchbait/credentials/preview`, `/ecosystem/witchbait/trips/summary`) in addition to register/list/delete/trip-history workflows.
  - Boundary contract: built-in baseline adapters are included for compatibility and local development; advanced module behavior can be delegated to external backends through `agents.<module>.backend` (`package.module:Class`).
  - Standalone contract: with `ecosystem.enabled=false` or module flags disabled, these module endpoints return `404` and baseline ClownPeanuts runtime behavior is unchanged.
- Campaign graph endpoints for attack-tree-style workflow composition (`GET /campaigns`, `GET|PUT|DELETE /campaigns/{campaign_id}`) with validated node/edge payload handling, status + prefix/query + graph-size filtering (`campaign_id_prefix`, `name_prefix`, `min_nodes`, `min_edges`, `query`), deterministic ordering controls (`sort_by`, `sort_order`), compact list mode (`compact=true`) on inventory views, portable inventory exports (`GET /campaigns/export?format=json|csv|tsv|ndjson|jsonl|logfmt`), and persisted graph version counters.
- Campaign workflow operations include status transitions (`POST /campaigns/{campaign_id}/status`), version-history retrieval (`GET /campaigns/{campaign_id}/versions`) with event/range/query/order controls (`event_type`, `min_version`, `max_version`, `query`, `sort_by`, `sort_order`) plus compact mode (`compact=true`), portable version-history exports (`GET /campaigns/{campaign_id}/versions/export?format=json|csv|tsv|ndjson|jsonl|logfmt`), and schema-tagged portability APIs (`POST /campaigns/import`, `GET /campaigns/{campaign_id}/export`) where embedded version exports support matching version-filter controls (`version_event_type`, `version_min`, `version_max`, `version_query`, `version_sort_by`, `version_sort_order`, `version_compact`).
- Campaign inventory/version read routes now use short-TTL response caching (including inventory/version export payload and rendered-output reuse) to reduce repeated graph/version recomputation and serialization overhead under rapid operator polling.
- Sessions + replay.
- Combined Theater replay payload endpoint (`/theater/sessions/{session_id}/bundle`) for one-shot replay + theater session refresh workflows.
- Session replay comparison endpoint (`/sessions/replay/compare`) with overlap/delta/similarity payloads.
- Theater live/session/recommendations/actions endpoints, plus action export route (`/theater/actions/export`) with `json|csv|tsv|ndjson|jsonl|logfmt|cef|leef|syslog` output adapters.
- Theater recommendations now support operator triage filters (`min_confidence`, `min_prediction_confidence`, `predicted_stage`, `lure_arm`, `context_key_prefix`, `apply_allowed_only`) and optional explanation suppression (`include_explanation=false`) with filtering metadata in response payloads.
- Template inventory/plan/validate/diff endpoints.
- Intel report/history/coverage and specialized views (profiles, fingerprints, kill-chain, geography, biometrics).
- SOC handoff summary endpoint (`/intel/handoff`) returning structured JSON plus direct markdown/csv/tsv/ndjson/jsonl/cef/leef/syslog/logfmt render modes (`?format=markdown|csv|tsv|ndjson|jsonl|cef|leef|syslog|logfmt`) for live or historical (`report_id`) intelligence payloads.
- `/dashboard/summary` supports optional batched handoff inclusion (`include_handoff=true`) alongside template/doctor toggles to keep dashboard polling consolidated.
- `/theater/live` now reuses short-TTL cached snapshots keyed by (`limit`, `events_per_session`) to reduce repeated live-view recomputation under high-frequency polling.
- `/theater/recommendations` now uses short-TTL cached base payloads before request-time filtering, supports compact payload mode (`compact=true`), exposes server-side ordering controls (`sort_by`, `sort_order`) with response-local ranking (`result_rank`), and supports additional queue slicing (`lure_arm`, `context_key_prefix`) for efficient triage polling.
- `/theater/actions` now reuses short-TTL cached responses keyed by full filter/sort query shape, memoizes parsed action timestamps during filter/sort passes, uses core-field fast-path query checks before payload/metadata serialization for lower triage-filter overhead, and supports actor/recommendation + session + prefix + free-text + timestamp-window filters (`actor`, `recommendation_id`, `session_id`, `actor_prefix`, `session_prefix`, `session_ids`, `query`, `created_after`, `created_before`), multi-action slicing (`action_types`), timestamp-aware ordering (`sort_by`, `sort_order`), and compact payload mode (`compact=true`) with response-local ranking (`result_rank`) for high-frequency triage polling.
- `/theater/actions/export` now reuses short-TTL cached base payloads keyed by filter/sort query shape and short-TTL cached rendered payloads before returning `json|csv|tsv|ndjson|jsonl|logfmt|cef|leef|syslog` output adapters.
- `/intel/handoff` now reuses short-TTL cached rendered handoff payloads for repeated identical request shapes, reducing export recomputation overhead.
- Bandit control/observability endpoints.
- STIX/TAXII endpoints including TAXII 2.1 discovery and collection routes.
- ATT&CK Navigator endpoints (`/intel/attack-navigator`, `/intel/attack-navigator/history/{report_id}`).
- WebSockets: `/ws/events`, `/ws/theater/live`.
- `/ws/events` supports cursor/batch polling controls (`cursor`, `batch_limit`, `interval_ms`), optional batched payload mode (`format=batch`), server-side filters (`topic`, `service`, `action`, `session_id`), and payload-trim mode (`include_payload=false`) to reduce high-volume websocket overhead.
- Redis-backed session export now uses a created-at sorted index with stale-index pruning to avoid full session-index sorting on each export.
- Shared short-TTL intelligence report caching now underpins `/intel/*` read endpoints so equivalent repeated polling requests reuse one computed report snapshot.
- Intel report cache behavior is tunable via `api.intel_report_cache_ttl_seconds` (set to `0` to disable cache reuse).
- API hardening controls via config (`api.docs_enabled`, `api.cors_allow_origins`, `api.trusted_hosts`, `api.auth_enabled`, operator/viewer tokens, `api.rate_limit_*`, `api.max_request_body_bytes`).
- Bundled runtime profiles now require explicit Redis credentials via `CP_REDIS_PASSWORD` interpolation (including `clownpeanuts/config/defaults.yml`) for Redis-backed session/event-bus URLs.
- Dashboard server route `/api/auth/session` now bootstraps browser auth via httpOnly `cp_api_token` cookie sourced from `CLOWNPEANUTS_API_TOKEN`, and API/websocket auth accepts that cookie token in addition to header/subprotocol paths.
- API middleware enforces request-size caps on mutation methods using `api.max_request_body_bytes` and returns HTTP `413` for oversized request bodies, including fallback size checks when `Content-Length` is missing or malformed.
- API startup now defensively rejects wildcard CORS with credentials (`api.cors_allow_credentials=true` with `api.cors_allow_origins` containing `*`) even when app config is constructed programmatically outside parser validation.
- `doctor` diagnostics include explicit Redis backend auth checks for both `session` and `event_bus` when configured in Redis mode, plus production API hardening posture checks including required API auth + non-empty operator tokens, minimum token-length enforcement (`>=24`) for operator/viewer tokens, rejection of placeholder API tokens (`replace-with-*`/`change-me` style values), required role-separated operator/viewer token sets, required authenticated health posture (`api.allow_unauthenticated_health=false`), required API rate limiting, bounded request-body limits, restrictive rate-limit exemption paths, bounded rate-limit burst posture (`rate_limit_burst <= rate_limit_requests_per_minute`), and bounded sustained production rate caps (`rate_limit_requests_per_minute <= 5000`).
- Ecosystem config now includes optional pre-seeded credential registry input (`ecosystem.witchbait_credentials`) and JIT lifecycle controls (`ecosystem.jit.enabled`, `ecosystem.jit.pool_size`, `ecosystem.jit.ttl_idle_seconds`, `ecosystem.jit.ttl_max_seconds`).
- Agent-module config namespaces now exist under `agents.*` (PripyatSprings, ADLibs, DirtyLaundry), with runtime status surfaced via orchestrator/API while keeping all modules disabled by default.
- Module config now supports backend delegation via `agents.pripyatsprings.backend`, `agents.adlibs.backend`, and `agents.dirtylaundry.backend` for private backend packages.

Dashboard (`/dashboard`):

- Main operations page (`/`) + Theater (`/theater`) + replay drilldown (`/theater/replay/<session_id>`).
- Stream reconnect/backoff and freshness indicators for degraded visibility.
- Theater live view now prefers websocket updates and falls back to slower HTTP polling cadence, reducing duplicate live summary fetch pressure during stable websocket connectivity.
- Replay fetch/refresh loops and bookmark-centric triage workflow.
- Responsive Swiss-style visual system:
  - high-contrast palette and strict typographic hierarchy,
  - asymmetrical but structured grid alignment,
  - desktop max-width containment to prevent ultra-wide drift,
  - invisible alignment grid approach (no visible overlay in runtime UI).
- Cross-repo control-plane integration status:
  - Shared multi-product operator UI/API now lives in SquirrelOps (`apps/controlplane-dashboard`, `apps/controlplane-api`).
  - ClownPeanuts endpoints are consumed there via `/deception/*` proxy and websocket relays (`/deception/ws/events`, `/deception/ws/theater/live`).
  - ClownPeanuts-local dashboard remains present for runtime-focused development and compatibility during cutover.

### 8) Platform and Deployment

- Threat-intel rotation scheduler using `threat_intel.rotation_interval_seconds`.
- HTTPS threat-intel feed fetch now re-resolves and re-validates public DNS targets immediately before request dispatch, reducing DNS-rebind drift risk for operator-configured feed URLs.
- Template path parsing now rejects relative `templates.paths` entries that escape the current workspace root, reducing operator misconfiguration blast radius for local file reads.
- Session metadata guardrails now cap per-session tag count and narrative touched-service count, limiting untrusted session-state growth.
- Multi-tenant override model with tenant-scoped planning/diff support.
- Deception templates with validation and diff matrix support.
- Red-team suppression controls (`red_team.*`) with retained telemetry.
- Network policy validation + optional firewall apply support (`iptables`, `nft`, `pfctl`).
- Docker Compose profiles:
  - `core`: emulator runtime + Redis.
  - `ops`: API (`--start-services`) + dashboard + Redis.
- Hardened deployment baseline config at `config/production-hardened.yml` with API auth enabled, docs disabled, explicit CORS/trusted-host defaults, and required Redis backends with credentialed URLs.
- Bundled starter config at `config/clownpeanuts.yml` now requires `CP_REDIS_PASSWORD` and uses credentialed Redis URLs to avoid unauthenticated Redis posture drift.
- Reverse-proxy hardening profile at `config/production-reverse-proxy.yml` provides auth-on/docs-off/operator token defaults with proxy-friendly host/origin allowlists for loopback-bound API deployments.
- Production and reverse-proxy hardened profiles now enable built-in API/WebSocket rate limiting defaults for operator-surface abuse resistance.
- Production and reverse-proxy hardened profiles now set conservative `api.max_request_body_bytes` defaults for operator API exposure.
- Session and event-bus Redis backend initialization logs now redact Redis URL passwords before emitting telemetry.
- SIEM HTTP forwarding now periodically re-validates endpoint DNS targets and rejects drifted public resolution sets, reducing DNS-rebind risk for operator-configured SIEM endpoints.
- One-command local demo scripts:
  - `scripts/dev-up-demo.sh`
  - `scripts/dev-down-demo.sh`

---

## Validation Baseline (Latest Local Run)

Executed on **February 21, 2026**:

1. Python tests
   - Command: `.venv/bin/pytest`
   - Result: `449 passed`

2. Dashboard production build
   - Command: `cd dashboard && npm run build`
   - Result: success, all app routes compiled (`/`, `/theater`, `/theater/replay/[sessionId]`).

3. Runtime smoke (default config)
   - Command: `.venv/bin/clownpeanuts up --once --config clownpeanuts/config/defaults.yml`
   - Result: failed in local environment with `OSError: [Errno 48] Address already in use` (expected when default bait ports are occupied by another local process/stack).

4. Runtime smoke (demo-safe config)
   - Command: `.venv/bin/clownpeanuts up --once --config config/local-theater-demo.yml`
   - Result: clean startup and shutdown on alternate local ports (`3222`, `28080`), with expected warnings for non-enforced segmentation in demo mode.

Interpretation:

- Codebase health is green (tests/build).
- Runtime startup logic is healthy.
- Default-port smoke reliability depends on local port availability; demo-safe config provides conflict-resistant validation path.

---

## Intentional Deception Behaviors (Do Not “Fix” by Default)

These are deliberate trap mechanics:

- Weak/accepting authentication patterns.
- Planted credentials and “oops” artifacts.
- Open-looking data paths (slow-drip/infinite exfil patterns).
- Unauthenticated-seeming database surfaces.
- Debug-style metadata leaks in fake environment artifacts.

Any changes here should be treated as deception-strategy decisions, not routine hardening.

---

## What Is Not a Current Blocker

At this head:

- No known functional gap prevents end-to-end local operation (CLI/API/dashboard/demo scripts all present).
- Remaining work areas are incremental enhancement lanes (deeper protocol realism, scaling ergonomics, and additional export interoperability), not missing foundations.
