# Agent Handoff Guide

This guide is for contributors and coding agents starting work in this repository without prior chat context.

## Source-of-Truth Order

When there is ambiguity, use this order:

1. `docs/current-state.md`
2. `docs/user-guide.md`
3. `docs/architecture.md`
4. `docs/public-extension-boundary.md`

## First 15 Minutes

### 1. Install and verify

```bash
git clone git@github.com:mattmacrocket/clownpeanuts.git
cd clownpeanuts
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev,api]
.venv/bin/pytest
```

Expected current result: `443 passed`.

### 2. Build dashboard once

```bash
cd dashboard
npm install
npm run build
cd ..
```

If your task is cross-product operator UX/API (Overview/Deception/Sentry/Orchestration), use the sibling `squirrelops` repository.

### 3. Smoke runtime

Use the conflict-resistant demo profile first:

```bash
.venv/bin/clownpeanuts up --once --config config/local-theater-demo.yml
```

Why: default profiles bind common bait ports that may already be occupied on developer workstations.

### 4. Optional full local demo

```bash
./scripts/dev-up-demo.sh
```

Stop with:

```bash
./scripts/dev-down-demo.sh
```

## Current Project Reality

At repository head, ClownPeanuts includes:

- Seven emulators (SSH, HTTP admin, Redis, MySQL, PostgreSQL, MongoDB, Memcached).
- Stateful Rabbit Hole deception engine with session-scoped continuity.
- Intelligence pipeline with persistence and export surfaces.
- Narrative + bandit + Theater live/replay workflows.
- FastAPI backend + websocket streams + Next.js dashboard.
- Optional ecosystem APIs (deployment lifecycle, activity injection, drift compare, JIT lifecycle, credential-trip registry, optional module contracts), all gated behind `ecosystem.enabled`.
- Public extension contracts for optional module delegation (`agents.pripyatsprings.backend`, `agents.adlibs.backend`, `agents.dirtylaundry.backend`).
- Standalone-by-default behavior (optional integrations disabled by default).

## High-Value Commands

```bash
# Runtime lifecycle
.venv/bin/clownpeanuts up --config ./config/clownpeanuts.yml
.venv/bin/clownpeanuts status --config ./config/clownpeanuts.yml
.venv/bin/clownpeanuts doctor --config ./config/clownpeanuts.yml

# API (with in-process emulators)
.venv/bin/clownpeanuts api --config ./config/clownpeanuts.yml --host 127.0.0.1 --port 8099 --start-services

# Intelligence
.venv/bin/clownpeanuts intel --config ./config/clownpeanuts.yml
.venv/bin/clownpeanuts intel-history --config ./config/clownpeanuts.yml --limit 20
.venv/bin/clownpeanuts intel-handoff --config ./config/clownpeanuts.yml --format markdown --output ./exports/soc-handoff.md

# Replay + Theater
.venv/bin/clownpeanuts replay --config ./config/clownpeanuts.yml --session-id <id> --events-limit 500 --bootstrap
.venv/bin/clownpeanuts replay-compare --config ./config/clownpeanuts.yml --left-session-id <id-a> --right-session-id <id-b> --events-limit 500 --bootstrap
.venv/bin/clownpeanuts theater-history --config ./config/clownpeanuts.yml --limit 200

# Templates and alerts
.venv/bin/clownpeanuts templates --config ./config/clownpeanuts.yml
.venv/bin/clownpeanuts templates-validate --config ./config/clownpeanuts.yml --all-tenants
.venv/bin/clownpeanuts alerts-routes --config ./config/clownpeanuts.yml --severity high --service ssh --action command
```

## Things That Look Wrong but Are Intentional

Do not “fix” these without explicit direction:

- Accept-after-failure authentication behavior.
- Deliberately leaked-looking credentials/artifacts.
- Open-looking backup/debug surfaces used as bait.
- Unauthenticated-style database responses in decoys.

These are core deception mechanics.

## Safe Working Rules

1. Run tests/build before and after meaningful changes.
2. Preserve defensive-only behavior and isolation guarantees.
3. Keep optional integrations additive and gated.
4. Update docs for operator-visible changes (CLI/API/config/dashboard).
5. Avoid naming external systems in code/docs/commits when describing capability goals.

## Where To Dive Deeper

- `docs/user-guide.md`: setup and operations runbook.
- `docs/current-state.md`: implementation inventory.
- `docs/architecture.md`: internals and trust boundaries.
- `docs/public-extension-boundary.md`: public/private integration contract.
