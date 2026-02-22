# ClownPeanuts Agent Handoff

This repository is intended to be executable by new coding agents without prior chat context.

## Primary Source of Truth

1. `/docs/user-guide.md` contains the complete setup and operations runbook.
2. `/docs/current-state.md` contains the implementation and validation snapshot at repository head.
3. `/docs/architecture.md` documents runtime boundaries, trust zones, and deployment topology.
4. `/docs/public-extension-boundary.md` defines public integration contracts and standalone guarantees.
5. `/docs/agent-handoff.md` defines contributor quick-start and safe working rules.

## Current Build State

- ClownPeanuts is a fully operational standalone deception platform.
- CLI commands cover runtime control, intelligence/reporting, exports, templates, alerting, canary workflows, replay, and Theater workflows.
- Service emulators implemented: SSH, HTTP admin, Redis, MySQL, PostgreSQL, MongoDB, Memcached.
- Rabbit Hole engine is implemented (stateful world model, credential cascade, lateral movement artifacts, oops artifacts, optional local LLM backend).
- Narrative engine, adaptive lure bandit, and Theater workflow stack are implemented.
- Alert routing adapters implemented (webhook/Slack/Discord/syslog/email/PagerDuty).
- FastAPI operations backend and Next.js dashboard are implemented.
- Optional ecosystem integration APIs are implemented and gated behind `ecosystem.enabled`.
- Docker Compose profiles are wired for local bootstrap (`core`) and full operator stack (`ops`).
- Expanded test coverage exists under `/tests` (current baseline: `443 passed`).

## Constraints

- License: PolyForm Noncommercial 1.0.0 for all source and docs.
- Defensive-only posture: passive deception and intelligence collection only.
- No network path from honeypot containers to production infrastructure.
- When implementing capabilities inspired by external platforms, do not name those systems explicitly in repository docs, code comments, commit messages, or user-facing text. Describe capabilities in neutral terms.

## Immediate Next Priorities

1. Protocol realism depth improvements (SSH/database/HTTP fidelity).
2. Operator UX refinements (triage ergonomics, replay workflows, template editing UX).
3. Deployment posture controls for stricter hardening profiles.
4. Intelligence export interoperability expansion.
5. Performance and scale optimization for higher event/session volume.
