# Documentation

This directory contains current-state, operator-facing documentation for ClownPeanuts.

## Documents

| Document | What It Covers | When to Read It |
| --- | --- | --- |
| **[User Guide](user-guide.md)** | Complete setup and operations runbook. Deployment modes, full configuration reference, day-2 workflows, troubleshooting, and operator cadence. | You are setting up or operating ClownPeanuts. |
| **[Architecture](architecture.md)** | Internal component structure, runtime data flow, trust boundaries, and deployment topology. | You want to understand internals before changing config or code. |
| **[Current State](current-state.md)** | Current implementation snapshot, command/API surface summary, and validation baseline. | You want to know exactly what exists at repository head. |
| **[Public Extension Boundary](public-extension-boundary.md)** | Public integration contracts for optional module backends and standalone compatibility constraints. | You are integrating optional modules or validating public/private boundaries. |
| **[Agent Handoff](agent-handoff.md)** | Quick-start guide for contributors and coding agents. | You are starting fresh in this repository. |

## Recommended Reading Order

1. **User Guide**
2. **Architecture**
3. **Current State**
4. **Public Extension Boundary**
5. **Agent Handoff**

Cross-repo note: the shared multi-product operator control-plane (Overview/Deception/Sentry/Orchestration) lives in [SquirrelOps](https://github.com/rocketweb/squirrelops). ClownPeanuts-local dashboard paths remain documented here for runtime-focused workflows and compatibility.

Integration note: optional integrations are additive. Core ClownPeanuts runtime behavior and baseline ClownPeanuts + SquirrelOps + PingTing operation remain supported without them.
