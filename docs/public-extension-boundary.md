# Public Extension Boundary

Last reviewed: **February 21, 2026**

This document defines what is intentionally public in ClownPeanuts for optional module integration, and what is expected to live outside this repository.

---

## Scope

Public repository responsibilities:

- Stable API contracts and route shapes.
- Stable config schema fields for extension wiring.
- Baseline adapter implementations for local development/testing.
- Compatibility guarantees for standalone operation.

Private repository responsibilities:

- Advanced module behavior and proprietary decision logic.
- Specialized data models and workflows behind optional module APIs.
- Deployment-specific tuning and optimization for optional modules.

---

## Public Contracts

### 1) API Surface Contracts

When `ecosystem.enabled=true` and module flags are enabled:

- `/ecosystem/pripyatsprings/*`
- `/ecosystem/adlibs/*`
- `/ecosystem/dirtylaundry/*`
- `/ecosystem/agents/status`

Route paths, HTTP methods, and payload shapes are public compatibility contracts.

### 2) Config Wiring Contracts

Optional backend delegation hooks:

- `agents.pripyatsprings.backend`
- `agents.adlibs.backend`
- `agents.dirtylaundry.backend`

Format:

- `package.module:ClassName`
- or `package.module.ClassName`

If unset, ClownPeanuts uses built-in baseline adapters.

### 3) Runtime Compatibility Contracts

- All optional module flags are disabled by default.
- With `ecosystem.enabled=false`, optional module routes return `404`.
- Baseline ClownPeanuts CLI/API/dashboard/runtime behavior must remain functional with no optional module backends configured.

---

## Backend Class Expectations

External backends must provide the same callable methods as the corresponding public manager classes:

- `PripyatSpringsManager` contract methods:
  - `close`, `status`, `resolve_toxicity_level`, `register_fingerprint`, `list_fingerprints`, `list_fingerprints_filtered`, `record_hit`, `list_hits`, `list_hits_filtered`, `transform`
- `ADLibsManager` contract methods:
  - `close`, `validate`, `seed`, `list_objects`, `list_objects_filtered`, `delete_object`, `list_trips`, `record_trip`
- `DirtyLaundryManager` contract methods:
  - `close`, `ingest_session`, `list_profiles`, `profile_detail`, `profile_sessions`, `add_note`, `stats`, `share_export`, `share_import`, `share_push`, `share_pull`

If a configured backend cannot be imported/instantiated or does not satisfy the method contract, startup fails fast with a backend load error.

---

## Example Wiring

```yaml
ecosystem:
  enabled: true
agents:
  pripyatsprings:
    enabled: true
    backend: "private_pripyatsprings.runtime:Backend"
  adlibs:
    enabled: true
    backend: "private_adlibs.runtime:Backend"
  dirtylaundry:
    enabled: true
    backend: "private_dirtylaundry.runtime:Backend"
```

---

## Documentation Policy

Public docs in this repository should describe:

- interfaces,
- schema contracts,
- compatibility constraints.

Public docs should avoid publishing deep private implementation logic for optional modules.
