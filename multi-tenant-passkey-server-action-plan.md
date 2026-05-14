# Multi-Tenant Passkey Server — Action Plan

**Version**: 1.0
**Date**: 2026-05-15
**Source PRD**: Multi-Tenant Passkey Server — PRD v1.0 (2026-05-15)
**Context**: Internal Tool (Company B2B Product)
**Status**: Draft

---

## 1. Executive Summary

This Action Plan breaks the Multi-Tenant Passkey Server PRD into an executable, single-developer plan. All PRD P0 scope is retained — no features are cut — but the timeline is recalibrated to a realistic solo-development pace. The estimate unit is **relative weeks (W1 = project start)**. The PRD's original 12-week timeline assumed a small focused team; for one backend developer the realistic v1 window is **W1–W26**, sequenced so that a working WebAuthn core exists by W9 and the full customer-facing platform is launch-ready by W26.

## 2. Scope Confirmation

### In Scope (v1)

| Priority | Feature | Complexity | Notes |
|----------|---------|------------|-------|
| P0 | WebAuthn core (registration/authentication) | High | webauthn4j-based; correctness-critical (signature counter, RP ID/origin) |
| P0 | Multi-tenant data model & isolation | High | Shared-schema + `tenant_id` + PostgreSQL RLS; highest-risk area |
| P0 | Credential lifecycle management | Medium | Register, list, rename, revoke; multi-credential per user |
| P0 | Exception infrastructure & standardized error codes | Low | Per uploaded "Spring Boot API Response Template" — reusable foundation |
| P0 | Session & token issuance layer | Medium | JWT, refresh tokens, RP API key management |
| P0 | RP onboarding & management console | High | Self-service tenant provisioning, API key mgmt, config, funnel visibility |
| P0 | Client JS SDK | High | Drop-in browser SDK wrapping WebAuthn ceremonies |
| P0 | Attestation policy management | Medium | Per-tenant AAGUID allow/deny, MDS/BLOB integration |
| P0 | Rate limiting & abuse prevention | Medium | Redis-backed per-tenant/per-endpoint limits |
| P0 | Audit logging | Medium | Append-only, hash-chain integrity, partitioned tables |
| P0 | Account recovery flow | Medium | Multi-credential fallback, RP-managed recovery, documented self-service limits |
| P0 | Monitoring & health checks | Low | Liveness/readiness, key metrics, per-tenant health |
| P0 | Platform documentation | Medium | Integration guide, API reference, error catalog, SDK docs |

### Deferred (v2+)

Carried over unchanged from the PRD — not part of this Action Plan's scope.

| Feature | Reason |
|---------|--------|
| Conditional UI (autofill passkey) | UX enhancement; needs SDK maturity first |
| Cross-device authentication (QR / hybrid) | High flow complexity; defer to v2 |
| Webhooks | Not blocking for core auth |
| Native mobile SDKs (iOS/Android) | Web-first launch via JS SDK |
| IdP integration (OIDC/SAML) | Separate authorization-layer effort |
| Multi-region HA | Single-region acceptable for v1 |
| SOC2 / formal certification | Pursue after first customer is live |
| On-prem / financial-cloud isolated deployment | v1 is public multi-tenant SaaS by decision |
| CXP/CXF support | FIDO Alliance standard still maturing |

## 3. Task Breakdown (WBS)

Effort is expressed as a **week span** (e.g., W3–W5). A solo developer works one major track at a time; parallelism is minimal and reflected in the sequencing.

### 3.1 Infrastructure / Foundation

| ID | Task | Description | Estimated Effort | Dependencies | Priority |
|----|------|-------------|-----------------|--------------|----------|
| INF-001 | Project scaffolding | Spring Boot 3.5.x + Java 21 project setup, package structure, build config (Gradle) | W1 | - | P0 |
| INF-002 | Local environment | Docker Compose for PostgreSQL + Redis; local run profile | W1 | INF-001 | P0 |
| INF-003 | Flyway migration baseline | Flyway integration, baseline migration, migration conventions | W2 | INF-002 | P0 |
| INF-004 | CI pipeline | Build + test + lint pipeline on commit | W2 | INF-001 | P0 |
| INF-005 | Deployment environment | Provision SaaS hosting environment, secrets management, deploy pipeline | W21–W22 | INF-004, BE-016 | P0 |

### 3.2 Backend — Core Foundation

| ID | Task | Description | Estimated Effort | Dependencies | Priority |
|----|------|-------------|-----------------|--------------|----------|
| BE-001 | Exception infrastructure | `ApiResponse<T>`, `ErrorCode` registry, `BusinessException`, `GlobalExceptionHandler`, `TraceIdFilter` — per uploaded API Response Template | W3 | INF-003 | P0 |
| BE-002 | Multi-tenant data model | `tenant` table, `tenant_id` on all tenant-scoped tables, tenant context resolution (filter/interceptor) | W3–W4 | BE-001 | P0 |
| BE-003 | PostgreSQL RLS policies | Row-Level Security policies enforcing tenant isolation at DB layer; session-variable wiring from app context | W4–W5 | BE-002 | P0 |
| BE-004 | Tenant isolation test suite | Cross-tenant access tests proving RLS holds even on missing app-layer filters | W5 | BE-003 | P0 |

### 3.3 Backend — WebAuthn Core

| ID | Task | Description | Estimated Effort | Dependencies | Priority |
|----|------|-------------|-----------------|--------------|----------|
| BE-005 | webauthn4j integration | Library integration, RP configuration model (RP ID, origin per tenant) | W6 | BE-003 | P0 |
| BE-006 | Challenge store | Redis-backed challenge storage, tenant-scoped, TTL handling | W6 | BE-005, BE-009 (partial) | P0 |
| BE-007 | Registration ceremony | Registration options API, attestation verification, credential persistence (public key, Credential ID, signature counter, User Handle) | W7–W8 | BE-006 | P0 |
| BE-008 | Authentication ceremony | Authentication options API, assertion verification (signature, RP ID, origin, challenge, signature counter regression check) | W8–W9 | BE-007 | P0 |
| BE-009 | Credential lifecycle | List, rename, revoke credentials; multi-credential-per-user enforcement | W9 | BE-007 | P0 |
| BE-010 | Attestation policy management | Per-tenant AAGUID allow/deny lists, attestation conveyance config, MDS/BLOB metadata fetch + integration | W10–W11 | BE-007 | P0 |

### 3.4 Backend — Platform Services

| ID | Task | Description | Estimated Effort | Dependencies | Priority |
|----|------|-------------|-----------------|--------------|----------|
| BE-011 | Session & token issuance | JWT issuance + signing key management, refresh token flow, token issued on successful assertion | W12–W13 | BE-008 | P0 |
| BE-012 | RP API key management | API key generation, hashing/storage, key-based RP authentication on platform APIs | W13 | BE-002 | P0 |
| BE-013 | Rate limiting & abuse prevention | Redis-backed per-tenant/per-endpoint rate limits; abuse detection on registration/auth endpoints | W14 | BE-006, BE-012 | P0 |
| BE-014 | Audit logging | Append-only audit log, hash-chain integrity, partitioned tables, write hooks on key events | W15–W16 | BE-003 | P0 |
| BE-015 | Monitoring & health checks | Liveness/readiness endpoints, key operational metrics, per-tenant health visibility | W17 | BE-011 | P0 |
| BE-016 | Backend hardening pass | End-to-end review, security review of verification paths, key rotation handling, load sanity check | W23–W24 | All BE tasks, FE-003 | P0 |

### 3.5 Frontend — RP Console & SDK

| ID | Task | Description | Estimated Effort | Dependencies | Priority |
|----|------|-------------|-----------------|--------------|----------|
| FE-001 | RP onboarding console — provisioning | Self-service tenant provisioning, API key management UI, RP ID/origin configuration | W17–W19 | BE-012 | P0 |
| FE-002 | RP onboarding console — visibility | Registration/authentication funnel metrics, tenant config screens, attestation policy UI | W19–W20 | FE-001, BE-010, BE-014 | P0 |
| FE-003 | Client JS SDK | Drop-in browser SDK wrapping WebAuthn ceremonies + platform API calls; packaging + versioning | W20–W22 | BE-008, BE-009 | P0 |

### 3.6 Cross-Cutting — Recovery, QA, Documentation

| ID | Task | Description | Estimated Effort | Dependencies | Priority |
|----|------|-------------|-----------------|--------------|----------|
| QA-001 | Account recovery flow | Multi-credential fallback path, RP-managed recovery process, documented self-service limits; implementation + tests | W16–W17 | BE-009, BE-011 | P0 |
| QA-002 | Integration test suite | End-to-end registration/auth/recovery flows, multi-tenant scenarios | W24 | BE-016, FE-003 | P0 |
| DOC-001 | Platform documentation | Integration guide, API reference, error code catalog, SDK docs | W24–W25 | FE-003, QA-002 | P0 |
| DOC-002 | First RP sandbox onboarding | Onboard a test RP end-to-end as launch validation; fix gaps surfaced | W25–W26 | DOC-001, INF-005 | P0 |

## 4. Dependency Map

### Critical Path

The longest dependent chain determines minimum project duration:

```
INF-001 → INF-002 → INF-003 → BE-001 → BE-002 → BE-003 → BE-005 → BE-006
  → BE-007 → BE-008 → BE-011 → BE-015 → FE-001 → FE-002 → FE-003
  → BE-016 → QA-002 → DOC-001 → DOC-002
```

The WebAuthn core (BE-005 → BE-008) and the RP console/SDK chain (FE-001 → FE-003) are the two heaviest segments. Because this is a solo effort, these run sequentially rather than in parallel, which is the primary reason the timeline extends to W26.

Branch chains feeding the path:
```
BE-003 → BE-014 (audit) → QA-001 (recovery) ↘
BE-008 → BE-009 → QA-001 ──────────────────→ feeds QA-002
BE-007 → BE-010 (attestation policy) → FE-002
```

### External Dependencies

| Dependency | Type | Impact if Delayed | Mitigation |
|------------|------|-------------------|------------|
| FIDO MDS / BLOB endpoint | External service | Attestation policy (BE-010) cannot validate authenticator metadata | Cache MDS BLOB locally; tolerate stale metadata with refresh schedule |
| SaaS hosting / financial-cloud environment | Infrastructure / approval | Blocks deployment (INF-005) and launch validation (DOC-002) | Start provisioning early (by W18); confirm environment choice well before W21 |
| Card-company security review of deployment model | Approval | Could invalidate public multi-tenant SaaS model entirely — re-scope risk | Engage customer security team in W1–W4, before core build locks in assumptions (see PRD Open Question #1) |
| webauthn4j library | Library | Low — stable, but version issues could surface | Pin version; monitor releases |

## 5. Milestones & Checkpoints

| # | Milestone | Target | Key Deliverables | Success Criteria |
|---|-----------|--------|------------------|------------------|
| M1 | Foundation ready | W5 | Scaffolding, environments, CI, exception infra, multi-tenant model + RLS | Tenant isolation test suite (BE-004) passes; RLS holds on missing app-layer filter |
| M2 | WebAuthn core working | W9 | Registration + authentication ceremonies, credential lifecycle | A passkey can be registered and used to authenticate end-to-end in a test tenant |
| M3 | Platform services complete | W17 | Session/token, API keys, rate limiting, audit logging, recovery, monitoring | RP can authenticate to platform; audit log hash chain verifies; recovery flow works |
| M4 | Customer-facing layer complete | W22 | RP onboarding console, JS SDK, deployment environment | A new tenant can self-provision and integrate via SDK in a sandbox |
| M5 | Launch-ready | W26 | Hardening, integration tests, documentation, first RP sandbox onboarding | First test RP onboarded end-to-end; documentation complete; no known verification gaps |

### Checkpoint Schedule

| Checkpoint | Timing | Purpose |
|------------|--------|---------|
| Deployment-model confirmation | W4 | Resolve PRD Open Question #1 before core assumptions lock in |
| WebAuthn correctness review | W9 | Dedicated review of signature counter, RP ID, origin, challenge handling before building on top |
| Mid-project scope/timeline review | W13 | Re-validate W26 target against actual solo velocity; adjust if slipping |
| Security review | W24 | Review all verification paths and key management before launch prep |

## 6. Risk Assessment & Mitigation

| # | Risk | Probability | Impact | Mitigation Strategy | Contingency |
|---|------|-------------|--------|---------------------|-------------|
| R1 | Public multi-tenant SaaS deployment model fails card-company security review (network separation, outsourcing, data residency) | Medium | High | Engage customer security team in W1–W4; document regulatory assumptions explicitly | Pivot to financial-cloud isolated deployment; re-scope INF and tenancy tasks |
| R2 | Solo-developer velocity slower than estimated; W26 slips | Medium | High | Conservative week spans already include buffer; W13 checkpoint to re-baseline | Defer lower-risk P0 polish (e.g., console funnel visibility, monitoring depth) to a fast-follow v1.1 |
| R3 | Tenant isolation bug leaks cross-tenant credential data | Low | High | RLS as DB-layer enforcement (not app-only); dedicated isolation test suite (BE-004) | Incident response; RLS makes app-layer bugs non-leaking by design |
| R4 | WebAuthn verification implemented incorrectly (silent security hole) | Medium | High | Use webauthn4j rather than hand-rolling; dedicated correctness review at W9 checkpoint | Re-test against FIDO conformance vectors; fix before any customer onboarding |
| R5 | JS SDK browser/authenticator compatibility issues across device stacks | Medium | Medium | Test across major browser/OS combinations during FE-003 | Document supported matrix; address gaps in v1.1 |
| R6 | Knowledge gaps as solo dev (no peer review) | Medium | Medium | Scheduled self-review checkpoints; lean on webauthn4j docs and FIDO specs | Budget time for external security review before launch |
| R7 | MDS/BLOB integration complexity underestimated | Low | Medium | Treat MDS as cacheable, tolerate staleness | Ship with a static AAGUID allowlist if dynamic MDS slips; add full integration in v1.1 |

## 7. Open Items

Carried from the PRD plus execution-specific items.

| # | Item | Impact | Decision Needed By |
|---|------|--------|--------------------|
| 1 | Deployment model: does public multi-tenant SaaS pass card-company security review? (PRD Open Question #1) | Critical — could force re-scope of tenancy and infra tasks | W4 (checkpoint) |
| 2 | Committed v1 release date and target SLA | High — converts relative weeks to absolute dates, sets monitoring targets | Before W1 ideally; by W13 at latest |
| 3 | Synced vs. device-bound passkey policy for card-company RPs | Medium — sets attestation policy defaults (BE-010) | W10 (before BE-010) |
| 4 | Per-RP sandbox/test environment required at v1? | Medium — affects RP console scope (FE-001/FE-002) | W17 (before FE-001) |
| 5 | Pricing model (per-auth / MAU / flat fee) | Low — not v1-blocking, but informs API key/metering design | Before v1.1 planning |
| 6 | Is external security review budgeted before launch? | Medium — solo dev has no peer review; affects W24 security review depth | W20 |

---

*Generated from Multi-Tenant Passkey Server PRD v1.0 by AP Generator — 2026-05-15*
