# Multi-Tenant Passkey Server — Product Requirements Document

**Version**: 1.0
**Date**: 2026-05-15
**Context**: Internal Tool (Company B2B Product)
**Status**: Draft

---

## 1. Overview

A multi-tenant FIDO2/WebAuthn (Passkey) authentication server, delivered as a B2B SaaS platform. The product enables Relying Party (RP) customers — initially card/financial companies — to add phishing-resistant passkey authentication to their services without building and operating WebAuthn infrastructure themselves. It provides the full platform surface: passkey registration/authentication APIs, an RP onboarding console, client SDKs, standardized error contracts, and operational tooling.

## 2. Problem Statement

Card financial companies face mounting regulatory and operational pressure to move beyond passwords and SMS OTP. Phishing-resistant MFA is increasingly cited as the benchmark in financial security guidance, and password reset tickets routinely consume 20–30% of B2B support volume. However, implementing FIDO2/WebAuthn correctly is hard: it requires deep handling of attestation, assertion verification, signature counters, discoverable credentials, AAGUID/MDS metadata, and Conditional UI. Most card companies do not have in-house WebAuthn expertise, and building it per-company duplicates effort across the industry.

Current workarounds fall short:
- **Building in-house**: Slow, expensive, and error-prone. WebAuthn verification mistakes (e.g., skipping signature counter checks) create silent security holes.
- **Generic CIAM platforms**: Native WebAuthn rollouts stall at 5–15% adoption without a device-aware orchestration layer, and SSO/enterprise tiers carry steep pricing.
- **Foreign passkey-as-a-service vendors**: Data residency and regulatory fit for Korean financial institutions are unresolved.

This product centralizes WebAuthn expertise into one correctly-implemented, multi-tenant platform that RP customers integrate via SDKs and APIs.

## 3. Target Users

### Primary Persona — RP Integration Developer (Customer-side)

| Attribute | Description |
|-----------|-------------|
| Who | Backend/frontend developer at a card financial company integrating the passkey platform into their auth flow |
| Demographics | 3–10 yr experience, works within strict financial-sector security and change-management constraints |
| Pain Points | No in-house WebAuthn expertise; needs predictable error contracts, clear SDKs, fast time-to-integration; must satisfy internal security review |
| Current Behavior | Uses password + SMS OTP; evaluating passkey vendors or considering in-house build |

### Secondary Persona — RP Administrator (Customer-side)

| Attribute | Description |
|-----------|-------------|
| Who | Security/operations owner at the card company managing the RP tenant |
| Demographics | Security team or IAM team member |
| Pain Points | Needs visibility into registration/auth funnels, control over attestation policy (which authenticators are allowed), audit evidence for compliance |
| Current Behavior | Manages auth policy through internal tools; expects a self-service console |

### Tertiary Persona — Platform Operator (Internal)

| Attribute | Description |
|-----------|-------------|
| Who | Our own team operating the multi-tenant platform |
| Pain Points | Needs tenant isolation guarantees, monitoring/health checks, abuse prevention, safe schema migration |
| Current Behavior | N/A — greenfield |

## 4. Goals & Success Metrics

| Goal | Metric | Target | Timeframe |
|------|--------|--------|-----------|
| Ship a launch-ready v1 platform | All P0 features complete and documented | 100% of P0 scope | v1 release |
| Fast RP integration | Time from API key issuance to first successful passkey auth in RP sandbox | < 1 day | Per onboarded RP |
| Correct, reliable WebAuthn core | Assertion/attestation verification correctness (signature counter, RP ID, origin checks) | 0 known verification gaps | v1 release |
| Tenant isolation integrity | Cross-tenant data access incidents | 0 | Ongoing |
| Platform availability | API uptime | TBD (target SLA, e.g. 99.9%) | Post-launch |
| Onboard first card-company RP | Signed RP customer live in production | 1 | TBD (depends on go-to-market) |

## 5. Features & Scope

### MVP (v1)

| Priority | Feature | Description | User Value |
|----------|---------|-------------|------------|
| P0 | WebAuthn core (registration/authentication) | Attestation verification, assertion verification, signature counter, RP ID/origin validation, discoverable credentials, User Handle/Credential ID handling — built on webauthn4j | The correct, hard-to-build core that is the reason to buy |
| P0 | Multi-tenant data model & isolation | Shared-schema + `tenant_id` model with PostgreSQL Row-Level Security enforcing isolation at the DB layer | Card companies' credential data cannot leak across tenants even on application-code mistakes |
| P0 | Credential lifecycle management | Register, list, rename, revoke credentials; enforce per-user multi-credential (one per device) | Users and RPs can manage device passkeys safely |
| P0 | Exception infrastructure & standardized error codes | Unified `ApiResponse<T>` envelope, central `ErrorCode` registry, `GlobalExceptionHandler`, traceId propagation (per uploaded API Response Template) | RP developers integrate against a stable, predictable error contract |
| P0 | Session & token issuance layer | JWT issuance, refresh tokens, API key management for RP authentication | RPs authenticate to the platform; end-user sessions are issued post-passkey-auth |
| P0 | RP onboarding & management console | Self-service tenant provisioning, API key management, RP ID/origin configuration, funnel visibility | Customer-facing entry point; without it the platform cannot be adopted |
| P0 | Client JS SDK | Drop-in browser SDK wrapping WebAuthn ceremonies and platform API calls | Removes the hardest integration work from the RP developer |
| P0 | Attestation policy management | Per-tenant configuration of allowed authenticators (AAGUID allowlist/denylist), attestation conveyance requirements, MDS/BLOB metadata integration | Card companies require control over which authenticators are trusted |
| P0 | Rate limiting & abuse prevention | Per-tenant and per-endpoint rate limits, abuse detection on registration/auth endpoints (Redis-backed counters) | Protects the platform and tenants from abuse and brute-force attempts |
| P0 | Audit logging | Append-only audit log with hash chain integrity and table partitioning, stored in PostgreSQL | Compliance evidence for financial-sector security review |
| P0 | Account recovery flow | Phishing-resistant recovery path (multi-credential fallback, RP-managed recovery process, documented self-service limits) | Device loss is the top real-world passkey failure mode; must be solved for financial users |
| P0 | Monitoring & health checks | Liveness/readiness endpoints, key operational metrics, per-tenant health visibility | Platform operability from day one |
| P0 | Platform documentation | Integration guide, API reference, error code catalog, SDK docs | Launch-readiness; RP developers self-serve |

### Out of Scope (v2+)

| Feature | Reason for Deferral |
|---------|--------------------|
| Conditional UI (autofill passkey) | Enhances UX but not required for a functioning v1 auth flow; needs SDK maturity first |
| Cross-device authentication (QR / hybrid transport) | Important for shared-workstation scenarios but adds significant flow complexity; defer to v2 |
| Webhooks | Useful for RP-side event-driven integration; not blocking for core auth |
| Native mobile SDKs (iOS/Android) | JS SDK covers web-first launch; native SDKs follow once web is validated |
| IdP integration (OIDC/SAML) | Passkeys operate at the authentication layer; SSO/authorization-layer integration is a separate, larger effort |
| Multi-region HA | Operational maturity concern; single-region is acceptable for v1 |
| SOC2 / formal compliance certification | Pursue after platform and first customer are live; design audit logging now to make it tractable later |
| On-prem / financial-cloud isolated deployment | v1 deployment model is public multi-tenant SaaS by decision; revisit if customer security review requires it (see Open Questions) |
| Credential Exchange Protocol (CXP/CXF) support | FIDO Alliance standard still maturing in 2026; monitor and adopt when stable |

## 6. User Stories & User Flow

### Key User Stories

- As an **RP integration developer**, I want to provision a tenant and get an API key from a console, so that I can start integrating without a manual sales/setup process.
- As an **RP integration developer**, I want a JS SDK that wraps the WebAuthn ceremony, so that I don't have to implement attestation/assertion handling myself.
- As an **RP integration developer**, I want every API error to follow a documented, stable error-code contract, so that my error handling doesn't break on platform changes.
- As an **RP administrator**, I want to configure which authenticators (by AAGUID) are allowed for my tenant, so that I can meet my company's authenticator trust requirements.
- As an **RP administrator**, I want to see registration and authentication funnel metrics, so that I can diagnose adoption drop-off.
- As an **end user** (card company customer), I want to register a passkey on my device, so that I can log in without a password.
- As an **end user**, I want a recovery path if I lose my device, so that I am not locked out of my financial account.
- As a **platform operator**, I want guaranteed tenant isolation at the database layer, so that an application bug cannot leak one card company's credentials to another.
- As a **platform operator**, I want an append-only, tamper-evident audit log, so that I can produce compliance evidence.

### Core User Flow — Passkey Registration (happy path)

1. RP's frontend calls the JS SDK to begin registration.
2. SDK requests registration options (challenge, RP ID, allowed parameters) from the platform API, authenticated by the RP's API key.
3. Platform generates and stores a challenge in Redis, scoped to the tenant; returns `PublicKeyCredentialCreationOptions`.
4. SDK invokes the browser WebAuthn API; the authenticator creates a credential.
5. SDK posts the attestation response to the platform API.
6. Platform verifies attestation (via webauthn4j), checks it against the tenant's attestation policy (AAGUID allowlist, MDS metadata), validates RP ID/origin/challenge.
7. Platform persists the credential (public key, Credential ID, signature counter, User Handle) under the tenant, writes an audit log entry.
8. Platform returns a standardized success response; SDK reports success to the RP frontend.

### Core User Flow — Passkey Authentication (happy path)

1. RP's frontend calls the JS SDK to begin authentication.
2. SDK requests authentication options from the platform API; platform issues a challenge (Redis, tenant-scoped).
3. SDK invokes the browser WebAuthn API; the authenticator signs the challenge.
4. SDK posts the assertion to the platform API.
5. Platform verifies the assertion: signature, RP ID, origin, challenge, and signature counter (rejecting counter regressions).
6. Platform issues a session token (JWT) for the authenticated end user; writes an audit log entry.
7. SDK returns the session token to the RP frontend.

## 7. Technical Considerations

| Aspect | Detail |
|--------|--------|
| Language / Runtime | Java 21 (LTS) |
| Framework | Spring Boot 3.5.x |
| FIDO2 Library | webauthn4j |
| Database | PostgreSQL — shared-schema multi-tenancy with `tenant_id` column, Row-Level Security (RLS) enforcing tenant isolation at the DB layer |
| Cache / Ephemeral Store | Redis — WebAuthn challenge storage, rate-limit counters, session data |
| Schema Migration | Flyway |
| API Response Standard | Unified `ApiResponse<T>` envelope, central `ErrorCode` registry, `GlobalExceptionHandler`, `TraceIdFilter` with MDC-based traceId propagation (per uploaded "Spring Boot API Response Template") |
| Audit Storage | PostgreSQL, partitioned tables, hash-chain integrity |
| Deployment Model | Public multi-tenant SaaS (v1) |
| Key Constraints | Greenfield — no existing infrastructure; tenant isolation correctness is the highest-risk area in the shared-schema model; RLS is the primary mitigation |
| Data / Privacy | Server stores only public keys and credential metadata — never private keys or biometrics. Tenant data segregation is a hard requirement. Financial-sector data residency requirements are an open risk (see Open Questions). |

## 8. Timeline & Milestones

Target dates are expressed as relative weeks (W1 = project start); absolute dates are TBD pending team size and release commitment.

| Phase | Milestone | Target | Deliverable |
|-------|-----------|--------|-------------|
| Foundation | Core infra in place | W1–W2 | Exception infrastructure, multi-tenant data model + RLS, API response standard, traceId filter |
| Core Auth | WebAuthn core working | W3–W5 | Registration/authentication APIs, credential lifecycle, attestation policy + MDS integration |
| Platform Layer | RP-facing surface | W6–W8 | Session/token issuance, RP onboarding console, rate limiting, audit logging |
| Integration Layer | Customer-facing tooling | W9–W10 | Client JS SDK, account recovery flow, monitoring/health checks |
| Launch Prep | Launch-ready | W11–W12 | Platform documentation, end-to-end hardening, first RP sandbox onboarding |

> Timeline assumes a small focused backend team; revise once team size is confirmed.

## 9. Competitive Analysis

| Competitor | Strengths | Weaknesses | Our Differentiation |
|------------|-----------|------------|---------------------|
| Corbado Connect | Managed passkeys with built-in analytics; strong device-aware orchestration (lifts adoption from 5–15% to 80%+ on targeted devices) | Foreign vendor; data residency / regulatory fit for Korean financial institutions unaddressed | Domestic platform purpose-built for Korean card-financial regulatory context |
| Auth0 (Okta CIC) | 7,000+ integrations, native passkey support across tiers, market-awareness leader | "SSO tax" — enterprise/SAML connections push pricing up sharply; passkey adoption still depends on custom orchestration work | Focused passkey-first platform without CIAM bloat; predictable contract for a single financial-sector buyer profile |
| MojoAuth | Passwordless-native, zero-store architecture, predictable pricing, free tier | Less mature B2B org-hierarchy / delegated-admin features; smaller integration ecosystem | Multi-tenant model designed around RP-as-tenant from day one; domestic regulatory alignment |
| HYPR Enterprise Passkey Suite | Strong phishing defense, risk signals, works alongside existing IAM; targets regulated finance/healthcare | Not a self-service developer platform — enterprise sales engagement only, no free/self-serve path | Self-service RP onboarding console and drop-in SDK — fast time-to-integration without a sales cycle |
| In-house build (by the card company itself) | Full control | WebAuthn correctness is hard; duplicates industry effort; slow; verification mistakes create silent security holes | Centralized, correctly-implemented WebAuthn core maintained by specialists |

### Market Context

Enterprise passkey adoption has crossed the tipping point — industry surveys in 2025–2026 report the large majority of enterprises actively deploying or piloting FIDO2 passkeys, driven by a convergence of regulatory mandates, platform maturity (Apple/Google/Microsoft all shipped cross-ecosystem improvements in 2025–2026), and measurable ROI. Regulatory frameworks increasingly cite phishing-resistant MFA as the benchmark, and payment-sector standards explicitly reference FIDO2 passkeys as a qualifying mechanism for personnel accessing cardholder data environments. NIST SP 800-63-4 (finalized July 2025) classifies both synced and device-bound passkeys as meeting AAL2, removing a prior compliance ambiguity. A recurring theme across the landscape: "the platform supports passkeys" is not the same as "the platform achieves adoption" — the orchestration and integration layer (SDKs, device-aware prompting, recovery) is where deployments succeed or stall. This validates the decision to treat customer-facing layers (console, SDK, error contracts) as P0, not afterthoughts.

## 10. Open Questions

| # | Question | Impact | Owner |
|---|----------|--------|-------|
| 1 | Does the public multi-tenant SaaS deployment model pass card-company security review? Korean financial-sector regulation (network separation, outsourcing rules, data residency) may require financial-cloud isolated or on-prem deployment. This is a launch-blocking risk if a target customer's security review rejects shared infrastructure. | Critical — could force a deployment-model change and re-scope | Product / Security |
| 2 | What is the committed v1 release date and target SLA? Needed to convert relative-week milestones into absolute dates and to set the availability metric. | High — milestone planning | Product |
| 3 | What is the backend team size? Drives whether the 12-week timeline is realistic. | High — timeline | Engineering Lead |
| 4 | Pricing model — per-authentication, MAU-based, or flat platform fee? Flat platform fee is common in regulated sectors. | Medium — go-to-market, not v1-blocking | Product / Business |
| 5 | Synced vs. device-bound passkey policy — will card-company RPs require device-bound credentials (common for financial institutions)? Affects attestation policy defaults. | Medium — attestation policy design | Product / Security |
| 6 | Is a sandbox/test environment per RP tenant required at v1, or is it acceptable to add post-launch? Affects onboarding console scope. | Medium — console scope | Product |

---

*Generated by PRD Generator — 2026-05-15*
