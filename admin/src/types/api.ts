// Server DTO mapping. Kept in sync manually with server admin controller records.
// See: server/src/main/java/com/crosscert/passkey/admin/controller/*.java

export interface FieldError {
  field: string;
  rejectedValue: unknown;
  reason: string;
}

export interface ApiEnvelope<T> {
  success: boolean;
  code: string;
  message: string;
  data?: T;
  error?: {
    errorCode: string;
    fieldErrors?: FieldError[];
  };
  traceId?: string;
  timestamp: string;
}

export interface PageResponse<T> {
  content: T[];
  page: number;
  size: number;
  totalElements: number;
  totalPages: number;
  hasNext: boolean;
  hasPrevious: boolean;
}

export type AdminRole = "PLATFORM_OPERATOR" | "RP_ADMIN";

export interface Me {
  adminId: string;
  role: AdminRole;
  tenantId: string | null;
  displayName: string;
}

// ─── Tenants ──────────────────────────────────────────────────────────────────
export type TenantStatus = "ACTIVE" | "SUSPENDED" | "DELETED";

export interface TenantView {
  id: string;
  name: string;
  slug: string;
  status: TenantStatus;
}

export interface CreateTenantRequest {
  name: string;
  slug: string;
}

// ─── WebAuthn Config ──────────────────────────────────────────────────────────
export type UserVerificationPolicy = "REQUIRED" | "PREFERRED" | "DISCOURAGED";
export type AttestationConveyance = "NONE" | "INDIRECT" | "DIRECT" | "ENTERPRISE";
export type ResidentKeyPolicy = "REQUIRED" | "PREFERRED" | "DISCOURAGED";
export type CredProtectPolicy =
  | "NONE"
  | "UV_OPTIONAL"
  | "UV_OPTIONAL_WITH_CREDID"
  | "UV_REQUIRED";

export interface WebauthnConfigView {
  rpId: string;
  rpName: string;
  origins: string[];
  timeoutMs: number;
  userVerification: UserVerificationPolicy;
  attestationConveyance: AttestationConveyance;
  residentKey: ResidentKeyPolicy;
  credProtect: CredProtectPolicy;
}

export interface WebauthnConfigUpsertRequest {
  rpId: string;
  rpName: string;
  origins: string[];
  timeoutMs: number;
  userVerification: UserVerificationPolicy;
  attestationConveyance: AttestationConveyance;
  residentKey: ResidentKeyPolicy;
  credProtect: CredProtectPolicy;
}

// ─── Attestation Policy (AAGUID) ──────────────────────────────────────────────
export type AttestationMode = "ANY" | "ALLOWLIST" | "DENYLIST";

export interface AttestationPolicyView {
  mode: AttestationMode;
  allowed: string[];
  denied: string[];
  mdsStrict: boolean;
  allowZeroAaguid: boolean;
  allowSyncable: boolean;
}

export interface AttestationPolicyUpsertRequest {
  mode: AttestationMode;
  allowedAaguids: string[];
  deniedAaguids: string[];
  mdsStrict: boolean;
  allowZeroAaguid: boolean;
  allowSyncable: boolean;
}

// ─── API Keys ─────────────────────────────────────────────────────────────────
export type ApiKeyStatus = "ACTIVE" | "REVOKED";

export interface ApiKeyView {
  id: string;
  prefix: string;
  name: string;
  status: ApiKeyStatus;
  createdAt: string;
  lastUsedAt: string | null;
}

export interface IssueApiKeyRequest {
  name: string;
}

export interface IssuedKeyView {
  id: string;
  /** plaintext shown ONCE — caller must wipe from memory after copy. */
  plaintext: string;
  prefix: string;
  name: string;
}

// ─── Credentials ──────────────────────────────────────────────────────────────
export type CredentialStatus = "ACTIVE" | "REVOKED";

export type CredentialRevokedReason =
  | "USER_REQUEST"
  | "ADMIN_FORCED"
  | "COMPROMISE_SUSPECTED"
  | "SIGNATURE_COUNTER_REGRESSION"
  | "LIFECYCLE_EXPIRED";

export const CREDENTIAL_REVOKED_REASONS: CredentialRevokedReason[] = [
  "ADMIN_FORCED",
  "COMPROMISE_SUSPECTED",
  "USER_REQUEST",
  "LIFECYCLE_EXPIRED",
];

export interface CredentialView {
  id: string;
  tenantUserId: string;
  credentialId: string;
  nickname: string | null;
  status: CredentialStatus;
  aaguid: string | null;
  transports: string | null;
  signatureCounter: number;
  lastUsedAt: string | null;
  createdAt: string;
  revokedAt: string | null;
  revokedReason: CredentialRevokedReason | null;
}

export interface AaguidCount {
  aaguid: string;
  count: number;
}

export interface RevokedReasonCount {
  reason: string;
  count: number;
}

export interface CredentialStatsView {
  aaguid: AaguidCount[];
  revokedReason: RevokedReasonCount[];
}

// ─── End Users (tenant_user) ──────────────────────────────────────────────────
export interface EndUserView {
  id: string;
  externalId: string;
  displayName: string | null;
  activeCredentialCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface EndUserDetailView {
  id: string;
  externalId: string;
  displayName: string | null;
  createdAt: string;
  updatedAt: string;
  activeCredentialCount: number;
  lastActivityAt: string | null;
  credentials: CredentialView[];
}

// ─── Audit ────────────────────────────────────────────────────────────────────
export type AuditEventType =
  | "TENANT_CREATED"
  | "API_KEY_ISSUED"
  | "API_KEY_REVOKED"
  | "CREDENTIAL_REGISTERED"
  | "CREDENTIAL_AUTHENTICATED"
  | "CREDENTIAL_REVOKED"
  | "CREDENTIAL_RENAMED"
  | "SIGNATURE_COUNTER_REGRESSION"
  | "ATTESTATION_TRUST_FAILED"
  | "CREDENTIAL_AUTH_RATE_LIMIT"
  | "WEBAUTHN_CONFIG_UPDATED"
  | "REGISTRATION_OPTIONS_REQUESTED"
  | "AUTHENTICATION_OPTIONS_REQUESTED"
  | "ADMIN_USER_CREATED"
  | "ADMIN_USER_DELETED"
  | "ADMIN_USER_PASSWORD_RESET"
  | "TENANT_SUSPENDED"
  | "TENANT_ACTIVATED"
  | "CREDENTIAL_REASSIGNED"
  | "USER_FORCE_LOGOUT";

export const AUDIT_EVENT_TYPES: AuditEventType[] = [
  "TENANT_CREATED",
  "API_KEY_ISSUED",
  "API_KEY_REVOKED",
  "CREDENTIAL_REGISTERED",
  "CREDENTIAL_AUTHENTICATED",
  "CREDENTIAL_REVOKED",
  "CREDENTIAL_RENAMED",
  "SIGNATURE_COUNTER_REGRESSION",
  "ATTESTATION_TRUST_FAILED",
  "CREDENTIAL_AUTH_RATE_LIMIT",
  "WEBAUTHN_CONFIG_UPDATED",
  "REGISTRATION_OPTIONS_REQUESTED",
  "AUTHENTICATION_OPTIONS_REQUESTED",
  "ADMIN_USER_CREATED",
  "ADMIN_USER_DELETED",
  "ADMIN_USER_PASSWORD_RESET",
  "TENANT_SUSPENDED",
  "TENANT_ACTIVATED",
  "CREDENTIAL_REASSIGNED",
  "USER_FORCE_LOGOUT",
];

export type AuditActorType = "END_USER" | "RP_API" | "ADMIN" | "SYSTEM";

export interface AuditView {
  id: string;
  createdAt: string;
  eventType: AuditEventType;
  actorType: AuditActorType;
  actorId: string | null;
  subjectType: string | null;
  subjectId: string | null;
  payload: string; // JSON-encoded string (jsonb column)
}

export interface ChainVerification {
  tenantId: string;
  from: string;
  to: string;
  verifiedRows: number;
  tamperedEntryIds: string[];
}

// ─── AdminUser (P2-2) ─────────────────────────────────────────────────────────
export type AdminUserStatus = "ACTIVE" | "SUSPENDED";

export interface AdminUserView {
  id: string;
  email: string;
  displayName: string;
  role: AdminRole;
  tenantId: string | null;
  status: AdminUserStatus;
  lastLoginAt: string | null;
  createdAt: string;
}

export interface CreateAdminRequest {
  email: string;
  displayName: string;
  role: AdminRole;
  tenantId?: string;
}

export interface CreatedAdminView {
  admin: AdminUserView;
  /** Plaintext shown ONCE — caller must wipe from memory after copy. */
  temporaryPassword: string;
}

export interface ResetPasswordView {
  /** Plaintext shown ONCE. */
  temporaryPassword: string;
}

export interface ChangeMyPasswordRequest {
  oldPassword: string;
  newPassword: string;
}

// ─── System (PLATFORM_OPERATOR) ──────────────────────────────────────────────
export type MdsStatus = "DISABLED" | "NEVER_FETCHED" | "READY";

export interface MdsStatusView {
  enabled: boolean;
  blobUrl: string | null;
  refreshCron: string | null;
  status: MdsStatus;
  lastFetched?: string;
  entryCount?: number;
  nextUpdate?: string;
  serialNumber?: number;
}

export interface RateLimitSnapshotView {
  enabled: boolean;
  since: string;
  limits: Record<string, number>;
  denyCount: Record<string, number>;
}

export interface Ceremonies24h {
  registrationStarted: number;
  registrationCompleted: number;
  authenticationAttempted: number;
  authenticationSucceeded: number;
}

export interface OverviewStatsView {
  activeCredentials: number;
  activeUsers: number;
  activeApiKeys: number;
  ceremonies24h: Ceremonies24h;
  lastAuditAt: string | null;
}

/** Cross-tenant aggregate counts for the platform-wide /tenants dashboard. */
export interface PlatformStatsView {
  activeCredentials: number;
  activeApiKeys: number;
  ceremonies24h: number;
}

// ─── Funnel ───────────────────────────────────────────────────────────────────
export interface FunnelView {
  registrationStarted: number;
  registrationCompleted: number;
  authenticationAttempted: number;
  authenticationSucceeded: number;
}
