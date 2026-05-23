package com.crosscert.passkey.common.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

/**
 * Single source of truth for error codes. Prefix conventions:
 *
 * <ul>
 *   <li>{@code C} — Common (M1)
 *   <li>{@code A} — Auth (RP API key, JWT, admin login) (M3, M4)
 *   <li>{@code T} — Tenant (M1)
 *   <li>{@code P} — Passkey / Credential (M2)
 *   <li>{@code R} — Rate-limit (M3)
 *   <li>{@code D} — Audit (auDit) (M3)
 *   <li>{@code M} — Admin (Manage) (M4)
 * </ul>
 */
@Getter
@RequiredArgsConstructor
public enum ErrorCode {

  // ---------- Common (C) ----------
  INVALID_INPUT(HttpStatus.BAD_REQUEST, "C001", "Invalid input value"),
  METHOD_NOT_ALLOWED(HttpStatus.METHOD_NOT_ALLOWED, "C002", "Method not allowed"),
  ENTITY_NOT_FOUND(HttpStatus.NOT_FOUND, "C003", "Entity not found"),
  MISSING_PARAMETER(HttpStatus.BAD_REQUEST, "C004", "Required parameter missing"),
  TYPE_MISMATCH(HttpStatus.BAD_REQUEST, "C005", "Type mismatch"),
  INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "C999", "Server error"),

  // ---------- Auth (A) ----------
  UNAUTHORIZED(HttpStatus.UNAUTHORIZED, "A001", "Authentication required"),
  ACCESS_DENIED(HttpStatus.FORBIDDEN, "A002", "Access denied"),
  EXPIRED_TOKEN(HttpStatus.UNAUTHORIZED, "A003", "Token expired"),
  INVALID_TOKEN(HttpStatus.UNAUTHORIZED, "A004", "Invalid token"),
  INVALID_API_KEY(HttpStatus.UNAUTHORIZED, "A005", "Invalid API key"),
  ADMIN_LOGIN_REQUIRED(HttpStatus.UNAUTHORIZED, "A010", "Admin login required"),
  REFRESH_TOKEN_REVOKED(HttpStatus.UNAUTHORIZED, "A011", "Refresh token revoked"),
  REFRESH_TOKEN_REUSED(HttpStatus.UNAUTHORIZED, "A012", "Refresh token reuse detected"),

  // ---------- Tenant (T) ----------
  TENANT_NOT_FOUND(HttpStatus.NOT_FOUND, "T001", "Tenant not found"),
  TENANT_INACTIVE(HttpStatus.FORBIDDEN, "T002", "Tenant is not active"),
  TENANT_CONTEXT_MISSING(HttpStatus.BAD_REQUEST, "T003", "Tenant context is required"),
  TENANT_SLUG_DUPLICATE(HttpStatus.CONFLICT, "T004", "Tenant slug already exists"),

  // ---------- Passkey/Credential (P) — M2 ----------
  WEBAUTHN_CONFIG_NOT_FOUND(HttpStatus.NOT_FOUND, "P001", "WebAuthn configuration is missing"),
  CHALLENGE_NOT_FOUND(HttpStatus.BAD_REQUEST, "P002", "Challenge expired or not found"),
  ATTESTATION_INVALID(HttpStatus.BAD_REQUEST, "P003", "Attestation verification failed"),
  ASSERTION_INVALID(HttpStatus.BAD_REQUEST, "P004", "Assertion verification failed"),
  SIGNATURE_COUNTER_REGRESSION(
      HttpStatus.UNAUTHORIZED, "P005", "Signature counter regression detected"),
  CREDENTIAL_NOT_FOUND(HttpStatus.NOT_FOUND, "P006", "Credential not found"),
  CREDENTIAL_REVOKED(HttpStatus.UNAUTHORIZED, "P007", "Credential is revoked"),
  AAGUID_NOT_ALLOWED(HttpStatus.FORBIDDEN, "P008", "Authenticator AAGUID not allowed"),
  ORIGIN_NOT_ALLOWED(HttpStatus.BAD_REQUEST, "P009", "Origin not in tenant allowlist"),
  MDS_TRUST_FAILED(HttpStatus.FORBIDDEN, "P010", "Attestation trust chain validation failed"),
  MDS_UNAVAILABLE(
      HttpStatus.SERVICE_UNAVAILABLE, "P011", "MDS service unavailable for strict tenant"),
  AUTHENTICATOR_REVOKED(
      HttpStatus.FORBIDDEN, "P012", "Authenticator has been revoked or compromised"),
  SYNCABLE_NOT_ALLOWED(
      HttpStatus.FORBIDDEN, "P013", "Syncable / backup-eligible authenticator not allowed"),
  MDS_DISABLED(HttpStatus.CONFLICT, "P014", "FIDO MDS is disabled on this deployment"),
  MDS_REFRESH_FAILED(HttpStatus.BAD_GATEWAY, "P015", "Failed to refresh FIDO MDS metadata"),
  CREDENTIAL_SUSPENDED(HttpStatus.FORBIDDEN, "P016", "Credential is suspended"),
  CREDENTIAL_INVALID_STATE(HttpStatus.CONFLICT, "P017", "Credential state transition not allowed"),

  // ---------- Rate-limit (R) — M3 ----------
  RATE_LIMIT_EXCEEDED(HttpStatus.TOO_MANY_REQUESTS, "R001", "Rate limit exceeded"),

  // ---------- Audit (D) — M3 ----------
  AUDIT_HASH_CHAIN_BROKEN(
      HttpStatus.INTERNAL_SERVER_ERROR, "D001", "Audit hash chain integrity violation"),

  // ---------- Admin (M) — M4 ----------
  ADMIN_USER_NOT_FOUND(HttpStatus.NOT_FOUND, "M001", "Admin user not found"),
  ADMIN_ROLE_FORBIDDEN(HttpStatus.FORBIDDEN, "M002", "Admin role does not permit this action"),
  ADMIN_USER_EMAIL_DUPLICATE(HttpStatus.CONFLICT, "M003", "Admin email already exists"),
  ADMIN_USER_SELF_DELETE_FORBIDDEN(
      HttpStatus.FORBIDDEN, "M004", "Cannot delete or modify your own account"),
  ADMIN_PASSWORD_INVALID(HttpStatus.UNAUTHORIZED, "M005", "Current password is incorrect");

  private final HttpStatus status;
  private final String code;
  private final String message;
}
