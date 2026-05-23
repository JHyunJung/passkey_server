package com.crosscert.passkey.credential.domain;

public enum CredentialStatus {
  ACTIVE,
  /** Post-registration auto-block (e.g. MDS critical AAGUID). Recoverable via PO unsuspend. */
  SUSPENDED,
  REVOKED
}
