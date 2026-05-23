package com.crosscert.passkey.fido2.attestation;

/**
 * The outcome of attestation statement verification. {@code trustPathPresent} is {@code false} for
 * none and self attestation — Milestone A formats carry no certificate chain; Milestone B will set
 * it for full attestation backed by an MDS trust anchor.
 */
public record AttestationResult(String format, boolean trustPathPresent) {}
