package com.crosscert.passkey.fido2;

import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.attestation.AttestationResult;
import com.crosscert.passkey.fido2.attestation.AttestationVerifiers;
import com.crosscert.passkey.fido2.model.AttestationObject;
import com.crosscert.passkey.fido2.model.AttestedCredentialData;
import com.crosscert.passkey.fido2.model.AuthenticatorData;
import com.crosscert.passkey.fido2.model.CollectedClientData;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Verifies a {@code navigator.credentials.create()} registration against the WebAuthn L3 §7.1
 * algorithm: client data type / challenge / origin, the RP id hash, the user-presence and
 * user-verification flags, the presence of attested credential data, and the attestation statement.
 * It returns the verified facts; tenant policy (AAGUID allow-list, syncable policy, MDS) stays with
 * the caller.
 */
public final class RegistrationVerifier {

  private static final Base64.Decoder B64URL = Base64.getUrlDecoder();

  /**
   * Verify the registration described by {@code req}, or throw {@link Fido2VerificationException}.
   */
  public RegistrationVerificationResult verify(RegistrationVerificationRequest req)
      throws Fido2VerificationException {
    if (req == null
        || req.clientDataJson() == null
        || req.attestationObject() == null
        || req.expectedChallenge() == null
        || req.expectedOrigins() == null
        || req.expectedRpId() == null) {
      throw new Fido2VerificationException(
          FailureReason.MALFORMED_CLIENT_DATA, "registration request is missing required inputs");
    }
    CollectedClientData clientData = parseClientData(req.clientDataJson());
    if (!"webauthn.create".equals(clientData.type())) {
      throw new Fido2VerificationException(
          FailureReason.WRONG_CEREMONY_TYPE, "clientData.type is not webauthn.create");
    }
    if (!constantTimeEquals(decodeB64Url(clientData.challenge()), req.expectedChallenge())) {
      throw new Fido2VerificationException(
          FailureReason.CHALLENGE_MISMATCH, "registration challenge does not match");
    }
    if (!req.expectedOrigins().contains(clientData.origin())) {
      throw new Fido2VerificationException(
          FailureReason.ORIGIN_MISMATCH, "origin not allow-listed: " + clientData.origin());
    }

    AttestationObject attestationObject = parseAttestationObject(req.attestationObject());
    AuthenticatorData authData = attestationObject.authenticatorData();
    verifyRpIdHash(authData, req.expectedRpId());
    if (!authData.flags().userPresent()) {
      throw new Fido2VerificationException(
          FailureReason.UP_FLAG_MISSING, "user-presence flag not set");
    }
    if (req.userVerificationRequired() && !authData.flags().userVerified()) {
      throw new Fido2VerificationException(
          FailureReason.UV_FLAG_REQUIRED, "user-verification required but flag not set");
    }
    AttestedCredentialData acd = authData.attestedCredentialData();
    if (acd == null) {
      throw new Fido2VerificationException(
          FailureReason.NO_ATTESTED_CREDENTIAL, "registration has no attested credential data");
    }
    int credIdLen = acd.credentialId().length;
    if (credIdLen < 1 || credIdLen > 1023) {
      throw new Fido2VerificationException(
          FailureReason.MALFORMED_CBOR,
          "credentialId length out of WebAuthn range (1..1023): " + credIdLen);
    }

    byte[] clientDataHash = sha256(req.clientDataJson());
    AttestationResult attestation =
        AttestationVerifiers.forFormat(attestationObject.format())
            .verify(attestationObject, clientDataHash, req.trustAnchors());

    return new RegistrationVerificationResult(
        acd.credentialId(),
        serializeAttestedCredentialData(acd),
        acd.aaguid(),
        authData.signCount(),
        authData.flags().userVerified(),
        authData.flags().backupEligible(),
        authData.flags().backupState(),
        attestation.format(),
        clientData.crossOrigin());
  }

  /**
   * Serialize attested credential data into the {@code aaguid(16) || credIdLen(2) || credentialId
   * || coseKey} layout that {@code credential.public_key_cose} stores — identical to the form
   * webauthn4j's {@code AttestedCredentialDataConverter} produced, so existing rows stay readable.
   */
  private static byte[] serializeAttestedCredentialData(AttestedCredentialData acd) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.writeBytes(acd.aaguid());
    int len = acd.credentialId().length;
    out.write((len >> 8) & 0xff);
    out.write(len & 0xff);
    out.writeBytes(acd.credentialId());
    out.writeBytes(acd.coseKeyBytes());
    return out.toByteArray();
  }

  private void verifyRpIdHash(AuthenticatorData authData, String rpId)
      throws Fido2VerificationException {
    byte[] expected = sha256(rpId.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    if (!constantTimeEquals(expected, authData.rpIdHash())) {
      throw new Fido2VerificationException(
          FailureReason.RPID_HASH_MISMATCH, "authenticator rpIdHash does not match RP id");
    }
  }

  private static CollectedClientData parseClientData(byte[] json)
      throws Fido2VerificationException {
    try {
      return CollectedClientData.parse(json);
    } catch (RuntimeException e) {
      // CborDecodeException for malformed JSON, or NullPointerException if the caller passed
      // a null clientDataJson — either way the registration cannot be trusted.
      throw new Fido2VerificationException(
          FailureReason.MALFORMED_CLIENT_DATA, "clientDataJSON unreadable: " + e.getMessage());
    }
  }

  private static AttestationObject parseAttestationObject(byte[] raw)
      throws Fido2VerificationException {
    try {
      return AttestationObject.parse(raw);
    } catch (RuntimeException e) {
      throw new Fido2VerificationException(
          FailureReason.MALFORMED_CBOR, "attestationObject unreadable: " + e.getMessage());
    }
  }

  private static byte[] decodeB64Url(String s) throws Fido2VerificationException {
    try {
      return B64URL.decode(s);
    } catch (IllegalArgumentException e) {
      throw new Fido2VerificationException(
          FailureReason.MALFORMED_CLIENT_DATA, "challenge is not valid base64url");
    }
  }

  private static byte[] sha256(byte[] data) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(data);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }

  private static boolean constantTimeEquals(byte[] a, byte[] b) {
    return MessageDigest.isEqual(a, b);
  }
}
