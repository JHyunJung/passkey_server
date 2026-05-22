package com.crosscert.passkey.fido2;

import com.crosscert.passkey.fido2.Fido2VerificationException.FailureReason;
import com.crosscert.passkey.fido2.cbor.CborDecodeException;
import com.crosscert.passkey.fido2.cose.CoseException;
import com.crosscert.passkey.fido2.cose.CoseKey;
import com.crosscert.passkey.fido2.cose.CoseSignatureVerifier;
import com.crosscert.passkey.fido2.model.AttestedCredentialData;
import com.crosscert.passkey.fido2.model.AuthenticatorData;
import com.crosscert.passkey.fido2.model.CollectedClientData;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Verifies a {@code navigator.credentials.get()} assertion against the WebAuthn L3 §7.2 algorithm:
 * client data type / challenge / origin, the RP id hash, the user-presence and user-verification
 * flags, and the credential signature. On success it returns the verified facts; it never applies
 * tenant policy (AAGUID allow-lists, signature-counter regression) — that stays with the caller.
 */
public final class AuthenticationVerifier {

  private static final Base64.Decoder B64URL = Base64.getUrlDecoder();

  /** Verify the assertion described by {@code req}, or throw {@link Fido2VerificationException}. */
  public AuthenticationVerificationResult verify(AuthenticationVerificationRequest req)
      throws Fido2VerificationException {
    CollectedClientData clientData = parseClientData(req.clientDataJson());

    if (!"webauthn.get".equals(clientData.type())) {
      throw new Fido2VerificationException(
          FailureReason.WRONG_CEREMONY_TYPE, "clientData.type is not webauthn.get");
    }
    if (!constantTimeEquals(decodeB64Url(clientData.challenge()), req.expectedChallenge())) {
      throw new Fido2VerificationException(
          FailureReason.CHALLENGE_MISMATCH, "assertion challenge does not match");
    }
    if (!req.expectedOrigins().contains(clientData.origin())) {
      throw new Fido2VerificationException(
          FailureReason.ORIGIN_MISMATCH, "origin not allow-listed: " + clientData.origin());
    }

    AuthenticatorData authData = parseAuthData(req.authenticatorData());
    verifyRpIdHash(authData, req.expectedRpId());
    if (!authData.flags().userPresent()) {
      throw new Fido2VerificationException(
          FailureReason.UP_FLAG_MISSING, "user-presence flag not set");
    }
    if (req.userVerificationRequired() && !authData.flags().userVerified()) {
      throw new Fido2VerificationException(
          FailureReason.UV_FLAG_REQUIRED, "user-verification required but flag not set");
    }

    verifySignature(req, authData);

    return new AuthenticationVerificationResult(
        authData.signCount(),
        authData.flags().userVerified(),
        authData.flags().backupEligible(),
        authData.flags().backupState());
  }

  private void verifySignature(AuthenticationVerificationRequest req, AuthenticatorData authData)
      throws Fido2VerificationException {
    CoseKey key;
    try {
      // storedCoseKeyBytes is the webauthn4j AttestedCredentialData blob; pull the COSE key out.
      AttestedCredentialData stored = AttestedCredentialData.parse(req.storedCoseKeyBytes());
      key = stored.coseKey();
    } catch (CborDecodeException | CoseException e) {
      throw new Fido2VerificationException(
          FailureReason.UNSUPPORTED_ALGORITHM,
          "stored credential key unreadable: " + e.getMessage());
    }
    byte[] clientDataHash = sha256(req.clientDataJson());
    ByteArrayOutputStream signedData = new ByteArrayOutputStream();
    signedData.writeBytes(authData.rawBytes());
    signedData.writeBytes(clientDataHash);
    if (!CoseSignatureVerifier.verify(key, signedData.toByteArray(), req.signature())) {
      throw new Fido2VerificationException(
          FailureReason.SIGNATURE_INVALID, "assertion signature verification failed");
    }
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
    } catch (CborDecodeException e) {
      throw new Fido2VerificationException(FailureReason.MALFORMED_CLIENT_DATA, e.getMessage());
    }
  }

  private static AuthenticatorData parseAuthData(byte[] raw) throws Fido2VerificationException {
    try {
      return AuthenticatorData.parse(raw);
    } catch (CborDecodeException e) {
      throw new Fido2VerificationException(FailureReason.MALFORMED_CBOR, e.getMessage());
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
