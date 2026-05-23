package com.crosscert.passkey.fido2;

import com.crosscert.passkey.fido2.mds.MdsTrustAnchorSource;
import java.util.List;

/**
 * Inputs for verifying a {@code navigator.credentials.create()} registration. {@code
 * attestationObject} and {@code clientDataJson} are the raw (base64url-decoded) ceremony outputs;
 * {@code expectedChallenge} is the raw challenge the server issued. {@code trustAnchors} is the MDS
 * trust anchor source for strict registration; null means non-strict (no cert chain validation, no
 * revocation check).
 */
public record RegistrationVerificationRequest(
    byte[] attestationObject,
    byte[] clientDataJson,
    byte[] expectedChallenge,
    List<String> expectedOrigins,
    String expectedRpId,
    boolean userVerificationRequired,
    MdsTrustAnchorSource trustAnchors) {}
