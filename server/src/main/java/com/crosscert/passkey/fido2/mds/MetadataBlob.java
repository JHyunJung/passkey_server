package com.crosscert.passkey.fido2.mds;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64;
import java.io.ByteArrayInputStream;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * A parsed, signature-verified FIDO MDS3 metadata BLOB. {@link #parse(String, X509Certificate)}
 * verifies the JWS signature using the {@code x5c} header chain, validates that chain up to the
 * supplied FIDO Alliance root CA via PKIX, then decodes the JSON payload into {@link MetadataEntry}
 * records. JWS parsing/verification uses nimbus-jose-jwt; chain validation uses the JDK's {@code
 * CertPathValidator}. Any failure throws {@link MdsException}.
 *
 * <p>Individual malformed entries, and entries without an AAGUID, are skipped — the BLOB remains
 * usable with its valid entries.
 */
public final class MetadataBlob {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  private final List<MetadataEntry> entries;
  private final String nextUpdate;
  private final Integer serialNumber;

  private MetadataBlob(List<MetadataEntry> entries, String nextUpdate, Integer serialNumber) {
    this.entries = entries;
    this.nextUpdate = nextUpdate;
    this.serialNumber = serialNumber;
  }

  /** The MDS entries, one per authenticator AAGUID. */
  public List<MetadataEntry> entries() {
    return entries;
  }

  /** The BLOB's declared {@code nextUpdate} date string (informational). */
  public String nextUpdate() {
    return nextUpdate;
  }

  /**
   * The BLOB's serial number ({@code no} field in the MDS3 JSON payload). May be null for BLOBs
   * that omit the field.
   */
  public Integer serialNumber() {
    return serialNumber;
  }

  /**
   * Parse and verify a FIDO MDS3 BLOB. {@code jws} is the raw JWS compact serialization; {@code
   * fidoRootCa} is the FIDO Alliance Global Root CA the BLOB's signing chain must chain to.
   */
  public static MetadataBlob parse(String jws, X509Certificate fidoRootCa) {
    JWSObject jwsObject;
    try {
      jwsObject = JWSObject.parse(jws);
    } catch (Exception e) {
      throw new MdsException("MDS BLOB is not a valid JWS: " + e.getMessage(), e);
    }
    List<X509Certificate> chain = extractX5cChain(jwsObject);
    verifyChainToRoot(chain, fidoRootCa);
    verifyJwsSignature(jwsObject, chain.get(0));

    String payloadJson = jwsObject.getPayload().toString();
    return decodePayload(payloadJson);
  }

  private static List<X509Certificate> extractX5cChain(JWSObject jwsObject) {
    List<Base64> x5c = jwsObject.getHeader().getX509CertChain();
    if (x5c == null || x5c.isEmpty()) {
      throw new MdsException("MDS BLOB JWS header has no x5c certificate chain");
    }
    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      List<X509Certificate> chain = new ArrayList<>(x5c.size());
      for (Base64 der : x5c) {
        chain.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der.decode())));
      }
      return chain;
    } catch (Exception e) {
      throw new MdsException("MDS BLOB x5c chain is unparseable: " + e.getMessage(), e);
    }
  }

  private static void verifyChainToRoot(List<X509Certificate> chain, X509Certificate fidoRootCa) {
    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      // The cert path excludes the trust anchor itself — drop the last cert if it equals the root.
      List<X509Certificate> pathCerts = new ArrayList<>(chain);
      if (!pathCerts.isEmpty() && pathCerts.get(pathCerts.size() - 1).equals(fidoRootCa)) {
        pathCerts.remove(pathCerts.size() - 1);
      }
      if (pathCerts.isEmpty()) {
        throw new MdsException("MDS BLOB x5c chain has no leaf after removing the root");
      }
      CertPath certPath = cf.generateCertPath(pathCerts);
      PKIXParameters params = new PKIXParameters(Set.of(new TrustAnchor(fidoRootCa, null)));
      params.setRevocationEnabled(false); // BLOB freshness is governed by nextUpdate, not CRL/OCSP
      CertPathValidator.getInstance("PKIX").validate(certPath, params);
    } catch (MdsException e) {
      throw e;
    } catch (Exception e) {
      throw new MdsException(
          "MDS BLOB signing chain does not validate to the FIDO root CA: " + e.getMessage(), e);
    }
  }

  private static void verifyJwsSignature(JWSObject jwsObject, X509Certificate signingCert) {
    try {
      if (!(signingCert.getPublicKey() instanceof RSAPublicKey rsaKey)) {
        throw new MdsException("MDS BLOB signing certificate is not RSA");
      }
      JWSVerifier verifier = new RSASSAVerifier(rsaKey);
      if (!jwsObject.verify(verifier)) {
        throw new MdsException("MDS BLOB JWS signature is invalid");
      }
    } catch (MdsException e) {
      throw e;
    } catch (Exception e) {
      throw new MdsException("MDS BLOB JWS signature verification failed: " + e.getMessage(), e);
    }
  }

  private static MetadataBlob decodePayload(String payloadJson) {
    try {
      JsonNode root = MAPPER.readTree(payloadJson);
      JsonNode entriesNode = root.get("entries");
      if (entriesNode == null || !entriesNode.isArray()) {
        throw new MdsException("MDS BLOB payload has no entries array");
      }
      List<MetadataEntry> entries = new ArrayList<>();
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      for (JsonNode entryNode : entriesNode) {
        // A FIDO MDS BLOB carries hundreds of entries; one malformed entry must not invalidate
        // the whole BLOB. Skip an entry that cannot be decoded, or one without an AAGUID — a
        // U2F-style entry keyed by attestationCertificateKeyIdentifiers, which the AAGUID-based
        // strict path (Phase 3) cannot use anyway.
        try {
          MetadataEntry entry = decodeEntry(entryNode, cf);
          if (entry.aaguid() != null) {
            entries.add(entry);
          }
        } catch (RuntimeException e) {
          // Malformed individual entry — skip it, keep the rest of the BLOB usable.
        }
      }
      JsonNode nextUpdate = root.get("nextUpdate");
      JsonNode no = root.get("no");
      return new MetadataBlob(
          Collections.unmodifiableList(entries),
          nextUpdate == null ? null : nextUpdate.asText(),
          no == null || no.isNull() ? null : no.intValue());
    } catch (MdsException e) {
      throw e;
    } catch (Exception e) {
      throw new MdsException("MDS BLOB payload is not valid JSON: " + e.getMessage(), e);
    }
  }

  private static MetadataEntry decodeEntry(JsonNode entryNode, CertificateFactory cf) {
    try {
      JsonNode aaguidNode = entryNode.get("aaguid");
      UUID aaguid = aaguidNode == null ? null : UUID.fromString(aaguidNode.asText());

      List<StatusReport> statuses = new ArrayList<>();
      JsonNode statusReports = entryNode.get("statusReports");
      if (statusReports != null && statusReports.isArray()) {
        for (JsonNode sr : statusReports) {
          JsonNode status = sr.get("status");
          if (status != null) {
            statuses.add(StatusReport.fromMdsString(status.asText()));
          }
        }
      }

      List<X509Certificate> rootCerts = new ArrayList<>();
      String description = null;
      JsonNode statement = entryNode.get("metadataStatement");
      if (statement != null) {
        JsonNode roots = statement.get("attestationRootCertificates");
        if (roots != null && roots.isArray()) {
          for (JsonNode certB64 : roots) {
            byte[] der = java.util.Base64.getDecoder().decode(certB64.asText());
            rootCerts.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der)));
          }
        }
        JsonNode desc = statement.get("description");
        if (desc != null && !desc.isNull()) {
          description = desc.asText();
        }
      }
      return new MetadataEntry(aaguid, rootCerts, statuses, description);
    } catch (RuntimeException e) {
      throw e;
    } catch (Exception e) {
      throw new MdsException("MDS BLOB entry is malformed: " + e.getMessage(), e);
    }
  }
}
