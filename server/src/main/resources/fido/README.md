# FIDO Alliance Root Certificates

This directory holds the trust anchor PEM used to verify the FIDO MDS3 BLOB JWT.

## Required file

`Global_Sign_Root_CA.pem` — the FIDO Alliance Metadata Service root certificate
issued by GlobalSign. The current cert is distributed by the FIDO Alliance at
<https://valid.r3.roots.globalsign.com/> and the MDS3 endpoint metadata
documentation.

## Why is this not committed?

Trust anchors should be controlled by ops, not by application code. In `prod`
profile (`application-prod.yml`) the property `passkey.mds.root-certificate-path`
defaults to `file:/etc/passkey/fido/Global_Sign_Root_CA.pem` — mount it via the
deployment manifest (k8s secret / configmap volume).

For local/test/dev profiles set `passkey.mds.enabled=false` (default) — no PEM
needed because no MDS calls are made.

## Verify before deploying

```bash
openssl x509 -in Global_Sign_Root_CA.pem -text -noout | grep -E "Issuer|Subject|Not (Before|After)"
```

Expected subject: `CN=GlobalSign Root CA - R3, O=GlobalSign, OU=GlobalSign Root CA - R3`
(or equivalent — confirm against the FIDO Alliance MDS3 publication notice).
