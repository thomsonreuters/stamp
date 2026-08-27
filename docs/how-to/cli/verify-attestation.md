# Verify an Attestation

Verify the cryptographic integrity of an attestation envelope, and optionally confirm its inclusion in a Rekor transparency log.

## Prerequisites

- An attestation envelope file (`.json`).
- For key-signed envelopes: the corresponding public key file.
- For Rekor checks: network reachability to the Rekor server.

## Recipe

### 1. Signature verification

For a Fulcio-signed envelope (certificate embedded), no key argument is needed:

```bash
stamp verify ./attestation.json
```

The certificate is extracted from the envelope and validated against the Fulcio root.

For a key-signed envelope, supply the public key explicitly:

```bash
stamp verify ./attestation.json --public-key ./signing.pub
```

### 2. Add transparency-log verification

```bash
stamp verify ./attestation.json --rekor
```

The verifier looks up the entry in Rekor (default `https://rekor.sigstore.dev`, override with `--rekor-url`) and confirms inclusion proof and signed entry timestamp.

### 3. Tighten the temporal policy

By default, temporal validation is `warn`: a Rekor entry integrated outside the certificate's validity window logs a warning but does not fail. To make it a hard failure:

```bash
stamp verify ./attestation.json --rekor --rekor-temporal-policy strict
```

Accepted values: `warn` (default), `strict`, `ignore`.

### 4. Save the verification result

```bash
stamp verify ./attestation.json --rekor \
  --output-verification ./verify-result.json
```

The output file contains the structured verification result, suitable for audit trails or policy engines.

## What each check guarantees

- **Signature** confirms the envelope was not modified after signing and was signed by the holder of the private key (or, for Fulcio, by a holder of a certificate Fulcio issued).
- **Rekor inclusion** adds non-repudiation: the envelope existed in the log at a recorded time.
- **Temporal policy** detects entries integrated into Rekor after the signing certificate expired, which is a strong signal of post-hoc fabrication.

A passing signature alone does not establish provenance; combine all three checks for high-assurance verification.

## See also

- [fetch-from-rekor.md](fetch-from-rekor.md)
- [a relative link](../../reference/transparency.md)
- [a relative link](../../explanation/transparency-and-verification.md)
