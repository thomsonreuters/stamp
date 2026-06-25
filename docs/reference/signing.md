# Signers

`stamp` signs in-toto statements using a pluggable signer interface. Two
signer backends ship in-tree: `key` (file-based asymmetric keys) and
`fulcio` (keyless, Sigstore Fulcio short-lived certificates). The signer
backend is chosen with `--signer key|fulcio` on the CLI, or
`pipeline.signing.signer` in the configuration file.

This page documents the contract of each signer, the OIDC token sources the
Fulcio signer accepts, what gets signed, and the consequences for
verification. For the authoritative list of signing flags, run
`stamp run --help`.

## Signers overview

A signer is a registered factory keyed by a short ID. Both shipped signers
implement the same lifecycle: validate configuration, do any one-time setup
during pre-sign (load a key, mint a certificate), produce a signature over
the DSSE pre-authentication encoding for each payload, and report a key ID
plus the corresponding public key. The Fulcio signer additionally satisfies
a certificate-bearing variant of the interface, which causes the certificate
to be embedded in each DSSE signature.

Signer selection is consumed by the pipeline before the statement is
encoded. Switching signer backends does not change the statement, the
predicate, or the envelope shape — only the contents of the
`signatures[]` entries.

Implementation: `pkg/signing`, `pkg/signing/key`, `pkg/signing/fulcio`.

## Key signer

The `key` signer loads an RSA or ECDSA private key from a PEM file on disk
and uses it for every signature in the run. The same key ID is used for the
lifetime of the process.

### Supported PEM formats

| PEM block type          | Contents             | Notes             |
| ----------------------- | -------------------- | ----------------- |
| `PRIVATE KEY`           | PKCS#8 (unencrypted) | RSA or EC         |
| `ENCRYPTED PRIVATE KEY` | PKCS#8 encrypted     | Password required |
| `RSA PRIVATE KEY`       | PKCS#1 RSA           | Unencrypted only  |
| `EC PRIVATE KEY`        | SEC1 EC              | Unencrypted only  |

Legacy RFC 1423 PEM encryption (the `Proc-Type: 4,ENCRYPTED` /
`DEK-Info` headers produced by older `openssl` invocations) is rejected
outright. Re-export such keys as PKCS#8 encrypted before use:

```sh
openssl pkcs8 -topk8 -in legacy.pem -out key.pem
```

### Password input

When the key is PKCS#8-encrypted, the password may be supplied through any
one of these mutually exclusive options:

- `--password <value>` — passes the password on the command line. Visible in
  process listings; suitable only for local experimentation.
- `--password-file <path>` — reads the password from the first line of a
  file (trailing whitespace stripped).
- `--prompt` — reads the password interactively from the controlling
  terminal, without echo.

For unencrypted keys, omit all three.

### Key ID derivation

The key ID for a private key is the lowercase hex SHA-256 of the DER-encoded
PKIX public key (the same encoding `x509.MarshalPKIXPublicKey` produces).
This makes the key ID a stable function of the public key alone — it does
not depend on the file the key was loaded from, the encryption status, or
the PEM block type.

### Algorithms

| Key type | Signature algorithm                  |
| -------- | ------------------------------------ |
| RSA      | PKCS#1 v1.5 with SHA-256             |
| ECDSA    | ASN.1 DER-encoded ECDSA with SHA-256 |

Other key types (Ed25519, ECDSA with non-SHA-256 hashes) are not
implemented and will fail at signing time.

## Fulcio signer

The `fulcio` signer is keyless. For each run it:

1. Resolves an OIDC token from one of the sources listed below.
2. Generates a fresh ephemeral ECDSA P-256 keypair in memory.
3. Sends the public key plus the OIDC token to Fulcio and receives a
   short-lived X.509 certificate binding the public key to the OIDC subject.
4. Signs each payload with the ephemeral private key.
5. Embeds the PEM-encoded Fulcio certificate in every DSSE signature
   (`signatures[].cert`).

The ephemeral private key never touches disk and is discarded when the
process exits.

The Fulcio server URL is set with `--fulcio-url`; the default Fulcio URL
is defined in `pkg/clients/fulcio` and points at the public Sigstore
Fulcio instance. `--insecure` skips TLS verification when talking
to Fulcio and should be used only against local test deployments.

## OIDC token sources for Fulcio

The Fulcio signer accepts an OIDC identity token from exactly one of the
sources below. They are mutually exclusive; combining them is a
configuration error.

### GitHub Actions (`--github`)

Uses the GitHub Actions OIDC issuer. The signer calls the
`ACTIONS_ID_TOKEN_REQUEST_URL` / `ACTIONS_ID_TOKEN_REQUEST_TOKEN` endpoint
exposed inside an Actions job and uses the returned ID token as the OIDC
credential. Requires `id-token: write` permission on the workflow.

When no token source is configured at all, the resolver in
`pkg/signing/fulcio/certificate.go` tries the GitHub Actions OIDC endpoint
first if `GITHUB_ACTIONS=true`, then falls back to the default SPIRE
socket. Passing `--github` explicitly is the recommended path: it makes
the intent obvious and produces a clear validation error in environments
where the GitHub Actions OIDC endpoint is not reachable, rather than
silently trying the next source.

### SPIRE (`--spire`, `--socket`)

Fetches a JWT-SVID from a SPIRE Agent over the Workload API. The audience
is derived from the host portion of the Fulcio URL. The socket location is
resolved in this order:

1. `--socket <path>` if given.
2. `SPIFFE_ENDPOINT_SOCKET` environment variable.
3. The platform default (`/tmp/spire-agent/public/api.sock` on Linux).

`--spire` selects this source explicitly; passing `--socket` alone has the
same effect.

### OIDC token file (`--oidc-token-file`)

Reads a static OIDC token from a file. Leading and trailing whitespace are
stripped. Useful when an external system (Vault, a sidecar) writes the
token to a known path.

### Inline OIDC token (`--oidc-token`)

Passes a token verbatim on the command line. This puts the token in the
process listing and the shell history; treat it as test-only and prefer
`--oidc-token-file` everywhere else.

## What's signed

The signed payload is the DSSE pre-authentication encoding (PAE) over the
in-toto statement, not the raw JSON. The statement is base64-encoded into
`Envelope.Payload`; the PAE input to the signer is reconstructed at sign and
verify time as:

```
DSSEv1 <len(payload_type)> <payload_type> <len(payload)> <payload>
```

Each signer call produces one entry in `signatures[]`. The output written
to destinations and uploaded to Rekor is the full DSSE envelope:

```json
{
  "payload":     "<base64 in-toto statement>",
  "payloadType": "application/vnd.in-toto+json",
  "signatures": [
    {
      "keyid": "<hex SHA-256 of public key>",
      "sig":   "<base64 signature>",
      "cert":  "<base64 PEM certificate, fulcio only>"
    }
  ]
}
```

The `cert` field is present only for envelopes produced by the Fulcio
signer (and any future signer satisfying the certificate-bearing interface).

## Verification implications

Verification needs the public key that signed each payload. Where it comes
from differs by signer:

- **Key-signer envelopes** carry only a key ID. The verifier must be given
  the matching public key out of band, via `--public-key <path>` on
  `stamp verify` (or `stamp upload`, when uploading to Rekor with a
  file-based signature).
- **Fulcio envelopes** embed the certificate in `signatures[].cert`. The
  verifier extracts the public key from the certificate and additionally
  validates the certificate against the configured Fulcio root.
  `--public-key` is not required and is ignored if both are present.

When uploading to Rekor, the same rule determines what verifier material
is sent to the log: certificates pulled from the envelope when present, or
the file passed via `--public-key` otherwise. See
[Transparency (Rekor)](transparency.md) for the upload contract.
