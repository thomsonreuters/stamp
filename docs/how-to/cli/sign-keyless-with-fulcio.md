# Sign Keyless with Fulcio

Produce a signed attestation without managing long-lived keys, by obtaining a short-lived certificate from Sigstore Fulcio using an OIDC identity token.

## Prerequisites

- A Fulcio instance you trust. The default is `https://fulcio.sigstore.dev`; override with `--fulcio-url`.
- One working OIDC token source. Exactly one of the following must be selected per run; they are mutually exclusive.

## Recipe

Pick the source that matches where you are signing from.

### In GitHub Actions

```bash
stamp run --attestor git --signer fulcio --github
```

The job needs `permissions: id-token: write` in its workflow YAML. When no
explicit token source is configured at all, the token resolver tries the
GitHub Actions endpoint first if `GITHUB_ACTIONS=true`, then falls back to
the default SPIRE socket; passing `--github` explicitly is preferred so
misconfiguration fails fast rather than silently sliding to the next
source.

### With SPIRE

```bash
stamp run --attestor git --signer fulcio --spire
# Or with an explicit socket:
stamp run --attestor git --signer fulcio --spire --socket /run/spire/agent.sock
```

`--socket` can also be supplied via the `SPIFFE_ENDPOINT_SOCKET` environment variable. Setting `--socket` implies `--spire`.

### With a token file

```bash
stamp run --attestor git --signer fulcio \
  --oidc-token-file /tmp/oidc-token
```

Useful for local development. Obtain the token however your IdP allows (for example, `gcloud auth print-identity-token > /tmp/oidc-token`) and ensure it is readable only by you.

### With an inline token string

```bash
stamp run --attestor git --signer fulcio --oidc-token "$JWT"
```

Testing only. Inline tokens leak into shell history and process listings; prefer `--oidc-token-file` for anything beyond a one-off.

## What happens during signing

Each invocation generates a fresh ephemeral ECDSA P-256 key pair, exchanges the OIDC token with Fulcio for a short-lived X.509 certificate bound to that key, signs the DSSE envelope, and embeds the certificate in the envelope's signature. The private key is discarded when the process exits.

## Verification side

Verifiers do not need `--public-key`. The certificate is extracted from the envelope and validated against the Fulcio root. See [verify-attestation.md](verify-attestation.md).

## See also

- [signing-and-trust.md](../../explanation/signing-and-trust.md)
- [verify-attestation.md](verify-attestation.md)
- [upload-to-rekor.md](upload-to-rekor.md)
