# Upload an Attestation to Rekor

Upload an existing signed attestation envelope to a Rekor transparency log.

## Prerequisites

- A signed attestation envelope on disk (typically from a prior `stamp run --persist`).
- Network reachability to the target Rekor server. The default is `https://rekor.sigstore.dev`.

## Recipe

### Fulcio-signed envelope

The certificate is embedded in the envelope, and the public key is extracted from it automatically:

```bash
stamp upload ./attestation.json
```

### Key-signed envelope

The envelope contains no certificate, so the matching public key must be supplied:

```bash
stamp upload ./attestation.json --public-key ./signing.pub
```

### Custom Rekor server

```bash
stamp upload ./attestation.json --rekor-url https://rekor.example.com
```

`--insecure` disables TLS verification. Use only against a local development server.

## Output

On success, the command reports the entry UUID, log index, integrated time, and a link to the Rekor entry. Persist these alongside the envelope if you need to reference the inclusion proof later.

## Alternative: sign and upload in one step

If you have not yet produced the envelope, you can sign and upload in a single invocation:

```bash
stamp run --attestor git \
  --signer fulcio --github \
  --rekor --rekor-upload individual
```

`--rekor-upload` accepts `individual`, `collection`, or `both`, matching the same value space as `--output-mode`. In collection mode, the rolled-up collection envelope is uploaded; in individual mode, each attestor envelope is uploaded; `both` uploads each.

## See also

- [fetch-from-rekor.md](fetch-from-rekor.md)
- [verify-attestation.md](verify-attestation.md)
- [a relative link](../../reference/transparency.md)
