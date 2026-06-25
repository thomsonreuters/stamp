# Transparency (Rekor)

`stamp` integrates with [Sigstore Rekor](https://docs.sigstore.dev/logging/overview/)
to publish and verify the inclusion of signed attestations in a tamper-evident
transparency log. The integration targets Rekor v1 and uses the DSSE entry
kind for every entry.

Three operations touch Rekor: `stamp upload` (publish an existing
envelope), `stamp fetch` (retrieve an entry), and `stamp verify
--rekor` (verify inclusion as part of attestation verification). The same
machinery is reachable as a library through `pkg/transparency`.

Implementation: `pkg/transparency`, `pkg/clients/rekor/v1`.

## Rekor overview

Rekor entries created by `stamp` are always of kind `dsse`. The body
contains the signed DSSE envelope plus one or more base64-encoded verifier
materials (public keys or certificates). Once accepted, the entry gets a
UUID, a log index, an integrated time, and an inclusion proof signed by the
log; these are returned to the caller and stored alongside the envelope
where the workflow's output mode permits.

## Upload

`stamp upload <path>` reads a signed envelope from disk and submits it
to Rekor as a DSSE entry.

What is uploaded:

- The full DSSE envelope, verbatim.
- One or more verifier materials. These are derived from the envelope and
  the CLI flags in this order:
  1. If any `signatures[].cert` field is non-empty, those certificates are
     used. This is the typical case for Fulcio-signed envelopes.
  2. Otherwise, the PEM file given by `--public-key` is uploaded as the
     verifier. This is required when the envelope was signed by the `key`
     signer.
  3. If neither is available, the upload aborts.

On success the CLI prints, and the library returns, the entry's UUID, log
index, and integrated time (Unix seconds), plus the Rekor server URL.

## Upload targets

In workflow mode, `pipeline.rekor.upload_target` (CLI: `--rekor-upload`)
selects which envelopes are pushed to Rekor when transparency is enabled
for the run. Values use the same vocabulary as the workflow's
`output_mode`:

| Value        | Behavior                                                        |
| ------------ | --------------------------------------------------------------- |
| `individual` | Upload each per-attestor envelope; do not upload the collection |
| `collection` | Upload only the collection envelope                             |
| `both`       | Upload each per-attestor envelope and the collection envelope   |

The selected target is filtered against what the workflow actually
produces: a workflow whose `output_mode` is `individual` has no collection
envelope to upload, so `--rekor-upload collection` has no effect. A
target asking for envelopes the workflow does not produce is a no-op,
not an error.

`stamp upload` ignores this setting; it always uploads exactly the
file path it was given.

## Fetch

`stamp fetch` retrieves a single entry from Rekor. Exactly one of three
mutually exclusive inputs must be supplied:

- `--file <path>` — read the attestation file, compute its SHA-256 against
  the serialized envelope, search Rekor for that hash, and return the first
  matching entry.
- `--uuid <rekor-uuid>` — fetch by the Rekor entry UUID (80 hex characters:
  16-character tree ID + 64-character entry hash).
- `--log-index <n>` — fetch by the entry's position in the log.

Output is a processed `FetchResult` with the UUID, integrated time, log
index, tree size, inclusion proof, and the base64-encoded entry body.
Pass `--raw` to instead emit the unmodified Rekor API response under
the entry UUID, suitable for piping into tools that expect the wire
format.

## Verification of inclusion

`stamp verify --rekor` performs a full signature verification and then
verifies the envelope's inclusion in Rekor: it locates the entry by hash,
fetches the inclusion proof, recomputes the Merkle path, and confirms the
result is signed by the log.

When the envelope carries a Fulcio certificate, an additional **temporal
policy** check compares the entry's integrated time against the
certificate's `Not Before` / `Not After` window. This is configured with
`--rekor-temporal-policy`:

| Policy   | Behavior                                                                                   |
| -------- | ------------------------------------------------------------------------------------------ |
| `warn`   | Default. Log a warning if the entry was integrated outside the certificate validity window |
| `strict` | Fail verification if the entry was integrated outside the certificate validity window      |
| `ignore` | Skip the temporal check entirely                                                           |

The check matters because a Fulcio certificate is intentionally short-lived
(typically minutes). If someone takes a signed envelope and uploads it to
Rekor weeks later, the entry will integrate fine but the certificate is no
longer valid, and the signature is no longer one a relying party should
trust. `strict` rejects such entries; `warn` flags them so they can be
audited; `ignore` is for diagnostic use only.

Envelopes signed with the `key` signer have no certificate validity
window, so the temporal check is a no-op for them regardless of policy.

## Server selection

The Rekor server URL is set with `--rekor-url`. The default URL is defined
in `pkg/clients/rekor/v1` and points at the public Sigstore Rekor
instance; override it to use a different deployment or your own
log.

`--rekor-url` must use the `https://` scheme; a `RequiresTLS` constraint
on the flag rejects plain `http://` URLs. `--insecure` skips TLS
certificate verification (useful for self-signed local deployments) but
the URL itself still has to be HTTPS.
