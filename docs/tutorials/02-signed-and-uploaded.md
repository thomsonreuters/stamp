# Signed with Fulcio, uploaded to Rekor

By the end of this tutorial you will have signed an attestation with a
Fulcio-issued certificate (no local keys), uploaded it to Rekor, and verified
inclusion in the transparency log.

This tutorial assumes you completed [tutorial 1](./01-first-attestation.md).

## What you will need

- The `stamp` binary on your `PATH`.
- An OIDC token that Fulcio will accept. The easiest paths, in order:
  1. Run inside a GitHub Actions workflow and pass `--github` instead of
     `--oidc-token-file`. The token is sourced from the runner automatically.
  2. Run locally with a token you obtained out of band and saved to a file.
     For how to obtain one against your IdP, see the explanation document on
     signing and trust.
- A git repository to attest, as in tutorial 1.

The steps below assume option (2): you have a token saved at `./token` (no
trailing newline) and you are running locally.

## Step 1: Run with the Fulcio signer

Tell `stamp run` to use Fulcio for keyless signing and Rekor for upload.
As in tutorial 1, pass `--log-level info` so you can see the progress
messages reproduced below.

```sh
stamp --log-level info run \
  --attestor git \
  --signer fulcio \
  --oidc-token-file ./token \
  --rekor \
  --rekor-upload individual \
  --persist \
  --template './attestations/${attestor}-${timestamp}.json'
```

Inside GitHub Actions, swap `--oidc-token-file ./token` for `--github`.

Abbreviated output:

```
INFO  requesting Fulcio certificate
INFO  certificate issued       san=https://github.com/your-org/your-repo/.github/workflows/release.yml@refs/heads/main
INFO  attestation signed       signer=fulcio
INFO  uploaded to Rekor        uuid=24296fb24b8ad77a... log_index=1428903 integrated_time=2026-05-28T10:21:44Z
INFO  attestation written      path=./attestations/git-1748000504.json
```

Three values matter for the rest of this tutorial:

- The Rekor **UUID** identifies the entry in the transparency log.
- The **log index** is a monotonic position in the log.
- The **integrated time** is when Rekor accepted the entry. The verifier uses
  this to check the entry was created during the signing certificate's
  validity window.

Copy the UUID into a shell variable.

```sh
UUID=24296fb24b8ad77a...   # paste the value from your output
```

## Step 2: Fetch the entry back from Rekor

Round-trip through the log to confirm the entry is really there.

```sh
stamp --log-level info fetch --uuid "$UUID"
```

Abbreviated output:

```
INFO  fetched Rekor entry  uuid=24296fb24b8ad77a... log_index=1428903
{
  "uuid": "24296fb24b8ad77a...",
  "log_index": 1428903,
  "integrated_time": "2026-05-28T10:21:44Z",
  "body": { "...": "..." }
}
```

If the UUID is wrong or the entry was never uploaded, `fetch` returns a
not-found error.

## Step 3: Verify inclusion

`verify` can check signature alone (as in tutorial 1) or signature plus Rekor
inclusion. Pass `--rekor` to do both.

```sh
ATTESTATION=$(ls ./attestations/git-*.json | tail -n 1)
stamp --log-level info verify "$ATTESTATION" --rekor
```

```
INFO  signature=valid (certificate)
INFO  rekor=valid    uuid=24296fb24b8ad77a... log_index=1428903
INFO  verification complete
```

Notice you did not pass `--public-key`. Fulcio-signed envelopes carry the
signing certificate inline, so the verifier extracts the public key from the
certificate and validates the certificate against the embedded Fulcio trust
bundle.

## Step 4: Temporal policy

Fulcio certificates are short-lived - typically ten minutes. If a Rekor entry
was integrated *after* its signing certificate expired, that is suspicious:
either the clock is wrong or the entry was backdated.

The `--rekor-temporal-policy` flag controls how `verify` reacts:

- `warn` (the default if you omit the flag): log a warning, do not fail.
- `strict`: fail verification.
- `ignore`: do not check.

Re-run verification with the strict policy.

```sh
stamp --log-level info verify "$ATTESTATION" --rekor --rekor-temporal-policy strict
```

For a freshly-signed attestation this still succeeds. Use `strict` in CI
policy gates where a temporal mismatch should block a release. Use the default
`warn` during onboarding so you find out about clock skew without breaking
existing pipelines.

## Where to next

You can now produce attestations whose signatures are tied to a verifiable
workload identity, published to a transparency log, and verifiable end-to-end
without any pre-shared keys. The next step is to run several attestors
together as a workflow.

- Tutorial 3 - [Author a workflow YAML](./03-workflow.md)
- Explanation - transparency and verification
