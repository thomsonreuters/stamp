# Your first attestation

By the end of this tutorial you will have generated and inspected a signed
in-toto attestation of a git repository, using a locally-generated key.

## What you will need

- The `stamp` binary on your `PATH`. Run `stamp --version` to confirm.
- A git repository to attest. You can use a clone of the attestor repo itself
  or any other repo you have locally.
- `jq` installed, for inspecting JSON.
- About five minutes.

The remaining steps assume your shell is inside the repository you want to
attest.

## Step 1: Generate a signing key

The `key` signer needs a private key to sign with and a matching public key to
verify with. Generate both with one command.

```sh
stamp generate-key --type ecdsa --output ./demo-key
```

This writes two files in the current directory:

```
-rw-------  1 you  staff  ...  demo-key.key
-rw-r--r--  1 you  staff  ...  demo-key.pub
```

The private key is mode `0600`; the public key is mode `0644`. Keep the
private key out of source control.

## Step 2: Produce an attestation

Run the `git` attestor and have it persist the signed envelope to disk.
The default log level is `warn`; pass `--log-level info` so you can see
the progress messages this tutorial reproduces.

```sh
stamp --log-level info run \
  --attestor git \
  --signer key \
  --private-key ./demo-key.key \
  --persist \
  --template './attestations/${attestor}-${timestamp}.json'
```

Abbreviated output:

```
INFO  starting attestor
INFO  attestation completed  attestor_id=git duration_ms=84
INFO  attestation written    path=./attestations/git-1748000062.json
```

`${timestamp}` resolves to a Unix timestamp (seconds since epoch); if you
prefer a human-readable filename, use `${date}` for `YYYY-MM-DD` instead.
The file at the printed path is a
[DSSE](https://github.com/secure-systems-lab/dsse) envelope containing
your signed in-toto statement.

## Step 3: Inspect what you got

The envelope has three top-level fields. Look at them.

```sh
ATTESTATION=$(ls ./attestations/git-*.json | head -n 1)
jq 'keys' "$ATTESTATION"
```

```json
["payload", "payloadType", "signatures"]
```

`payload` is a base64-encoded in-toto Statement. Decode it.

```sh
jq -r '.payload' "$ATTESTATION" | base64 -d | jq '.'
```

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "git+https://github.com/your-org/your-repo@a1b2c3d4e5f6...",
      "digest": {
        "sha1": "a1b2c3d4e5f6..."
      }
    }
  ],
  "predicateType": "https://github.com/thomsonreuters/stamp/git/v1",
  "predicate": {
    "commit": { "...": "..." },
    "remotes": [ "..." ]
  }
}
```

Two things to notice:

- The `predicateType` URI tells a verifier how to interpret the `predicate`
  body. For the git attestor it is `https://github.com/thomsonreuters/stamp/git/v1`.
- The `subject` digest identifies *what* this attestation is about - here, a
  specific commit SHA.

The `signatures` array carries the signature itself.

```sh
jq '.signatures' "$ATTESTATION"
```

```json
[
  {
    "keyid": "SHA256:...",
    "sig": "MEUCIQD..."
  }
]
```

## Step 4: Verify the signature

Confirm the envelope was signed by the key you generated.

```sh
stamp --log-level info verify "$ATTESTATION" --public-key ./demo-key.pub
```

```
INFO  verification complete  signature=valid
```

If you tamper with the file (change a byte in the payload, for example) and
re-run `verify`, the command exits non-zero and reports an invalid signature.

## Where to next

You now have a signed attestation backed by a key file you own. In practice
you want signatures backed by short-lived, identity-bound certificates so
verifiers do not have to trust a long-lived key. That is the next tutorial.

- Tutorial 2 - [Signed with Fulcio and uploaded to Rekor](./02-signed-and-uploaded.md)
- Explanation - the attestation model (envelope, statement, predicate)
