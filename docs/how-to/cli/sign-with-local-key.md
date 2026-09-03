# Sign with a Local Key

Produce a signed attestation using an RSA or ECDSA private key that you control on disk.

## Prerequisites

- `stamp` binary on `PATH`.
- A private key file. If you do not have one, see [generate-keys.md](generate-keys.md).
- The password for the key, if it is encrypted.

## Recipe

1. Locate the private key file you want to sign with. If the file is encrypted, decide how you will supply the password: inline (`--password`), from a file (`--password-file`), or interactively (`--prompt`). These three options are mutually exclusive.

2. Run the attestor with the `key` signer:

   ```bash
   stamp run --attestor git \
     --signer key \
     --private-key /path/to/signing.key
   ```

   For an encrypted key, add one of:

   ```bash
   --password-file /path/to/password.txt
   # or
   --prompt
   ```

3. To also write the signed envelope to disk, add `--persist` and (optionally) `--template`:

   ```bash
   stamp run --attestor git \
     --signer key --private-key ./signing.key \
     --persist --template './attestations/${attestor}-${date}.json'
   ```

## Accepted key formats

- Unencrypted PKCS#8 (`BEGIN PRIVATE KEY`).
- Unencrypted PKCS#1 RSA (`BEGIN RSA PRIVATE KEY`).
- Unencrypted SEC1 EC (`BEGIN EC PRIVATE KEY`).
- Encrypted PKCS#8 (`BEGIN ENCRYPTED PRIVATE KEY`).

Legacy RFC 1423 PEM encryption (`Proc-Type: 4,ENCRYPTED`) is not supported. Re-encrypt such keys as PKCS#8 before use.

## Key ID

The signer's key ID is the SHA256 fingerprint of the PKIX DER-encoded public key, rendered as hex. Verifiers can use this to match envelopes to public keys.

## Gotcha

Envelopes produced this way do not embed a certificate. Whoever verifies the attestation needs the matching public key and must pass it explicitly with `--public-key`. Distribute the `.pub` file alongside the envelope, or publish it in a known location.

## See also

- [generate-keys.md](generate-keys.md)
- [verify-attestation.md](verify-attestation.md)
- [signing.md](../../reference/signing.md)
