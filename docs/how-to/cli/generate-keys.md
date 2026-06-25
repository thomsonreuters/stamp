# Generate a Signing Key Pair

Create a new signing key pair for use with `--signer key`.

## Prerequisites

- `stamp` binary on `PATH`.
- Write access to the chosen output directory.

## Recipe

1. Choose a key type. ECDSA P-256 is recommended (smaller and faster); RSA 2048 is widely supported and useful for compatibility with older tooling.

   ```bash
   stamp generate-key --type ecdsa --output ./examplekey
   # or
   stamp generate-key --type rsa   --output ./examplekey
   ```

   The `--output` value is a base path. Two files are produced:

   - `./examplekey.key` — PEM-encoded private key, mode `0600`.
   - `./examplekey.pub` — PEM-encoded public key, mode `0644`.

2. Optionally encrypt the private key (PKCS#8 encryption). Pick one of the three password sources; they are mutually exclusive:

   ```bash
   stamp generate-key --type ecdsa --output ./examplekey --prompt
   # or read from a file
   stamp generate-key --type ecdsa --output ./examplekey --password-file ./pass.txt
   # or pass inline (testing only; leaks via process listing and shell history)
   stamp generate-key --type ecdsa --output ./examplekey --password 's3cret'
   ```

3. If files already exist at the chosen base path, the command refuses to overwrite them. To replace existing files:

   ```bash
   stamp generate-key --type ecdsa --output ./examplekey --overwrite
   ```

## Protect the private key

- Keep `.key` files out of version control. The repository's `.gitignore` already excludes `*.key` and `*.pub`, but verify before committing.
- For CI use, store the private key in a secret manager (GitHub Actions secrets, Vault, AWS Secrets Manager) and materialise it to disk at runtime with `0600` permissions.
- For long-lived production signing, prefer keyless signing via Fulcio — see [sign-keyless-with-fulcio.md](sign-keyless-with-fulcio.md).

## See also

- [sign-with-local-key.md](sign-with-local-key.md)
- [sign-keyless-with-fulcio.md](sign-keyless-with-fulcio.md)
- `../../reference/signing.md`
