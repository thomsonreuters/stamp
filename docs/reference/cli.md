# CLI commands

The `stamp` binary is a Cobra application with a small set of top-level
commands. Each command groups one or more flag sets defined under
`pkg/config/flags`. This page documents the purpose, inputs, outputs, exit
behavior, and non-obvious flag interactions for every command. For the
authoritative list of flags, their defaults, and short forms, run
`stamp --help` and `stamp <command> --help`. Those outputs are generated
from the flag definitions themselves and will never drift.

## Configuration precedence

Every flag may also be set through environment variables (`STAMP_*`) or a
YAML configuration file (`~/.stamp.yaml`, or the path given by `--config`).
Values are resolved in this order, highest first:

1. CLI flags
2. Environment variables
3. Config file
4. Built-in defaults

Mutual-exclusion and `requires` constraints declared on flags apply equally no
matter which layer set the value.

## `run`

### Synopsis

```text
stamp run [workflow-name ...] [flags]
```

### Purpose

Execute attestors and produce signed in-toto attestations. `run` is the primary
command and operates in two distinct modes: single-attestor mode and
workflow mode (one or many workflows defined in the configuration file).

### Inputs

- Positional arguments are workflow names. Passing one or more workflow
  names selects exactly those workflows; passing none plus a selection
  flag (`--all`, `--tags`, `--include`, `--exclude`) selects by filter;
  passing none plus `--attestor` runs a single ad-hoc attestor.
- Selection flags (`--attestor`, `--all`, `--tags`, `--include`, `--exclude`)
  choose what to execute when no positional names are given.
- Signing flag groups (`--signer`, `--oidc-token`/`--oidc-token-file`/`--spire`/`--github`,
  `--private-key`, `--public-key`, password flags) control how attestations
  are signed.
- Rekor flag groups (`--rekor`, `--rekor-url`, `--rekor-upload`) control
  transparency-log upload.
- Output flags (`--output-mode`, `--persist`, `--template`, `--force`)
  control how attestations leave the process.
- For workflow mode, the config file's `workflows:` section is the source of
  attestor definitions and per-workflow Rekor settings.
- `--set key=value` (repeatable) overrides values inside the selected
  attestor's per-attestor configuration map. Values are type-coerced using the
  attestor's `ConfigSchema()`.

### Outputs

- Attestation JSON (in-toto Statement wrapped in a DSSE Envelope) on stdout
  by default, one document per attestation in `individual` mode, or one
  collection envelope in `collection` mode.
- When `--persist` is set, attestations are also written to files using the
  path template (see the path-template how-to for variable syntax).
- Logs on stderr (suppressed by `--quiet`, redirected by `--log-file`).
- When Rekor upload is enabled, an entry is created on the configured Rekor
  server; the UUID and log index are logged.

### Flag interactions

- `--attestor` is mutually exclusive with `--all`, `--tags`, `--include`,
  and `--exclude`. You cannot mix single-attestor mode and workflow mode.
- `--set` requires `--attestor` and is mutually exclusive with the workflow
  selectors. Per-attestor overrides only make sense for a single attestor
  invocation; workflow configurations carry their own per-attestor blocks.
- `--persist`, `--force`, and `--template` require `--attestor`. File
  persistence in workflow mode is not currently exposed via configuration;
  this is tracked as planned work.
- `--force` additionally requires `--persist`.
- `--template` additionally requires `--persist`.
- Signing token flags (`--oidc-token`, `--oidc-token-file`, `--spire`,
  `--github`, `--socket`) are mutually exclusive with one another. Pick one
  source for the OIDC token.
- Password flags (`--password`, `--password-file`, `--prompt`) are mutually
  exclusive.
- `--continue-on-error` only affects workflow-to-workflow progression. It
  does not override a workflow's own `failure_policy` for the attestors
  inside it.

### Examples

```sh
# Single attestor with key-based signing, written to a file
stamp run --attestor git --signer key --private-key ./signing.key \
  --persist --template './attestations/${attestor}.json'

# All workflows defined in the config file, fail-fast across workflows
stamp run --all

# Workflows matching a glob, excluding experimental ones
stamp run --all --include '*-prod' --exclude 'experimental-*' \
  --continue-on-error
```

## `list`

### Synopsis

```text
stamp list [attestor-id]
```

### Purpose

Enumerate registered attestors and, optionally, describe their per-attestor
configuration schema. This is the discovery surface for `--set` keys and for
authoring `workflows[].attestors[].config` blocks.

### Inputs

- Optional positional `attestor-id`. If given, only that attestor's details
  are shown.
- `--show-config` expands the output to include each configuration field with
  its type, default, and description.

### Outputs

- Tabular listing on stdout. Without `--show-config`, one row per attestor
  with the identifier and a short description. With `--show-config` (or with
  a positional `attestor-id`), the per-attestor configuration schema.

### Flag interactions

None worth calling out; `list` has no mutual exclusions.

### Examples

```sh
# Compact list of every registered attestor
stamp list

# Configuration schema for one attestor (use this when authoring config)
stamp list git

# Schema for all attestors at once
stamp list --show-config
```

## `verify`

### Synopsis

```text
stamp verify <attestation-file> [flags]
```

### Purpose

Verify the cryptographic signature on an attestation and, optionally, its
inclusion in a Rekor transparency log. Auto-detects whether the envelope was
signed by an embedded Fulcio certificate or by a static key.

### Inputs

- Required positional `attestation-file`: path to a DSSE envelope JSON file.
- `--public-key` for static-key signatures. For certificate-based signatures
  the embedded certificate is used and a Fulcio trust bundle is fetched from
  `--fulcio-url`.
- `--rekor` enables transparency-log verification; `--rekor-url` selects the
  server; `--rekor-temporal-policy` controls how to treat entries logged
  outside the certificate's validity window.
- `--output-verification` writes a detailed verification result to the named
  JSON file in addition to the stdout summary.

### Outputs

- Verification result on stdout (status, signer identity, Rekor entry details
  when applicable).
- When `--output-verification` is given, the same result is serialized to the
  specified JSON file.
- Non-zero exit code on verification failure (see "Exit codes").

### Flag interactions

- `--rekor-temporal-policy` only takes effect when `--rekor` is set. The
  policy is silently ignored otherwise; supplying it without `--rekor` is a
  no-op rather than an error.
- `--public-key` is an alternative to certificate-based verification, not a
  supplement. When a certificate is present in the envelope, `--public-key`
  is unused.

### Examples

```sh
# Auto-detect signature type
stamp verify attestation.json

# Static-key verification
stamp verify attestation.json --public-key ./public.pem

# Full transparency-log verification with strict temporal validation
stamp verify attestation.json --rekor --rekor-temporal-policy strict
```

## `upload`

### Synopsis

```text
stamp upload <attestation-file> [flags]
```

### Purpose

Upload an already-signed attestation to a Rekor transparency log. This is the
out-of-band path for attestations generated without `--rekor` at `run` time,
or for re-uploading to a different server.

### Inputs

- Required positional `attestation-file`: the DSSE envelope to upload.
- `--rekor-url` selects the Rekor instance.
- `--public-key` is required when the attestation was signed with a static
  key; it is not required for certificate-based signatures because the
  certificate is embedded in the envelope.

### Outputs

- Rekor entry UUID and log index on stdout.
- Logs on stderr.

### Flag interactions

None beyond the standard global flags. The "public key required only for
file-based signatures" behavior is enforced at validation time, not via a
flag constraint.

### Examples

```sh
# Upload a certificate-signed attestation to the default server
stamp upload attestation.json

# Static-key attestation, custom server
stamp upload attestation.json --public-key ./public.pem \
  --rekor-url https://rekor.example.com
```

## `fetch`

### Synopsis

```text
stamp fetch [flags]
```

### Purpose

Retrieve an entry from a Rekor transparency log. Supports three input
identifiers: an attestation file (hash is computed and looked up), a Rekor
entry UUID, or a sequential log index.

### Inputs

- `--file`, `--uuid`, or `--log-index`: exactly one of the three.
- `--rekor-url` selects the Rekor instance.
- `--raw` returns the unprocessed Rekor API response; useful for debugging.
- `--output` writes the result to a JSON file in addition to stdout.

### Outputs

- Processed Rekor entry (or raw API response with `--raw`) on stdout as
  JSON.
- Same content to the file given by `--output`, when set.

### Flag interactions

- `--file`, `--uuid`, and `--log-index` are mutually exclusive. The command
  fails if more than one is set and if none is set.

### Examples

```sh
# Look up a Rekor entry by attestation file
stamp fetch --file attestation.json

# Look up by log index, save raw API response
stamp fetch --log-index 12345 --raw --output entry.json
```

## `generate-key`

### Synopsis

```text
stamp generate-key [flags]
```

### Purpose

Generate an asymmetric key pair for use with the `key` signing backend.
Produces a private key file (`<output>.key`, mode `0600`) and a public key
file (`<output>.pub`, mode `0644`).

### Inputs

- `--type` selects the key algorithm (`rsa`, `ecdsa`).
- `--output` (required) is the base path for the generated key files.
- Password flags (`--password`, `--password-file`, `--prompt`) optionally
  encrypt the private key.
- `--overwrite` permits replacing existing files at the destination paths.

### Outputs

- Two files on disk: `<output>.key` and `<output>.pub`.
- Success summary on stdout.

### Flag interactions

- Password flags (`--password`, `--password-file`, `--prompt`) are mutually
  exclusive. Prefer `--prompt` or `--password-file` over `--password` to
  keep the password out of the process command line.

### Examples

```sh
# Unencrypted RSA pair
stamp generate-key --type rsa --output ./signing

# Encrypted ECDSA pair with interactive password prompt
stamp generate-key --type ecdsa --output ./signing --prompt

# Replace an existing pair
stamp generate-key --type rsa --output ./signing --overwrite
```

## Global flags

The following flags are persistent and may be used with any command. They
control infrastructure rather than the operation of a specific command.

- `--config, -c` — Path to an explicit configuration file. When unset, the
  binary loads `~/.stamp.yaml` if present. Cannot itself be set via the
  config file (it is bootstrap-only).
- `--log-level` — Log threshold (`debug`, `info`, `warn`, `error`).
  `--debug` overrides this to `debug`.
- `--log-format` — `console` for human-readable text, `json` for structured
  output.
- `--log-file` — Write logs to a file instead of stderr. The file is opened
  in append mode.
- `--quiet, -q` — Suppress logs and user messages; data output (attestations,
  fetch results) still goes to stdout. Mutually exclusive with `--log-only`
  and `--debug`.
- `--log-only` — Inverse of `--quiet`: suppress data output, keep logs and
  user messages. Mutually exclusive with `--quiet`.
- `--debug` — Enable debug-level logging and attach source-file annotations
  to log records. Mutually exclusive with `--quiet`.
- `--no-color` — Disable ANSI color in terminal output. The `NO_COLOR`
  environment variable has the same effect.
- `--insecure` — Skip TLS certificate verification on outbound HTTPS calls.
  Use only for development and internal testing.

The flags compose: for example, `--quiet --log-file ./stamp.log` discards
on-screen logs but still captures them to disk, leaving stdout for the
attestation JSON.

## Exit codes

The constants are defined in `pkg/errors` and are stable.

| Code | Name                  | Meaning                                                         |
| ---- | --------------------- | --------------------------------------------------------------- |
| 0    | `ExitSuccess`         | Operation completed successfully.                               |
| 1    | `ExitGeneralError`    | Unspecified error.                                              |
| 2    | `ExitUsageError`      | Invalid CLI usage (bad flag combination, etc.).                 |
| 3    | `ExitValidationError` | Field-level validation failed.                                  |
| 4    | `ExitConfigError`     | Configuration could not be loaded or parsed.                    |
| 5    | `ExitRuntimeError`    | Failure during execution (pipeline, attestor, signing, upload). |

Errors raised through `pkg/errors` carry their own exit code; unhandled
errors fall through to `ExitGeneralError`.
