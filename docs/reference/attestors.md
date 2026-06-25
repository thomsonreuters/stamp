# Attestors Reference

This page lists every attestor shipped with the framework, the predicate URI it emits, and the behaviors that are not obvious from configuration alone. For the full configuration schema of any attestor, run:

```
stamp list --show-config <id>
```

This reference focuses on what `--show-config` does not tell you: which subjects are produced, what auto-detection rules apply, what defaults are silently injected, and what host prerequisites must be satisfied.

## Index

| ID                | Predicate URI                                                | What it attests                                                                            |
| ----------------- | ------------------------------------------------------------ | ------------------------------------------------------------------------------------------ |
| `git`             | `https://github.com/thomsonreuters/stamp/git/v1`             | Source control state: commit, repository status, optional refs/remotes/tags/submodules     |
| `file`            | `https://github.com/thomsonreuters/stamp/file/v1`            | File and directory hashes plus optional metadata for one or more paths                     |
| `command`         | `https://github.com/thomsonreuters/stamp/command/v1`         | Execution of a command or script, including timing, exit status, output, and environment   |
| `github-workflow` | `https://github.com/thomsonreuters/stamp/github-workflow/v1` | GitHub Actions workflow run context (workflow, runner, trigger, repository, optional OIDC) |
| `go-builder`      | `https://slsa.dev/provenance/v1`                             | SLSA v1 provenance for a Go binary built from a `.slsa-goreleaser.yml` specification       |
| `jwt`             | `https://witness.dev/attestations/jwt/v0.1`                  | A JWT token's header, claims, and signature-verification result                            |
| `sbom`            | `https://github.com/thomsonreuters/stamp/sbom/v1`            | A CycloneDX or SPDX SBOM document, with optional schema validation                         |
| `ec2`             | `https://github.com/thomsonreuters/stamp/ec2/v1`             | AWS EC2 runtime environment metadata collected from IMDS                                   |

---

## git

### Purpose

Captures the state of a Git working tree at attestation time. Use it to bind downstream attestations (builds, tests, SBOMs) to a specific commit and to record whether the tree was clean. This is a source-control attestation, not SLSA build provenance.

### Predicate URI

`https://github.com/thomsonreuters/stamp/git/v1`

See [predicates.md#git](./predicates.md#git) for shape.

### Subjects produced

A single subject naming the repository and commit:

- Name: `git+<repo-url>@<commit-sha>`. The URL is the resolved HTML URL of `origin` when available; otherwise `file://<absolute-working-dir>`.
- Digest: always includes `sha1` (the commit hash). Additional algorithms (`sha256`, `sha512`) are added when configured via `hash-algorithms`.

### Key behaviors

- Working directory must contain a Git repository and at least one commit; an empty repository fails with a validation error.
- `dirty-behavior` controls what happens when the worktree has uncommitted changes:
  - `allow` (default): proceed silently, include file status in the predicate.
  - `warn`: proceed and log a warning.
  - `fail`: abort attestation.
- Detached HEAD and shallow clones are detected and reflected as flags in `repository_status`; neither is fatal.
- `redact-identity` replaces author and committer name/email with `[REDACTED]` but preserves timestamps. `sensitive-fields` accepts dotted JSON paths (e.g. `author.email`, `repository`) for more targeted redaction.
- `include-refs`, `include-all-remotes`, `include-tags`, `include-submodules` are off by default; opt in only when you need the extra data, as each adds Git invocations.
- `include-binary-hash` hashes the `git` binary itself; this adds noticeable startup cost.
- `include-signature` is on by default and captures the commit's GPG signature block if present; the attestor does not verify it.

### Prerequisites

- A `git` binary on PATH.
- A Git repository at the configured working directory (default `.`).
- At least one commit in the repository.

### See also

- Predicate shape: [predicates.md#git](./predicates.md#git)

---

## file

### Purpose

Hashes files and (optionally) directory metadata to produce evidence of artifact contents. Use it to attest build outputs, source inputs, or any set of paths that should be pinned by digest.

### Predicate URI

`https://github.com/thomsonreuters/stamp/file/v1`

### Subjects produced

Subject set depends on `subject-mode`:

- `manifest-only` (default): one subject named `file-manifest+<absolute-base-path>` whose digest is computed across the collected artifact set.
- `hybrid`: the manifest subject plus one subject per artifact matching `subject-include` patterns.
- `all-files`: the manifest subject plus one subject per collected file. This can produce very large statements.

Each per-file subject uses the artifact's path (relative to base) as the name and the artifact's digest map as the digest.

### Key behaviors

- `paths` is required and may contain absolute or base-path-relative entries, including directories and glob patterns.
- `include-patterns` defaults to `["**"]` if left empty after parsing; `exclude-patterns` is evaluated before include matching.
- Glob matching follows gitignore semantics.
- `follow-symlinks=false` (default) records the symlink itself as an artifact of type `symlink` with target information; setting it to `true` follows the link and hashes the destination.
- `capture-permissions` is on by default; `capture-ownership` and `capture-timestamps` are off because they can leak host details and reduce reproducibility.
- `deduplicate` skips paths that resolve to the same inode.
- `error-on-missing=false` (default) treats missing paths as warnings rather than failures.
- `size-warning-threshold` (15 MB by default) triggers a warning log in `PostAttest`; set to `0` to disable. The threshold does not abort attestation.
- Hash algorithms default to `sha256`; `sha512`, `blake3`, `sha3-256`, and `sha3-512` are also supported. Names are lowercased on parse.

### Prerequisites

- The configured base path exists and is readable.
- Sufficient permissions to stat and read the paths under attestation.

### See also

- Predicate shape: [predicates.md#file](./predicates.md#file)

---

## command

### Purpose

Records the execution of a single command, script, or shell line and the environment it ran in. Use it to capture build, test, or deploy steps as discrete attestations.

### Predicate URI

`https://github.com/thomsonreuters/stamp/command/v1`

### Subjects produced

A single deterministic subject derived from the command string:

- Name: `pkg:generic/command-execution@command`.
- Digest: `sha256` of the configured `command` value.

The subject identifies what was asked to run, not what was produced. Pair this attestor with the `file` attestor if you need to bind outputs.

### Key behaviors

- `execution_mode` selects how the command is run:
  - `shell` (default): invoked through the configured shell with `-c` (or `/c` on Windows `cmd.exe`); supports pipes, globs, redirection.
  - `direct`: parsed into argv and executed without a shell; the first token must resolve via PATH or be an absolute path.
  - `script`: the command string is written to a temporary file, made executable, and run via the configured shell. Long script bodies (over 100 lines) are summarized in the predicate's `command_line` field as `[script: N lines]`.
- Default shell is `/bin/bash` on Unix-like systems and `cmd.exe` on Windows.
- `timeout` defaults to 600 seconds; allowed range is 1 to 86400. Hitting the timeout sets `status=timeout` and `exit_code=-1`.
- `max_output_size` (default 10 MB) bounds captured stdout and stderr independently; truncation sets `output.truncated=true`. Hard ceiling is 100 MB.
- Stdout and stderr that are valid UTF-8 are stored as strings with `encoding=utf-8`; otherwise they are base64-encoded with `encoding=base64`. A `sha256` digest of each stream is always recorded when capture is enabled.
- `allowed_exit_codes` defaults to `["0"]`. A disallowed code fails the attestation only when `fail_on_error=true` (the default); when false, the attestation captures the failure as evidence and succeeds.
- Built-in redaction patterns always run regardless of `redact_patterns`: `password=...`, `token=...`, `api[_-]?key=...`, `secret=...`. Custom patterns from `redact_patterns` are appended. Invalid regexes fail validation.
- Redaction is applied to stdout, stderr, and the recorded `command_line` after execution; the executed command itself is not redacted.
- Resource metrics (CPU, memory, I/O) are populated from `getrusage` on Unix and may be empty on platforms where the data is unavailable.

### Prerequisites

- The configured `shell` is resolvable via PATH (validated during `ValidateConfig`).
- For `direct` mode, the executable is resolvable via PATH or exists at the given absolute path.
- The configured `working_directory`, if set, exists.

### See also

- Predicate shape: [predicates.md#command](./predicates.md#command)

---

## github-workflow

### Purpose

Captures the runtime context of a GitHub Actions workflow run, including workflow identity, runner, trigger event, repository, and optionally the OIDC token. Use it to bind other attestations to a specific workflow run.

### Predicate URI

`https://github.com/thomsonreuters/stamp/github-workflow/v1`

### Subjects produced

- Always: `github-workflow://<repository>/runs/<run_id>` with a digest map containing `run_id`, `run_attempt`, and `sha1` (the commit SHA).
- When `subject-workflow-file=true` and the workflow file is locatable in the checkout: `github-workflow-file://<repository>/<workflow-file-path>` with the file's SHA-256 digest.

### Key behaviors

- The attestor pulls most fields from the GitHub Actions OIDC token (claims like `repository`, `run_id`, `workflow`, `event_name`, `actor`). Some fields come from the runner environment (`GITHUB_JOB`, `RUNNER_*`, `GITHUB_EVENT_PATH`) and are marked as such in the predicate.
- OIDC token acquisition requires `ACTIONS_ID_TOKEN_REQUEST_TOKEN` and `ACTIONS_ID_TOKEN_REQUEST_URL`. The audience is configurable via `oidc-audience` (default `https://github.com`).
- `capture-event-payload=true` (default) reads `$GITHUB_EVENT_PATH`. `missing-event-behavior` controls what happens when the file is unreadable: `allow` (continue silently), `warn` (default), `fail`.
- `redact-event-payload` runs the built-in plus custom regex patterns over the payload while preserving JSON structure. Custom `redact-patterns` cannot include catch-all expressions (`.*`, `.+`, `^.*$`, `[\s\S]*`); these are rejected as dangerous.
- `capture-environment=false` by default. When enabled, environment variables are filtered by `env-include-patterns` (default `GITHUB_*`, `RUNNER_*`, `CI`, `ACTIONS_*`) and `env-exclude-patterns`. Excludes always take precedence. Built-in security exclusions for `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*API_KEY*`, `*ACCESS_KEY*`, `*PRIVATE_KEY*`, `*CREDENTIALS*`, `ACTIONS_ID_TOKEN*`, `ACTIONS_RUNTIME*`, `*_SIGNING_KEY*`, and `*AUTH*TOKEN*` are always applied regardless of configuration.
- `sensitive-fields` accepts dotted predicate paths (e.g. `actor`, `repository.owner`, `trigger.event_payload`). A small set of critical fields cannot be redacted: `workflow.run_id`, `run_id`, `repository.sha`, `metadata.started_on`.
- `redact-actor` is a shortcut that sets `trigger.actor` and `trigger.actor_id` to `[REDACTED]`.

### Prerequisites

- Must run inside a GitHub Actions runner. The OIDC environment variables above are required for token capture; runs without them will still produce a predicate but with an empty OIDC section and missing OIDC-sourced fields.
- `$GITHUB_EVENT_PATH` must point at a readable file when `capture-event-payload=true`, or `missing-event-behavior` must allow the absence.

### See also

- Predicate shape: [predicates.md#github-workflow](./predicates.md#github-workflow)

---

## go-builder

### Purpose

Produces SLSA v1 provenance for a Go binary built according to a `.slsa-goreleaser.yml` specification. Use it as the build step in a SLSA-aligned pipeline; the predicate type is the standard SLSA Provenance URI, not a Thomson Reuters custom predicate.

### Predicate URI

`https://slsa.dev/provenance/v1`

### Subjects produced

A single subject for the built binary:

- Name: the binary's resolved name (from the build config).
- Digest: `sha256` of the produced binary file.

### Key behaviors

- `build-config` is required and points at a `.slsa-goreleaser.yml` file. The file defines the binary name, output path, Go command flags, and environment.
- The attestor auto-detects the build environment in this order: GitHub Actions, EC2, then generic. Detection failures for GitHub Actions can be fatal (when GitHub indicators are present but the environment is misconfigured); EC2 detection failures fall through to the generic detector silently.
  - GitHub Actions populates `external_parameters.source` and workflow `inputs` from the OIDC token and runner env; sets `builder.id` from the workflow ref.
  - EC2 populates `internal_parameters` with instance metadata pulled from IMDS.
  - Generic uses any locally-available git remote for source URI, generates a UUID for `invocation_id`, and reports `environment_type=generic` in internal parameters.
- `capture-event-payload` (default true) includes the GitHub Actions event payload in `internal_parameters`. Ignored outside GitHub Actions.
- The build type URI is fixed at `https://github.com/thomsonreuters/stamp/build/golang/v1`.
- `builder.builder_dependencies` is currently emitted as an empty array.

### Prerequisites

- A Go toolchain capable of running the configured build command.
- A valid `.slsa-goreleaser.yml` at the path given by `build-config`.
- For full GitHub Actions context, the OIDC environment variables described under `github-workflow`.
- For EC2 context, IMDS must be reachable from the build host.

### See also

- Predicate shape: [predicates.md#provenance-slsa-v1](./predicates.md#provenance-slsa-v1)
- Environment detection lives in the `pkg/buildenv` package.

---

## jwt

### Purpose

Acquires a JWT (from a file, stdin, environment variable, or a known identity provider) and produces an attestation of its header, claims, and signature-verification outcome. Use it to record that a particular OIDC or service-account token was in scope at a given point in the pipeline.

### Predicate URI

`https://witness.dev/attestations/jwt/v0.1`

This URI is intentionally aligned with the Witness project's JWT attestation rather than the Thomson Reuters convention used by the other custom attestors.

### Subjects produced

A single subject:

- Name: the JWT's `sub` claim if present; otherwise the literal `jwt:no-subject-claim`.
- Digest: `sha256` of the raw token string.

### Key behaviors

- Exactly one token source must be configured. Sources are evaluated in priority order: `jwt-token-file`, `jwt-from-stdin`, `jwt-from-env`, then auto-discovery flags. Validation rejects multiple sources.
- Auto-discovery flags each probe a specific environment:
  - `jwt-auto-discover-github`: requires `ACTIONS_ID_TOKEN_REQUEST_TOKEN` and `ACTIONS_ID_TOKEN_REQUEST_URL`; audience comes from `jwt-expected-audience[0]` or defaults to `https://github.com`.
  - `jwt-auto-discover-aws`: requires the AWS IRSA environment variables (`AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_ROLE_ARN`).
  - `jwt-auto-discover-kubernetes`: requires the in-pod service-account token at the standard mount path.
- Verification key sources are evaluated in priority order: `jwt-public-key-file`, `jwt-jwks-url`, `jwt-oidc-discovery-url`, then auto-discovery from the token's `iss` claim. If none are configured and `jwt-skip-verification=false`, verification fails.
- `jwt-skip-verification=true` records `verification: skipped` in the predicate; the token is still parsed and its claims emitted.
- Algorithm filtering: `jwt-denied-algorithms` always wins over `jwt-allowed-algorithms`. The attestor's `SupportedAlgorithms` list excludes `none` by design; `none` can appear only in the denylist for explicit rejection.
- Claims output is governed by `jwt-include-all-claims` (default true), `jwt-claims-allowlist` (additive for custom claims), `jwt-claims-denylist`, and `jwt-redact-claims`. Standard registered claims (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`) are always included regardless of filters.

### Prerequisites

- For auto-discovery, the corresponding identity environment must be present.
- For JWKS or OIDC discovery verification, network access to the issuer; optionally a CA bundle via `jwt-ca-cert`.

### See also

- Predicate shape: [predicates.md#jwt](./predicates.md#jwt)

---

## sbom

### Purpose

Wraps an existing CycloneDX or SPDX SBOM document in an in-toto attestation. The attestor does not generate the SBOM; it ingests and attests an SBOM produced by another tool.

### Predicate URI

`https://github.com/thomsonreuters/stamp/sbom/v1`

### Subjects produced

A single subject for the SBOM file itself:

- Name: `sbom+<file-basename>`.
- Digest: `sha256` of the SBOM file contents.

### Key behaviors

- `sbom-path` is required and must point to a JSON document. Format is detected by inspecting the file; CycloneDX and SPDX are supported.
- `validate-schema=true` (default) validates the document against its specification's JSON schema. `validation-behavior` controls outcome on failure: `allow` (include the SBOM regardless), `warn` (default; include and log), `fail` (abort).
- The full SBOM contents are embedded in the predicate's `content` field. Large SBOMs produce large attestations.

### Prerequisites

- The SBOM file exists and is valid JSON.

### See also

- Predicate shape: [predicates.md#sbom](./predicates.md#sbom)

---

## ec2

### Purpose

Collects identity, network, and (optionally) IAM and tag metadata from the AWS EC2 Instance Metadata Service (IMDS). Use it to attest the runtime environment of a workload running on EC2.

### Predicate URI

`https://github.com/thomsonreuters/stamp/ec2/v1`

### Subjects produced

A single subject identifying the instance:

- Name: `ec2+<region>://<instance-id>`.
- Digest map: `instanceId`, `imageId`, `accountId`. Note these are identifiers, not cryptographic hashes; the digest map is used here as a name-value bag per the in-toto subject convention.

### Key behaviors

- `imds-version` controls the protocol: `v2` (default; token-based, recommended), `v1` (legacy), or `auto` (try v2, fall back to v1).
- `not-ec2-behavior` controls what happens when IMDS is unreachable during `PreAttest`: `fail` (default), `warn` (log and continue with partial data), `skip` (silently no-op the attestation).
- `imds-unavailable-behavior` is a second gate evaluated during `Attest` for the case where IMDS was initially reachable but later requests fail: `fail` aborts; `warn` produces a partial predicate.
- The instance identity document is always collected when IMDS is reachable. Network details, IAM info, and tags are off-by-default opt-ins (`include-network-details` is the exception and is on by default).
- Instance lifecycle detection (`spot`, `on-demand`, `scheduled`) is best-effort: failures default the value to `on-demand` without aborting.
- Tag collection requires the instance's IAM role to grant `ec2:DescribeTags`.
- `redact-account-id` and `redact-private-ips` replace those specific fields with `[REDACTED]`. `sensitive-fields` accepts additional dotted paths (e.g. `accountId`, `vpcId`).
- `token-ttl` for IMDSv2 ranges from 1 to 21600 seconds.

### Prerequisites

- The host must be an EC2 instance, or IMDS must be reachable at the configured endpoint, unless `not-ec2-behavior` is set to `warn`/`skip`.
- For `include-tags=true`, the instance IAM role must allow `ec2:DescribeTags`.

### See also

- Predicate shape: [predicates.md#ec2](./predicates.md#ec2)
