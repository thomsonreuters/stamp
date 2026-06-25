# Predicates Reference

Every attestor in this framework produces an in-toto Statement whose `predicateType` is one of the URIs listed below. Custom predicate types defined by this project follow the convention:

```
https://github.com/thomsonreuters/stamp/<name>/v<major>
```

The major version is encoded in the URI path. Breaking changes to a predicate's shape require a new major version (and a new versioned package under `pkg/predicates/<name>/`); additive changes (new optional fields) stay within the existing version. Two predicate URIs do not follow this convention by design:

- The Go Builder attestor emits the standard SLSA Provenance v1 URI rather than a custom one, so consumers that already understand SLSA can parse it without special-casing.
- The JWT attestor emits the Witness project's JWT attestation URI for interoperability with the Witness ecosystem.

The framework's registry maps attestors to predicate URIs, and a single predicate URI may be produced by more than one attestor when their output shapes are compatible. Today this only applies to SLSA Provenance v1 (produced by `go-builder`); the framework is designed to allow additional builder attestors to share the same URI.

## Index

| Predicate URI                                                | Producing attestor(s) | One-line purpose                                       |
| ------------------------------------------------------------ | --------------------- | ------------------------------------------------------ |
| `https://slsa.dev/provenance/v1`                             | `go-builder`          | SLSA v1 build provenance                               |
| `https://github.com/thomsonreuters/stamp/collection/v1`      | (pipeline output)     | Wraps a set of attestations from a single pipeline run |
| `https://github.com/thomsonreuters/stamp/command/v1`         | `command`             | Evidence of a command or script execution              |
| `https://github.com/thomsonreuters/stamp/ec2/v1`             | `ec2`                 | AWS EC2 instance runtime environment                   |
| `https://github.com/thomsonreuters/stamp/file/v1`            | `file`                | File and directory hashes plus metadata                |
| `https://github.com/thomsonreuters/stamp/git/v1`             | `git`                 | Git repository commit and working-tree state           |
| `https://github.com/thomsonreuters/stamp/github-workflow/v1` | `github-workflow`     | GitHub Actions workflow run context                    |
| `https://witness.dev/attestations/jwt/v0.1`                  | `jwt`                 | JWT header, claims, and verification result            |
| `https://github.com/thomsonreuters/stamp/sbom/v1`            | `sbom`                | Wrapped CycloneDX or SPDX SBOM document                |

All predicates are wrapped in an in-toto Statement v1 envelope. See the [in-toto Statement specification](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) for the envelope shape (`_type`, `subject`, `predicateType`, `predicate`).

---

## provenance (SLSA v1)

### URI

`https://slsa.dev/provenance/v1`

### Producer(s)

- `go-builder`

### Top-level shape

Two top-level objects per the SLSA v1 specification:

- `buildDefinition`: identifies the build (`buildType` URI), the user-controlled `externalParameters` (source URI, build config source, workflow inputs), the platform-controlled `internalParameters`, and the `resolvedDependencies` array.
- `runDetails`: identifies the `builder` (id, version map, builder dependencies), `metadata` (invocation id, start and finish timestamps), and `byproducts` array.

The Go builder uses build type `https://github.com/thomsonreuters/stamp/build/golang/v1` and populates external and internal parameters according to the detected build environment (GitHub Actions, EC2, or generic).

### Spec reference

- [SLSA Provenance v1.0](https://slsa.dev/spec/v1.0/provenance)
- [in-toto Resource Descriptor](https://github.com/in-toto/attestation/blob/main/spec/v1/resource_descriptor.md) for the shape of entries in `resolvedDependencies`, `byproducts`, and `builderDependencies`.

### Notes

- The `go-builder` package emits this URI directly; it does not use the framework's `pkg/predicates/provenance/v1` definitions (which exist for use by other future builder attestors).
- JSON field names in the emitted predicate use camelCase per the SLSA spec, in contrast to the snake_case convention used by the custom Thomson Reuters predicates.

---

## collection

### URI

`https://github.com/thomsonreuters/stamp/collection/v1`

### Producer(s)

Emitted by the pipeline itself, not by any individual attestor. A collection is the aggregate output of a single attestation run that produced more than one predicate.

### Top-level shape

- `name`: the pipeline or run identifier.
- `created`: timestamp when the collection was assembled.
- `attestations`: an array of entries. Each entry carries the producing `attestor_id`, the `predicate_type` URI, the full `predicate` object (not a reference), and the `subjects` that attestation declared.

### Spec reference

This is a project-specific predicate type. The entries themselves follow the same in-toto subject convention as standalone statements.

### Notes

- A collection embeds full original predicates, not digests or links to them. Verifiers do not need to fetch additional artifacts to inspect the contents.
- The collection's own subject set (in the enclosing in-toto Statement) is determined by the pipeline, typically the union of the contained attestations' subjects.

---

## command

### URI

`https://github.com/thomsonreuters/stamp/command/v1`

### Producer(s)

- `command`

### Top-level shape

- `command`: what was asked to run (full command line, plus parsed executable/arguments for direct mode, plus shell for shell or script mode).
- `execution`: timing and outcome (start/end timestamps, duration in ms, exit code, status: `success`/`failure`/`timeout`/`cancelled`).
- `environment`: host context (working directory, user, hostname, OS/arch/version).
- `output` (optional): captured stdout/stderr with their encoding (`utf-8` or `base64`), size in bytes, SHA-256 digests, and a `truncated` flag.
- `resources` (optional): CPU, memory, and I/O metrics from `getrusage` when available.

### Spec reference

This is a project-specific predicate type. The in-toto Statement envelope follows the [in-toto v1 Statement spec](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md).

### Notes

- When stdout or stderr contains non-UTF-8 bytes, the field is base64-encoded and `*_encoding` is set to `base64`. Consumers must check the encoding field before treating the output as text.
- Output digests are always computed from the raw, pre-redaction bytes; the embedded text is post-redaction.

---

## ec2

### URI

`https://github.com/thomsonreuters/stamp/ec2/v1`

### Producer(s)

- `ec2`

### Top-level shape

- `environment`: instance metadata from IMDS.
  - `identity_document`: the verifiable instance identity (instance id, type, image id, availability zone, account id, region, architecture, private IP, kernel/ramdisk ids, billing/marketplace product codes, pending time, version).
  - `network`: VPC, subnet, security groups, MAC, and IPv4/IPv6 addresses (private and public when present).
  - `iam` (optional): instance profile info when `include-iam-info=true`.
  - `instance_lifecycle`: `spot`, `on-demand`, or `scheduled`.
  - `tags` (optional): instance tags when `include-tags=true`.
- `verification`: how the data was collected.
  - `imds`: which IMDS version and endpoint were used and whether IMDS was accessible.
  - `attested_at`: UTC timestamp.
  - `attestor_version`: version of the attestor that produced the predicate.

### Spec reference

This is a project-specific predicate type. The identity document corresponds to the AWS document returned by `/latest/dynamic/instance-identity/document`.

### Notes

- Fields can be present but redacted (set to `[REDACTED]`) when `redact-account-id`, `redact-private-ips`, or `sensitive-fields` are configured.
- When IMDS is unreachable and `imds-unavailable-behavior=warn`, the predicate is emitted with `verification.imds.accessible=false` and an otherwise empty `environment` section.

---

## file

### URI

`https://github.com/thomsonreuters/stamp/file/v1`

### Producer(s)

- `file`

### Top-level shape

- `attestor_config`: a record of the configuration used to produce the predicate (base path, hash algorithms, capture flags, include/exclude patterns). This makes attestations self-describing.
- `artifacts`: array of file entries. Each entry has the path (relative to base), type (`file` or `symlink`), size, digest map, and optional permissions, ownership, timestamps, and symlink target sub-objects (each present only when the corresponding capture flag was set).
- `directories` (optional): directory entries with file and subdirectory counts and optional permissions.
- `summary`: aggregate counts, total size, capture start time, and elapsed duration.

### Spec reference

This is a project-specific predicate type. Digest maps follow the [in-toto DigestSet convention](https://github.com/in-toto/attestation/blob/main/spec/v1/digest_set.md).

### Notes

- `attestor_config` is embedded so a verifier can reproduce the file selection used during attestation.
- The `digests` map keys are lowercased algorithm names (`sha256`, `sha512`, `blake3`, `sha3-256`, `sha3-512`).

---

## git

### URI

`https://github.com/thomsonreuters/stamp/git/v1`

### Producer(s)

- `git`

### Top-level shape

- `repository`: URL (HTML form when derivable from `origin`, otherwise `file://...`) and current branch.
- `commit`: full commit metadata (hash, tree hash, parents, author and committer with timestamps, message, optional GPG signature block, and a multi-algorithm digest map).
- `repository_status`: dirty flag, per-file staging and worktree status, detached-HEAD flag, shallow-clone flag.
- `git_binary` (optional): tool version, path, and binary hash; emitted only when `include-binary-hash=true` and the path is known.
- `refs`, `remotes`, `tags`, `submodules` (each optional): collected only when the matching `include-*` configuration is set.

### Spec reference

This is a project-specific predicate type. File status follows `git status --porcelain` semantics (two single-character codes per file, staging then worktree).

### Notes

- Identity fields can be replaced with `[REDACTED]` via `redact-identity` or `sensitive-fields`; timestamps are retained even when names and emails are redacted.
- The predicate does not verify GPG signatures; it records the signature block as-is for downstream verification.

---

## github-workflow

### URI

`https://github.com/thomsonreuters/stamp/github-workflow/v1`

### Producer(s)

- `github-workflow`

### Top-level shape

- `workflow`: workflow identity (name, ref, sha, job/workflow ref, run id, run number, run attempt, job, action info).
- `runner`: runner host context (name, OS, arch, hosted type, optional filtered environment variables).
- `trigger`: event context (event name, actor and actor id, raw event payload as JSON, payload size, head/base refs for PRs).
- `repository`: repository identity (full name, owner, owner id, repo id, visibility, sha, ref, ref name, ref type).
- `metadata`: GitHub server URL.
- `oidc` (optional): OIDC token information when the token was successfully acquired - token hash, standard JWT claims (issuer, subject, audience, exp/iat/nbf/jti), and verification metadata (verified flag, verify method/source, key algorithm and id, discovery URL, fetched timestamp).

### Spec reference

This is a project-specific predicate type. The OIDC claim names follow [RFC 7519 JWT registered claims](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1).

### Notes

- Fields populated from the OIDC token take precedence over fields populated from runner environment variables. The package's type comments record which fields come from which source.
- `trigger.event_payload` is a `json.RawMessage`; consumers should treat it as opaque JSON and parse based on `trigger.event_name`.
- Critical fields (`workflow.run_id`, `run_id`, `repository.sha`, `metadata.started_on`) cannot be redacted via `sensitive-fields`.

---

## jwt

### URI

`https://witness.dev/attestations/jwt/v0.1`

### Producer(s)

- `jwt`

### Top-level shape

- `source`: how the token was acquired (`file`, `stdin`, `env`, `auto:github-actions`, `auto:aws-irsa`, `auto:kubernetes`).
- `digest`: SHA-256 of the raw token string.
- `header`: parsed JWT header (`alg`, `typ`, optional `kid`, `x5c`, `x5t`, `x5t#S256`).
- `claims`: registered claims (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`) plus a `custom_claims` map for everything else (subject to allowlist/denylist/redact configuration).
- `verification`: outcome string - `verified`, `unverified`, or `skipped`.
- `key` (optional): how the verification key was obtained when verification ran - method (`static-key`, `jwks`, `oidc-discovery`), source identifier, optional discovery URL, and the timestamp at which the key was fetched.

### Spec reference

- [Witness JWT attestation](https://witness.dev) defines this predicate type for cross-tool compatibility.
- [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) for JWT semantics and registered claim names.

### Notes

- The URI uses the `witness.dev` host and does not follow the Thomson Reuters convention; this is deliberate so that Witness-aware verifiers can consume the predicate without configuration.
- `verification: unverified` indicates the attestor attempted verification and it failed; `skipped` indicates verification was explicitly disabled. Distinguishing these matters for policy.

---

## sbom

### URI

`https://github.com/thomsonreuters/stamp/sbom/v1`

### Producer(s)

- `sbom`

### Top-level shape

- `format`: `cyclonedx` or `spdx`.
- `version`: the spec version reported by the SBOM document itself.
- `content`: the full parsed SBOM document as a map.

### Spec reference

- [CycloneDX specification](https://cyclonedx.org/specification/overview/)
- [SPDX specification](https://spdx.dev/specifications/)

The wrapping predicate is project-specific; the embedded `content` is the upstream SBOM in its native shape.

### Notes

- The predicate embeds the SBOM in full rather than by reference. For large component graphs this produces correspondingly large attestations; consider this when configuring downstream storage and transparency logs.
- Schema validation is performed at attestation time according to `validate-schema` and `validation-behavior`; the predicate itself does not carry validation status.
