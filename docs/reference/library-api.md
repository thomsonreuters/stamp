# Go library API

`stamp` is built around a small, stable Go API that the CLI itself
consumes. Embedding applications can call the same surface to run
attestations, verify envelopes, upload to Rekor, and so on, without
shelling out to the binary.

This page documents the stable surface, the lifecycle every operation
follows, and the supporting types that operations return. For an
end-to-end embedding walkthrough, see [Embed attestor in a Go
application](../how-to/library/embed-in-a-go-app.md).

## Overview

The stable library surface is `pkg/operations`. Each command in the CLI
corresponds to one Op type in that package. Every Op follows the same
three-step lifecycle:

```go
type Op interface {
    // Validate inspects configuration and arguments. Safe to call before
    // Execute; returns a typed error suitable for surfacing to the user.
    Validate(args /* or string */) error

    // Execute performs the operation. Context cancellation is respected.
    Execute(ctx context.Context, args /* or string */) error
}

// Ops that produce structured results additionally expose:
type ResultProvider interface {
    GetResult() *pipeline.Result  // type varies per op
}
```

`Validate` is a pure check; it does not mutate external state. `Execute`
performs the work. Ops that produce structured output expose a
`GetResult()` method whose return type is documented per Op below.

`pkg/operations` is the only package in the codebase with a stability
contract. Helper packages (`pkg/pipeline`, `pkg/intoto`, `pkg/types`)
expose result types and enums consumed by operations and are stable for
that purpose. Everything else under `pkg/` is internal in spirit; it may
change without notice.

## Bootstrap

Every Op takes three collaborators: a configuration source, a logger, and
an output handler. Construct them once per process:

```go
import (
    "github.com/spf13/viper"
    "github.com/thomsonreuters/stamp/pkg/config"
    "github.com/thomsonreuters/stamp/pkg/config/flags"
    "github.com/thomsonreuters/stamp/pkg/logger"
    "github.com/thomsonreuters/stamp/pkg/operations"
    "github.com/thomsonreuters/stamp/pkg/output"
    "github.com/thomsonreuters/stamp/pkg/types"
)

v := viper.New()
v.Set(flags.RunAttestor, "git")
v.Set("attestors.git.repo_path", ".")

cfg := config.NewConfiguration(v)

log := logger.New(&logger.Config{
    Level:  types.LogLevelInfo,
    Format: types.LogFormatJSON,
})

// Suppress the human-friendly output stream when embedding.
out := output.New(output.WithQuiet(true))

op := operations.NewRunOp(cfg, log, out)
```

Embedders typically pass `output.WithQuiet(true)` so that progress
messages, success banners, and list rendering do not write to the
process's standard streams. Structured data emitted via `output.Data`
is still suppressed in quiet mode — read the result directly from the
Op instead.

## Operations

### `RunOp`

Executes one attestor, one workflow, multiple workflows, all workflows,
or a filtered subset, depending on which flags are set in the
configuration. This mirrors the CLI's `run` command.

```go
op := operations.NewRunOp(cfg, log, out)
if err := op.Validate(args); err != nil { ... }
if err := op.Execute(ctx, args); err != nil { ... }
result := op.GetResult()  // *pipeline.Result
```

- `Validate` resolves the execution mode (single attestor / single
  workflow / multiple workflows / filtered / all) from the configuration,
  rejects incompatible flag combinations, checks that referenced
  workflows and attestor types exist, and validates the signer and
  transparency configuration.
- `Execute` runs the selected attestors, signs the resulting statements,
  dispatches to destinations, and optionally uploads to Rekor.
- `GetResult` returns the aggregated `*pipeline.Result`. `nil` before the
  first call to `Execute`.

### `ListOp`

Lists the registered attestors or shows configuration schema for one
attestor. Mirrors `stamp list`.

```go
op := operations.NewListOp(cfg, log, out)
err := op.Execute(ctx, args)  // args[0] optionally selects one attestor
```

`ListOp` does not implement `Validate` (input is the args slice and the
list-show-config flag, both of which are checked in `Execute`) and does
not produce a structured result; output is emitted through the configured
`output.Output`.

### `FetchOp`

Retrieves a Rekor entry by file hash, UUID, or log index. Mirrors
`stamp fetch`. Exactly one of the three inputs must be set in the
configuration; `Validate` rejects combinations.

```go
op := operations.NewFetchOp(cfg, log, out)
if err := op.Validate(nil); err != nil { ... }
err := op.Execute(ctx, nil)
```

The fetched entry is emitted as structured data through the output
handler. To consume the result programmatically without going through
the output stream, call `transparency.NewClient` directly.

### `UploadOp`

Uploads a signed envelope to Rekor. Mirrors `stamp upload`.

```go
op := operations.NewUploadOp(cfg, log, out)
if err := op.Validate(attestationPath); err != nil { ... }
err := op.Execute(ctx, attestationPath)
```

`Validate` confirms the attestation file is readable and within size
limits, and that the Rekor URL is well-formed. `Execute` parses the
envelope, determines the verifier material (certificates from the
envelope when present, otherwise the `--public-key` file), uploads to
Rekor, and emits the UUID, log index, and integrated time. As with
`FetchOp`, programmatic consumers should call `transparency.NewClient`
directly when they need the entry struct back.

### `VerifyOp`

Verifies an envelope's signature and, optionally, its Rekor inclusion
with the configured temporal policy. Mirrors `stamp verify`.

```go
op := operations.NewVerifyOp(cfg, log, out)
if err := op.Validate(attestationPath); err != nil { ... }
err := op.Execute(ctx, attestationPath)
```

`Execute` returns `nil` on a successful verification and a wrapped error
on failure. The structured `verification.VerificationResult` (valid /
errors / warnings / Rekor UUID / attestation hash) is emitted via the
output handler. To get the struct in-process, call
`verification.New(...).Verify(ctx, env)` directly.

### `GenerateKeyOp`

Generates an RSA or ECDSA key pair and writes the private and public
halves to disk. Mirrors `stamp generate-key`.

```go
op := operations.NewGenerateKeyOp(cfg, log, out)
err := op.Execute(ctx, nil)
```

Reads key type, output path, overwrite flag, and password source (one of
inline, file, interactive prompt) from the configuration. `Validate` is
not implemented; configuration is checked inside `Execute`. The operation
has no structured result.

## Result types

### `pipeline.Result`

Aggregates the outcome of one or more pipeline executions. The contract:

- `Successful()`, `Failed()` — slices of per-attestor results filtered by
  whether the attestor produced an envelope without error.
- `Envelopes()` — every non-nil `*intoto.Envelope` across the result,
  regardless of error state on the producing attestor.
- `Errors()` — every non-nil error encountered.
- `HasCollection()` — whether any collection envelopes were produced.
- `Merge(other)` — combine another `*Result` into this one. Used by the
  multi-workflow execution path.

The `Metrics` field is a `*pipeline.Metrics`; the `Collections` field is a
slice of `pipeline.CollectionResult` pairing each collection envelope
with the workflow that produced it.

### `pipeline.EnvelopeResult`

The atom of `Result.Attestations`. Holds the envelope (if any), the
producing attestor's name and predicate type, and any error encountered
during that attestor's execution. A nil `Error` and a non-nil `Envelope`
means success.

### `pipeline.Metrics`

Tracks timing and counts across a pipeline run: start/end time,
successful and failed attestor counts, and the cumulative time spent in
signing, destination writes, and Rekor uploads. `Duration()` and
`Finalize()` close out the window; `Merge(other)` accumulates metrics
across multiple runs.

## In-toto types

`pkg/intoto` provides the DSSE envelope and in-toto statement
implementations consumed throughout the library.

### `intoto.Envelope`

A DSSE envelope. Carries the base64-encoded payload, the payload type
URI, and the list of signatures. Notable methods:

- `Sign(ctx, signer)` — append a signature using a `signing.Signer`. If
  the signer also satisfies `signing.CertificateSigner` (the Fulcio
  signer does), the certificate is embedded in the signature.
- `Verify(verifier)` — verify every signature with the supplied verifier.
- `GetStatement()` — decode the payload back into an `*intoto.Statement`.
- `SHA256()` — hex SHA-256 of the serialized envelope. This is the value
  Rekor indexes against.
- `ExtractCertificate()`, `ExtractCertificates()` — pull X.509
  certificates out of `signatures[].cert`.

The `Signature.Certificate` field is the one place certificate-based
signing differs visibly from key-based signing: it is empty for `key`
signer output and populated with the base64-encoded PEM certificate for
`fulcio` signer output. Verification and Rekor upload both branch on
this field.

### `intoto.Statement`

The in-toto v1 statement embedded in the envelope payload. `Validate()`
enforces the statement-type URI, presence of at least one subject with at
least one digest, a non-empty predicate type, and a non-nil predicate.
`ToJSON()` and `ToJSONIndent()` serialize the statement.

### `intoto.Subject`

A name plus a digest map (algorithm to hex hash). One or more are
required by every statement.

## Stability

| Package                                                                                  | Stability            |
| ---------------------------------------------------------------------------------------- | -------------------- |
| `pkg/operations`                                                                         | Stable               |
| `pkg/pipeline` (result types: `Result`, `EnvelopeResult`, `CollectionResult`, `Metrics`) | Stable               |
| `pkg/intoto` (envelope, statement, subject)                                              | Stable               |
| `pkg/types` (enums: log level, output mode, temporal policy, failure policy, signer ID)  | Stable               |
| All other packages under `pkg/`                                                          | Internal; may change |

Internal packages remain importable, but consumers should expect them to
break across versions. Pin a dependency and read the release notes
before upgrading if you import anything outside the stable surface.

## See also

- [Embed attestor in a Go application](../how-to/library/embed-in-a-go-app.md)
- [Signers](signing.md), [Destinations](destinations.md),
  [Transparency (Rekor)](transparency.md) — reference for the runtime
  components an embedded `RunOp` will exercise.
