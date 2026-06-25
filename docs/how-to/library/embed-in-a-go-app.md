# Embed the attestor in a Go application

This guide shows how to drive the attestor programmatically from inside a Go
application, instead of shelling out to the `stamp` binary. Use this when
you want to produce attestations from a long-running process, a custom build
tool, or a webhook handler that already has access to the artifacts it needs
to attest.

## Prerequisites

- A Go module (with `go.mod`) using a Go version compatible with the one
  pinned in this project's `go.mod`.
- Network access to the project module.

Add the dependency:

```sh
go get github.com/thomsonreuters/stamp
```

## What you wire together

The library does not expose a single "run an attestation" function. Instead,
you compose four small pieces that mirror what the CLI does internally:

- **Viper instance** — holds raw configuration (the same keys you'd put in a
  YAML config file or pass via `--set`).
- **`config.ConfigurationIface`** — wraps the viper instance so the rest of
  the framework reads configuration through a stable interface.
- **`logger.Logger`** — structured logger used by all internal components.
- **`output.OutputIface`** — handles user-facing output. In a library
  context you almost always want this in quiet mode.

You then construct an operation (`operations.NewRunOp`) and invoke it in two
phases: `Validate` to fail fast on bad input, then `Execute` to do the work.

## Example: run a single attestor with inline config

This example runs the `git` attestor against the current directory. No
configuration file is involved — everything is set on the viper instance
directly.

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/spf13/viper"

    "github.com/thomsonreuters/stamp/pkg/config"
    "github.com/thomsonreuters/stamp/pkg/config/flags"
    "github.com/thomsonreuters/stamp/pkg/logger"
    "github.com/thomsonreuters/stamp/pkg/operations"
    "github.com/thomsonreuters/stamp/pkg/output"
)

func main() {
    v := viper.New()

    // Select the attestor (equivalent to --attestor git on the CLI).
    v.Set(flags.RunAttestor, "git")

    // Inline attestor configuration (equivalent to --set key=value on the CLI).
    // Config keys must match the target attestor's schema; for git the
    // working-directory key is "git-working-dir".
    v.Set(flags.RunSet, []string{
        "git-working-dir=.",
    })

    cfg := config.NewConfiguration(v)
    log := logger.NewDefault()
    out := output.New(output.WithQuiet(true))

    op := operations.NewRunOp(cfg, log, out)

    args := []string{}
    if err := op.Validate(args); err != nil {
        log.Error("validation failed", "error", err)
        return
    }

    ctx := context.Background()
    if err := op.Execute(ctx, args); err != nil {
        log.Error("execution failed", "error", err)
        return
    }

    result := op.GetResult()
    fmt.Printf("attestations: %d successful, %d failed\n",
        len(result.Successful()), len(result.Failed()))

    for _, env := range result.Envelopes() {
        sum, err := env.SHA256()
        if err != nil {
            log.Error("failed to hash envelope", "error", err)
            continue
        }
        fmt.Printf("envelope sha256: %s\n", sum)
    }
}
```

## Example: run a named workflow from a config file

Workflows live in a configuration file. Point viper at it before
constructing the operation. Positional arguments become workflow names —
exactly as on the CLI.

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/spf13/viper"

    "github.com/thomsonreuters/stamp/pkg/config"
    "github.com/thomsonreuters/stamp/pkg/logger"
    "github.com/thomsonreuters/stamp/pkg/operations"
    "github.com/thomsonreuters/stamp/pkg/output"
)

func main() {
    v := viper.New()
    v.SetConfigFile("./stamp.yaml")
    if err := v.ReadInConfig(); err != nil {
        log.Fatalf("read config: %v", err)
    }

    cfg := config.NewConfiguration(v)
    lg := logger.NewDefault()
    out := output.New(output.WithQuiet(true))

    op := operations.NewRunOp(cfg, lg, out)

    args := []string{"release-evidence"} // workflow name

    if err := op.Validate(args); err != nil {
        log.Fatalf("validate: %v", err)
    }

    if err := op.Execute(context.Background(), args); err != nil {
        log.Fatalf("execute: %v", err)
    }

    result := op.GetResult()
    fmt.Printf("workflow finished with %d attestations\n", len(result.Envelopes()))

    if result.HasCollection() {
        fmt.Printf("collection envelopes produced: %d\n", len(result.Collections))
    }
}
```

## Inspecting results

`op.GetResult()` returns a `*pipeline.Result` with these stable accessors:

- `Successful()` — envelope results without errors.
- `Failed()` — envelope results that recorded an error.
- `Envelopes()` — all non-nil envelopes across both buckets.
- `Errors()` — non-nil errors across all attestations.
- `HasCollection()` — true if any workflow produced a collection envelope.
- `Collections` — slice of `CollectionResult` (envelope + originating
  workflow name). See
  [Work with collection envelopes](work-with-collection-envelopes.md).

## API stability

The following packages are considered stable for library consumers:

- `pkg/operations` — high-level entry points (`NewRunOp`, future
  `NewVerifyOp`, etc.).
- `pkg/pipeline` — `Result`, `EnvelopeResult`, `CollectionResult`.
- `pkg/intoto` — `Envelope`, `Statement`, `Subject`.
- `pkg/types` — enums (`OutPutMode`, `LogLevel`, etc.).
- `pkg/config` — `ConfigurationIface` and `NewConfiguration`.

Other packages under `pkg/` may change between releases without notice.
Prefer importing through the stable surface above; reach into internals
only when there is no alternative.

## Known limitation: collections across multiple workflows in one call

When you invoke `Execute` with several workflow names at once (multi-workflow
mode), every workflow's collection envelope is appended to
`result.Collections`, but they share the same `Result` and the same metrics
accumulator. If you need each workflow's collection envelope kept separate
with its own metrics — for example to write each to a distinct destination,
or to compare them — call `Execute` once per workflow and keep the
per-call `Result` yourself.

## See also

- [Library API reference](../../reference/library-api.md)
- [Work with collection envelopes](work-with-collection-envelopes.md)
