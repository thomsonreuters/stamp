# Coding conventions

This document records the conventions used throughout the codebase. New code
should follow them; existing code that drifts from them is a bug.

The conventions below are derived from the source, not from intent. When the
two disagree, the source wins and this document should be updated.

## Table of contents

1. [JSON naming](#json-naming)
2. [Configuration key naming](#configuration-key-naming)
3. [Package layout](#package-layout)
4. [Error handling](#error-handling)
5. [Logging](#logging)
6. [Configuration access in attestors](#configuration-access-in-attestors)
7. [The Attestor interface](#the-attestor-interface)
8. [Attestor file layout](#attestor-file-layout)
9. [Predicates](#predicates)
10. [Tests](#tests)
11. [File headers and package docs](#file-headers-and-package-docs)
12. [Pre-commit and lint](#pre-commit-and-lint)

---

## JSON naming

All JSON tags on predicate types and on any struct that is serialized to a
DSSE envelope use **snake_case**. This is consistent with the SLSA
provenance spec for fields we serialize ourselves (we leave the SLSA-defined
`buildDefinition` / `runDetails` camelCase alone in `pkg/predicates/go-builder/v1`
because the SLSA spec uses camelCase).

Correct:

```go
type Predicate struct {
    Repository    Repository `json:"repository"`
    Commit        Commit     `json:"commit"`
    GitBinary     *Binary    `json:"git_binary,omitempty"`
}
```

Guidelines:

- Use `omitempty` for fields that can be legitimately absent.
- Acronyms render as lowercase: `instance_id`, `vpc_id`, `run_id` — not
  `instanceID` or `runID`.
- Go field names stay PascalCase; only the JSON tag is snake_case.

## Configuration key naming

Configuration keys for attestors are **not uniform** across the codebase. Two
conventions are in use today:

- **kebab-case**: most attestors. Examples: `git-working-dir`, `dirty-behavior`,
  `hash-algorithms`, `include-refs`, `redact-account-id`,
  `sbom-path`.
- **snake_case**: the `command` attestor. Examples: `execution_mode`,
  `capture_stdout`, `redact_patterns`, `max_output_size`.

When adding a key to an existing attestor, match that attestor's existing
convention. When adding a new attestor, prefer **kebab-case** unless there
is a reason to do otherwise; that is the majority convention.

The top-level configuration file (`~/.stamp.yaml`) and viper-bound keys
use **snake_case with dots as separators**: `pipeline.signing.signer`,
`pipeline.rekor.upload_target`, `cryptography.key.private_key`. See
`pkg/config/flags/constants.go` for the full list of bound keys.

## Package layout

```
cmd/
  main.go                     # package main; calls cmd/stamp.Execute
  attestor/                   # cobra command definitions (not main)
pkg/
  attestors/                  # one subpackage per attestor implementation
    command/
    ec2/
    file/
    git/
    github-workflow/
    go-builder/
    jwt/
    sbom/
  predicates/                 # one subpackage per predicate version
    collection/v1/
    command/v1/
    ec2/v1/
    file/v1/
    git/v1/
    github-workflow/v1/
    go-builder/v1/
    jwt/v1/
    provenance/v1/
    sbom/v1/
  core/                       # Attestor interface, Config, registry
  config/                     # configuration loading; flag bindings under flags/
  errors/                     # BaseError, ValidationError, exit codes
  logger/                     # slog-based Logger interface
  pipeline/                   # AttestorPipeline, WorkflowPipeline, Result types
  operations/                 # stable Op types consumed by cmd/stamp
  signing/                    # Signer interface + key/, fulcio/ subpackages
  destination/                # Destination interface + file/ subpackage
  transparency/               # Rekor client wrapper
  clients/                    # typed clients (rekor, fulcio, github, spire, jwt, k8s, aws, git)
  crypto/                     # keys, hash, dsse helpers
  intoto/                     # Statement and DSSE Envelope types
  output/                     # user-facing output sink
  types/                      # cross-cutting enums (LogLevel, FailurePolicy, ...)
  utils/                      # small generic helpers
  validation/                 # command-constraint validators
  http/                       # HTTP client wrapper used by clients/
  verification/               # high-level Verify implementation
  errors/                     # see above
plugins/
  cobra/                      # FlagDefinition, FlagGroup, env-binding plumbing
```

Naming rules:

- For new attestor and predicate packages, prefer **snake_case directory
  names** so the directory name and the Go package identifier read the
  same (`docker_image/` → `package docker_image`). Several in-tree
  packages use kebab-case (`github-workflow/`, `go-builder/`); those
  identifiers collapse the dash (`githubworkflow`, `gobuilder`), which
  hides the boundary. New packages should not repeat that pattern.
- Single-word package names stay lowercase with no separator (`logger`,
  `output`).
- Singular for one-thing packages, plural for collection packages
  (`attestors`, `predicates`).
- Versioned APIs live in `vN/` subdirectories with `package vN`.

## Error handling

The project's error types live in `pkg/errors`. There are two:

- `*BaseError` — message plus optional `Component`, `Operation`, `Cause`,
  `Suggestions`, and `ExitCode`.
- `*ValidationError` — `BaseError` plus a `map[string][]string` of
  per-field validation messages.

### Constructors

```go
import pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"

// Simple error.
err := pkgerrors.New("something went wrong")

// Error with component and operation context.
err := pkgerrors.NewWithContext("git", "collect", "failed to read commit")

// Wrap an existing error with context, preserving its exit code.
err := pkgerrors.WrapWithContext(err, "pipeline", "attest", "attestation failed")

// Wrap an error inside an attestor (sets ExitRuntimeError).
err := pkgerrors.WrapAttestor(err, attestorID, "attest")

// Pipeline-phase wrapper.
err := pkgerrors.WrapPipeline(err, "sign", attestorID)

// Usage error with suggestions (sets ExitUsageError).
err := pkgerrors.NewUsageError("invalid flag value",
    "Try --flag=value", "See 'stamp run --help'")

// Plain wrap (returns a non-typed wrapped error).
err := pkgerrors.Wrap(err, "load config")
```

### Validation errors

```go
v := pkgerrors.NewValidatorFor("file")
if len(paths) == 0 {
    v.AddError("paths", "at least one path must be specified")
}
if basePath == "" {
    v.AddError("base-path", "base path cannot be empty")
}
if v.HasErrors() {
    return v
}
```

### Exit codes

Defined in `pkg/errors/errors.go`:

| Constant              | Value | Meaning                          |
| --------------------- | ----- | -------------------------------- |
| `ExitSuccess`         | 0     | Operation completed successfully |
| `ExitGeneralError`    | 1     | Unspecified error                |
| `ExitUsageError`      | 2     | Invalid CLI usage                |
| `ExitValidationError` | 3     | Field-level validation failed    |
| `ExitConfigError`     | 4     | Configuration load/parse failed  |
| `ExitRuntimeError`    | 5     | Failure during execution         |

`pkgerrors.GetExitCode(err)` extracts the code from any error type (returns
`ExitGeneralError` for non-`BaseError`/`ValidationError` values).

### Guidelines

- Prefer wrapping (`WrapWithContext`, `WrapAttestor`, `WrapPipeline`) over
  re-formatting; wrapping keeps the original cause and exit code reachable
  through `errors.Is` / `errors.As`.
- Set `ExitUsageError` for any error caused by a bad flag combination.
- Never call `os.Exit` from non-`main` packages; return an error and let
  `cmd/stamp.Execute` map it to an exit code.

## Logging

`pkg/logger` defines a small `Logger` interface backed by Go's standard
`log/slog`. There is **no zap dependency**; do not assume zap APIs (`Infow`,
`Debugw`, `SugaredLogger`) are available.

### Interface

```go
type Logger interface {
    Debug(msg string, args ...any)
    Info(msg string, args ...any)
    Warn(msg string, args ...any)
    Error(msg string, args ...any)
    DebugContext(ctx context.Context, msg string, args ...any)
    InfoContext(ctx context.Context, msg string, args ...any)
    WarnContext(ctx context.Context, msg string, args ...any)
    ErrorContext(ctx context.Context, msg string, args ...any)
    With(args ...any) Logger
    WithGroup(name string) Logger
}
```

### Usage

```go
// Plain message.
logger.Info("starting attestation")

// Structured fields are slog key/value variadic args.
logger.Info("attestation completed",
    "duration_ms", time.Since(start).Milliseconds(),
    "status", status,
)

// Bind persistent context to a child logger.
log := logger.With(
    "attestor_id", attestorID,
    "working_dir", workingDir,
)
log.Debug("executing git command", "args", strings.Join(args, " "))
```

### Levels

- `Debug` — detailed execution flow, only useful during development or
  triage.
- `Info` — significant events (phase transitions, completion).
- `Warn` — recoverable issues that the user should know about.
- `Error` — failures.

The default level on the CLI is `warn` (`pkg/config/flags/global.go`). When
demonstrating behavior in docs or tests, either pass `--log-level info` or
note that the user must enable info-level logging to see the messages.

### Field naming

Field keys use snake_case. Common keys: `attestor_id`, `duration_ms`,
`error`, `exit_code`, `working_dir`, `file_path`, `component`.

### Guidelines

- Use structured args, not `fmt.Sprintf` inline strings.
- Include `duration_ms` for any operation worth measuring.
- Never log secret values. The `--quiet` flag suppresses logs entirely
  when the calling pipeline expects clean stdout.

## Configuration access in attestors

Attestor configuration is a `core.Config` (which is `map[string]any`). The
type provides typed accessors with defaults; use them rather than asserting
types yourself.

```go
import "github.com/thomsonreuters/stamp/pkg/core"

func (a *Attestor) parseConfig(config core.Config) {
    a.basePath        = config.GetString("base-path", ".")
    a.followSymlinks  = config.GetBool("follow-symlinks", false)
    a.timeout         = config.GetDuration("timeout", 30*time.Second)
    a.maxDepth        = config.GetInt("max-depth", -1)
    a.paths           = config.GetStringSlice("paths")
    a.hashAlgorithms  = config.GetStringSlice("hash-algorithms", []string{"sha256"})
    a.envVars         = config.GetMap("environment_variables")
}
```

Conventions:

- The default value is the second argument. Use `-1` for "unlimited",
  `""` for unset strings, `false` for disabled features.
- `IsEmpty(key)` returns true when the key is missing or its string value
  is empty.
- Schema validation happens in `ValidateConfig` via `config.Validate(schema)`;
  add a `pkgerrors.NewValidatorFor(...)` collector for additional rules
  that the schema can't express.

## The Attestor interface

All attestors implement `core.Attestor` (`pkg/core/attestor.go`):

```go
type Attestor interface {
    ID() string
    PredicateURI() string
    Name() string
    Description() string
    ConfigSchema() []ConfigField
    ValidateConfig(Config) error
    PreAttest(ctx context.Context, config Config) error
    Attest(ctx context.Context, config Config) error
    PostAttest(ctx context.Context, config Config) error
    GeneratePredicate(config Config) (any, error)
    Subjects(config Config) []intoto.Subject
    Schema() *jsonschema.Schema
}
```

Registration happens in `init()`:

```go
func init() {
    _ = core.RegisterAttestor(func(log logger.Logger) core.Attestor {
        return &Attestor{
            logger: log.With("attestor_id", "git"),
        }
    })
}
```

The factory must return a fresh instance on every call — never share state
between invocations. The registry is keyed by `ID()`; a second registration
of the same ID fails.

Lifecycle:

1. `ValidateConfig` — pure check, may run multiple times.
2. `PreAttest` — parse config into typed fields, verify environment
   preconditions (file exists, command on PATH).
3. `Attest` — collect evidence. The only phase that does real I/O.
4. `PostAttest` — release resources.
5. `GeneratePredicate` / `Subjects` — pure functions over the state
   collected in `Attest`. The framework may call them more than once.

`Schema()` returns the predicate's JSON schema (from `invopop/jsonschema`),
typically generated from the predicate type with `jsonschema.Reflect`.

## Attestor file layout

A typical attestor package looks like:

```
pkg/attestors/<name>/
├── attestor.go         # Attestor type + interface methods (ID, PredicateURI, lifecycle)
├── attestor_test.go
├── collection.go       # evidence collection invoked from Attest
├── collection_test.go
├── validation.go       # ValidateConfig business rules + sensitive-field validators
├── validation_test.go
├── constants.go        # config key names, default values, schema URIs
├── helpers.go          # small package-private helpers
└── helpers_test.go
```

Optional files: `predicate.go` (only when the attestor builds a complex
predicate inline), `redaction.go` (for attestors with non-trivial
redaction), `platform_*.go` (build-tagged platform code).

Tests live next to the code (`*_test.go` in the same package). Tests must
write only to `t.TempDir()` or equivalent; writes to the repository or to
absolute paths under `/tmp` make tests flake under parallel execution.

## Predicates

Predicate packages live under `pkg/predicates/<name>/v<major>/predicate.go`.

```go
package v1

const PredicateURI = "https://github.com/thomsonreuters/stamp/git/v1"

type Predicate struct {
    Repository       Repository       `json:"repository"`
    Commit           Commit           `json:"commit"`
    RepositoryStatus RepositoryStatus `json:"repository_status"`
    GitBinary        *GitBinary       `json:"git_binary,omitempty"`
}
```

Rules:

- Top-level type is `Predicate`; URI constant is `PredicateURI` (or `<Name>V1URI`
  when a single package exports multiple).
- Snake_case JSON tags. Optional fields use `,omitempty`.
- Avoid pointers unless the absence of the field is semantically distinct
  from its zero value.
- Predicate URIs for project-defined predicates follow
  `https://github.com/thomsonreuters/stamp/<name>/v<major>`. Reuse upstream
  URIs (SLSA, Witness JWT) when the predicate matches an upstream spec.
- Additive changes (new optional fields) stay within the existing version.
  Breaking changes require a new versioned package.

See [Add a new predicate](add-a-new-predicate.md) for the full step-by-step.

## Tests

- Test files: `*_test.go` in the same package.
- Use table-driven tests for input variation, with `t.Run(tc.name, ...)`
  per case.
- Use `t.TempDir()` for filesystem side effects.
- `testify/assert` and `testify/require` are already imported throughout
  the tree; prefer them for new tests for consistency.
- Mark tests that require external services (`AWS_*`, `GITHUB_ACTIONS`,
  network) so they skip cleanly outside their environment.

Skeleton:

```go
func TestAttestor_Identifier(t *testing.T) {
    a := &Attestor{}
    require.Equal(t, "git", a.ID())
}

func TestValidateConfig(t *testing.T) {
    cases := []struct {
        name      string
        config    core.Config
        wantError bool
    }{
        {
            name: "valid",
            config: core.Config{
                "git-working-dir": ".",
            },
        },
        {
            name: "missing required field",
            config: core.Config{},
            wantError: true,
        },
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            a := &Attestor{}
            err := a.ValidateConfig(tc.config)
            if tc.wantError {
                require.Error(t, err)
                return
            }
            require.NoError(t, err)
        })
    }
}
```

## File headers and package docs

Every Go source file must carry the Apache-2.0 header:

```go
// Copyright 2026 Thomson Reuters
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
```

The pre-commit hook (`.pre-commit-config.yaml`) enforces this; the easiest
way to fix a missing header is to copy it from a neighboring file.

Exported types, functions, and methods must have a doc comment starting
with the symbol name. Document the "why" when it isn't obvious from the
signature; don't restate the signature in prose.

## Pre-commit and lint

- `golangci-lint run` — same configuration as CI (`.golangci.yml`).
- `pre-commit install` then `pre-commit run --all-files` — runs lint plus
  the copyright-header check.
- `go build ./...` and `go test ./...` must pass before opening a PR.

See [development-setup.md](development-setup.md) for the full setup flow.

---

## Summary checklist

When contributing code, verify:

- [ ] JSON tags on serialized structs use snake_case (or follow the SLSA
      camelCase shape for SLSA-defined fields).
- [ ] Errors use `pkg/errors` (`NewWithContext`, `WrapWithContext`,
      `WrapAttestor`, `NewValidatorFor`).
- [ ] Logging uses the `Logger` interface from `pkg/logger`; no zap
      methods (`Infow` etc.); fields are snake_case.
- [ ] Attestor configuration keys match the convention of the package
      (kebab-case for most, snake_case for `command`).
- [ ] Exported APIs are documented.
- [ ] Tests are table-driven where applicable and write only to
      `t.TempDir()`.
- [ ] Apache-2.0 copyright header is present in every new Go file.
- [ ] Predicate types are versioned correctly and use `omitempty` on
      optional fields.

## References

- `pkg/core/attestor.go` — the `Attestor` interface.
- `pkg/core/config.go` — `Config` and its typed accessors.
- `pkg/errors/errors.go` — `BaseError`, `ValidationError`, exit codes.
- `pkg/logger/logger.go` — `Logger` interface.
- `pkg/attestors/git/` — a comprehensive reference implementation.
- [in-toto Attestation Spec](https://github.com/in-toto/attestation)
- [SLSA Provenance v1](https://slsa.dev/spec/v1.0/provenance)
