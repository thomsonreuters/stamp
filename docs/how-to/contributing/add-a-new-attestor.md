# Add a new attestor

This guide walks through introducing a new attestor type — for example
`docker-image`, `terraform-plan`, or `helm-chart` — into the framework.
Use the existing `git` attestor as a working reference; nearly every step
below has a direct counterpart there.

## Prerequisites

Before you start, have answers to three questions:

1. **What are you attesting?** A file? A running process? A build output?
   This determines what data your `Attest` method needs to collect.
2. **What predicate URI will you publish under?** For custom predicates
   defined by this project the convention is
   `https://github.com/thomsonreuters/stamp/<name>/v1`. For predicates
   defined elsewhere (SLSA Provenance, SPDX, etc.) reuse the upstream URI.
3. **What is the subject naming pattern?** The `Subjects` method must
   return stable, content-addressed identifiers so verifiers can correlate
   your attestation with the artifact it describes.

## Step 1 — Choose an ID and predicate URI

The attestor ID is lowercase kebab-case and must be unique across the
registry: `docker-image`, `terraform-plan`, `helm-chart`. It is the
identifier users will pass to `--attestor`.

The predicate URI is the value `PredicateType()` returns in the resulting
in-toto statement. Multiple attestors may legitimately share one URI (for
example several SBOM generators all emit
`https://spdx.dev/Document/v2.3`), but each attestor's ID must be unique.

## Step 2 — Create the predicate package

Put the predicate type next to its peers under
`pkg/predicates/<name>/v1/`. The `git` predicate package is the canonical
example. At minimum:

```go
// pkg/predicates/docker_image/v1/predicate.go

package v1

const PredicateURI = "https://github.com/thomsonreuters/stamp/docker-image/v1"

type Predicate struct {
    Image     ImageReference `json:"image"`
    BuiltAt   string         `json:"built_at"`
    BuiltBy   string         `json:"built_by,omitempty"`
}

type ImageReference struct {
    Registry   string `json:"registry"`
    Repository string `json:"repository"`
    Digest     string `json:"digest"`
    Tag        string `json:"tag,omitempty"`
}
```

JSON tags are snake_case. Optional fields use `omitempty`. Avoid pointers
unless a field can be genuinely absent — see
[add-a-new-predicate](add-a-new-predicate.md) for the full rules.

## Step 3 — Create the attestor package

Create `pkg/attestors/<name>/` with these files:

- `attestor.go` — implements the `core.Attestor` interface (the methods
  `ID`, `PredicateURI`, `Name`, `Description`, `ConfigSchema`,
  `ValidateConfig`, `PreAttest`, `Attest`, `PostAttest`,
  `GeneratePredicate`, `Subjects`, `Schema`).
- `validation.go` — configuration validation using
  `pkg/errors.NewValidator` (or `NewValidatorFor`).
- `constants.go` — your config key names (kebab-case strings) and any
  other constants that other files in the package reference.
- `*_test.go` — co-located unit tests.

Use `pkg/attestors/git` as a working reference. The
[coding conventions](coding-conventions.md) document covers the
attestor-internal patterns (logging, config helpers, error wrapping) in
detail.

## Step 4 — Register the attestor

Register inside an `init()` block in `attestor.go`:

```go
func init() {
    _ = core.RegisterAttestor(func(log logger.Logger) core.Attestor {
        return &Attestor{
            logger: log.With("attestor_id", "docker-image"),
        }
    })
}
```

`core.RegisterAttestor` is keyed by ID; the second registration of the
same ID fails. The factory receives the framework logger and must return
a new instance — never share state between factory invocations.

## Step 5 — Wire the import path

Registration only runs when the package's `init()` is reached, which only
happens when something imports it. The convention is a blank import in
`pkg/pipeline/init.go`:

```go
import (
    _ "github.com/thomsonreuters/stamp/pkg/attestors/docker_image"
)
```

The directory name uses snake_case so the package identifier matches
exactly (`docker_image`). Existing in-tree packages with kebab-case
directories (`github-workflow`, `go-builder`) collapse to identifiers
without the dash (`githubworkflow`, `gobuilder`); prefer snake_case for
new packages so the directory and the package name read the same way.

Add your attestor alongside the others. The CLI imports `pkg/pipeline`,
so this is enough to make the attestor visible to `stamp list` and
`stamp run`.

## Step 6 — Update flag and config mappings

The repository keeps two mapping files at the top level that describe the
full flag-to-config-path surface area:

- `flag-path-command-mapping.yaml`
- `config-structure-mapping.yaml`

Most attestors only need entries here if they add a **global** configuration
path (one that lives outside `attestor.<id>.*`). Attestor-scoped settings
work without touching these files because the pipeline reads them from
`attestor.<id>` automatically.

If your attestor introduces a new global path (for example a credential
location that several attestors share), add it to both mapping files.

## Step 7 — Verify

From a clean build:

```sh
go build ./...
go test ./pkg/attestors/docker_image/...
go run ./cmd list                       # your attestor appears
go run ./cmd list --show-config docker-image
go run ./cmd run --attestor docker-image --set image_ref=...
```

The directory is `docker_image/`; the attestor ID exposed to the CLI
(`--attestor docker-image`) remains kebab-case to match the convention
used by other registered attestor IDs.

If `list` does not show your attestor, you almost certainly forgot the
blank import in step 5.

## Lifecycle expectations

The pipeline calls your attestor in this order:

1. `ValidateConfig` — schema check plus business rules. May run multiple
   times (CLI parses, then again before execution); keep it pure and cheap.
2. `PreAttest` — set up resources, parse config into your `Attestor`
   struct, verify preconditions (file exists, command is on PATH, etc.).
3. `Attest` — collect evidence. This is where the real work belongs.
4. `PostAttest` — release resources, clean up temp files.
5. `GeneratePredicate` and `Subjects` — produce the final outputs from
   data your `Attest` method stored on the receiver.

Do not perform expensive work in `ConfigSchema` or `ValidateConfig`; the
former is called during help/listing, the latter during dry-runs.

## Common pitfalls

- **Forgetting the JSON schema.** `Schema()` should return a
  `jsonschema.Schema` derived from your predicate type. Verifiers and
  documentation tooling depend on it.
- **Leaking secrets into the predicate.** Tokens, credentials, and request
  headers should be redacted by default. Look at the `git` attestor's
  `RedactIdentity` and `SensitiveFields` options for the established
  pattern.
- **No `omitempty` on optional fields.** An empty string or zero value
  serialized into the predicate is permanent — once a verifier sees a
  field it cannot tell if its absence is meaningful.
- **Stateful factories.** The factory passed to `RegisterAttestor` must
  return a fresh `*Attestor` on every call. Holding shared state across
  invocations breaks concurrent workflows.

## See also

- [Add a new predicate](add-a-new-predicate.md)
- [Coding conventions](coding-conventions.md)
- [Attestors reference](../../reference/attestors.md)
