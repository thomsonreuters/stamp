# Add a new predicate

This guide covers defining a new predicate type — the typed structure that
appears as the `predicate` field of an in-toto statement. Most of the time
a new predicate is introduced alongside a new attestor, but predicates can
also be defined independently and reused across attestors.

## Prerequisites

- A clear, written definition of what the predicate describes. The
  predicate is a contract: once it is published and signed envelopes carry
  its URI, you cannot change its shape without versioning.
- A chosen URI (see step 1 below).
- Familiarity with the in-toto Statement v1 specification — the predicate
  is one field of that statement, and the framework handles wrapping it
  for you.

## Step 1 — Pick a URI

For predicates published by this project, the convention is:

```
https://github.com/thomsonreuters/stamp/<name>/v<major>
```

For example:

- `https://github.com/thomsonreuters/stamp/git/v1`
- `https://github.com/thomsonreuters/stamp/collection/v1`

For standard predicates defined elsewhere, reuse the upstream URI. Do not
mint a custom URI for something that already has a canonical one:

- SLSA Provenance: `https://slsa.dev/provenance/v1`
- SPDX 2.3 Document: `https://spdx.dev/Document/v2.3`

## Step 2 — Create the predicate package

Predicate packages live under `pkg/predicates/<name>/v1/` and contain a
single `predicate.go` plus its tests. Keep the package name `v1` (or
`v2`, etc.) — the version is encoded in the directory, not in the
package identifier.

```go
// pkg/predicates/docker_image/v1/predicate.go

package v1

import "time"

// PredicateURI is the predicate type URI emitted in the in-toto statement.
const PredicateURI = "https://github.com/thomsonreuters/stamp/docker-image/v1"

// Predicate describes a built container image.
type Predicate struct {
    Image    ImageReference `json:"image"`
    BuildEnv BuildEnv       `json:"build_env"`
    BuiltAt  time.Time      `json:"built_at"`
    Labels   map[string]string `json:"labels,omitempty"`
}

// ImageReference identifies an image in a registry.
type ImageReference struct {
    Registry   string `json:"registry"`
    Repository string `json:"repository"`
    Digest     string `json:"digest"`
    Tag        string `json:"tag,omitempty"`
}

// BuildEnv describes the environment that produced the image.
type BuildEnv struct {
    Builder    string `json:"builder"`
    BuilderVersion string `json:"builder_version,omitempty"`
}
```

Hard rules:

- Top-level type is named `Predicate`; the URI constant is named
  `PredicateURI`.
- All JSON tags are snake_case.
- Optional fields use `,omitempty`.
- Avoid pointers unless the absence of a field is semantically distinct
  from its zero value. Pointers complicate verifiers and round-trip
  testing.
- Group related fields into sub-structs (`ImageReference`, `BuildEnv`) so
  the predicate documents itself.

## Step 3 — Add tests

A `predicate_test.go` file in the same package must, at minimum, round-trip
a populated predicate through JSON marshal then unmarshal and verify all
fields. Use table-driven cases — one for the populated case, one for the
minimal (only required fields) case, one for the empty case.

```go
func TestPredicate_RoundTrip(t *testing.T) {
    tests := []struct {
        name string
        in   Predicate
    }{
        {
            name: "minimal",
            in: Predicate{
                Image: ImageReference{
                    Registry:   "ghcr.io",
                    Repository: "exampleorg/example",
                    Digest:     "sha256:abc",
                },
            },
        },
        // ...
    }

    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            data, err := json.Marshal(tc.in)
            if err != nil {
                t.Fatalf("marshal: %v", err)
            }
            var out Predicate
            if err := json.Unmarshal(data, &out); err != nil {
                t.Fatalf("unmarshal: %v", err)
            }
            if !reflect.DeepEqual(tc.in, out) {
                t.Fatalf("round-trip mismatch:\nin=%+v\nout=%+v", tc.in, out)
            }
        })
    }
}
```

Round-trip tests catch typos in JSON tags, missing `omitempty` on fields
that should be optional, and accidental use of unsupported types.

## Step 4 — Version it correctly

The directory name and the URI's `v<n>` suffix must agree. Versioning
rules:

- **Additive changes** — new optional fields with `omitempty` — stay in
  the current version. Existing signed envelopes remain valid; new
  envelopes carry the additional fields.
- **Breaking changes** — removing a field, changing its type, changing
  semantics — require a new major version. Create `pkg/predicates/<name>/v2/`,
  define `PredicateURI = "https://github.com/thomsonreuters/stamp/<name>/v2"`,
  and leave `v1/` in place for as long as you intend to support reading
  old attestations.

Never reuse a URI for a structurally different predicate. Verifiers key
their decoding off the URI; changing the shape silently turns previously
valid attestations into garbage.

## Step 5 — (Optional) reuse across attestors

The core registry indexes attestors by both ID and predicate URI. Two
attestors may legitimately emit the same predicate URI — for example a
"fast" and a "full" variant of the same evidence. `core.ListAttestorsByPredicateURI`
returns every attestor registered for a URI, so consumers can route based
on either ID or predicate type.

If you intend a predicate to be shared, document the expectation in the
package comment so contributors do not assume there is only one producer.

## Things to avoid

- **Methods that depend on runtime state.** Predicates are pure data.
  Helper functions that operate on a predicate are fine; methods that read
  the file system, the clock, or environment variables are not — they
  break serialization determinism.
- **Time defaults inside the struct.** Never call `time.Now()` in a
  predicate constructor or default. The attestor that produces the
  predicate decides what timestamp to record, and the framework asks for
  the same predicate twice in a single run; non-deterministic defaults
  produce two different envelopes for the same evidence.
- **Cyclic types.** A struct field whose type transitively contains the
  outer type will marshal forever. The Go compiler accepts this through
  pointers, but `encoding/json` does not survive it.
- **Embedding interfaces.** Predicates must serialize identically given
  the same inputs; an `any`-typed field is fine for opaque pass-through
  data (the collection predicate does this), but a field typed as a
  domain interface will serialize whatever concrete type happens to be
  populated, which is rarely what verifiers expect.

## See also

- [Add a new attestor](add-a-new-attestor.md)
- [Predicates reference](../../reference/predicates.md)
- [Coding conventions](coding-conventions.md)
