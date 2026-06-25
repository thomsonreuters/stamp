# Work with collection envelopes

A collection envelope wraps several individual attestations into a single
in-toto statement. Workflows produce one when configured with
`output_mode: collection` or `output_mode: both`. This guide shows how to
detect a collection programmatically, decode its predicate, and walk the
wrapped attestations.

## Prerequisites

- A workflow execution that produced a collection — that is,
  `result.HasCollection()` returns `true`. See
  [Embed the attestor in a Go application](embed-in-a-go-app.md) for how to
  obtain a `*pipeline.Result`.
- Or a collection envelope previously written to disk (a JSON file
  containing a DSSE envelope whose payload statement has predicate type
  `https://github.com/thomsonreuters/stamp/collection/v1`).

## Detect a collection on a Result

```go
if result.HasCollection() {
    for _, c := range result.Collections {
        fmt.Printf("workflow %q produced a collection\n", c.WorkflowName)
        // c.Envelope is *intoto.Envelope
    }
}
```

`Collections` is a slice — one entry per workflow that produced a
collection envelope.

## Read the wrapped statement

`*intoto.Envelope` exposes two methods you will use here:

- `SHA256()` returns the hex SHA-256 of the canonical envelope JSON. This
  is the same value Rekor indexes by.
- `GetStatement()` decodes the base64 payload and returns the embedded
  `*intoto.Statement`. The statement carries the subject list (deduplicated
  across all wrapped attestations) and the predicate.

```go
env := result.Collections[0].Envelope

stmt, err := env.GetStatement()
if err != nil {
    return fmt.Errorf("decode statement: %w", err)
}

fmt.Printf("predicate_type=%s\n", stmt.PredicateType)
fmt.Printf("subject_count=%d\n", len(stmt.Subject))
```

## Decode the collection predicate

The collection predicate has a fixed shape defined in
`pkg/predicates/collection/v1`. Type-assert `stmt.Predicate` to it:

```go
import (
    collectionv1 "github.com/thomsonreuters/stamp/pkg/predicates/collection/v1"
)

coll, ok := stmt.Predicate.(collectionv1.CollectionPredicate)
if !ok {
    return fmt.Errorf("predicate is not a collection v1")
}

for _, att := range coll.Attestations {
    fmt.Printf("- attestor_id=%s predicate_type=%s subjects=%d\n",
        att.AttestorID, att.PredicateType, len(att.Subjects))
}
```

Each `CollectionAttestation` contains:

- `AttestorID` — the identifier of the attestor that produced the wrapped
  attestation (e.g. `git`, `sbom`).
- `PredicateType` — the URI of the wrapped predicate.
- `Predicate` — the **full** original predicate value, not a reference. It
  is typed as `any`; decode it the same way you would decode any predicate
  for that URI.
- `Subjects` — the subjects from that specific wrapped attestation.

Note that when `stmt.Predicate` arrives via JSON unmarshalling (rather than
directly from an in-process workflow), it will be a `map[string]any` rather
than a `CollectionPredicate`. Re-encode and decode if you need the strongly
typed form.

## Complete example: read a collection from disk

```go
package main

import (
    "encoding/base64"
    "encoding/json"
    "fmt"
    "log"
    "os"

    "github.com/thomsonreuters/stamp/pkg/intoto"
    collectionv1 "github.com/thomsonreuters/stamp/pkg/predicates/collection/v1"
)

func main() {
    raw, err := os.ReadFile("./collection.json")
    if err != nil {
        log.Fatalf("read: %v", err)
    }

    var env intoto.Envelope
    if err := json.Unmarshal(raw, &env); err != nil {
        log.Fatalf("unmarshal envelope: %v", err)
    }

    sum, err := env.SHA256()
    if err != nil {
        log.Fatalf("hash: %v", err)
    }
    fmt.Printf("envelope_sha256=%s\n", sum)

    // GetStatement leaves Predicate as map[string]any after JSON decoding;
    // re-encode then decode into the typed CollectionPredicate.
    payload, err := base64.StdEncoding.DecodeString(env.Payload)
    if err != nil {
        log.Fatalf("decode payload: %v", err)
    }

    var typed struct {
        Type          string                          `json:"_type"`
        PredicateType string                          `json:"predicateType"`
        Subject       []intoto.Subject                `json:"subject"`
        Predicate     collectionv1.CollectionPredicate `json:"predicate"`
    }
    if err := json.Unmarshal(payload, &typed); err != nil {
        log.Fatalf("decode statement: %v", err)
    }

    fmt.Printf("collection=%s wraps=%d subjects=%d\n",
        typed.Predicate.Name,
        len(typed.Predicate.Attestations),
        len(typed.Subject))

    for _, att := range typed.Predicate.Attestations {
        fmt.Printf("  - %s [%s] subjects=%d\n",
            att.AttestorID, att.PredicateType, len(att.Subjects))
    }
}
```

## Consistency guarantee

The `*intoto.Envelope` you hold in memory after `op.Execute` is
byte-identical to the JSON the framework emits to stdout, persists to a
file destination, and uploads to Rekor. That means:

- The value returned by `env.SHA256()` matches the Rekor entry's
  payload hash.
- A round-trip through `json.Marshal` + `json.Unmarshal` (or simply reading
  the persisted file back) produces an envelope whose `SHA256()` is the
  same value.

This makes it safe to compute the hash once and use it as a stable handle
across log search, local verification, and downstream systems.

## See also

- [Library API reference](../../reference/library-api.md)
- [Workflows explained](../../explanation/workflows.md)
