# Workflows

A workflow is the framework's unit of policy. It is a named collection of
attestors that share a signing configuration, an output strategy, a failure
policy, and a transparency-log strategy. If an attestor is the smallest unit
of evidence and a destination is the smallest unit of delivery, the workflow
is what binds them together with rules.

This document explains why workflows are shaped the way they are and how the
three biggest knobs — output mode, failure policy, and Rekor upload target —
interact.

## What a workflow is, and why

A typical CI pipeline does not produce one attestation; it produces several.
A build job might want to attest its git state, the workflow context, the
build command itself, and the SLSA provenance of the resulting binary. Each
of those is a different attestor, but they all need to be signed the same
way, written to the same place, and treated under the same failure rules.
Doing this by hand — invoking each attestor with the full set of policy
flags repeated — is repetitive and error-prone. Workflows are the
configuration object that collects all of those decisions once.

A workflow is also the natural granularity at which to talk about
verification. A consumer asking "did the artifact go through *the release
process*?" wants a yes/no answer about a coherent set of attestations, not a
manual reconciliation across N separately-signed envelopes.

## The three big knobs

The workflow configuration exposes three policies that compose in ways that
are not always obvious. Get these right and the rest of the system follows.

### Output mode

The output mode controls how many envelopes the workflow emits when it
completes successfully.

- `individual` — emit one DSSE envelope per attestor. Each envelope wraps a
  single statement with that attestor's predicate.
- `collection` — emit one DSSE envelope containing a collection statement
  whose predicate bundles all of the individual predicates inline. The
  wrapped predicates are present in full, not as references; a verified
  collection envelope is self-contained evidence for every attestor.
- `both` — emit both forms. Useful when downstream consumers have different
  preferences, or when you want individual envelopes for granular policies
  and a collection envelope for "did the whole workflow succeed" checks.

Each mode has a use case. Individual envelopes are cheap to verify in
isolation and easy to revoke or replace one at a time. A collection envelope
is harder to attack piecewise (you cannot strip out the part you do not
like) and gives a verifier a single thing to check. Both is the safe
default for systems that need to support both styles of consumer.

### Failure policy

A workflow runs many attestors, any of which can fail. The failure policy
decides what to do when one does. Two values are accepted (defined in
`pkg/types/failure_policy.go`):

- `fail-fast` (default) — abort on the first attestor error. No further
  attestors run, no envelopes are emitted, the workflow exits with an error.
- `continue` — record the failure, continue with the remaining attestors,
  and produce envelopes for the ones that succeeded. The workflow itself
  exits successfully, with the failed attestors flagged in the result.

`fail-fast` is the right default for build pipelines where partial evidence
is misleading: if you cannot attest the git state, you probably should not
ship the binary. `continue` is the right choice for diagnostic or
exploratory runs where you want as much signal as you can get.

The destination subsystem has its own internal failure policies (`ignore`,
`warn`, `fail-fast`, `quorum`) but those are not the same vocabulary as
workflow failure policies and are not currently selectable from workflow
configuration. Today the only destination wired through workflow execution
is the file destination added by `--persist`, and any error writing it
fails the run.

### Rekor upload target

The Rekor upload target controls which envelopes are sent to the
transparency log.

- `individual` — upload each individual envelope.
- `collection` — upload only the collection envelope.
- `both` — upload everything that exists.

The target interacts directly with the output mode. Combinations that make
sense:

```
output_mode    rekor_upload    behavior
-------------  --------------  -----------------------------------------
individual     individual      N entries, one per attestor
individual     collection      no-op (no collection envelope to upload)
individual     both            N entries (no collection exists)
collection     individual      no-op (no individual envelopes exist)
collection     collection      1 entry
collection     both            1 entry (collection only)
both           individual      N entries
both           collection      1 entry
both           both            N+1 entries
```

The "no-op" cells are the important ones. Asking to upload something that
was not produced is not an error — it simply has nothing to do. This is
intentional: it lets you set a single workflow-level Rekor policy and vary
the output mode per environment without having to keep both fields in
strict sync.

## Selecting workflows

A run can target one workflow, a set of workflows by tag, all workflows, or
a name-glob filter. Tag-based selection is the operational sweet spot: tag
a workflow `release` and another `nightly` and you can run the right set
without naming each one. Include/exclude globs are the escape hatch for
ad-hoc selection (`--include "release-*" --exclude "release-experimental"`).

The selection logic is order-independent: `--tags` filters first, then
`--include`, then `--exclude`. Each filter narrows; none can add a workflow
that was not already in scope.

## The mental model

A useful way to keep these moving parts straight is to remember the three
roles each concept plays:

- An **attestor** is the unit of evidence. It speaks for one fact.
- A **destination** is the unit of delivery. It puts bytes somewhere.
- A **workflow** is the unit of policy. It decides how attestors compose,
  how failures are handled, what gets signed, and where it goes.

When configuration gets confusing, ask which role the piece in question
belongs to. Signing config is policy, so it lives on the workflow. A path
to write to is delivery, so it belongs on a destination (today, on the
`--persist` and `--template` flags). "Capture this optional metadata" is
evidence, so it lives on the attestor. The framework tries hard to keep
this separation; configurations that violate it tend to be the source of
subtle bugs.
