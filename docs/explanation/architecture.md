# Architecture

This document discusses the layered design of the attestor framework and the
reasoning behind it. It is aimed at contributors and integrators who want to
think clearly about why the code is shaped the way it is, rather than how to
invoke any particular feature.

## The layers

The framework is organized as four conceptual layers. Each layer has a single,
narrow responsibility and depends only on the layers below it.

```
+--------------------------------------------------------------+
|  Command layer  (cobra)                                      |
|     - parses flags, loads config, dispatches to operations   |
+--------------------------------------------------------------+
|  Operations layer  (pkg/operations)                          |
|     - run, verify, upload, fetch, generate-key, list         |
|     - the stable verbs that compose into user workflows      |
+--------------------------------------------------------------+
|  Pipelines layer  (pkg/pipeline)                             |
|     - orchestrates a set of attestors with one policy        |
|     - BasePipeline -> AttestorPipeline, WorkflowPipeline     |
+--------------------------------------------------------------+
|  Attestors layer  (pkg/attestors)                            |
|     - individual evidence collectors                         |
|     - git, file, command, github-workflow, ec2, go-builder…  |
+--------------------------------------------------------------+
```

The Command layer is intentionally thin. It exists to translate CLI ergonomics
(flags, positional arguments, environment variables) into a structured
operation invocation. It does not contain business logic. This is what makes
it possible to drive the framework from a SDK or from a non-CLI host without
forking; everything below the command layer is reachable as ordinary Go API.

The Operations layer holds the verbs of the system. An operation is a coarse
unit of work that maps cleanly to a user intent: run an attestation, verify a
signed envelope, upload to Rekor, fetch a Rekor entry, generate a signing key.
Operations are deliberately stateless. They take typed inputs, build the
necessary pipelines and signers, run them, and return typed results. Treating
operations as the public verb surface keeps the CLI honest: every flag must
correspond to something the API can express.

The Pipelines layer is where most orchestration lives. A pipeline takes a
collection of attestors and runs them under a single policy (failure policy,
signing config, output destinations). It is the smallest unit that produces a
signed in-toto envelope. There are two flavours, sharing a common base, and
the distinction matters for how state is gathered and emitted; see *The
pipeline hierarchy* below.

The Attestors layer is where evidence is collected. Each attestor speaks for
one well-defined fact: the state of a git working tree, the contents of a
file, the output of a command, the identity of an EC2 instance. Attestors
know nothing about signing, transport, or composition. They produce a typed
predicate and a set of subjects, and that is all.

## The registry pattern

Attestors, signers, and destinations are all registered into typed registries
at process init time. Each registration is a factory function that returns a
fresh instance, not a singleton.

There are two reasons to do this.

First, factory functions defer instantiation until the operation knows what
configuration applies. This matters because attestors carry per-run state
(working directory, parsed config, collected evidence). A singleton would
either need to be reset between runs or guarded by locks; a fresh instance
per run avoids both problems and keeps each attestor's lifecycle contained.

Second, init-time registration means the set of available components is
determined by which packages are imported, not by a hand-maintained switch
statement. Adding a new attestor is a matter of dropping a package under
`pkg/attestors/` and adding a blank import; the rest of the framework
discovers it. This is the conventional Go plug-in idiom and it carries the
usual tradeoff: there is no compile-time check that a given attestor name is
registered, only a runtime lookup.

The registry is also the indirection point for substitutions in tests. A test
can replace the global factory with a mock and exercise the pipeline without
touching real git repos or AWS metadata services.

## The pipeline hierarchy

`BasePipeline` is the shared substrate. It holds the things that every
pipeline needs regardless of whether it produces one envelope or many: the
logger, the signing configuration, the destination manager, the failure
policy, and a cache of per-attestor results so they can be assembled into
the final output.

`AttestorPipeline` is the simple case. It runs a single attestor, produces
one statement, signs it into one envelope, and writes it to the configured
destinations.

`WorkflowPipeline` is the composite case. It runs multiple attestors under a
shared policy and can emit results in three modes: individual envelopes per
attestor, a single collection envelope wrapping all predicates, or both. The
collection envelope preserves each wrapped predicate in full rather than as
a reference, so a single verified collection is self-sufficient evidence for
all included attestors. The workflows concept is discussed in more depth in
*workflows.md*.

Sharing a base type matters because failure handling, signer setup, and
destination dispatch are non-trivial and easy to get subtly wrong. Centralising
them ensures that the single-attestor and multi-attestor paths behave the
same under the same policy.

## The attestor lifecycle

An attestor is driven through a fixed sequence of phases:

1. `PreAttest` — set up, parse config into typed fields, validate
   preconditions that depend on the environment (a git directory exists, a
   path is readable, an executable is on PATH).
2. `Attest` — collect evidence. This is the only phase that does real work
   against the world (shells out, reads files, calls APIs).
3. `PostAttest` — release resources, finalize internal state.
4. `GeneratePredicate` / `Subjects` — produce the typed output. These are
   pure functions over the state collected during `Attest`.

The split between Attest and predicate generation looks redundant at first
glance, but it matters. It separates *gathering evidence* from *shaping the
output*, which lets the framework retry, log, or fail-handle the noisy I/O
phase independently from the deterministic serialization phase. It also
means a workflow can gather evidence from all of its attestors before
committing to an output mode — useful, for instance, when a collection
envelope needs subjects unioned across all participants.

PreAttest and PostAttest exist for the same reason: a well-behaved attestor
should be able to clean up after itself even if Attest fails, and it should
be able to fail-fast on configuration mistakes before doing any expensive
work.

## Dependency injection

Loggers, configuration, and output targets are passed in through
constructors and setters rather than reached for through package globals.
This is mostly a testability concern: a pipeline test should be able to hand
in a captured logger and an in-memory destination and observe exactly what
the code under test produced. The convention also keeps the dependency
graph honest — if a component needs the logger, that requirement is visible
in its signature.

There is one global, `pkg/logger`, that holds the process-wide structured
logger. Components are expected to derive child loggers with bound fields
rather than write directly to the global; the global exists so that early
init code (registries, flag parsing) has somewhere to log before the per-run
context is built.

## The public surface

Not every package in the tree is meant to be consumed by external code.
The intended stable surface is:

- `pkg/operations` — the verbs. If you want to drive the framework from
  another Go program, start here.
- `pkg/intoto` — the Statement and DSSE Envelope types. These match the
  external specs and are the natural exchange format between the framework
  and its consumers.
- `pkg/types` — the small shared types (digests, subjects, the like) that
  cross layer boundaries.
- `pkg/pipeline` result types — what an operation returns when it completes.

Packages outside that set should be treated as internal, even though Go's
visibility model does not enforce it. In particular, the attestors, signers,
and destinations are reached through their registries, not by importing the
concrete types. This boundary is what allows the framework to evolve
implementations without breaking integrators.
