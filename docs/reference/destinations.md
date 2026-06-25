# Destinations

A destination is an output sink for signed attestations. The framework
provides a destination subsystem (`pkg/destination`) with a registry, a
dispatch manager that handles retries, parallel writes, and failure
policies, and one shipping implementation (`file`).

## Current status

Today the destination manager is constructed and configured only through
the `stamp run --persist` flow. When `--persist` is set, the pipeline
adds a single file destination configured from `--template`, `--force`,
and a small set of fixed defaults (pretty-print JSON, atomic writes, parent
directories created on demand).

Workflow YAML does not yet expose a `destinations:` field, and configuring
multiple destinations or a non-file destination from configuration is not
possible from a configuration file in the current codebase. The
infrastructure described below is what the destination subsystem can do
internally; not all of it is reachable from the CLI today.

Implementation: `pkg/destination`, `pkg/destination/file`,
`pkg/pipeline/base.go` (`GetDestinationManager`).

## Overview

Destinations sit at the tail of the pipeline. Once an attestor has produced
a statement and the signer has wrapped it in a DSSE envelope, every
configured destination receives the envelope plus metadata (attestation ID,
attestor ID, workflow name, predicate type, content hash). The destination
decides where and how to persist it.

Two output paths exist alongside the destination manager:

- **Stdout** — every signed envelope is written to the process's standard
  output as JSON unless suppressed by `--quiet` or `--log-only`. This is
  always on, regardless of `--persist`.
- **`stamp run --persist`** — adds a single file destination to the
  manager for this run. Without `--persist`, no destination manager is
  constructed and nothing is written to disk through the destination
  subsystem.

## File destination

The `file` destination serializes each envelope and writes it to the local
filesystem. It is the only destination implementation that ships today.

### Configuration keys

The keys below are what the file destination accepts when configured via
`Configure(map[string]any)`. Today only the keys set by `--persist` (path,
overwrite, pretty, create_dirs, atomic_writes) are reachable from the CLI.

| Key             | Type   | Default                                 | Notes                                                   |
| --------------- | ------ | --------------------------------------- | ------------------------------------------------------- |
| `path`          | string | `./attestations/${attestor}/${id}.json` | Path template, see below                                |
| `format`        | string | `json`                                  | `json`, `yaml`, `yaml-stream`                           |
| `compression`   | string | `none`                                  | `none`, `gzip`, `zstd`                                  |
| `permissions`   | string | `0644`                                  | Octal file mode                                         |
| `create_dirs`   | bool   | `true`                                  | Create parent directories on demand                     |
| `overwrite`     | bool   | `false`                                 | Replace an existing file at the resolved path           |
| `atomic_writes` | bool   | `true`                                  | Write to a `.tmp` sibling, then rename                  |
| `pretty`        | bool   | `false`                                 | Pretty-print JSON output                                |
| `aggregate`     | bool   | `false`                                 | Write all envelopes to a single file (see below)        |
| `metadata`      | map    | unset                                   | Static key/value pairs available as `${metadata.<key>}` |

### Output formats

- `json` — one JSON document per file. In aggregate mode, a single JSON
  array of envelopes.
- `yaml` — one YAML document per file. In aggregate mode, a single YAML
  document containing the array of envelopes.
- `yaml-stream` — aggregate mode only in practice; emits multiple YAML
  documents separated by `---`, one per envelope.

### Compression

`none`, `gzip`, or `zstd`. Compression is applied transparently to the
serialized form; no file-extension change is performed, so include `.gz`
or `.zst` in the path template if you need it.

### Atomic writes

When `atomic_writes` is true (the default), the destination writes the
serialized envelope to `<path>.tmp`, calls `fsync`, and renames over the
final path. A crash mid-write leaves no half-written file at `<path>`.
The temporary file is removed on error.

### Aggregate mode

When `aggregate: true`, a single `WriteBatch` call collects every envelope
in the batch into one output file. The path template may not use
per-attestation variables (`${id}`, `${sha256}`, `${attestor}`,
`${predicate_type}`, `${short_predicate_type}`) because no single value
exists for the batch; validation rejects such templates up front.

## Path template variables

Path templates support two equivalent syntaxes, `${var}` and `{{.var}}`,
and resolve at the moment of write. Environment-variable interpolation
uses the same `${...}` syntax. Unknown template variables are left
verbatim; unset environment variables resolve to the empty string (or to
the supplied default, if any).

| Variable                  | Replaced by                                                             |
| ------------------------- | ----------------------------------------------------------------------- |
| `${id}`                   | Attestation UUID (per envelope)                                         |
| `${attestor}`             | Attestor identifier; empty for collection envelopes                     |
| `${date}`                 | Current date, `YYYY-MM-DD`                                              |
| `${timestamp}`            | Current Unix timestamp (seconds since epoch)                            |
| `${year}`                 | Current four-digit year                                                 |
| `${month}`                | Current two-digit month (`01`-`12`)                                     |
| `${day}`                  | Current two-digit day of month (`01`-`31`)                              |
| `${sha256}`               | Hex SHA-256 of the serialized envelope                                  |
| `${workflow}`             | Workflow name; requires workflow context (i.e. `stamp run`)             |
| `${predicate_type}`       | Full predicate-type URI, sanitized for path safety                      |
| `${short_predicate_type}` | Last two path segments of the predicate-type URI (e.g. `provenance_v1`) |
| `${ENV_VAR}`              | Value of the named environment variable, or empty                       |
| `${ENV_VAR:default}`      | Value of the named environment variable, or `default` if unset          |

### Examples

A per-attestor file organized by date:

```text
./attestations/${date}/${attestor}/${id}.json
```

A single per-workflow file containing every envelope (aggregate mode is
internal-only today):

```text
./out/${workflow}-${date}.yaml
```

A path keyed by CI run, falling back when run outside CI:

```text
./out/${BUILD_ID:local}/${attestor}.json
```

## Failure policy

The destination manager supports per-batch failure policies. These are
exposed through the manager's `WriteOptions` API and are not currently
selectable through the CLI.

| Policy      | Semantics                                                                 |
| ----------- | ------------------------------------------------------------------------- |
| `ignore`    | Continue on any destination error; the error is logged but never returned |
| `warn`      | Continue, but log a prominent warning for each failed write               |
| `fail-fast` | Abort the batch on the first destination error                            |
| `quorum`    | Succeed if at least `quorum_count` destinations write successfully        |

## Retry

The destination manager retries failed writes with exponential backoff
before applying the failure policy. The retry envelope is configured on
the manager (maximum attempts, initial delay, maximum delay, backoff
multiplier). Only errors that the destination flags as retryable are
retried; the file destination treats write errors as retryable and
configuration or context-cancellation errors as terminal.
