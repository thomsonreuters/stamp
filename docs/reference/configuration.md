# Configuration

`stamp` reads configuration from three sources in addition to CLI flags:
environment variables, a YAML configuration file, and built-in defaults.
This page describes the shape of the configuration file, the precedence
rules, the environment-variable convention, and the workflow schema.

For the exhaustive list of configuration keys and the mapping between CLI
flags, environment variables, and YAML paths, consult the two source-of-truth
documents at the repository root:

- `flag-path-command-mapping.yaml` — every flag, its YAML path, and the
  commands that consume it.
- `config-structure-mapping.yaml` — the full configuration tree, plus
  per-attestor and per-destination schemas.

## Overview

The configuration file is YAML. Two locations are supported:

- `~/.stamp.yaml` — default. Used when no `--config` flag is given.
- A path supplied via `--config, -c`. When set, only this file is loaded
  and a load error is fatal. When unset, a missing default file is silently
  ignored.

The same configuration file is used by every command. A command only reads
the subset of keys it cares about, so it is normal for a single file to
contain settings for `run`, `verify`, `upload`, and so on side by side.

## Precedence

For any setting, the first source in this list that provides a value wins:

1. CLI flags
2. Environment variables (`STAMP_*`)
3. Configuration file
4. Built-in defaults

Constraints declared on a flag — mutual exclusions, `requires`/`required by`
relationships, value enumerations — are enforced on the resolved value,
regardless of which layer supplied it. Setting two mutually exclusive flags
via the config file produces the same error as setting them on the command
line.

One exception: `--config` itself is bootstrap-only and cannot be set through
the configuration file (the file has not been loaded at the point the path
is needed).

## Environment variables

Viper auto-binds environment variables prefixed with `STAMP_`. The
convention is to uppercase the YAML path and replace dots and dashes with
underscores. A flag's explicit environment-variable annotation (when set,
visible in `--help`) overrides this default.

For example, the YAML key `pipeline.rekor.url` becomes
`STAMP_PIPELINE_REKOR_URL`:

```sh
export STAMP_PIPELINE_REKOR_URL=https://rekor.example.com
stamp run --all
```

Sensitive values (OIDC tokens, key passwords) are best supplied through
environment variables or file-based flags rather than the configuration
file or the command line.

## Top-level shape

The configuration file has a small number of stable top-level keys. Most
are populated by flags through Viper bindings; user-authored content
generally lives under `workflows` and (when used) per-attestor `config`
blocks inside each workflow.

```yaml
log:
  level: info          # debug | info | warn | error
  format: console      # console | json
  file: ""             # log file path; empty means stderr

settings:
  quiet: false
  log_only: false
  debug: false
  no_color: false
  insecure: false
  max_retries: 3
  retry_delay: 1s
  timeout: 30s
  parallel: false

pipeline:
  signing:
    signer: fulcio     # key | fulcio
    fulcio_url: https://fulcio.example.com
    # OIDC token sources (mutually exclusive)
    oidc_token: ""
    oidc_token_file: ""
    use_spire: false
    use_github: false
    spire_socket: ""
  rekor:
    enable: false
    url: https://rekor.example.com
    upload_target: individual  # individual | collection | both
    temporal_policy: warn      # strict | warn | ignore
  settings:
    failure_policy: fail-fast  # fail-fast | continue

cryptography:
  key:
    private_key: ""
    public_key: ""
    password: ""
    password_file: ""
    password_prompt: false

commands:
  run: { ... }       # per-command defaults; flags override
  list: { ... }
  fetch: { ... }
  verify: { ... }
  upload: { ... }
  generatekey: { ... }

workflows:
  - name: example-workflow
    ...
```

The `commands.*` blocks mirror the per-command flag groups. Setting
`commands.run.persist: true` is equivalent to passing `--persist` to
`stamp run`. The leaves under each block follow the same kebab-to-snake
naming convention the flag bindings use (`--continue-on-error` becomes
`continue_on_error`).

See `config-structure-mapping.yaml` for the full leaf list and
`flag-path-command-mapping.yaml` for the flag-to-path mapping. Those files
are kept in sync with the code.

## Workflows

A workflow is a named, reproducible execution of one or more attestors with
its own signing and Rekor settings. Workflows are the part of the
configuration that has no `--help` equivalent and is fully user-authored, so
they are documented in detail here. The Go type definitions live in
`pkg/config/types.go` (the `Workflow` and `Attestor` structs).

The top-level `workflows` is a list of workflow entries. Each entry has
the following fields:

- `name` (string, required) — the workflow identifier used by
  `stamp run <name>` and `--include`/`--exclude` globs. Must be unique
  across the configuration.
- `tags` (string list, optional) — labels used by `stamp run --tags` for
  filtering.
- `output_mode` (string, optional) — `individual`, `collection`, or `both`.
  Defaults to the global output mode.
- `failure_policy` (string, optional) — `fail-fast` or `continue`.
  Controls how attestor failures inside this workflow are handled.
  Defaults to the global `pipeline.settings.failure_policy`.
- `rekor` (object, optional) — per-workflow transparency-log settings. See
  below.
- `attestors` (list, required) — the attestors to run, in order.

Workflow-level output destinations are not currently configurable via YAML;
see "Destinations" below.

Each entry in `attestors` is an object with:

- `name` (string, required) — a stable identifier for this attestor
  invocation within the workflow. Must be unique inside the workflow.
- `type` (string, required) — the registered attestor identifier (for
  example `git`, `command`, `file`). Use `stamp list` to enumerate
  available types.
- `config` (map, optional) — type-specific configuration. See
  "Per-attestor config blocks".

A complete, realistic example:

```yaml
workflows:
  - name: ci-build
    tags: [ci, build]
    output_mode: collection
    failure_policy: fail-fast
    rekor:
      upload: true
      upload_target: collection
    attestors:
      - name: source
        type: git
        config:
          git-working-dir: .
          dirty-behavior: fail
          redact-identity: true
      - name: build
        type: command
        config:
          command: make build
          working_directory: .
          timeout: 10m
          capture_stdout: true
          capture_stderr: true
      - name: binary
        type: file
        config:
          base-path: ./dist
          paths: [attestor]
          hash-algorithms: [sha256, sha512]
```

### Per-workflow Rekor settings

The `rekor` block has two fields:

- `upload` (bool) — whether to upload attestations from this workflow to a
  Rekor server. The server URL still comes from `pipeline.rekor.url`.
- `upload_target` (string) — `individual`, `collection`, or `both`. When the
  workflow's `output_mode` is `both`, this selects which envelopes to push
  to Rekor.

### Validation

A workflow is rejected at load time if:

- `name` is empty.
- `attestors` is empty.
- Any attestor entry has an empty `name` or `type`.
- Two attestors in the same workflow share a `name`.
- `failure_policy` or `output_mode` is set to an unknown value.

## Per-attestor config blocks

Every attestor type publishes a configuration schema describing the keys it
accepts under `config:`. The schema is the source of truth for both
configuration files and `--set key=value` overrides on `stamp run`.

Inspect the schema for a single attestor:

```sh
stamp list <attestor-id>
```

Or list every attestor with its schema in one pass:

```sh
stamp list --show-config
```

This documentation deliberately does not enumerate per-attestor keys. The
schemas evolve with each attestor, and `stamp list --show-config` is the
only place where they are guaranteed to be current.

## Destinations

The destination subsystem (`pkg/destination`) is a plugin registry with a
`Manager` that handles parallel writes, retries, and failure policies. One
destination implementation (`file`) ships in-tree.

Today the destination manager is constructed and configured exclusively by
the `stamp run --persist` flow. When `--persist` is set, a single file
destination is created using `--template` (or its default), `--force`, and a
fixed set of file-destination defaults. Workflow YAML does not yet expose
a `destinations:` field; that wiring is planned but not present in the
current codebase.

To configure where attestations are written today:

```sh
stamp run \
    --attestor git \
    --signer key --private-key ./signing.key \
    --persist \
    --template './attestations/${attestor}-${timestamp}.json' \
    --force
```

See the [Use path templates](../how-to/cli/use-path-templates.md) how-to for
the supported variables and the [destinations reference](destinations.md) for
the file destination's configuration keys.

## See also

- [CLI commands](cli.md) — flags grouped by command, plus mutual-exclusion
  and `requires` rules.
- [Attestors](attestors/) — per-attestor reference pages.
- [Use path templates for persisted output](../how-to/cli/use-path-templates.md)
  — template variables for `--template` and the file destination.
- `flag-path-command-mapping.yaml` (repo root) — flag-to-YAML-path mapping.
- `config-structure-mapping.yaml` (repo root) — complete configuration tree
  and per-attestor / per-destination schemas.
