# Use Path Templates for Attestation Output

Write attestation output files using a dynamic, structured path layout
instead of a fixed filename.

## Prerequisites

- `stamp run --persist --template '...'`.

Workflow YAML does not yet expose a destinations field, so the template
flag is the only path-template surface today.

## Variables

| Variable                          | Substitution                                                       |
| --------------------------------- | ------------------------------------------------------------------ |
| `${id}`                           | Attestation UUID (per envelope).                                   |
| `${attestor}`                     | Attestor identifier (e.g. `git`, `ec2`).                           |
| `${date}`                         | Current date, `YYYY-MM-DD`.                                        |
| `${timestamp}`                    | Current Unix timestamp (seconds since epoch), as decimal digits.   |
| `${year}` / `${month}` / `${day}` | Individual date components (`YYYY`, `01`-`12`, `01`-`31`).         |
| `${sha256}`                       | Hex SHA-256 of the serialized envelope.                            |
| `${workflow}`                     | Workflow name. Only valid in workflow context.                     |
| `${predicate_type}`               | Full predicate type URI, sanitized for path safety.                |
| `${short_predicate_type}`         | Last two path segments of the URI joined with `_` (e.g. `git_v1`). |
| `${ENV_VAR}`                      | Value of the named environment variable, or empty.                 |
| `${ENV_VAR:default}`              | Same, with a fallback when the variable is unset or empty.         |

Both `${var}` and `{{.var}}` syntaxes are accepted. The `${VAR:default}`
fallback applies only to environment-variable lookups — there is no
substring slicing syntax (`${sha256:0:12}` is not supported).

## Examples

Per-day, per-attestor layout:

```bash
stamp run --attestor git --persist \
  --template './attestations/${date}/${attestor}-${id}.json'
```

S3-style date partitions for archival:

```bash
stamp run --attestor ec2 --persist \
  --template './out/${year}/${month}/${day}/${attestor}.json'
```

Pull an identifier from a CI environment variable, with a local fallback:

```bash
stamp run --attestor git --persist \
  --template './attestations/${BUILD_ID:local}/${attestor}.json'
```

In a workflow (where `${workflow}` resolves) you can scope by workflow name:

```bash
stamp --config ./stamp.yaml run example-release --persist \
  --template './attestations/${workflow}/${date}/${attestor}-${id}.json'
```

## Behaviour

- Missing intermediate directories are created automatically.
- Writes are atomic: the file is written to a temporary path in the same
  directory and renamed into place.
- If the target file already exists, the command fails. Pass `--force` to
  replace.
- Per-attestation variables (`${id}`, `${sha256}`, `${attestor}`,
  `${predicate_type}`, `${short_predicate_type}`) cannot be used in
  aggregate-mode destination paths because no single value exists for the
  batch; the validator rejects such templates up front.

## See also

- [destinations.md](../../reference/destinations.md)
- [sign-with-local-key.md](sign-with-local-key.md)
- [sign-keyless-with-fulcio.md](sign-keyless-with-fulcio.md)
