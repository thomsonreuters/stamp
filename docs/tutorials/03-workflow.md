# Run multiple attestors as a workflow

By the end of this tutorial you will have a YAML workflow that runs the
`git`, `file`, and `command` attestors, bundles their results into a single
collection envelope, and uploads it to Rekor in one operation.

This tutorial assumes you completed
[tutorial 1](./01-first-attestation.md) and
[tutorial 2](./02-signed-and-uploaded.md).

## What you will need

- The `stamp` binary on your `PATH`.
- The same OIDC token setup as tutorial 2: either `--github` inside Actions
  or a token file at `./token`.
- A git repository to attest.
- Some artifact to point the file attestor at. The repository's `README.md`
  works fine as a stand-in.

## Step 1: Discover available attestors

Before authoring YAML, see what is registered.

```sh
stamp list
```

Abbreviated output:

```
NAME              VERSION   DESCRIPTION
git               v1        Git repository metadata
file              v1        File hashes and metadata
command           v1        Captures stdout/stderr of an executed command
github-workflow   v1        GitHub Actions workflow context
...
```

To see the configuration schema for one attestor, name it as a positional
argument:

```sh
stamp list git
```

Abbreviated output:

```
git
  git-working-dir       string   Path to the git repo (default: ".")
  dirty-behavior        string   What to do on a dirty tree: allow|warn|fail
  include-refs          bool     Include refs in the predicate (default: false)
  include-all-remotes   bool     Include all remote URLs (default: false)
  include-tags          bool     Include tags (default: false)
  include-submodules    bool     Include submodules (default: false)
  hash-algorithms       []string Commit-digest algorithms (default: ["sha1","sha256"])
  ...
```

You will use the schema to fill in `config:` blocks below.

## Step 2: Author a workflow YAML

Create `./stamp.yaml` in the repository root.

```yaml
workflows:
  - name: example-release
    output_mode: collection
    failure_policy: fail-fast
    rekor:
      upload: true
      upload_target: collection
    attestors:
      - name: source
        type: git
        config:
          include-all-remotes: true

      - name: artifact
        type: file
        config:
          paths:
            - ./README.md
          hash-algorithms:
            - sha256

      - name: build
        type: command
        config:
          command: "echo 'simulated build'"
          shell: /bin/bash
```

What each top-level field does:

- `output_mode: collection` - emit a single envelope whose predicate wraps the
  per-attestor results, instead of one envelope per attestor.
- `failure_policy: fail-fast` - stop the workflow on the first attestor error.
  The alternative, `continue`, runs the remaining attestors and reports
  failures at the end.
- `rekor.upload: true` - publish to the transparency log.
- `rekor.upload_target: collection` - upload only the collection envelope,
  not the inner ones. (With `output_mode: collection` there are no inner
  envelopes to upload anyway.)

## Step 3: Run the workflow

Point the CLI at the file and run everything in it. The default log level
is `warn`; pass `--log-level info` so you can see the progress messages
reproduced below.

```sh
stamp --config ./stamp.yaml --log-level info run \
  --all \
  --signer fulcio \
  --oidc-token-file ./token
```

Abbreviated output:

```
INFO  loaded 1 workflow(s) from ./stamp.yaml
INFO  starting workflow         name=example-release
INFO  attestor completed        name=source   duration_ms=72
INFO  attestor completed        name=artifact duration_ms=14
INFO  attestor completed        name=build    duration_ms=31
INFO  built collection envelope attestors=3
INFO  uploaded to Rekor         uuid=24296fb2... log_index=1428977
INFO  workflow completed        name=example-release duration_ms=412
```

One signed collection envelope is produced, signed once with one Fulcio
certificate, and uploaded once to Rekor.

## Step 4: Inspect the collection

The collection envelope's payload is an in-toto Statement whose predicate
type is the collection type and whose predicate wraps the per-attestor
attestations.

```sh
COLLECTION=$(ls ./attestations/collection-*.json 2>/dev/null | tail -n 1)
jq -r '.payload' "$COLLECTION" | base64 -d | jq '.predicateType, .predicate.attestations | length'
```

```
"https://github.com/thomsonreuters/stamp/collection/v1"
3
```

List the wrapped attestor names and their predicate types.

```sh
jq -r '.payload' "$COLLECTION" | base64 -d | \
  jq '.predicate.attestations[] | {name, predicate_type}'
```

```json
{ "name": "source",   "predicate_type": "https://github.com/thomsonreuters/stamp/git/v1" }
{ "name": "artifact", "predicate_type": "https://github.com/thomsonreuters/stamp/file/v1" }
{ "name": "build",    "predicate_type": "https://github.com/thomsonreuters/stamp/command/v1" }
```

This is the value of the collection mode: a verifier downloads one envelope,
checks one signature, and gets access to every attestor's output.

## Step 5: Emit both individual and collection envelopes

Sometimes you want the collection *and* the per-attestor envelopes - for
example, so different downstream consumers can subscribe to whichever
predicate type they care about. Change one field in `stamp.yaml`:

```yaml
    output_mode: both
```

Re-run the same command from Step 3. Output now includes per-attestor
envelopes alongside the collection:

```
./attestations/source-2026-05-28T...json
./attestations/artifact-2026-05-28T...json
./attestations/build-2026-05-28T...json
./attestations/collection-2026-05-28T...json
```

Because `rekor.upload_target` is still `collection`, only the collection is
uploaded. Set it to `individual` to upload only the inner envelopes, or
`both` to upload everything. Pick based on how much log volume you want and
what your verifiers expect to fetch.

## Where to next

You now have the pieces to build production attestation pipelines: per-attestor
configuration, workflow orchestration, output shaping, and transparency log
publication.

- Reference - configuration file format
- Reference - the attestor catalog
- Explanation - workflows, output modes, and failure policies
