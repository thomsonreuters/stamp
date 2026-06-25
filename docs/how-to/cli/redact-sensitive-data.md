# Redact Sensitive Data from Attestations

Prevent secrets, tokens, and sensitive identifiers from being captured into
attestation evidence.

## Prerequisites

- Know which attestor(s) produce the data you want to redact. Redaction is
  configured per attestor; there is no global redaction policy.

## How redaction works

Redaction does not strip values silently. Each attestor replaces matched
content with the literal string `[REDACTED]` so a verifier can see that a
value was present and was redacted. Two mechanisms are used:

- **Regex patterns** (command, github-workflow event payload) scan free-form
  text and replace matches.
- **Field paths** (git, ec2, github-workflow, jwt) target specific dotted
  paths inside the structured predicate.

Per-attestor configuration lives under `workflows[].attestors[].config` in
the YAML config file, or is passed via `--set key=value` on the CLI.

## Recipes by attestor

### Command attestor

Captured stdout, stderr, and the recorded command line are scanned against
a regex list. Four built-in patterns are always applied (you cannot disable
them):

- `password=[\S]+`
- `token=[\S]+`
- `api[_-]?key=[\S]+`
- `secret=[\S]+`

Add your own via `redact_patterns` (note: `command` uses snake_case keys).
They are appended to the defaults, not replaced.

```yaml
workflows:
  - name: ci
    attestors:
      - name: build
        type: command
        config:
          command: ./build.sh
          capture_stdout: true
          capture_stderr: true
          redact_patterns:
            - '(?i)customer[-_]id[=:]\s*\S+'
            - 'Bearer\s+[A-Za-z0-9\._\-]+'
```

If you don't need the output at all, skip capture entirely:

```yaml
config:
  capture_stdout: false
  capture_stderr: false
```

Dangerous catch-all patterns (`.*`, `.+`, `^.*$`, `[\s\S]*`) are rejected at
validation time.

### GitHub Workflow attestor

The github-workflow attestor enforces a set of built-in env-var exclusions
that you cannot weaken:

- `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*API_KEY*`, `*ACCESS_KEY*`,
  `*PRIVATE_KEY*`, `*CREDENTIALS*`, `ACTIONS_ID_TOKEN*`,
  `ACTIONS_RUNTIME*`, `*_SIGNING_KEY*`, `*AUTH*TOKEN*`.

On top of those:

- `env-include-patterns` (default `["GITHUB_*","RUNNER_*","CI","ACTIONS_*"]`)
  is the allow-list of env-var name globs included in the predicate.
- `env-exclude-patterns` (default
  `["*TOKEN*","*SECRET*","*PASSWORD*","*KEY*","*CREDENTIAL*","GITHUB_TOKEN","GH_TOKEN"]`)
  is the deny-list applied after the allow-list. Excludes always take
  precedence.
- `redact-event-payload: true` enables regex redaction inside the webhook
  event JSON while preserving JSON structure. Patterns come from
  `redact-patterns`.
- `redact-actor: true` is a shortcut that redacts `trigger.actor` and
  `trigger.actor_id`.
- `sensitive-fields` accepts dotted paths inside the predicate (for
  example, `actor`, `repository.owner`, `trigger.event_payload.head_commit.author.email`).

A small set of critical fields cannot be redacted by `sensitive-fields`:
`workflow.run_id`, `run_id`, `repository.sha`, `metadata.started_on`.

### Git attestor

- `redact-identity: true` replaces author and committer name/email with
  `[REDACTED]`. Timestamps are preserved.
- `sensitive-fields` adds further field-level redactions. Recognised paths
  include `author.name`, `author.email`, `committer.name`, `committer.email`,
  `commit.message`, `commit.signature`, `repository.url`, `remotes`, `refs`,
  `tags`, `submodules`.

### EC2 attestor

- `redact-account-id: true` redacts the AWS account ID.
- `redact-private-ips: true` redacts RFC 1918 addresses.
- `sensitive-fields` accepts additional dotted paths in the EC2 predicate
  (for example, `network.publicIpv4`, `network.macAddress`, `tags`,
  `iam.instanceProfile`).

### JWT attestor

- `jwt-claims-denylist` drops named custom claims from the predicate
  entirely.
- `jwt-redact-claims` keeps the claim keys but replaces their values with a
  placeholder. Use this when downstream consumers need to know a claim was
  present without seeing its value.
- Standard registered claims (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`,
  `jti`) are always included regardless of allow/deny filters.

## Verify before shipping

Run with `--log-level info` (or `--debug`) and inspect the produced
envelope locally before publishing or signing in production. The framework's
own logs never include the secret values it is asked to redact, but your
configuration is responsible for keeping sensitive content out of the
predicate itself.

## See also

- `../../reference/attestors.md`
- `../../explanation/security-considerations.md`
