# STAMP

A streamlined attestation framework for generating, signing, and uploading
[in-toto](https://github.com/in-toto/attestation) attestations as part of a
software supply chain.

STAMP collects evidence from your build (git state, file hashes, command
output, CI context, EC2 metadata, JWT/OIDC tokens, SBOMs, Go build provenance),
packages it as a signed in-toto statement, and optionally uploads it to a Rekor
transparency log so downstream consumers can verify what was built, where, and
how.

## Features

- **Multiple attestor types** out of the box: git, file, command, github-workflow,
  go-builder (SLSA v1 provenance), ec2, jwt, sbom.
- **Pluggable signing** — local key files or keyless via Sigstore Fulcio,
  with OIDC tokens sourced from GitHub Actions, SPIRE, or a token file.
- **Workflows** — declare reusable attestation pipelines in YAML and run them
  by name, by tag, or by glob pattern.
- **Collection envelopes** bundle multiple attestations into a single signed
  statement with aggregated subjects.
- **Rekor integration** for upload, fetch, and verify against a transparency log.
- **Use it as a CLI or a Go library** — the `pkg/operations` API is a stable
  surface for embedding attestation generation inside other tools.

## Install

### Binary release

Download the appropriate binary for your platform from the releases page.

### From source

```bash
git clone https://github.com/thomsonreuters/stamp.git
cd stamp
go build -o stamp ./cmd
```

The build produces a single binary named `stamp`. Move it onto your
`PATH`.

## Quickstart

Generate a signed attestation of the current git repository state using a
local key:

```bash
# 1. Generate a signing key (one-time setup)
stamp generate-key --type ecdsa --output ./signing

# 2. Produce a signed git attestation, persisted to disk
stamp run \
    --attestor git \
    --signer key \
    --private-key ./signing.key \
    --persist \
    --template './attestations/${attestor}-${timestamp}.json'
```

The result is a signed in-toto DSSE envelope on stdout and on disk, containing
the commit hash, repository state, and a SHA256-rooted subject.

To upload to a transparency log:

```bash
stamp run \
    --attestor git \
    --signer fulcio --github \
    --rekor --rekor-upload individual
```

Verify any attestation:

```bash
stamp verify ./attestations/git-*.json --rekor
```

For a full walkthrough, start with the [first-attestation
tutorial](docs/tutorials/01-first-attestation.md).

## Documentation

Documentation follows the [Diataxis](https://diataxis.fr/) framework. Pick the
quadrant that matches what you're trying to do:

| You want to ...                                         | Read ...                         |
| ------------------------------------------------------- | -------------------------------- |
| **Learn the tool** by following a worked example        | [Tutorials](docs/tutorials/)     |
| **Solve a specific problem** (sign with X, upload to Y) | [How-to guides](docs/how-to/)    |
| **Look up** a flag, config key, attestor, or API        | [Reference](docs/reference/)     |
| **Understand** how the framework is put together        | [Explanation](docs/explanation/) |

The top-level [docs landing page](docs/README.md) has the full index.

## Status & support

STAMP is developed by Thomson Reuters and licensed under Apache 2.0.

- Source: this repository
- Issues / bug reports: open an issue on the repository
- Coding conventions and contributor guide:
  [`docs/how-to/contributing/`](docs/how-to/contributing/)

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to set
up your environment, the expected workflow, and the checks to run before opening
a pull request.

## Security

To report a security vulnerability, follow the process in
[SECURITY.md](SECURITY.md). Please do not open public issues for security
problems.

## License

Apache License 2.0. See [LICENSE](LICENSE) and the copyright headers in
individual source files.
