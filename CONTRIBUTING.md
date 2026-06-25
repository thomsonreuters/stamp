# Contributing

Thanks for your interest in contributing to the attestor. This document covers
the essentials; the detailed guides under
[`docs/how-to/contributing/`](docs/how-to/contributing/) go deeper.

## Getting started

1. Fork and clone the repository.
2. Follow the [development setup guide](docs/how-to/contributing/development-setup.md)
   to install the toolchain and pre-commit hooks.
3. Create a branch for your change off `main`.

## Making changes

- Match the existing style. The
  [coding conventions](docs/how-to/contributing/coding-conventions.md) describe
  the patterns this codebase follows.
- Adding an attestor or predicate? See
  [add a new attestor](docs/how-to/contributing/add-a-new-attestor.md) and
  [add a new predicate](docs/how-to/contributing/add-a-new-predicate.md).
- Keep changes focused. Unrelated refactors belong in their own pull request.

## Before you open a pull request

- `go build ./...` succeeds.
- `go test ./...` passes.
- `golangci-lint run` is clean (or run `pre-commit run --all-files`).
- New source files carry the Apache 2.0 copyright header. The `addlicense`
  pre-commit hook adds it automatically.

## Pull requests

- Describe what changed and why.
- Reference any related issue.
- Ensure CI is green before requesting review.

## Reporting bugs

Open an issue on the repository. For **security vulnerabilities**, do not open a
public issue — follow the process in [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the
[Apache License 2.0](LICENSE).
