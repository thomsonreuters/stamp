# Development setup

This guide walks through setting up a local environment to build, test, and
contribute to the attestor. Follow it once when you clone the repository;
afterwards the day-to-day workflow is just `go build`, `go test`, and your
editor.

## Prerequisites

- A Go toolchain matching the version pinned in `go.mod`. Check it with
  `go mod edit -json | jq -r .Go` (or simply open `go.mod`). Newer Go
  releases work as long as the toolchain directive in `go.mod` permits
  them.
- `git`.
- `make` is optional; nothing in the contribution flow strictly requires
  it.
- `golangci-lint` and `pre-commit` if you want the same checks CI runs.

## Clone the repository

```sh
git clone https://github.com/thomsonreuters/stamp.git
cd stamp
```

## Compile everything

```sh
go build ./...
```

A clean build is the fastest signal that your toolchain version is
compatible and that no broken dependencies have crept in. Run this first
after pulling new commits.

## Run the test suite

```sh
go test ./...
```

Most packages have unit tests that run in seconds and do not touch the
network. A few attestors have integration tests that are stricter about
their environment:

- The `ec2` attestor has tests that expect to be able to call the AWS
  instance metadata service. They are designed to skip cleanly when run
  outside EC2, but if you see unexpected timeouts, run just the unit tests
  for that package: `go test ./pkg/attestors/ec2 -run Unit`.
- The `github-workflow` attestor reads environment variables that GitHub
  Actions sets at runtime (`GITHUB_ACTIONS`, `GITHUB_REPOSITORY`, etc.).
  Tests either set these explicitly or skip; running with those variables
  set in your shell can change test behaviour.

If you want to run a single package's tests with verbose output:

```sh
go test -v ./pkg/attestors/git/...
```

## Lint

```sh
golangci-lint run
```

The configuration lives at `.golangci.yml`. The same command runs in CI;
if it passes locally it will pass there.

## Pre-commit hooks

```sh
pre-commit install
```

The configuration lives at `.pre-commit-config.yaml`. After installing the
hook runs lint plus the copyright-header check on every commit. To run all
hooks against the entire tree on demand:

```sh
pre-commit run --all-files
```

If the copyright-header hook fails, the missing header is the Apache-2.0
banner used throughout the project — copy it from any existing source
file.

## Running the CLI from source

The `main` package lives at `./cmd` (the `./cmd/stamp` directory holds
the Cobra command definitions but is not itself a `main` package). Invoke
`go run` against `./cmd` to always run the code in your working tree:

```sh
go run ./cmd --log-level info list
go run ./cmd --log-level info run --attestor git --set git-working-dir=.
go run ./cmd --config ./.ignored/stamp.yaml --log-level info run release
```

When you need a binary on `PATH` (for example to test shell integration),
build one into the project's `bin/` directory rather than into
`$GOPATH/bin`:

```sh
go build -o bin/stamp ./cmd
./bin/stamp list
```

## Scratch files

The repository's `.gitignore` excludes `.ignored/`. Use it for any local
experiments — sample configs, throwaway scripts, captured envelopes. The
top-level `dist/` directory is reserved for GoReleaser output and should
not be edited or committed by hand.

Tests must keep their side effects inside `t.TempDir()` (or an equivalent
test-managed directory). Writing to the repository root or to absolute
paths under `/tmp` makes tests flake under parallel execution and on CI
runners that reuse working directories.

## See also

- [Coding conventions](coding-conventions.md)
