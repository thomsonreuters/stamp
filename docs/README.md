# Documentation

Documentation for STAMP follows the [Diataxis](https://diataxis.fr/)
framework. Each document fits exactly one of four categories. Pick the one
matching your goal.

## Tutorials — learning by doing

Step-by-step lessons that take a newcomer to a successful outcome.

- [Your first signed attestation](tutorials/01-first-attestation.md)
- [Sign with Fulcio and upload to Rekor](tutorials/02-signed-and-uploaded.md)
- [Build a multi-attestor workflow](tutorials/03-workflow.md)

## How-to guides — recipes

Task-focused instructions for users who already know what they want to do.

### CLI

- [Sign with a local private key](how-to/cli/sign-with-local-key.md)
- [Sign keyless with Fulcio and OIDC](how-to/cli/sign-keyless-with-fulcio.md)
- [Upload an existing attestation to Rekor](how-to/cli/upload-to-rekor.md)
- [Verify an attestation](how-to/cli/verify-attestation.md)
- [Fetch a Rekor entry](how-to/cli/fetch-from-rekor.md)
- [Generate signing keys](how-to/cli/generate-keys.md)
- [Redact sensitive data from attestations](how-to/cli/redact-sensitive-data.md)
- [Use path templates for persisted output](how-to/cli/use-path-templates.md)

### Go library

- [Embed attestor in a Go application](how-to/library/embed-in-a-go-app.md)
- [Work with collection envelopes programmatically](how-to/library/work-with-collection-envelopes.md)

### Contributing

- [Coding conventions](how-to/contributing/coding-conventions.md)
- [Set up a development environment](how-to/contributing/development-setup.md)
- [Add a new attestor](how-to/contributing/add-a-new-attestor.md)
- [Add a new predicate type](how-to/contributing/add-a-new-predicate.md)

## Reference — the dictionary

Information-oriented lookup. No narrative — facts only. Drift-prone details
(every flag, every default) live in the tool itself; use `attestor <cmd> --help`
and `stamp list --show-config` to enumerate those.

- [CLI commands](reference/cli.md)
- [Configuration](reference/configuration.md)
- [Attestors](reference/attestors.md)
- [Predicates](reference/predicates.md)
- [Signers](reference/signing.md)
- [Destinations](reference/destinations.md)
- [Transparency (Rekor)](reference/transparency.md)
- [Go library API](reference/library-api.md)

## Explanation — discussions and concepts

Understanding-oriented reading. The "why" behind the design.

- [Architecture](explanation/architecture.md)
- [The attestation model: in-toto, DSSE, statements, envelopes](explanation/attestation-model.md)
- [Workflows, output modes, and failure policies](explanation/workflows.md)
- [Signing and trust](explanation/signing-and-trust.md)
- [Transparency and verification](explanation/transparency-and-verification.md)
- [Build environment detection](explanation/build-environment.md)
- [Security considerations](explanation/security-considerations.md)
