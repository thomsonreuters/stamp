# Security considerations

This document discusses the security properties the framework provides,
the ones it does not, and the operational pitfalls that show up in
practice. It is aimed at integrators planning a verification policy and at
operators running the framework in CI/CD.

The framing throughout is "what does a signed attestation actually
prove?". Confusion on that question is the source of most attestation
mistakes, so it is worth getting right before anything else.

## What an attestation proves

A signed in-toto attestation proves exactly two things:

1. **Cryptographic integrity.** The predicate has not been altered since
   it was signed. The DSSE envelope's signature covers the
   pre-authentication encoding of the payload; any change to the payload
   bytes invalidates the signature.
2. **Identity binding at sign-time.** The signature was produced by the
   holder of a specific private key, or — for Fulcio-signed material —
   by a workload that authenticated to an OIDC IdP as a specific identity
   during a specific short window.

That is the entirety of the cryptographic claim. Anything beyond it is
inference, not proof.

## What an attestation does not prove

An attestation says nothing about whether the predicate's claims are
*true*. The git attestor will faithfully sign a predicate claiming that
the working tree is clean and the commit is X, regardless of whether the
working tree was clean or the commit was X. If you tell the framework to
attest a lie, it will sign your lie with the same fidelity it would sign
the truth. The signer is responsible for the contents of what it signs;
the framework does not validate the predicate against any external
ground-truth.

This is not a flaw to be patched. It is the same property every signing
system has, and the reason verification systems pair attestation
checking with code review, build reproducibility, source pinning, and
runtime policy. Garbage in, signed garbage out, is the cost of having a
neutral signing layer.

## Trust boundaries

A complete verification story requires trusting several things outside
the attestation itself.

- **The signer's identity provider.** Either the holder of the long-lived
  signing key (for file-based signing) or the OIDC IdP that authenticated
  the workload (for Fulcio). Compromise here forges legitimate-looking
  signatures.
- **The Rekor operator** (when verifying inclusion proofs). The operator
  is trusted not to issue inclusion proofs for entries that were never
  actually included. Running your own Rekor instance moves this trust
  inside your organization at the cost of operating it.
- **The TLS chain to Fulcio and Rekor.** When the verifier fetches roots,
  certificates, or proofs over the network, the path is trusted to deliver
  what the legitimate operators published. Pinning the relevant root
  material out-of-band reduces dependency on the live TLS chain.

These are the conventional trust roots of a sigstore-style system. They
are explicit on purpose — making them opaque would be the failure mode.

## Secret hygiene

A framework that emits structured records is a framework that can leak
secrets in those records. The framework takes some precautions, but they
are not exhaustive and integrator caution remains essential.

The command and github-workflow attestors include default redaction
patterns for common secret-shaped values (API keys, tokens, well-known
environment variable names). These patterns catch the common cases but
not all cases. A user-supplied secret with an unusual name will not be
redacted; an inline secret embedded in a command argument will be captured
verbatim unless the user adds a pattern.

By convention, the logger does not print secrets at any level the
framework controls. User-supplied configuration that names secret values
directly is the exception — anything you pass in is fair game for being
written to the configured destinations.

For pipelines that pipe framework output into other tools, the `--quiet`
and `--log-only` flags control what reaches stdout. Use them when the
calling pipeline is reading the framework's stdout as data; otherwise
informational logging can poison the consumer.

## Untrusted inputs

Two attestors interact with potentially untrusted input in ways worth
discussing explicitly.

**The file attestor** validates paths against a configured base path
before reading them. Symlinks, path traversal (`..`), and absolute paths
that escape the base are rejected. This is intended to prevent an
attacker who controls the *path list* from reading arbitrary parts of the
filesystem. It is not intended to defend against an attacker who controls
the *base path itself* — that is a configuration-level trust decision.

**The command attestor** has two execution modes with different security
properties.

- `direct` — the command is executed without a shell. Arguments are
  passed as an argv vector; no interpretation, no metacharacters, no
  injection. This is the safe default.
- `shell` — the command is executed through a shell. This is what enables
  pipelines, redirection, and variable expansion. It also accepts shell
  injection. Use `shell` only when you control the entire command string.

The distinction matters in CI contexts where part of a command line might
come from a variable that itself comes from user-influenced input (a PR
title, a branch name, a tag). Under `direct`, that input is data; under
`shell`, it might be code.

## Replay and freshness

A signed envelope is a static artifact. Nothing about the envelope itself
prevents it from being replayed — copied verbatim and presented later as
fresh evidence. Mitigation comes from two places.

- **Rekor inclusion** binds the envelope to a witnessed time. A verifier
  that requires a Rekor entry will reject a replayed envelope unless the
  attacker also submitted it to Rekor at signing time. (And if they did,
  the entry is on the public record, which limits how stealthily it can
  be reused.)
- **Temporal policy** binds the witnessed Rekor time to the cert validity
  window when verifying Fulcio material. This is what closes the
  long-after-expiry replay window. See *transparency-and-verification.md*
  for the policy options.

A reasonable production policy: treat the absence of a Rekor entry as
suspicious for any artifact you are going to ship. The framework does not
enforce this — it is a verifier-side choice — but it is the right default
for high-value pipelines.

## Operational guidance

A short list of things that go wrong in practice.

- **Do not ship key or certificate material in artifacts.** `.key`,
  `.pem`, and `.pub` files have a way of ending up in archives, container
  images, and SDist tarballs. Audit artifacts before publication.
- **Pin the Fulcio and Rekor URLs in workflow configurations.** Defaults
  are convenient but they change. A pinned URL is reproducible and
  reviewable; an unpinned one is whatever the framework's default was on
  the day the build ran.
- **Audit Rekor periodically for entries against your identities.** A
  signature you did not make, made under your identity, is the signal
  that something has gone wrong upstream. The cost of looking is low; the
  cost of not looking can be very high.
- **Pin the framework version itself.** A signed attestation produced by
  a known build of the framework is auditable against the source of that
  build; one produced by "whatever was on PATH" is not.
- **Treat the workflow file as part of the supply chain.** A change to
  the workflow file is a change to what gets attested. Code review your
  workflows with the same care you give your build scripts.

None of these are unique to this framework. They are the standard
practices for systems that emit signed evidence, applied to the specifics
of how this framework emits it.
