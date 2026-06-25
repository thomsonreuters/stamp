# Signing and trust

A signature is only as useful as the trust story behind the key that made
it. This document discusses the two signing modes the framework supports,
what each one anchors trust on, and the failure modes you should plan
around.

## Two signing modes

The framework supports two ways to sign an envelope.

- **File-based key signing.** A long-lived private key (typically PKCS#8
  PEM, with or without a passphrase) lives on disk or in a secret manager.
  Verifiers hold the matching public key and check signatures against it.
- **Fulcio keyless signing.** A short-lived signing certificate is issued
  by a Fulcio certificate authority on demand, in exchange for proof of an
  OIDC identity. The certificate binds an ephemeral keypair to that
  identity for a few minutes; the keypair signs the envelope and is then
  discarded.

These are not interchangeable. They make different tradeoffs about what
must be true for a signature to be trustworthy, and what fails when an
attacker compromises something.

## Trust anchors

For **key signing**, the trust anchor is the public key the verifier has
out of band. Whoever holds the matching private key can sign anything they
like, and the verifier has no way to know who did the signing or when —
only that someone holding *that* private key did it. This makes key
provenance an operational problem: the verifier must obtain the right
public key through a channel they already trust, and they must rotate it
when the private key is compromised.

For **Fulcio**, the trust anchor is the Fulcio root certificate. A
verifier who trusts Fulcio's root can validate the per-signature
certificate, read its Subject Alternative Name to learn which OIDC identity
was authenticated at sign time, and then decide whether *that identity* was
allowed to sign this artifact. The signing key itself is irrelevant — it
existed for minutes, signed once, and is gone. Trust collapses onto the
combination of "did Fulcio issue this cert" and "did the OIDC IdP assert
this identity".

The contrast is the point. With key signing, you trust the key. With
Fulcio, you trust the identity behind the key, and the key is incidental.

## Why keyless signing matters for CI/CD

A traditional CI signing setup requires a long-lived signing key to be
present at build time. That key is a secret, and secrets in CI have all
the usual failure modes: they leak to logs, they end up in container
images, they survive in artifact stores, and rotating them across a fleet
of pipelines is painful enough that it rarely happens promptly.

Keyless signing eliminates the key from the steady-state. There is no
secret to rotate, no secret to leak, no secret to extract from a
compromised build. The OIDC token that authorizes the cert issuance is
short-lived and bound to a specific build context; the cert itself
expires in minutes; the private key is generated in memory and never
persisted. Compromise of the build agent at any moment in time only buys
the attacker the ability to sign while the build is running.

This is a structural improvement, not just a convenience. It changes the
class of failures you have to defend against.

## OIDC token sources

The framework supports three sources of OIDC identity for Fulcio.

- **GitHub Actions** — the workflow's built-in OIDC token, asserting the
  repository, ref, workflow file path, and run identifiers.
- **SPIRE** — a SPIFFE-issued identity, asserting the workload identity
  established by the SPIRE control plane.
- **Manual token** — an OIDC token obtained out-of-band and passed in.
  This is the escape hatch for environments the framework does not natively
  understand.

Each source asserts a different *kind* of identity. A GitHub token says
"this run, in this repo, on this ref, triggered this way". A SPIRE token
says "this workload, with this SPIFFE ID, in this trust domain". A manual
token says whatever its issuer chose to say. The verifier must understand
which claim is meaningful for its policy: pinning to a SPIFFE ID does not
defend against a malicious GitHub workflow, and vice versa.

## Key fingerprints and KeyIDs

The framework computes key fingerprints as the SHA-256 of the PKIX DER
encoding of the public key, rendered as lowercase hex. This is the value
placed in the DSSE envelope's `keyid` field.

A fingerprint is not strictly required by DSSE — `keyid` is opaque — but a
deterministic, key-derived value is what makes verification tractable. A
verifier that has a public key in hand can compute the same fingerprint
and find the corresponding signature in the envelope without trial-and-
error. The choice of SHA-256 over PKIX DER is just the closest thing to a
universal convention in the ecosystem.

## What is actually signed

A common confusion: the signature does not cover the statement JSON
directly. It covers the DSSE Pre-Authentication Encoding (PAE) of the
payload and its declared type. This matters for two reasons. First,
attempts to verify the signature by hashing the raw payload will always
fail; you must reconstruct the PAE. Second, the PAE binds the payload type
into the signed material, which is what prevents a signature over an
in-toto statement from being replayed against a different `payloadType`.
The full mechanics are discussed in *attestation-model.md*.

## Failure modes

No signing scheme is perfect. Different things go wrong for different
schemes, and it is worth being explicit about them.

**Expired Fulcio certificate at verification time.** A Fulcio cert is
valid for minutes. By the time a verifier looks at it, the cert is almost
certainly expired. This is fine, *if* the verifier has independent
evidence that the signature was made while the cert was still valid. That
evidence is the Rekor inclusion proof, combined with a temporal policy
that requires the Rekor entry's witnessed timestamp to fall within the
cert's `notBefore`/`notAfter` window. Without that binding, expired certs
are useless. With it, expired certs are unproblematic, because the
combination of cert + Rekor proof attests that the signing happened during
the validity window. See *transparency-and-verification.md* for the
temporal policy options.

**Compromised private key (file signing).** If the long-lived private key
leaks, every past and future signature made with it is suspect. You cannot
distinguish legitimate signatures made before the leak from forged ones
made after, because they are signed by the same key in the same way. The
mitigation is to revoke the public key (i.e., update verifiers to no
longer trust it) and re-attest the artifacts that should still be trusted
with a new key. This is the same blast radius problem that motivates
keyless signing in the first place.

**Compromised OIDC identity provider (Fulcio).** A compromised IdP can
mint identities of its choosing, which Fulcio will then bind to certs,
which can then sign envelopes that look perfectly legitimate. The blast
radius is wider than a single private key — it is every identity the IdP
can mint — but the damage is bounded in time, because the IdP compromise
will be detected and ended, and Rekor's inclusion times let you tell
which entries fell inside the bad window.

These are not equivalent. A leaked private key is worse than a brief IdP
compromise for the *specific* identities affected (every signature is
forever in doubt), but better than a sustained IdP compromise for the
*scope* of affected identities (one identity vs. all of them).

## Why we do not support legacy encrypted PEM

OpenSSL's traditional encrypted PEM format (RFC 1423, with `Proc-Type:
4,ENCRYPTED` and a `DEK-Info` header) uses a key derivation that has been
known-weak for a long time: a single MD5 round over the passphrase and
8-byte IV. Modern tooling has migrated to PKCS#8 encrypted private keys,
which use proper KDFs (PBKDF2, scrypt, etc.) with iteration counts and
salts.

The framework deliberately does not accept the legacy format. Supporting
it would silently permit weak-passphrase keys to be the trust anchor of
production attestations. PKCS#8 (with or without encryption) is the only
input format for file-based signing keys, and the framework will produce a
clear error rather than load a legacy-format file.
