# Transparency and verification

A signature proves who signed something. A transparency log proves that
the signature was published — irrevocably, in public, at a particular
point in time. These are different guarantees, and serious supply-chain
verification needs both. This document discusses what Rekor adds to the
trust story, what it does not, and how to think about temporal policy.

## What Rekor is

Rekor is an append-only, cryptographically-verifiable log of signed
software artifacts. Each entry is a structured record (in the framework's
case, a DSSE entry carrying an in-toto envelope and the verifier material
needed to check it). The log is organized as a Merkle tree, and a signed
tree head is published continuously. Once an entry is included and a tree
head incorporating it is published, the entry is part of the public
record forever; the operator cannot remove or alter it without producing a
detectably broken Merkle proof.

The point of Rekor is not to store attestations — they can live anywhere —
but to *witness* them. A Rekor entry says "this exact signed envelope
existed at this exact time, and we have committed to it publicly".

## What transparency gives you

- **Non-repudiation.** A signer who signed something cannot later claim
  they did not. The Rekor entry is on the record, with a timestamp.
- **Public audit.** Anyone can scan the log for entries claiming a given
  identity, and detect signatures made by an identity that shouldn't have
  been signing.
- **Time-witnessing.** The Rekor entry's inclusion time is an upper bound
  on when the signature could have been made. This is what enables
  verification of short-lived certs (see below).

These properties matter most in failure-mode planning. If an attacker
forges a signature, the forgery is either logged (in which case it is
visible, and the affected identity can investigate) or it is not (in
which case a verifier with a strict Rekor policy will reject it). The
attacker cannot choose to forge silently *and* pass strict verification.

## What transparency does not give you

A common over-claim is that Rekor inclusion makes a signature trustworthy.
It does not. Rekor records what was signed; it has no view into whether
the signing was legitimate or whether the predicate's claims are true.

In particular, Rekor does not protect against:

- **A bad signer at the moment of signing.** If an authorized signer
  signs a malicious attestation, the signature is genuine and the Rekor
  entry will record it. The log is doing its job; the failure is in
  signer compromise.
- **Correctness of the predicate's claims.** The git attestor will
  faithfully sign a predicate claiming whatever commit you tell it. The
  signature proves the predicate has not been altered; it does not prove
  the predicate is true.

Both of these are out of scope for any transparency log. They are real
problems, but they belong to detection, policy, and code-review layers, not
to Rekor.

## Inclusion proofs

When Rekor accepts an entry, it returns enough material for a verifier to
recompute the path from the entry to the signed tree head. This is the
inclusion proof: a list of intermediate Merkle hashes that, combined with
the entry's leaf hash, reproduce the root the operator signed.

The practical implication: a verifier who has the Rekor public key and a
recent signed tree head can verify, offline, that any inclusion proof is
genuine. They do not need to trust Rekor at the moment of verification —
they only need to have trusted Rekor enough to obtain the public key once.

The framework verifies inclusion proofs as part of its standard
verification flow when a Rekor reference is available, either because the
envelope was uploaded during attestation or because the verifier supplied
a UUID or log index.

## The DSSE entry kind

Rekor supports several entry kinds (HashedRekord, intoto, DSSE, etc.).
The framework uses the DSSE entry kind for its envelopes. A DSSE entry
records:

- The DSSE envelope itself (payload, type, signatures).
- The verifier material: the public key or certificate chain that should
  be used to check the signatures.

Storing the verifier material in the entry is what makes the entry
self-describing. Anyone who pulls the entry has everything they need to
verify it, without an out-of-band lookup for the public key. This is
especially important for Fulcio-signed envelopes, where the cert that
verifies the signature lives in the entry next to it.

## Temporal policy

Fulcio certificates are deliberately short-lived (minutes). By the time a
human or a periodic verifier looks at one, it is almost always expired.
That is fine — but only if the verifier has independent evidence that the
signing happened *while* the cert was valid. That evidence is the Rekor
inclusion time.

The framework exposes three temporal policies, with the following
semantics:

- `warn` (default) — note a discrepancy between the Rekor inclusion time
  and the cert's validity window, but do not fail verification. This is
  appropriate for inspection, debugging, and migration scenarios.
- `strict` — fail verification if the Rekor entry's witnessed time falls
  outside the cert's `notBefore`/`notAfter`. This is the policy you want
  for production verification of Fulcio-signed material.
- `ignore` — do not check time at all. This effectively trades temporal
  binding for compatibility with environments where the verifier cannot
  reliably obtain Rekor timestamps. Use sparingly.

The default is `warn` because the framework cannot know whether a given
verification context can support strict checking. Operators are expected to
upgrade to `strict` when their pipeline is wired up.

## Why temporal policy matters for Fulcio

To see why temporal binding is load-bearing, imagine the failure mode it
prevents.

An attacker briefly compromises a build agent and triggers Fulcio to
issue a signing cert for a legitimate identity. They use it to sign a
malicious envelope and walk away. The cert expires; the private key is
gone. Months later, the attacker submits the envelope (still signed by the
now-long-expired cert) to a Rekor instance, perhaps a different one, or
they re-upload it after a brief outage on the original. If the verifier's
policy is "the cert was valid at *some* point" without checking whether
Rekor inclusion fell inside that window, the envelope verifies.

Strict temporal policy refuses that envelope: the Rekor inclusion is
months after `notAfter`, so the signing cannot have happened during the
validity window the cert claims, so the signature is not trustworthy
regardless of being cryptographically intact.

This is the same general structure as expiry checking in TLS, with the
twist that the cert is *expected* to be expired at check time and the
witnessed timestamp is what re-validates it.

## Fetch as an audit tool

Rekor is searchable. Given a UUID or a log index, the framework's fetch
operation will retrieve the entry, re-verify the inclusion proof, and
optionally re-verify the envelope against its embedded verifier material.

This is what makes ad-hoc audit feasible. A security responder
investigating a compromise can walk a list of entries claiming a given
identity, fetch each, and check them against their expectations without
needing the original signing infrastructure available. The fetched
material is self-sufficient evidence; it does not depend on anything still
being live other than Rekor itself.

This is also where transparency pays off in practice: it transforms "I
think I know what was signed" into "I can prove what was signed, and
when".
