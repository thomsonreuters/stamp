# The attestation model

This document discusses the data model the framework produces: in-toto
Statements wrapped in DSSE envelopes. The goal is to give you a mental
picture clear enough that you can read any signed output the framework
emits and understand what it is asserting and how it is protected.

## Why a layered model

A signed attestation has two distinct jobs. It must say something specific
about the world ("this git commit was produced from this working tree"),
and it must be cryptographically protected so a verifier can decide whether
to believe it. These concerns are kept in separate layers on purpose.

- The **statement** is the meaning.
- The **envelope** is the protection.

Mixing them would make either harder to evolve. New predicate types appear
all the time; new signing schemes appear far less often. The split lets the
two move on independent schedules, which is exactly the structure in-toto
and DSSE settled on.

## The in-toto Statement (v1)

An in-toto Statement has four fields:

```
{
  "_type":         "https://in-toto.io/Statement/v1",
  "subject":       [ { "name": "...", "digest": { "sha256": "..." } }, ... ],
  "predicateType": "https://github.com/thomsonreuters/stamp/git/v1",
  "predicate":     { /* typed body */ }
}
```

- `_type` identifies the statement schema itself. Today this is always the
  in-toto v1 Statement URI.
- `subject` is the list of things the statement is about. A subject is a
  human-meaningful name and a content-addressable digest. The digest is a
  map keyed by algorithm name (`sha256`, `sha512`, etc.) so the same
  subject can carry multiple hashes if needed.
- `predicateType` is the URI naming the schema of `predicate`. Verifiers
  use this to route the statement to a typed parser.
- `predicate` is the typed body — the actual claim being made.

This is a deliberately small surface. Everything that says "what kind of
fact is this" lives in the URI; everything that says "what are the facts"
lives in the predicate body. The framework follows that discipline: each
attestor has exactly one predicate URI, and the URI changes when the schema
changes incompatibly.

## Subjects, and why they matter

The subject list is the most important and most underappreciated part of an
attestation. It is what binds the predicate to specific artifacts. Without
subjects, a signed attestation would say "something with this property
exists" — useful for nothing. With subjects, it says "*this artifact*, named
this way and hashing to these values, has this property".

This is also where verification ultimately grounds out. To trust an
attestation about a binary, a verifier hashes the binary it has in hand and
checks that the digest appears in the subject list. The signature proves
the attestation has not been tampered with; the subject digest proves the
attestation is about the artifact in front of you.

Digests are expressed as a map of algorithm to lowercase hex string. The
map shape exists so a subject can carry both a modern hash (sha256) and an
older or stronger one without versioning the schema.

## Predicates and their URIs

A predicate is a typed body. The framework defines predicates for git
state, file metadata, command execution, GitHub workflow context, EC2
instance metadata, JWT contents, SLSA provenance, and a collection wrapper
that bundles others.

Predicate URIs include a version path component, by convention `/v1`. A
breaking change to a predicate's shape requires a new URI (a `/v2`); an
additive change does not. This is the same versioning discipline you would
apply to a public REST schema, and it serves the same purpose: a verifier
that understands `/v1` should always be able to parse a `/v1` predicate,
forever.

A nice consequence of the URI-as-type model is that more than one attestor
can produce the same predicate type. The registry indexes by URI, so two
attestors that legitimately produce, say, SLSA provenance can coexist; a
workflow picks one (or both, into separate envelopes) by configuration.

## The DSSE envelope

A signed statement is not signed directly. It is wrapped in a DSSE envelope,
which looks like this:

```
{
  "payload":     "<base64( statement JSON )>",
  "payloadType": "application/vnd.in-toto+json",
  "signatures": [
    {
      "keyid": "<fingerprint>",
      "sig":   "<base64( signature )>"
    },
    ...
  ]
}
```

`payload` is the original statement JSON, base64-encoded. `payloadType`
declares what the bytes inside `payload` are; for in-toto statements it is
`application/vnd.in-toto+json`. `signatures` is a list because DSSE
permits multiple signers over the same payload.

## Why DSSE instead of signing the JSON directly

Signing JSON directly is a classic foot-gun. JSON has multiple equivalent
serializations of the same data (whitespace, key order, number formatting),
which means two parties can "have the same statement" and disagree on what
bytes to sign. The naive workaround — canonical JSON — has its own problems
(no widely-deployed canonicalization, subtle Unicode pitfalls).

DSSE sidesteps the issue entirely. It treats the payload as an opaque byte
string and signs a deterministic encoding of that byte string together with
its declared type. The verifier reconstructs the exact same byte string from
the envelope and verifies against it. No canonical JSON, no key-ordering
arguments, no Unicode surprises.

## The Pre-Authentication Encoding (PAE)

The bytes actually fed to the signer are not the payload by itself. DSSE
defines a Pre-Authentication Encoding that mixes in the payload type:

```
PAE = "DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload
```

`SP` is a literal ASCII space; `LEN(x)` is the byte length of `x` rendered
in decimal ASCII. Both lengths and both bodies are concatenated in this
strict, length-prefixed form.

The reason for the length prefixing is to defeat type confusion. Without
it, a signature over `("application/vnd.in-toto+json", <some json>)` could
plausibly be replayed against `("application/json", <other bytes>)` if an
attacker could find a collision in the concatenation. Length-prefixing makes
the encoding unambiguously parseable, so the signed material commits to both
the type and the payload as distinct fields.

The practical implication for you, the integrator: you cannot verify a
signature by hashing the payload alone. You must reconstruct the PAE from
the envelope and verify against that.

## A worked example: a git attestation

Suppose the git attestor runs against a working tree at commit
`abc123…`. Conceptually, here is what each layer holds.

The predicate (truncated):

```json
{
  "commit": {
    "sha": "abc123def456…",
    "author": { "name": "...", "email": "..." },
    "message": "...",
    "tree": "789…"
  },
  "status": { "clean": true },
  "remotes": [ ... ]
}
```

The statement that wraps it:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "git+ssh://example.com/repo.git",
      "digest": { "sha1": "abc123def456…" } }
  ],
  "predicateType": "https://github.com/thomsonreuters/stamp/git/v1",
  "predicate": { ... the predicate above ... }
}
```

The DSSE envelope that signs it:

```json
{
  "payload":     "eyJfdHlwZSI6...",      // base64 of the statement JSON
  "payloadType": "application/vnd.in-toto+json",
  "signatures": [
    { "keyid": "a1b2c3...",              // sha256 of the signer's PKIX DER
      "sig":   "MEUCIQDk..." }           // base64 of the raw signature
  ]
}
```

To verify, a consumer base64-decodes `payload`, reconstructs the PAE using
the declared `payloadType`, looks up the signer's public key by `keyid`,
and verifies the signature against the PAE bytes. Only then are the
contents of `payload` parsed as a statement, the `predicateType` URI
checked, and the predicate examined.

## Further reading

- in-toto Attestation Framework: <https://github.com/in-toto/attestation>
- DSSE specification: <https://github.com/secure-systems-lab/dsse>
- SLSA Provenance v1: <https://slsa.dev/spec/v1.0/provenance>
