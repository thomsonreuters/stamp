# Verification Test Fixtures

This directory holds pre-signed sigstore Bundle v0.3 fixtures for verifier
tests. After the C3 sigstore-go migration, the verifier operates on Bundle
v0.3 JSON (produced by `sigstore-go/pkg/sign.Bundle`) rather than raw DSSE
envelopes.

## Regenerating fixtures

Fixtures should be generated once against public sigstore and checked in,
mirroring the container-sign test pattern in
`pkg/signing/container/testdata/`.

Steps (network + OIDC required — cannot run in offline CI):

```bash
# 1. Sign against public sigstore
stamp attest --attestor git \
    --signer fulcio \
    --fulcio-url https://fulcio.sigstore.dev \
    --rekor \
    --rekor-url https://rekor.sigstore.dev \
    > testdata/git.sigstore.json

# 2. Same for a negative case with a tampered signature
python3 -c 'import json,sys; b = json.load(open("testdata/git.sigstore.json")); \
   b["dsseEnvelope"]["signatures"][0]["sig"]="AAAAAA=="; \
   json.dump(b, open("testdata/git-bad-signature.sigstore.json","w"))'
```

## Current state (C3)

Fixtures are pending regeneration. The current verifier test suite (see
`../verifier_test.go`) is table-driven and exercises the option-building
code path with stub inputs; end-to-end bundle verification tests will
follow once the OIDC-issuing runner is wired into CI.
