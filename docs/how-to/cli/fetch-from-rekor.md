# Fetch an Entry from Rekor

Retrieve a Rekor entry by file hash, UUID, or log index.

## Prerequisites

- Network reachability to the Rekor server (default `https://rekor.sigstore.dev`; override with `--rekor-url`).
- One of: a local attestation file, an entry UUID, or a log index. The three are mutually exclusive.

## Recipes

### By attestation file

The SHA-256 of the serialized DSSE envelope (the same hash Rekor indexes
the entry by) is computed from the file's contents and used to look up the
matching entry:

```bash
stamp fetch --file ./attestation.json
```

### By UUID

```bash
stamp fetch --uuid 5b40a1363fa79794676e15895eac2f3ff881d4337ee6fe1b6817a05709d12a1c
```

### By log index

```bash
stamp fetch --log-index 12345
```

## Useful options

- `--raw` returns the unmodified Rekor API response. Use this when feeding the result to other tooling that expects the wire-format payload.
- `--output ./entry.json` writes the result to a file. Output is also emitted to stdout.
- `--rekor-url <url>` targets a non-default Rekor server.

## See also

- [verify-attestation.md](verify-attestation.md)
- [upload-to-rekor.md](upload-to-rekor.md)
- `../../reference/transparency.md`
