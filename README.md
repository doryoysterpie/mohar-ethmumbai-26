# Mohar

> **SIMULATED.** Every issuer, credential and certificate in this repository is simulated test data. No real issuing body is connected.

Mohar records that a school verified a teacher's eligibility credential, and makes that record checkable later by anyone holding the export bundle.

## Run

Requires Node 22 or later.

```
npm ci
npm test
```

## Issuer (SIMULATED)

The issuer signs eligibility credentials as SD-JWT VCs with Ed25519, identifies itself with did:web, and publishes a one-bit status list. Every certificate field is a separate disclosure. Fixture certificates in `fixtures/certificates/` describe invented people.

```
node bin/issuer.mjs keygen                                   # key in .keys/ (not tracked); writes site/did.json
node bin/issuer.mjs publish                                  # writes site/status/tet-eligibility.jwt from fixtures/issuance.json
node bin/issuer.mjs issue fixtures/certificates/teacher-a.json <holder did:key>
```

A status check returns `not_revoked`, `revoked` or `unknown`. `unknown` covers a list that cannot be fetched, is not signed by the credential's issuer, or was published for another address.

## Log

The log service accepts only `{ entry_type, commitment }`, where `entry_type` is `consent`, `presentation`, `receipt` or `recheck` and `commitment` is a SHA-256 hex string. Each entry is chained: `entry_hash = SHA-256(prev_hash || entry_type || commitment || ts)`, with `prev_hash` of the first entry set to 64 zeros. Committing the same type and commitment again returns the existing entry. The store keeps a head checkpoint (the sequence number and hash of the last entry appended) and refuses to append when the stored tail does not match it or a closed batch ends after it. Before closing or anchoring a batch, the service re-checks the whole chain, the checkpoint and every closed batch root, and refuses if any of them is wrong.

A batch closes over every waiting entry. Its root is a Merkle tree over the entries: leaves are `SHA-256(0x00 || entry_hash)`, inner nodes `SHA-256(0x01 || left || right)`, and the tree is padded to a power of two with `SHA-256(0x02)`, which no entry can produce. The root is anchored twice:

- Ethereum Sepolia: a zero-value transaction from the operator address to itself whose calldata is the 32-byte root. The transaction is signed once and sent to each configured RPC in turn.
- Bitcoin, through OpenTimestamps: the root is stamped on the public calendars. The proof reads `pending` until a calendar returns a Bitcoin block header attestation, then `complete` with that block height. Checking the attestation against Bitcoin is the verifier's job.

The two anchors are reported separately. If one fails, the batch stays closed, the failure is recorded on it, and `anchor` retries.

```
node --env-file=.env bin/log.mjs serve     # PORT (default 8081), batch every MOHAR_BATCH_SECONDS (default 3600)
node --env-file=.env bin/log.mjs batch     # close and anchor a batch now
node --env-file=.env bin/log.mjs anchor    # anchor batches still missing an anchor
node --env-file=.env bin/log.mjs upgrade   # ask the calendars for Bitcoin attestations
node bin/log.mjs check                     # re-check chain, head checkpoint and batch roots
node --env-file=.env bin/log.mjs check --anchors   # also compare each stored root with its Sepolia calldata
```

`.env` (not tracked) holds `MOHAR_SEPOLIA_KEY` (operator key, `0x…`), `MOHAR_SEPOLIA_RPCS` (comma-separated), and `MOHAR_ADMIN_TOKEN`. Set `MOHAR_OTS=off` to skip OpenTimestamps.

| Method | Path | Result |
|---|---|---|
| POST | `/commit` | 201 new entry, 200 existing entry, 400 for anything that is not exactly `{ entry_type, commitment }` |
| GET | `/proof/{commitment}` | the entry, its Merkle path and its batch with both anchors; no batch while the batch is open; `?entry_type=` chooses when the same commitment is logged under several types (409 otherwise) |
| GET | `/batches/{id}` | batch summary |
| POST | `/batch`, `/upgrade` | operator token (`authorization: Bearer <MOHAR_ADMIN_TOKEN>`); off when the token is not set |

## Licence

Apache-2.0. See `LICENSE`.
