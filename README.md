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

The issuer signs eligibility credentials as SD-JWT VCs with Ed25519, identifies itself with did:web, and publishes a one-bit status list. Every certificate field is a separate disclosure. The credential also carries `certificate_commitment = SHA-256("mohar/cert/v1" || certificate_salt || canonical certificate JSON)` and the 32-byte random `certificate_salt`, both selectively disclosable; without the salt the commitment cannot be recomputed from the certificate. Fixture certificates in `fixtures/certificates/` describe invented people.

```
node bin/issuer.mjs keygen                                   # key in .keys/ (not tracked); writes site/did.json
node bin/issuer.mjs publish                                  # writes site/status/tet-eligibility.jwt from fixtures/issuance.json
node bin/issuer.mjs issue fixtures/certificates/teacher-a.json <holder did:key>
```

A status check returns `not_revoked`, `revoked` or `unknown`. `unknown` covers a list that cannot be fetched, is not signed by the credential's issuer, was published for another address, or does not allocate the credential's index. The signed list states how many indices it allocates (`entries`), and the bits that pad it to a whole byte are set.

## Teacher

The teacher holds a did:key, signs a consent record naming the school, the purpose, the claims to disclose and an end date (the end of the academic year, 31 March by default; set `MOHAR_ACADEMIC_YEAR_END=MM-DD` to change it), and builds a presentation that discloses only those claims. Before presenting, the teacher verifies the credential against the issuer's did:web document and refuses it unless its always-visible part is exactly `iss`, `sub` (this teacher), `vct`, `iat`, `status.status_list` with only `idx` and the issuer's list `uri`, `cnf.jwk` with only `kty`, `crv` and this teacher's `x`, `_sd` and `_sd_alg`, and unless every disclosed value has its allowed type (no nested structure). Consent times must be ISO 8601 UTC with milliseconds. The presentation carries a key-binding JWT with the school as `aud`, the school's `nonce`, `iat`, and the SHA-256 of the consent record. Roll number, date of birth, category, family names and marks are never disclosed.

The presentation and the consent go to the school directly. The log service receives only their salted commitments (see Log). The teacher keeps both salts and sends the presentation salt to the school with the presentation.

```
node bin/holder.mjs keygen teacher-a                         # prints the teacher's did:key
node bin/holder.mjs consent teacher-a <school did:key> > consent.jws
MOHAR_SITE_DIR=site node bin/holder.mjs present teacher-a credential.txt consent.jws <school did:key> <nonce> > presentation.json
```

`present` prints `{ presentation, presentation_salt }`, keeps the consent salt in `consent.jws.salt`, and posts both salted commitments to the log service when `MOHAR_LOG_URL` is set (it prints them otherwise). `MOHAR_SITE_DIR` reads the issuer's `did.json` from a local copy of the site instead of fetching it.

The consent record follows the shape of a consent record under India's Digital Personal Data Protection Rules, 2025. Mohar is not a registered Consent Manager and does not claim to be. Withdrawal is recorded as available; a withdrawal endpoint is not in this version.

## School

The school issues single-use nonces and verifies each presentation: the issuer signature and disclosure digests against the issuer's did:web document, the key binding against the credential's holder key (audience, nonce, age under five minutes, consent hash), that the visible credential and every disclosed value match the eligibility-credential profile exactly, the consent record (signed by the holder, for this school, valid now, with ISO 8601 UTC times), that the consent covers the claims the receipt needs and the disclosures equal the consent, and the credential's status. Times on the credential and key binding may run up to 60 seconds ahead of the school's clock. On success it signs a receipt with its did:key; the receipt carries the presentation hash, certificate commitment, consent hash, issuer, status result, the disclosed eligibility claims (no name, no holder identifier), purpose, time and the next term check date. On failure it returns one of `issuer_signature_invalid`, `key_binding_invalid`, `nonce_stale`, `consent_mismatch`, `status_revoked`, `scope_insufficient`, records the presentation hash and the reason, and signs nothing.

At each term boundary (1 October and 1 January by default; set `MOHAR_TERM_BOUNDARIES=MM-DD,MM-DD`) the school re-reads the status of every receipt whose consent is still valid and signs a re-check receipt. `alert` is true when the result is `revoked` or differs from the previous result.

```
node bin/school.mjs keygen                                   # prints the school's did:key
PORT=8080 MOHAR_LOG_URL=... MOHAR_ADMIN_TOKEN=... node bin/school.mjs serve
node bin/school.mjs recheck                                  # term check against the local store
```

| Method | Path | Result |
|---|---|---|
| GET | `/nonce` | `{ nonce, expires_at }`, valid for ten minutes, usable once |
| POST | `/present` | `{ presentation, consent, presentation_salt }` → 200 with the receipt, 422 with the refusal, 400 without a valid salt |
| GET | `/status/{holder_did}` | latest receipt, status result, last check time, next check date, alert; staff token |
| POST | `/recheck` | term check; staff token |
| GET | `/export/{id}` | export bundle for a receipt or re-check receipt (needs `MOHAR_LOG_URL`); 409 while its batch is open |

Staff routes take `authorization: Bearer <MOHAR_ADMIN_TOKEN>` and are off when the token is not set. Receipt and re-check commitments go to the log service when `MOHAR_LOG_URL` is set.

## Log

The log service accepts only `{ entry_type, commitment }`, where `entry_type` is `consent`, `presentation`, `receipt` or `recheck` and `commitment` is `SHA-256("mohar/commit/v1" || salt || record)`: the ASCII domain string, a 32-byte random salt and the UTF-8 bytes of the record. Whoever creates a record makes its salt and keeps it; the salt never goes to the log, so no log field can be recomputed from a record, or from anything in it, without that salt. The school keeps the receipt and re-check salts and the presentation salt it receives. Each entry is chained: `entry_hash = SHA-256(prev_hash || entry_type || commitment || ts)`, with `prev_hash` of the first entry set to 64 zeros. Committing the same type and commitment again returns the existing entry. The store keeps a head checkpoint (the sequence number and hash of the last entry appended), authenticated with an HMAC under `MOHAR_LOG_HEAD_KEY` when that key is set, and refuses to append when the checkpoint is missing or not authenticated, when the stored tail does not match it, or when a closed batch ends after it. An operator adopts a checkpoint for a log that has none with `adopt-head`. Before closing or anchoring a batch, the service re-checks the whole chain, the checkpoint and every closed batch root, and refuses if any of them is wrong.

A batch closes over every waiting entry. Its root is a Merkle tree over the entries: leaves are `SHA-256(0x00 || entry_hash)`, inner nodes `SHA-256(0x01 || left || right)`, and the tree is padded to a power of two with `SHA-256(0x02)`, which no entry can produce. The batch root commits to the batch header and that tree root: `SHA-256(0x03 || "mohar/batch/v1" || batch_id || first_seq || size || closed_at || tree_root)`, with the numbers as 8-byte big-endian and `closed_at` as its 24 ASCII characters. The batch root is anchored twice:

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

### Acknowledgements

Every accepted `/commit` returns an `ack`: a JWS (`log-ack+jwt`) signed by the log operator's Ed25519 key over `{ seq, entry_hash, entry_type, commitment, ts, operator_key_id }`. The log stores nothing extra; the teacher and the school keep their acknowledgements with their salts. The operator key is separate from the Sepolia key and is published in `site/operator.json`: `did:key:z6MkgvDZZZ8ExoJ489rWxMJsWh4fe6hhFzZ6Nd61PVcyZyy2`. Two acknowledgements with the same `seq` and different entry hashes are a signed proof that the operator replaced an entry:

```
node bin/log.mjs operator-keygen                       # operator key in .keys/ (not tracked); writes site/operator.json
node bin/log.mjs equivocation a.ack b.ack [--operator site/operator.json]   # exit 3 on equivocation
```

Reuse of a sequence number is detectable by any acknowledgement holder.

## Inspector

An export bundle holds the signed receipt or re-check receipt, its salt, its log entry, its Merkle path, the batch root, the Sepolia transaction, the OpenTimestamps proof and the log operator's acknowledgement of the entry. It holds no presentation, no consent and no personal data.

`bin/inspect.mjs` checks a bundle on its own, with no connection to the school or the log service:

1. signature: the record is signed by the school did:key it names, resolved from the identifier itself;
2. entry: the log entry's commitment recomputes from the record and its salt, and its `entry_hash` recomputes;
3. merkle: the entry's path and the batch header (id, first seq, size, closing time) recompute the batch root, and the entry's seq is its position in the batch;
4. sepolia: from one RPC that reports chain 11155111 and has the transaction: the transaction succeeded, its calldata is the batch root, and its block is the block the bundle names;
5. ots: the OpenTimestamps proof is for the batch root, and its Bitcoin attestation matches the merkle root of that Bitcoin block. A proof with calendar attestations only is reported as `pending`;
6. acknowledgement: the acknowledgement is signed by the published operator key, and its `seq`, `entry_hash` and `commitment` are those of the bundle's log entry. A bundle without one reports `not supplied`, never `pass`;
7. certificate binding (optional): with `--certificate` and `--certificate-salt` (both from the presentation the school holds), the certificate and salt recompute the receipt's `certificate_commitment`; reported as `not supplied` otherwise.

```
node bin/inspect.mjs bundle.json [--operator site/operator.json]   # MOHAR_SEPOLIA_RPCS and MOHAR_ESPLORA_URL override the public defaults
node bin/inspect.mjs bundle.json --certificate certificate.json --certificate-salt <hex>
```

Each check runs whatever the others found and fails with its own reason. The bundle verifies when checks 1 to 4 pass, check 5 passes or is pending, and checks 6 and 7 pass or are not supplied. Bitcoin block headers come from a public block explorer (blockstream.info by default), which the check trusts for the header.

## Limitations

Before a batch is anchored, the log operator can roll back unbatched entries; the log cannot prevent this, and clients hold signed acknowledgements that make it provable. Rotation of the operator key is not in this version.

### Inspector page

`site/inspector/index.html` is the same verifier as one static page, built for the browser:

```
node bin/build-inspector.mjs            # writes site/inspector/index.html (not tracked; built for publishing)
```

The page loads `site/sample/bundle.json` and `site/operator.json` on open, and takes a pasted bundle or a chosen file. Besides the site itself, it contacts only the public Sepolia RPCs and the public Bitcoin block explorer. It shows the six checks; the certificate-binding line appears only when a certificate and salt are entered. OpenTimestamps proofs are read in the page by `src/anchor/ots-parse.mjs`, which has no dependency on Node built-ins.

## Licence

Apache-2.0. See `LICENSE`.
