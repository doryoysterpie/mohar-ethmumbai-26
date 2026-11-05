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

## Teacher

The teacher holds a did:key, signs a consent record naming the school, the purpose, the claims to disclose and an end date (the end of the academic year, 31 March by default; set `MOHAR_ACADEMIC_YEAR_END=MM-DD` to change it), and builds a presentation that discloses only those claims. The presentation carries a key-binding JWT with the school as `aud`, the school's `nonce`, `iat`, and the SHA-256 of the consent record. Roll number, date of birth, category, family names and marks are never disclosed.

The presentation and the consent go to the school directly. The log service receives only their SHA-256 commitments.

```
node bin/holder.mjs keygen teacher-a                         # prints the teacher's did:key
node bin/holder.mjs consent teacher-a <school did:key> > consent.jws
node bin/holder.mjs present teacher-a credential.txt consent.jws <school did:key> <nonce> > presentation.txt
```

`present` posts both commitments to the log service when `MOHAR_LOG_URL` is set, and prints them otherwise.

The consent record follows the shape of a consent record under India's Digital Personal Data Protection Rules, 2025. Mohar is not a registered Consent Manager and does not claim to be. Withdrawal is recorded as available; a withdrawal endpoint is not in this version.

## School

The school issues single-use nonces and verifies each presentation: the issuer signature and disclosure digests against the issuer's did:web document, the key binding against the credential's holder key (audience, nonce, age under five minutes, consent hash), the consent record (signed by the holder, for this school, valid now), that the disclosures match the consent, and the credential's status. On success it signs a receipt with its did:key; the receipt carries the presentation hash, certificate commitment, consent hash, issuer, status result, the disclosed eligibility claims (no name, no holder identifier), purpose, time and the next term check date. On failure it returns one of `issuer_signature_invalid`, `key_binding_invalid`, `nonce_stale`, `consent_mismatch`, `status_revoked`, `scope_insufficient`, records the presentation hash and the reason, and signs nothing.

At each term boundary (1 October and 1 January by default; set `MOHAR_TERM_BOUNDARIES=MM-DD,MM-DD`) the school re-reads the status of every receipt whose consent is still valid and signs a re-check receipt. `alert` is true when the result is `revoked` or differs from the previous result.

```
node bin/school.mjs keygen                                   # prints the school's did:key
PORT=8080 MOHAR_LOG_URL=... MOHAR_ADMIN_TOKEN=... node bin/school.mjs serve
node bin/school.mjs recheck                                  # term check against the local store
```

| Method | Path | Result |
|---|---|---|
| GET | `/nonce` | `{ nonce, expires_at }`, valid for ten minutes, usable once |
| POST | `/present` | `{ presentation, consent }` → 200 with the receipt, or 422 with the refusal |
| GET | `/status/{holder_did}` | latest receipt, status result, last check time, next check date, alert; staff token |
| POST | `/recheck` | term check; staff token |
| GET | `/export/{receipt_id}` | not in this version |

Staff routes take `authorization: Bearer <MOHAR_ADMIN_TOKEN>` and are off when the token is not set. Receipt and re-check commitments go to the log service when `MOHAR_LOG_URL` is set.

## Licence

Apache-2.0. See `LICENSE`.
