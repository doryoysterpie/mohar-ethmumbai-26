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

A status check returns `not_revoked`, `revoked` or `unknown`. `unknown` covers a list that cannot be fetched, is not signed by the credential's issuer, was published for another address, or does not allocate the credential's index. The signed list states how many indices it allocates (`entries`), and the bits that pad it to a whole byte are set.

## Teacher

The teacher holds a did:key, signs a consent record naming the school, the purpose, the claims to disclose and an end date (the end of the academic year, 31 March by default; set `MOHAR_ACADEMIC_YEAR_END=MM-DD` to change it), and builds a presentation that discloses only those claims. Before presenting, the teacher verifies the credential against the issuer's did:web document and refuses one of another type, issued to someone else, or carrying any always-visible claim outside `iss`, `sub`, `vct`, `iat`, `status`, `cnf`, `_sd`, `_sd_alg`. The presentation carries a key-binding JWT with the school as `aud`, the school's `nonce`, `iat`, and the SHA-256 of the consent record. Roll number, date of birth, category, family names and marks are never disclosed.

The presentation and the consent go to the school directly. The log service receives only their SHA-256 commitments.

```
node bin/holder.mjs keygen teacher-a                         # prints the teacher's did:key
node bin/holder.mjs consent teacher-a <school did:key> > consent.jws
MOHAR_SITE_DIR=site node bin/holder.mjs present teacher-a credential.txt consent.jws <school did:key> <nonce> > presentation.txt
```

`present` posts both commitments to the log service when `MOHAR_LOG_URL` is set, and prints them otherwise. `MOHAR_SITE_DIR` reads the issuer's `did.json` from a local copy of the site instead of fetching it.

The consent record follows the shape of a consent record under India's Digital Personal Data Protection Rules, 2025. Mohar is not a registered Consent Manager and does not claim to be. Withdrawal is recorded as available; a withdrawal endpoint is not in this version.

## Licence

Apache-2.0. See `LICENSE`.
