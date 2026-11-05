import { Resolver } from 'did-resolver';
import { getResolver } from 'web-did-resolver';

/**
 * did:web identifier for a site base URL, e.g. https://host/path -> did:web:host:path.
 * @param {string} baseUrl
 * @returns {string}
 */
export function didWebFromBase(baseUrl) {
  const u = new URL(baseUrl);
  if (u.protocol !== 'https:') throw new TypeError('didWebFromBase: https only');
  const parts = [encodeURIComponent(u.host), ...u.pathname.split('/').filter(Boolean).map(encodeURIComponent)];
  return `did:web:${parts.join(':')}`;
}

/**
 * DID document with one Ed25519 assertion key.
 * @param {string} did
 * @param {import('../shared/keys.mjs').Ed25519Jwk} publicJwk
 * @returns {{ document: object, kid: string }}
 */
export function didDocument(did, publicJwk) {
  const kid = `${did}#key-1`;
  return {
    kid,
    document: {
      '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
      id: did,
      verificationMethod: [{ id: kid, type: 'JsonWebKey2020', controller: did, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: publicJwk.x } }],
      assertionMethod: [kid],
    },
  };
}

/**
 * Resolves the issuer's assertion key named by `kid` from its did:web document.
 * Throws if the document cannot be fetched, or `kid` is not an Ed25519 assertion key of `did`.
 * @param {string} did
 * @param {string} kid
 * @param {{ fetch?: import('web-did-resolver').WebDidFetch }} [options]
 * @returns {Promise<import('../shared/keys.mjs').Ed25519Jwk>}
 */
export async function resolveIssuerKey(did, kid, options = {}) {
  if (!did.startsWith('did:web:')) throw new Error('issuer is not a did:web');
  if (!kid.startsWith(`${did}#`)) throw new Error('key id does not belong to the issuer');
  const resolver = new Resolver(getResolver({ fetch: options.fetch }));
  const { didDocument: doc, didResolutionMetadata } = await resolver.resolve(did);
  if (!doc) throw new Error(`issuer DID could not be resolved: ${didResolutionMetadata?.error ?? 'unknown error'}`);
  if (doc.id !== did) throw new Error('DID document id does not match the issuer');
  const asserts = (doc.assertionMethod ?? []).map((m) => (typeof m === 'string' ? m : m.id));
  if (!asserts.includes(kid)) throw new Error('key is not an assertion key of the issuer');
  const vm = (doc.verificationMethod ?? []).find((m) => m.id === kid);
  const jwk = vm?.publicKeyJwk;
  if (!jwk || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') {
    throw new Error('issuer key is not an Ed25519 JWK');
  }
  return { kty: 'OKP', crv: 'Ed25519', x: jwk.x };
}
