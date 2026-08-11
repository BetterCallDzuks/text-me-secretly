// crypto.js — small Web Crypto helpers still needed outside the Noise layer.
//
// The E2EE handshake + transport encryption now live in the audited Noise XX
// library (see e2ee.js + www/js/vendor/noise-xx.js), so the hand-rolled ECDH /
// HKDF / AES-GCM code that used to be here is gone. What remains:
//   * base64url + base32 + SHA-256 helpers
//   * the identity-key fingerprint (anonId) derivation
//   * offline RS256 JWT verification for subscription proofs

const subtle = crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

// ---- base64url -------------------------------------------------------------

export function bytesToB64u(bytes) {
  let bin = '';
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i = 0; i < b.length; i++) bin += String.fromCharCode(b[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64uToBytes(str) {
  const pad = str.length % 4 ? '='.repeat(4 - (str.length % 4)) : '';
  const bin = atob(str.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// Standard base64 (used to persist raw keypair bytes).
export function bytesToB64(bytes) {
  let bin = '';
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i = 0; i < b.length; i++) bin += String.fromCharCode(b[i]);
  return btoa(bin);
}

export function b64ToBytes(str) {
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ---- hashing + fingerprints ------------------------------------------------

export async function sha256(bytes) {
  const digest = await subtle.digest('SHA-256', bytes);
  return new Uint8Array(digest);
}

// RFC 4648 base32 (A-Z2-7), no padding — used for human-shareable anonIds.
const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function base32(bytes) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

/**
 * Fingerprint of a raw public key (32-byte X25519): base32(SHA-256(pub))[:20],
 * i.e. 100 bits. This IS the anonId, so identities are self-certifying: a peer
 * verifies the Noise static key it receives hashes to the id it dialed, which
 * defeats a signaling-server MITM (swapping keys would change the shared id).
 */
export async function fingerprintOfRawKey(rawPublicKey) {
  const hash = await sha256(rawPublicKey);
  return base32(hash).slice(0, 20);
}

// ---- text helpers ----------------------------------------------------------

export const utf8 = {
  encode: (s) => enc.encode(s),
  decode: (b) => dec.decode(b),
};

// ---- RS256 JWT offline verification ---------------------------------------

let cachedVerifyKey = null;
let cachedJwkKid = null;

/** Import (and cache) the server's RSA public key from its JWK. */
export async function importRs256VerifyKey(jwk) {
  if (cachedVerifyKey && cachedJwkKid === jwk.kid) return cachedVerifyKey;
  cachedVerifyKey = await subtle.importKey(
    'jwk',
    { ...jwk, alg: 'RS256', ext: true },
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  );
  cachedJwkKid = jwk.kid || null;
  return cachedVerifyKey;
}

/**
 * Verify an RS256 JWT fully offline and return its claims, or null if invalid.
 * Checks signature, iss, aud, exp, and (if provided) that sub === expectSub.
 */
export async function verifyJwtRs256(token, verifyKey, { issuer, audience, expectSub } = {}) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [h, p, s] = parts;

    const signingInput = enc.encode(`${h}.${p}`);
    const signature = b64uToBytes(s);
    const ok = await subtle.verify(
      { name: 'RSASSA-PKCS1-v1_5' },
      verifyKey,
      signature,
      signingInput
    );
    if (!ok) return null;

    const claims = JSON.parse(dec.decode(b64uToBytes(p)));
    const now = Math.floor(Date.now() / 1000);
    if (claims.exp && now >= claims.exp) return null;
    if (claims.nbf && now < claims.nbf) return null;
    if (issuer && claims.iss !== issuer) return null;
    if (audience && claims.aud !== audience) return null;
    if (expectSub && claims.sub !== expectSub) return null;
    return claims;
  } catch {
    return null;
  }
}
