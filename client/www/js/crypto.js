// crypto.js — Web Crypto helpers. No external libraries: everything here runs
// on the platform SubtleCrypto available in Capacitor's WebView.
//
// Provides the primitives for:
//   * E2EE: ECDH (P-256) key agreement, HKDF-SHA256, AES-256-GCM AEAD, and a
//     public-key fingerprint used to bind an identity key to an anonId.
//   * Offline subscription proof: RS256 JWT verification with the server's
//     public key.
//
// P-256 is used for ECDH because it is supported in every current mobile
// WebView. X25519 is preferable where available (Safari 17+, recent Chromium);
// swapping the namedCurve/algorithm here is the only change required.

const subtle = crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

// ---- base64 / base64url ----------------------------------------------------

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
 * Fingerprint of an ECDH public key: base32(SHA-256(SPKI-DER)), truncated to
 * 20 chars (100 bits). This IS the anonId, which makes identities
 * self-certifying — a peer verifies the key they receive hashes to the id they
 * dialed, so the signaling server cannot swap keys (MITM) without changing the
 * id the user shared out-of-band.
 */
export async function fingerprintOfPublicKey(publicKey) {
  const spki = await subtle.exportKey('spki', publicKey);
  const hash = await sha256(new Uint8Array(spki));
  return base32(hash).slice(0, 20);
}

// ---- ECDH (P-256) ----------------------------------------------------------

export async function generateEcdhKeypair(extractable = true) {
  return subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, extractable, [
    'deriveBits',
  ]);
}

export async function exportEcdhPublicJwk(publicKey) {
  return subtle.exportKey('jwk', publicKey);
}

export async function exportEcdhKeypairJwks(keypair) {
  return {
    priv: await subtle.exportKey('jwk', keypair.privateKey),
    pub: await subtle.exportKey('jwk', keypair.publicKey),
  };
}

export async function importEcdhPrivateJwk(jwk) {
  return subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, [
    'deriveBits',
  ]);
}

export async function importEcdhPublicJwk(jwk) {
  // Public key: no key usages.
  return subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
}

/** Raw ECDH shared secret (32 bytes for P-256). */
export async function ecdhSharedSecret(privateKey, publicKey) {
  const bits = await subtle.deriveBits(
    { name: 'ECDH', public: publicKey },
    privateKey,
    256
  );
  return new Uint8Array(bits);
}

// ---- HKDF + AES-GCM --------------------------------------------------------

export async function hkdf(ikm, salt, infoStr, lengthBytes) {
  const baseKey = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(infoStr) },
    baseKey,
    lengthBytes * 8
  );
  return new Uint8Array(bits);
}

export async function importAesGcmKey(rawKeyBytes) {
  return subtle.importKey('raw', rawKeyBytes, { name: 'AES-GCM' }, false, [
    'encrypt',
    'decrypt',
  ]);
}

/**
 * AES-256-GCM encrypt. Returns [12-byte IV || ciphertext+tag] as one Uint8Array.
 * A fresh random 96-bit IV per message is safe because each direction uses its
 * own key (see e2ee.js).
 */
export async function aesGcmEncrypt(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ct), 12);
  return out;
}

export async function aesGcmDecrypt(key, envelope) {
  const buf = envelope instanceof Uint8Array ? envelope : new Uint8Array(envelope);
  const iv = buf.subarray(0, 12);
  const ct = buf.subarray(12);
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return new Uint8Array(pt);
}

// ---- text helpers ----------------------------------------------------------

export const utf8 = {
  encode: (s) => enc.encode(s),
  decode: (b) => dec.decode(b),
};

export function concatBytes(...arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

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
