// identity.js — anonymous, persistent, local-only, self-certifying identity.
//
// The app has NO account system. On first run it generates a long-term ECDH
// identity keypair and derives the anonId as a FINGERPRINT of the identity
// public key (base32(sha256(spki))[:20]).
//
// Why the id is a key fingerprint: it makes identities self-certifying. During
// the E2EE handshake each peer proves it holds the private key matching the
// fingerprint the other side dialed, so the signaling server cannot
// man-in-the-middle by swapping keys — doing so would change the id the user
// shared out-of-band. The id is still fully anonymous (no PII, no server
// record).

import { store } from './storage.js';
import {
  generateEcdhKeypair,
  exportEcdhKeypairJwks,
  importEcdhPrivateJwk,
  importEcdhPublicJwk,
  fingerprintOfPublicKey,
} from './crypto.js';

const IDENTITY_KEY = 'tms.identity'; // { id, priv: jwk, pub: jwk }

let cached = null; // { id, keypair: {privateKey, publicKey}, pubJwk }

async function createIdentity() {
  const keypair = await generateEcdhKeypair(true);
  const id = await fingerprintOfPublicKey(keypair.publicKey);
  const jwks = await exportEcdhKeypairJwks(keypair);
  await store.set(IDENTITY_KEY, { id, priv: jwks.priv, pub: jwks.pub });
  return { id, keypair, pubJwk: jwks.pub };
}

async function loadIdentity() {
  if (cached) return cached;

  const saved = await store.get(IDENTITY_KEY);
  if (saved && saved.priv && saved.pub && saved.id) {
    const privateKey = await importEcdhPrivateJwk(saved.priv);
    const publicKey = await importEcdhPublicJwk(saved.pub);
    cached = { id: saved.id, keypair: { privateKey, publicKey }, pubJwk: saved.pub };
    return cached;
  }

  cached = await createIdentity();
  return cached;
}

/** Return the device's anon ID (the identity key fingerprint). */
export async function getMyId() {
  return (await loadIdentity()).id;
}

/** Full identity: { id, keypair, pubJwk } — used by the E2EE handshake. */
export async function getIdentity() {
  return loadIdentity();
}
