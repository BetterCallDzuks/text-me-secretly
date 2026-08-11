// identity.js — anonymous, persistent, local-only, self-certifying identity.
//
// The app has NO account system. On first run it generates a long-term X25519
// keypair (the Noise "static" key) and derives the anonId as a FINGERPRINT of
// its public key (base32(sha256(pub))[:20]).
//
// Because the id is the static-key fingerprint, identities are self-certifying:
// during the Noise XX handshake each peer learns the other's static public key
// and checks it hashes to the id it dialed. A signaling-server MITM that swaps
// keys is therefore detected — it would change the id the user shared
// out-of-band. The id is still fully anonymous (no PII, no server record).

import { store } from './storage.js';
import { curve } from './vendor/noise-xx.js';
import { fingerprintOfRawKey, bytesToB64, b64ToBytes } from './crypto.js';

const IDENTITY_KEY = 'tms.identity.xx'; // { id, pub: b64, sec: b64 }

let cached = null; // { id, keyPair: { publicKey: Uint8Array, secretKey: Uint8Array } }

async function createIdentity() {
  const keyPair = curve.generateKeyPair();
  const id = await fingerprintOfRawKey(keyPair.publicKey);
  await store.set(IDENTITY_KEY, {
    id,
    pub: bytesToB64(keyPair.publicKey),
    sec: bytesToB64(keyPair.secretKey),
  });
  return { id, keyPair };
}

async function loadIdentity() {
  if (cached) return cached;

  const saved = await store.get(IDENTITY_KEY);
  if (saved && saved.pub && saved.sec && saved.id) {
    cached = {
      id: saved.id,
      keyPair: { publicKey: b64ToBytes(saved.pub), secretKey: b64ToBytes(saved.sec) },
    };
    return cached;
  }

  cached = await createIdentity();
  return cached;
}

/** Return the device's anon ID (the identity key fingerprint). */
export async function getMyId() {
  return (await loadIdentity()).id;
}

/** Full identity: { id, keyPair } — the keyPair is the Noise static keypair. */
export async function getIdentity() {
  return loadIdentity();
}
