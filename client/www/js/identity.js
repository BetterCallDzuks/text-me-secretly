// identity.js — anonymous, persistent, local-only identity.
//
// The app has NO account system. On first run it mints a random alphanumeric ID
// and stores it locally. That ID is the only thing a peer needs to reach you.

import { store } from './storage.js';

const ID_KEY = 'tms.anonId';
const ID_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
const ID_LEN = 20;

function randomId() {
  const bytes = new Uint8Array(ID_LEN);
  crypto.getRandomValues(bytes);
  let out = '';
  for (let i = 0; i < ID_LEN; i++) {
    out += ID_ALPHABET[bytes[i] % ID_ALPHABET.length];
  }
  return out;
}

let cached = null;

/** Return the device's anon ID, creating and persisting one on first call. */
export async function getMyId() {
  if (cached) return cached;
  let id = await store.get(ID_KEY);
  if (!id || !/^[A-Za-z0-9_-]{8,64}$/.test(id)) {
    id = randomId();
    await store.set(ID_KEY, id);
  }
  cached = id;
  return id;
}
