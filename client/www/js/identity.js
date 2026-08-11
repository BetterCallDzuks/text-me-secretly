// identity.js — anonymous, recoverable, self-certifying identity.
//
// Model (wallet-style):
//   * PUBLIC key  → the anonId (its fingerprint) is your shareable address;
//     other people add you as a contact using it.
//   * PRIVATE key → derived deterministically from a BIP39 RECOVERY PHRASE
//     (mnemonic). The phrase is your login/backup: enter it on any device to
//     restore the same identity (same keypair, same anonId).
//
// The identity keypair is the Noise XX static key (X25519). Because the anonId
// is the static-key fingerprint, identities stay self-certifying — during the
// handshake each peer verifies the key it learns hashes to the dialed anonId,
// defeating a signaling-server MITM.

import { store } from './storage.js';
import { curve } from './vendor/noise-xx.js';
import {
  generateMnemonic,
  validateMnemonic,
  normalizeMnemonic,
  mnemonicToSeed32,
} from './vendor/mnemonic.js';
import { fingerprintOfRawKey } from './crypto.js';

const IDENTITY_KEY = 'tms.identity.mnemonic'; // { mnemonic }

let cached = null; // { id, keyPair, mnemonic }

/** Derive the full identity ({ id, keyPair, mnemonic }) from a recovery phrase. */
async function fromMnemonic(mnemonic) {
  const normalized = normalizeMnemonic(mnemonic);
  const keyPair = curve.generateSeedKeyPair(mnemonicToSeed32(normalized));
  const id = await fingerprintOfRawKey(new Uint8Array(keyPair.publicKey));
  return { id, keyPair, mnemonic: normalized };
}

async function loadIdentity() {
  if (cached) return cached;

  const saved = await store.get(IDENTITY_KEY);
  if (saved && typeof saved.mnemonic === 'string' && validateMnemonic(saved.mnemonic)) {
    cached = await fromMnemonic(saved.mnemonic);
    return cached;
  }

  // First run (or no valid stored phrase): mint a fresh recovery phrase.
  const mnemonic = generateMnemonic();
  cached = await fromMnemonic(mnemonic);
  await store.set(IDENTITY_KEY, { mnemonic: cached.mnemonic });
  return cached;
}

/** Return the device's anon ID (the identity key fingerprint / contact address). */
export async function getMyId() {
  return (await loadIdentity()).id;
}

/** Full identity: { id, keyPair, mnemonic } — keyPair is the Noise static keypair. */
export async function getIdentity() {
  return loadIdentity();
}

/** The recovery phrase to display for backup. */
export async function getMnemonic() {
  return (await loadIdentity()).mnemonic;
}

/**
 * Restore / log in from a recovery phrase. Replaces the local identity.
 * Returns the restored { id, keyPair, mnemonic }, or throws on an invalid phrase.
 */
export async function restoreFromMnemonic(phrase) {
  if (!validateMnemonic(phrase)) {
    throw new Error('invalid-recovery-phrase');
  }
  const identity = await fromMnemonic(phrase);
  await store.set(IDENTITY_KEY, { mnemonic: identity.mnemonic });
  cached = identity;
  return identity;
}
