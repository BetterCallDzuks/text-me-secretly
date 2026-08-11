// identity.js — anonymous, recoverable, self-certifying identity.
//
// Model (wallet-style):
//   * PUBLIC key  → the anonId (its fingerprint) is your shareable contact
//     address; other people add you using it. It is also the Noise static-key
//     fingerprint, so it doubles as a verifiable safety number.
//   * PRIVATE key → derived deterministically from a BIP39 RECOVERY PHRASE
//     (mnemonic) plus an OPTIONAL user passphrase. The phrase (± passphrase) is
//     your login/backup: enter it on any device to restore the same identity.
//
// The optional passphrase is a BIP39 "25th word" second factor: with it set,
// the written phrase alone can't restore the account. It changes the derived
// keypair — and therefore the anonId — so setting/removing it is effectively
// switching to a different address.
//
// The derived keypair is persisted locally so normal launches never prompt for
// the passphrase; the passphrase is required only to re-derive on a new device.

import { store } from './storage.js';
import { curve, ready as cryptoReady } from './vendor/noise-xx.js';
import {
  generateMnemonic,
  validateMnemonic,
  normalizeMnemonic,
  mnemonicToSeed32,
} from './vendor/mnemonic.js';
import { fingerprintOfRawKey, bytesToB64, b64ToBytes } from './crypto.js';

const IDENTITY_KEY = 'tms.identity.mnemonic'; // { mnemonic, hasPassphrase, pub, sec }

let cached = null; // { id, keyPair, mnemonic, hasPassphrase }

/** Derive + persist the full identity from a recovery phrase (+ passphrase). */
async function deriveAndStore(mnemonic, passphrase = '') {
  await cryptoReady; // curve.generateSeedKeyPair runs on libsodium WASM
  const normalized = normalizeMnemonic(mnemonic);
  const keyPair = curve.generateSeedKeyPair(mnemonicToSeed32(normalized, passphrase));
  const publicKey = new Uint8Array(keyPair.publicKey);
  const id = await fingerprintOfRawKey(publicKey);
  const hasPassphrase = !!passphrase;

  await store.set(IDENTITY_KEY, {
    mnemonic: normalized,
    hasPassphrase,
    pub: bytesToB64(publicKey),
    sec: bytesToB64(new Uint8Array(keyPair.secretKey)),
  });

  cached = { id, keyPair, mnemonic: normalized, hasPassphrase };
  return cached;
}

async function loadIdentity() {
  if (cached) return cached;

  const saved = await store.get(IDENTITY_KEY);

  // Preferred path: a persisted keypair (works regardless of passphrase).
  if (saved && saved.pub && saved.sec && typeof saved.mnemonic === 'string') {
    const keyPair = { publicKey: b64ToBytes(saved.pub), secretKey: b64ToBytes(saved.sec) };
    const id = await fingerprintOfRawKey(new Uint8Array(keyPair.publicKey));
    cached = { id, keyPair, mnemonic: saved.mnemonic, hasPassphrase: !!saved.hasPassphrase };
    return cached;
  }

  // Migration: an older record stored only the (passphrase-less) mnemonic.
  if (saved && typeof saved.mnemonic === 'string' && validateMnemonic(saved.mnemonic)) {
    return deriveAndStore(saved.mnemonic, '');
  }

  // First run: mint a fresh recovery phrase (no passphrase).
  return deriveAndStore(generateMnemonic(), '');
}

/** Return the device's anon ID (the identity key fingerprint / contact address). */
export async function getMyId() {
  return (await loadIdentity()).id;
}

/** Full identity: { id, keyPair, mnemonic, hasPassphrase }. */
export async function getIdentity() {
  return loadIdentity();
}

/** The recovery phrase to display for backup. */
export async function getMnemonic() {
  return (await loadIdentity()).mnemonic;
}

/** Whether the current identity is protected by a user passphrase. */
export async function hasPassphrase() {
  return (await loadIdentity()).hasPassphrase;
}

/**
 * Restore / log in from a recovery phrase (+ optional passphrase). Replaces the
 * local identity. Returns the restored identity, or throws on an invalid phrase.
 */
export async function restoreFromMnemonic(phrase, passphrase = '') {
  if (!validateMnemonic(phrase)) {
    throw new Error('invalid-recovery-phrase');
  }
  return deriveAndStore(phrase, passphrase);
}

/**
 * Re-derive the CURRENT recovery phrase under a new passphrase (pass '' to
 * remove it). This changes the keypair and the anonId — i.e. it switches to a
 * different address. Returns the new identity.
 */
export async function setPassphrase(passphrase) {
  const { mnemonic } = await loadIdentity();
  return deriveAndStore(mnemonic, passphrase);
}
