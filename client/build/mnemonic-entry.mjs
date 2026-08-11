// mnemonic-entry.mjs — bundle entry for BIP39 recovery-phrase support.
//
// `npm run build:mnemonic` bundles this (via esbuild) into
// `www/js/vendor/mnemonic.js`. Libraries:
//   * @scure/bip39   — audited BIP39 mnemonic generation/validation/seed
//   * @noble/hashes  — audited SHA-256 (transitive dep of @scure/bip39)
//
// The recovery phrase is the user's LOGIN / backup credential: the identity
// keypair is derived deterministically from it, so the same phrase restores the
// same anonId (public-key fingerprint) on any device. The public key / anonId
// is what a user shares to be added as a contact.

import {
  generateMnemonic as genM,
  mnemonicToSeedSync,
  validateMnemonic as valM,
} from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { sha256 } from '@noble/hashes/sha2.js';

const enc = new TextEncoder();

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/** Normalise a phrase the way BIP39 expects (NFKD, lowercased, single spaces). */
export function normalizeMnemonic(phrase) {
  return phrase.normalize('NFKD').trim().toLowerCase().replace(/\s+/g, ' ');
}

/** Fresh 12-word (128-bit) mnemonic. */
export function generateMnemonic() {
  return genM(wordlist, 128);
}

/** True if the phrase is a valid BIP39 mnemonic (checksum + wordlist). */
export function validateMnemonic(phrase) {
  try {
    return valM(normalizeMnemonic(phrase), wordlist);
  } catch {
    return false;
  }
}

/**
 * Deterministic 32-byte X25519 seed from the mnemonic and an OPTIONAL user
 * passphrase (a BIP39 "25th word" second factor).
 *
 * The BIP39 passphrase is `"text-me-secretly" + userPassphrase`:
 *   - an empty userPassphrase reproduces the original app-namespaced seed, so
 *     existing (passphrase-less) identities are unchanged;
 *   - a non-empty userPassphrase yields a different keypair (a different anonId)
 *     that cannot be restored from the written recovery phrase alone.
 *
 * A domain-separation tag then derives the curve seed. Feed the result to the
 * Noise curve's generateSeedKeyPair().
 */
export function mnemonicToSeed32(phrase, userPassphrase = '') {
  const bip39Passphrase = 'text-me-secretly' + (userPassphrase || '');
  const bip39Seed = mnemonicToSeedSync(normalizeMnemonic(phrase), bip39Passphrase);
  return sha256(concat(new Uint8Array(bip39Seed), enc.encode('tms-x25519-identity')));
}
