// sodium-adapter.mjs — presents the small slice of the `sodium-universal` API
// that noise-handshake uses, backed by the OFFICIAL AUDITED libsodium WASM
// (`libsodium-wrappers`, jedisct1). esbuild aliases `sodium-universal` to this
// file when building the Noise bundle, so the handshake runs on audited WASM
// primitives instead of the pure-JS sodium-javascript port.
//
// noise-handshake calls everything synchronously with output buffers passed in
// (Node/sodium-native style). libsodium-wrappers returns values instead and
// must be initialised (`await sodium.ready`) before first use — so:
//   * constants are hard-coded (they are fixed, standardised values), which
//     lets noise-handshake destructure them at import time, before init;
//   * each function delegates to libsodium-wrappers and copies the result into
//     the caller's output buffer;
//   * `ready` resolves once WASM is initialised — the app awaits it before any
//     key derivation or handshake (see app.js boot).

import sodium from 'libsodium-wrappers';

export const ready = sodium.ready;

// --- Constants (fixed by the algorithms; safe to expose before init) --------
export const crypto_kx_SEEDBYTES = 32;
export const crypto_scalarmult_BYTES = 32;
export const crypto_scalarmult_SCALARBYTES = 32;
export const crypto_aead_chacha20poly1305_ietf_NPUBBYTES = 12;
export const crypto_aead_chacha20poly1305_ietf_ABYTES = 16;

// --- Helpers ----------------------------------------------------------------
// libsodium-wrappers is strict about receiving plain Uint8Arrays; b4a buffers
// are Uint8Array subclasses, but normalise to a clean view to be safe.
function u8(x) {
  if (x == null) return x;
  return x instanceof Uint8Array && x.constructor === Uint8Array
    ? x
    : new Uint8Array(x.buffer, x.byteOffset, x.byteLength);
}

// --- Key agreement (X25519) -------------------------------------------------
export function crypto_kx_keypair(pk, sk) {
  const r = sodium.crypto_kx_keypair();
  pk.set(r.publicKey);
  sk.set(r.privateKey);
}

export function crypto_kx_seed_keypair(pk, sk, seed) {
  const r = sodium.crypto_kx_seed_keypair(u8(seed));
  pk.set(r.publicKey);
  sk.set(r.privateKey);
}

export function crypto_scalarmult(out, n, p) {
  out.set(sodium.crypto_scalarmult(u8(n), u8(p)));
}

export function crypto_scalarmult_base(out, n) {
  out.set(sodium.crypto_scalarmult_base(u8(n)));
}

// --- Hashing (BLAKE2b) ------------------------------------------------------
export function crypto_generichash(out, input) {
  out.set(sodium.crypto_generichash(out.length, u8(input)));
}

export function crypto_generichash_batch(out, inputs) {
  const state = sodium.crypto_generichash_init(null, out.length);
  for (const chunk of inputs) sodium.crypto_generichash_update(state, u8(chunk));
  out.set(sodium.crypto_generichash_final(state, out.length));
}

// --- AEAD (ChaCha20-Poly1305 IETF) -----------------------------------------
export function crypto_aead_chacha20poly1305_ietf_encrypt(
  ciphertext,
  message,
  ad,
  _nsec,
  npub,
  key
) {
  const ct = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
    u8(message),
    ad && ad.length ? u8(ad) : null,
    null, // secret nonce (unused)
    u8(npub),
    u8(key)
  );
  ciphertext.set(ct);
}

export function crypto_aead_chacha20poly1305_ietf_decrypt(
  message,
  _nsec,
  ciphertext,
  ad,
  npub,
  key
) {
  // Throws on authentication failure — noise-handshake/e2ee treats that as a
  // dropped message, which is the intended tamper behaviour.
  const pt = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
    null, // secret nonce (unused)
    u8(ciphertext),
    ad && ad.length ? u8(ad) : null,
    u8(npub),
    u8(key)
  );
  message.set(pt);
}

// --- Misc -------------------------------------------------------------------
export function sodium_memzero(buf) {
  sodium.memzero(u8(buf));
}
