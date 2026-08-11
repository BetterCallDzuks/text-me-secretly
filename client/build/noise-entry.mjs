// noise-entry.mjs — bundle entry for the audited Noise XX library.
//
// This is the ONLY place a build step touches the client. `npm run build:noise`
// bundles this (via esbuild) into `www/js/vendor/noise-xx.js`, a single
// self-contained ES module the app loads directly — the rest of the app stays
// buildless vanilla JS.
//
// Library: noise-handshake (Holepunch) — the same Noise implementation that
// powers the Keet P2P messenger. Protocol suite:
//   Noise_XX_25519_ChaChaPoly_BLAKE2b
//
// Primitives: the build aliases `sodium-universal` to ./sodium-adapter.mjs,
// which is backed by the OFFICIAL AUDITED libsodium WASM (libsodium-wrappers).
// `ready` resolves once WASM is initialised — the app must await it before any
// key derivation or handshake.
//
// Regenerate the bundle after changing a pinned version:
//   cd client && npm install && npm run build:noise

import Noise from 'noise-handshake';
import curve from 'noise-handshake/dh';
import { ready } from './sodium-adapter.mjs';

export { Noise, curve, ready };
