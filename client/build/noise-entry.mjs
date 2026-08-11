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
// Regenerate the bundle after changing the pinned version:
//   cd client && npm install && npm run build:noise

import Noise from 'noise-handshake';
import curve from 'noise-handshake/dh';

export { Noise, curve };
