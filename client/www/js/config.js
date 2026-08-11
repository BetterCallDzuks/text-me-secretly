// config.js — client-side endpoints.
//
// Point these at your VPS. For local development against a server on the same
// machine, use ws://localhost:8080 / http://localhost:8080.
//
// In production always use wss:// and https:// (TLS terminated by your reverse
// proxy) so signaling metadata is encrypted in transit.

export const CONFIG = {
  SIGNALING_URL: 'wss://your-vps-host.example/signal',
  API_BASE: 'https://your-vps-host.example',

  // Optional: pin the server's signing key by kid (from GET /api/pubkey). When
  // set, a public key whose kid differs is rejected — defends against a swapped
  // key. Leave null to trust-on-first-use.
  EXPECTED_JWT_KID: null,
};
