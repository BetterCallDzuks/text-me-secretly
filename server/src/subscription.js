'use strict';

// Subscription token issuer + verifier — RS256.
//
// The proof a paying user presents to a peer is a short JWT signed with the
// server's PRIVATE key (RS256). Peers verify it OFFLINE with the server's
// PUBLIC key (served at /api/pubkey and imported via SubtleCrypto in the
// browser). No verification round-trip, no metadata leak.
//
// Trust model:
//   - The SENDER obtains an RS256 token for their own anonId after paying.
//   - The RECEIVER holds only the PUBLIC key, so it can verify but never forge.
//   - The token's `sub` is bound to the sender's anonId; the receiver checks it
//     against the peer id it is actually talking to, stopping token reuse by a
//     different peer.
//
// The /api/verify endpoint remains as a fallback for clients that cannot import
// the public key, but the client's default path is offline verification.

const jwt = require('jsonwebtoken');
const config = require('./config');

const ISSUER = 'text-me-secretly';
const AUDIENCE = 'tms-peers';

/**
 * Issue a subscription proof for an anonymous ID.
 * Asserts: "the holder of this anonId has an active subscription until `exp`."
 * Contains no contact list and no message data.
 *
 * @param {string} anonId
 * @param {number} paidUntilMs epoch ms when the subscription lapses
 * @returns {{ token: string, expiresAt: number }}
 */
function issueToken(anonId, paidUntilMs) {
  const nowSec = Math.floor(Date.now() / 1000);
  const expSec = Math.floor(paidUntilMs / 1000);

  const payload = {
    sub: anonId,
    scope: 'subscription',
    plan: 'premium-monthly',
  };

  // `iat` is added automatically by jsonwebtoken; passing it in options throws.
  const token = jwt.sign(payload, config.jwtPrivatePem, {
    algorithm: 'RS256',
    keyid: config.jwtKid,
    issuer: ISSUER,
    audience: AUDIENCE,
    expiresIn: Math.max(60, expSec - nowSec),
  });

  return { token, expiresAt: paidUntilMs };
}

/**
 * Server-side verification (fallback path for /api/verify). Uses the PUBLIC key.
 *
 * @param {string} token
 * @param {string} expectAnonId
 * @returns {{ valid: boolean, reason?: string, claims?: object }}
 */
function verifyToken(token, expectAnonId) {
  try {
    const claims = jwt.verify(token, config.jwtPublicPem, {
      algorithms: ['RS256'],
      issuer: ISSUER,
      audience: AUDIENCE,
    });
    if (expectAnonId && claims.sub !== expectAnonId) {
      return { valid: false, reason: 'sub-mismatch' };
    }
    if (claims.scope !== 'subscription') {
      return { valid: false, reason: 'wrong-scope' };
    }
    return { valid: true, claims };
  } catch (err) {
    return { valid: false, reason: err.message };
  }
}

module.exports = { issueToken, verifyToken, ISSUER, AUDIENCE };
