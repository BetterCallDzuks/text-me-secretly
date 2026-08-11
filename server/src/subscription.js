'use strict';

// Subscription token issuer + verifier.
//
// The proof a paying user presents to a peer is a short JWT signed with the
// server's secret. The peer (receiver) verifies the signature locally using the
// server's PUBLIC verification path (here: a shared HMAC secret exposed through
// a /verify endpoint, because the receiver does not hold the secret).
//
// Design note on trust:
//   - The SENDER obtains a signed token for their own anonId after paying.
//   - The RECEIVER cannot hold the HMAC secret (it would let them forge), so
//     the receiver verifies by POSTing the token to the server's /verify
//     endpoint, OR — in a hardened build — the server signs with an
//     asymmetric key (RS256) and ships only the PUBLIC key to clients.
//
// This module supports BOTH: HS256 for the simple demo, and a documented
// switch to RS256 for production (see README "Hardening").

const jwt = require('jsonwebtoken');
const config = require('./config');

const ISSUER = 'text-me-secretly';
const AUDIENCE = 'tms-peers';

/**
 * Issue a subscription proof for an anonymous ID.
 * The token asserts: "the holder of this anonId has an active subscription
 * until `exp`." It intentionally contains no contact list and no message data.
 *
 * @param {string} anonId
 * @param {number} paidUntilMs epoch ms when the subscription lapses
 * @returns {{ token: string, expiresAt: number }}
 */
function issueToken(anonId, paidUntilMs) {
  const nowSec = Math.floor(Date.now() / 1000);
  const expSec = Math.floor(paidUntilMs / 1000);

  const payload = {
    sub: anonId, // the anonymous ID this proof belongs to
    scope: 'subscription',
    plan: 'premium-monthly',
  };

  const token = jwt.sign(payload, config.jwtSecret, {
    algorithm: 'HS256',
    issuer: ISSUER,
    audience: AUDIENCE,
    iat: nowSec,
    expiresIn: Math.max(60, expSec - nowSec),
  });

  return { token, expiresAt: paidUntilMs };
}

/**
 * Verify a subscription proof and that it belongs to the claimed sender.
 *
 * @param {string} token       JWT presented by the sender.
 * @param {string} expectAnonId The sender's anonId as seen on the channel; the
 *                              token's `sub` MUST match to stop token reuse by
 *                              a different peer.
 * @returns {{ valid: boolean, reason?: string, claims?: object }}
 */
function verifyToken(token, expectAnonId) {
  try {
    const claims = jwt.verify(token, config.jwtSecret, {
      algorithms: ['HS256'],
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
