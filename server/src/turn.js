'use strict';

// turn.js — ephemeral TURN credentials (coturn REST / `use-auth-secret`).
//
// Long-lived TURN passwords are a liability. Instead we mint short-TTL
// credentials on demand using the shared secret configured on the TURN server
// (coturn `static-auth-secret`):
//
//   username   = "<unix-expiry>[:anonId]"
//   credential = base64( HMAC-SHA1( secret, username ) )
//
// coturn validates the HMAC itself, so the app server and TURN server share
// only the secret — the TURN server needs no user database. TURN only ever
// relays already-encrypted media, and only when direct P2P fails.

const crypto = require('crypto');
const config = require('./config');

/**
 * Build the ICE server list a client should use. Always includes STUN; adds
 * TURN with fresh credentials when a TURN secret + URLs are configured.
 *
 * @param {string} [anonId] optional, embedded in the username for auditing
 * @returns {{ iceServers: Array, ttl: number }}
 */
function iceServers(anonId) {
  const servers = [{ urls: config.stunUrls }];

  if (config.turnUrls.length && config.turnSecret) {
    const ttl = config.turnTtlSeconds;
    const expiry = Math.floor(Date.now() / 1000) + ttl;
    const username = anonId ? `${expiry}:${anonId}` : `${expiry}`;
    const credential = crypto
      .createHmac('sha1', config.turnSecret)
      .update(username)
      .digest('base64');

    servers.push({
      urls: config.turnUrls,
      username,
      credential,
    });
    return { iceServers: servers, ttl };
  }

  return { iceServers: servers, ttl: 0 };
}

module.exports = { iceServers };
