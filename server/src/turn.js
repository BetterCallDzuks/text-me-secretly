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

/**
 * Secret-free summary of the TURN configuration, safe to expose to ops/clients.
 * Never includes the shared secret, URL-embedded credentials, or any generated
 * ephemeral credential.
 *
 * @returns {{ turnConfigured: boolean, misconfigured: boolean,
 *             stunCount: number, turnCount: number, ttlSeconds: number }}
 */
function status() {
  const hasUrls = config.turnUrls.length > 0;
  const hasSecret = Boolean(config.turnSecret);
  return {
    turnConfigured: hasUrls && hasSecret,
    // Exactly one of the two set — a half-configured deployment (a footgun).
    misconfigured: hasUrls !== hasSecret,
    stunCount: config.stunUrls.length,
    turnCount: config.turnUrls.length,
    ttlSeconds: config.turnTtlSeconds,
  };
}

/**
 * Startup self-test. When TURN is configured, actually exercises the HMAC
 * credential path (generates an ICE list for a probe id) and confirms a TURN
 * entry with a non-empty username + credential comes out. Never throws.
 *
 * @returns {{ ok: boolean, reason?: string }}
 */
function selfTest() {
  const s = status();
  if (s.misconfigured) {
    return { ok: false, reason: 'half-configured' };
  }
  if (!s.turnConfigured) {
    return { ok: false, reason: 'not-configured' };
  }
  try {
    const { iceServers: servers } = iceServers('selftestprobe');
    const turnEntry = servers.find((srv) => srv.username && srv.credential);
    if (!turnEntry) {
      return { ok: false, reason: 'no-turn-entry' };
    }
    return { ok: true };
  } catch (err) {
    return { ok: false, reason: err.message };
  }
}

module.exports = { iceServers, status, selfTest };
