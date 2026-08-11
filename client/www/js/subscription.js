// subscription.js — freemium enforcement, done locally on BOTH peers.
//
// The server never sees messages, so it cannot count them. Instead:
//
//   * Every client keeps a durable per-contact counter (contactId -> count).
//   * Sender AND receiver each increment their own counter for the same
//     conversation, so the limit is enforced symmetrically even if one side is
//     malicious or patched — the honest side still stops rendering.
//   * Once a contact's count reaches the free limit (20), further messages
//     require the SENDER to present a valid, server-signed subscription token.
//     The receiver verifies it before rendering; the sender withholds sending
//     until it holds one.
//
// The token proves "this anonId has paid" — it is NOT per-contact, so one
// subscription unlocks all of the subscriber's contacts (a business choice; the
// per-contact free tier still applies to the OTHER party until they subscribe).

import { store } from './storage.js';
import { CONFIG } from './config.js';
import { importRs256VerifyKey, verifyJwtRs256 } from './crypto.js';

const COUNT_KEY = 'tms.counts'; // { [contactId]: number }
const TOKEN_KEY = 'tms.subToken'; // { token, expiresAt }
const PUBKEY_KEY = 'tms.pubjwk'; // cached server signing key (JWK)

const JWT_ISSUER = 'text-me-secretly';
const JWT_AUDIENCE = 'tms-peers';

let serverConfig = { freeMessagesPerContact: 20, priceCents: 500, currency: 'EUR' };

export function setServerConfig(cfg) {
  serverConfig = { ...serverConfig, ...cfg };
}

export function freeLimit() {
  return serverConfig.freeMessagesPerContact;
}

// ---- Per-contact counting --------------------------------------------------

async function loadCounts() {
  return (await store.get(COUNT_KEY)) || {};
}

export async function getCount(contactId) {
  const counts = await loadCounts();
  return counts[contactId] || 0;
}

/** Increment and persist a contact's counter; returns the new count. */
export async function bumpCount(contactId) {
  const counts = await loadCounts();
  counts[contactId] = (counts[contactId] || 0) + 1;
  await store.set(COUNT_KEY, counts);
  return counts[contactId];
}

/**
 * Is the NEXT message to/from this contact still free?
 * True while count < limit.
 */
export async function isWithinFreeTier(contactId) {
  return (await getCount(contactId)) < freeLimit();
}

// ---- Subscription token cache ---------------------------------------------

export async function getToken() {
  const cached = await store.get(TOKEN_KEY);
  if (cached && cached.expiresAt && cached.expiresAt > Date.now()) return cached.token;
  return null;
}

export async function hasActiveSubscription() {
  return (await getToken()) !== null;
}

async function saveToken(token, expiresAt) {
  await store.set(TOKEN_KEY, { token, expiresAt });
}

// ---- Server interaction (mock payment -> signed proof) ---------------------

let apiBase = '';
export function setApiBase(base) {
  apiBase = base.replace(/\/$/, '');
}

// ---- Server public key (for OFFLINE token verification) --------------------

let verifyKeyPromise = null;

/**
 * Fetch (and cache) the server's RSA public JWK, then import it as a
 * non-extractable verify key. Cached in storage so verification keeps working
 * offline after the first successful fetch.
 *
 * For production you can PIN the key by shipping the expected `kid` in config
 * and rejecting a mismatch here.
 */
async function getVerifyKey() {
  if (verifyKeyPromise) return verifyKeyPromise;
  verifyKeyPromise = (async () => {
    let jwk = null;
    try {
      const res = await fetch(`${apiBase}/api/pubkey`);
      if (res.ok) {
        const data = await res.json();
        jwk = data.jwk;
        await store.set(PUBKEY_KEY, jwk);
      }
    } catch {
      /* fall through to cached copy */
    }
    if (!jwk) jwk = await store.get(PUBKEY_KEY);
    if (!jwk) return null;

    // Optional key pinning: reject a public key whose kid isn't the expected
    // one (defends against a swapped signing key).
    if (CONFIG.EXPECTED_JWT_KID && jwk.kid !== CONFIG.EXPECTED_JWT_KID) {
      return null;
    }
    return importRs256VerifyKey(jwk);
  })();
  return verifyKeyPromise;
}

/** Warm the public key cache at startup (best-effort). */
export async function preloadVerifyKey() {
  try {
    await getVerifyKey();
  } catch {
    /* ignore */
  }
}

/** Kick off the (mocked) purchase and cache the returned proof token. */
export async function subscribe(anonId) {
  const res = await fetch(`${apiBase}/api/subscribe`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ anonId }),
  });
  if (!res.ok) throw new Error(`subscribe failed: ${res.status}`);
  const data = await res.json();
  await saveToken(data.token, data.expiresAt);
  return data;
}

/**
 * Verify a peer's presented subscription token.
 *
 * Primary path: OFFLINE RS256 verification with the server's public key — no
 * network call, no metadata leak. The token's `sub` must equal the peer's
 * anonId so a token can't be reused by a different peer.
 *
 * Fallback path: if the public key can't be obtained (e.g. first run while
 * offline), POST to /api/verify. Returns true only if the token is valid.
 */
export async function verifyPeerToken(token, expectAnonId) {
  if (!token) return false;

  const key = await getVerifyKey();
  if (key) {
    const claims = await verifyJwtRs256(token, key, {
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
      expectSub: expectAnonId,
    });
    if (claims && claims.scope === 'subscription') return true;
    // A well-formed key that rejects the token is authoritative — don't fall
    // back to the server (which would only reach the same verdict).
    return false;
  }

  // No key available: fall back to the server verify endpoint.
  try {
    const res = await fetch(`${apiBase}/api/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token, expectAnonId }),
    });
    if (!res.ok) return false;
    const data = await res.json();
    return data.valid === true;
  } catch {
    return false;
  }
}
