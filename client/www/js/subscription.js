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

const COUNT_KEY = 'tms.counts'; // { [contactId]: number }
const TOKEN_KEY = 'tms.subToken'; // { token, expiresAt }

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
 * Verify a peer's presented token. In the HS256 demo the receiver cannot hold
 * the secret, so it asks the server. (A hardened RS256 build verifies locally.)
 * Returns true if the token is valid AND belongs to `expectAnonId`.
 */
export async function verifyPeerToken(token, expectAnonId) {
  if (!token) return false;
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
