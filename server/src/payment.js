'use strict';

// Mock payment gateway.
//
// In production this module is the ONLY place that talks to Stripe / a real
// PSP. It deliberately knows nothing about messages or contacts — it only
// answers one question: "has this anonymous ID paid for the current period?"
//
// The rest of the server treats it as an opaque oracle, so swapping in a real
// gateway later means editing only this file.

const crypto = require('crypto');

// In-memory store of "who has paid". A real deployment would replace this with
// a webhook-fed record keyed by the anonymous ID (still no PII). We keep it in
// memory so the demo has zero external dependencies.
const paidUntilByAnonId = new Map();

/**
 * Simulate creating a checkout session. Returns a fake client secret / URL that
 * a real client would open. Here we auto-"pay" so the handshake can be tested
 * end to end.
 *
 * @param {string} anonId  Anonymous client identifier.
 * @param {number} ttlDays How long the simulated subscription lasts.
 */
function createCheckout(anonId, ttlDays) {
  const now = Date.now();
  const expiresAt = now + ttlDays * 24 * 60 * 60 * 1000;

  // Mock: mark as paid immediately. Replace with real PSP redirect + webhook.
  paidUntilByAnonId.set(anonId, expiresAt);

  return {
    provider: 'mock',
    checkoutId: 'cs_mock_' + crypto.randomBytes(8).toString('hex'),
    // A real integration returns a hosted checkout URL instead.
    checkoutUrl: null,
    paid: true,
    expiresAt,
  };
}

/**
 * Return the timestamp (ms) until which this anon ID is considered subscribed,
 * or 0 if there is no active subscription.
 */
function paidUntil(anonId) {
  const until = paidUntilByAnonId.get(anonId) || 0;
  if (until && until < Date.now()) {
    paidUntilByAnonId.delete(anonId);
    return 0;
  }
  return until;
}

function isActive(anonId) {
  return paidUntil(anonId) > Date.now();
}

module.exports = { createCheckout, paidUntil, isActive };
