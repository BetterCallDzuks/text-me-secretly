'use strict';

// Payment gateway — dual-mode (mock by default, real Stripe when configured).
//
// This module is the ONLY place in the server that talks to a real PSP. It
// deliberately knows nothing about messages or contacts — it only answers one
// question: "has this anonymous ID paid for the current period, and until
// when?" The rest of the server treats it as an opaque oracle.
//
// Mode is decided once, at load time, by `config.stripeEnabled`:
//   - MOCK   (no keys): `createCheckout` auto-marks the anonId paid and the
//            server hands back a token immediately. Zero external deps — this
//            keeps dev + the whole test suite green with no Stripe account.
//   - STRIPE (STRIPE_SECRET_KEY + STRIPE_PRICE_ID set): `createCheckout`
//            creates a hosted Stripe Checkout Session and returns its URL; the
//            anonId is NOT paid until Stripe calls our webhook, which flips the
//            in-memory store via `handleStripeEvent`.
//
// The Stripe SDK is loaded lazily so that when no keys are present the module
// (and the tests) never even require it.

const crypto = require('crypto');
const config = require('./config');

// In-memory store of "who has paid, until when (ms epoch)". A real deployment
// would replace this Map with a durable store (Postgres/Redis) fed by the
// Stripe webhook and keyed by the anonymous ID (still no PII). We keep it in
// memory so the demo has zero external dependencies. NOTE: because it is
// in-memory, paid-state is lost on restart in BOTH modes — fine for the
// scaffolding, must be swapped for a DB before going live with Stripe.
const paidUntilByAnonId = new Map();

// Lazily-constructed Stripe client (only in Stripe mode).
let _stripe = null;
function stripeClient() {
  if (!config.stripeEnabled) return null;
  if (!_stripe) {
    // eslint-disable-next-line global-require
    const Stripe = require('stripe');
    _stripe = Stripe(config.stripeSecretKey);
  }
  return _stripe;
}

/**
 * Record that an anonId has paid until `untilMs`. Idempotent; only ever
 * extends to the later expiry so out-of-order webhooks can't shorten a
 * subscription. Exported for the webhook handler (and tests).
 */
function markPaid(anonId, untilMs) {
  if (!anonId || !Number.isFinite(untilMs)) return;
  const current = paidUntilByAnonId.get(anonId) || 0;
  paidUntilByAnonId.set(anonId, Math.max(current, untilMs));
}

/** Forget an anonId's subscription entirely (e.g. subscription cancelled). */
function clearPaid(anonId) {
  if (anonId) paidUntilByAnonId.delete(anonId);
}

/**
 * Begin a checkout for an anonymous ID.
 *
 * Always returns a Promise resolving to a descriptor with a `provider` and a
 * `paid` flag so the caller can branch:
 *   - mock:   { provider:'mock',   paid:true,  expiresAt, checkoutUrl:null, checkoutId }
 *   - stripe: { provider:'stripe', paid:false, expiresAt:null, checkoutUrl, checkoutId }
 *
 * In mock mode the anonId is marked paid immediately (so the handshake can be
 * exercised end to end). In Stripe mode nothing is marked paid here — that only
 * happens when the webhook confirms the payment.
 *
 * @param {string} anonId  Anonymous client identifier.
 * @param {number} ttlDays Subscription length (used for the mock; Stripe uses
 *                         the price's real billing period).
 */
async function createCheckout(anonId, ttlDays) {
  if (config.stripeEnabled) {
    const stripe = stripeClient();
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [{ price: config.stripePriceId, quantity: 1 }],
      // Carry the anonId both ways so the webhook can recover it whether it
      // arrives on the checkout session or on the subscription object.
      client_reference_id: anonId,
      metadata: { anonId },
      subscription_data: { metadata: { anonId } },
      success_url: config.stripeSuccessUrl,
      cancel_url: config.stripeCancelUrl,
    });

    return {
      provider: 'stripe',
      checkoutId: session.id,
      checkoutUrl: session.url,
      paid: false, // flipped later by the webhook
      expiresAt: null,
    };
  }

  // --- Mock path: auto-"pay" immediately -----------------------------------
  const now = Date.now();
  const expiresAt = now + ttlDays * 24 * 60 * 60 * 1000;
  markPaid(anonId, expiresAt);

  return {
    provider: 'mock',
    checkoutId: 'cs_mock_' + crypto.randomBytes(8).toString('hex'),
    checkoutUrl: null,
    paid: true,
    expiresAt,
  };
}

/**
 * Return the timestamp (ms) until which this anon ID is considered subscribed,
 * or 0 if there is no active subscription. Same contract in both modes.
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

// --- Stripe webhook handling ------------------------------------------------

/**
 * Verify a raw webhook request and return the parsed Stripe event. Throws if
 * the signature is invalid or Stripe is not configured — the route turns that
 * into an HTTP 400. Kept separate from `handleStripeEvent` so the state
 * transitions can be unit-tested without a signature/network.
 *
 * @param {Buffer|string} rawBody   The UNPARSED request body (express.raw).
 * @param {string} signature        The `Stripe-Signature` header.
 * @returns {object} the verified Stripe Event.
 */
function constructWebhookEvent(rawBody, signature) {
  const stripe = stripeClient();
  if (!stripe) throw new Error('stripe-not-configured');
  return stripe.webhooks.constructEvent(
    rawBody,
    signature,
    config.stripeWebhookSecret
  );
}

/**
 * Apply a (already-verified) Stripe event to the paid-state store. Pure w.r.t.
 * I/O — no network, no signature check — so tests can drive it with synthesized
 * event objects. Returns a small summary for logging/testing.
 *
 * Handled events:
 *   - checkout.session.completed        → mark paid (period from ttl fallback)
 *   - customer.subscription.created     → mark paid until current_period_end
 *   - customer.subscription.updated     → extend if active, else clear
 *   - customer.subscription.deleted     → clear
 *
 * @param {object} event  A Stripe Event object.
 * @returns {{ handled: boolean, type: string, anonId: (string|null), action: string }}
 */
function handleStripeEvent(event) {
  const type = event && event.type;
  const object = (event && event.data && event.data.object) || {};

  switch (type) {
    case 'checkout.session.completed': {
      const anonId = object.client_reference_id || (object.metadata && object.metadata.anonId);
      if (!anonId) return { handled: false, type, anonId: null, action: 'no-anon-id' };
      // The checkout session alone doesn't carry the subscription period end;
      // grant the configured TTL now — the follow-up subscription.* events will
      // set the exact period. (A production handler could retrieve the
      // subscription here for the precise end.)
      const until = Date.now() + config.subscriptionTtlDays * 24 * 60 * 60 * 1000;
      markPaid(anonId, until);
      return { handled: true, type, anonId, action: 'paid' };
    }

    case 'customer.subscription.created':
    case 'customer.subscription.updated': {
      const anonId = object.metadata && object.metadata.anonId;
      if (!anonId) return { handled: false, type, anonId: null, action: 'no-anon-id' };
      const active = object.status === 'active' || object.status === 'trialing';
      if (active && object.current_period_end) {
        markPaid(anonId, object.current_period_end * 1000);
        return { handled: true, type, anonId, action: 'extended' };
      }
      clearPaid(anonId);
      return { handled: true, type, anonId, action: 'cleared' };
    }

    case 'customer.subscription.deleted': {
      const anonId = object.metadata && object.metadata.anonId;
      if (!anonId) return { handled: false, type, anonId: null, action: 'no-anon-id' };
      clearPaid(anonId);
      return { handled: true, type, anonId, action: 'cleared' };
    }

    default:
      return { handled: false, type, anonId: null, action: 'ignored' };
  }
}

module.exports = {
  createCheckout,
  paidUntil,
  isActive,
  // Stripe-mode helpers (no-ops / unused in mock mode):
  markPaid,
  clearPaid,
  constructWebhookEvent,
  handleStripeEvent,
  // Handy for callers/tests that want to branch on mode without re-reading env.
  stripeEnabled: config.stripeEnabled,
};
