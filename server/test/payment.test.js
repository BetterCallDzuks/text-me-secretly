'use strict';

// Payment gateway tests. Cover the MOCK path deterministically (no real Stripe,
// no network, no keys) and the Stripe webhook STATE TRANSITIONS by driving the
// pure `handleStripeEvent` handler with synthesized event objects — the
// signature check (`constructWebhookEvent`) is not exercised here so no keys or
// network are needed.

// payment -> config generates an RSA keypair on first require; steer it to a
// throwaway temp dir, and make sure no Stripe env leaks in so we stay in mock
// mode.
const os = require('os');
const path = require('path');
const fs = require('fs');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tms-pay-'));
process.env.JWT_PRIVATE_KEY_PATH = path.join(tmp, 'priv.pem');
process.env.JWT_PUBLIC_KEY_PATH = path.join(tmp, 'pub.pem');
delete process.env.STRIPE_SECRET_KEY;
delete process.env.STRIPE_PRICE_ID;
process.env.SUBSCRIPTION_TTL_DAYS = '30';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const config = require('../src/config');
const payment = require('../src/payment');

// Unique ids per test so the shared in-memory store can't cross-contaminate.
let n = 0;
const anon = () => `TESTANON${String(n++).padStart(6, '0')}XX`;

const DAY = 24 * 60 * 60 * 1000;

test('mock mode is the default with no Stripe keys', () => {
  assert.equal(config.stripeEnabled, false);
});

test('createCheckout (mock) marks the anonId paid immediately', async () => {
  const id = anon();
  assert.equal(payment.isActive(id), false);

  const checkout = await payment.createCheckout(id, 30);
  assert.equal(checkout.provider, 'mock');
  assert.equal(checkout.paid, true);
  assert.equal(checkout.checkoutUrl, null);
  assert.ok(checkout.expiresAt > Date.now());

  assert.equal(payment.isActive(id), true);
  assert.equal(payment.paidUntil(id), checkout.expiresAt);
});

test('paidUntil is 0 / isActive false for an unknown anonId', () => {
  const id = anon();
  assert.equal(payment.paidUntil(id), 0);
  assert.equal(payment.isActive(id), false);
});

test('an expired subscription reports lapsed and is purged', () => {
  const id = anon();
  // Directly seed an already-past expiry via markPaid, then read it back.
  payment.markPaid(id, Date.now() - 1000);
  assert.equal(payment.paidUntil(id), 0);
  assert.equal(payment.isActive(id), false);
});

test('markPaid only ever extends (out-of-order webhooks cannot shorten)', () => {
  const id = anon();
  const far = Date.now() + 60 * DAY;
  const near = Date.now() + 1 * DAY;
  payment.markPaid(id, far);
  payment.markPaid(id, near); // older/earlier — must be ignored
  assert.equal(payment.paidUntil(id), far);
});

test('webhook checkout.session.completed marks paid (client_reference_id)', () => {
  const id = anon();
  const res = payment.handleStripeEvent({
    type: 'checkout.session.completed',
    data: { object: { client_reference_id: id } },
  });
  assert.equal(res.handled, true);
  assert.equal(res.anonId, id);
  assert.equal(payment.isActive(id), true);
  // Roughly the configured TTL out.
  const until = payment.paidUntil(id);
  assert.ok(until > Date.now() + (config.subscriptionTtlDays - 1) * DAY);
});

test('webhook checkout.session.completed also reads metadata.anonId', () => {
  const id = anon();
  const res = payment.handleStripeEvent({
    type: 'checkout.session.completed',
    data: { object: { metadata: { anonId: id } } },
  });
  assert.equal(res.handled, true);
  assert.equal(payment.isActive(id), true);
});

test('webhook subscription.updated extends to current_period_end when active', () => {
  const id = anon();
  const periodEnd = Math.floor((Date.now() + 45 * DAY) / 1000); // unix seconds
  const res = payment.handleStripeEvent({
    type: 'customer.subscription.updated',
    data: {
      object: { status: 'active', current_period_end: periodEnd, metadata: { anonId: id } },
    },
  });
  assert.equal(res.action, 'extended');
  assert.equal(payment.paidUntil(id), periodEnd * 1000);
});

test('webhook subscription.updated clears paid when not active', () => {
  const id = anon();
  payment.markPaid(id, Date.now() + 30 * DAY);
  const res = payment.handleStripeEvent({
    type: 'customer.subscription.updated',
    data: { object: { status: 'canceled', metadata: { anonId: id } } },
  });
  assert.equal(res.action, 'cleared');
  assert.equal(payment.isActive(id), false);
});

test('webhook subscription.deleted clears the subscription', () => {
  const id = anon();
  payment.markPaid(id, Date.now() + 30 * DAY);
  assert.equal(payment.isActive(id), true);
  const res = payment.handleStripeEvent({
    type: 'customer.subscription.deleted',
    data: { object: { metadata: { anonId: id } } },
  });
  assert.equal(res.action, 'cleared');
  assert.equal(payment.isActive(id), false);
});

test('webhook ignores unrelated event types without touching state', () => {
  const id = anon();
  payment.markPaid(id, Date.now() + 30 * DAY);
  const res = payment.handleStripeEvent({
    type: 'invoice.payment_succeeded',
    data: { object: {} },
  });
  assert.equal(res.handled, false);
  assert.equal(payment.isActive(id), true); // untouched
});

test('webhook is a no-op when the event carries no anonId', () => {
  const res = payment.handleStripeEvent({
    type: 'checkout.session.completed',
    data: { object: {} },
  });
  assert.equal(res.handled, false);
  assert.equal(res.action, 'no-anon-id');
});
