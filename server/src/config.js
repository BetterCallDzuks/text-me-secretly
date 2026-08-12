'use strict';

// Central config loader. All tunables come from the environment so the same
// build runs in dev and on a VPS without code changes.
require('dotenv').config();

const { buildKeyMaterial } = require('./keys');

function int(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const n = parseInt(raw, 10);
  return Number.isFinite(n) ? n : fallback;
}

function list(name) {
  return (process.env[name] || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

// --- RS256 signing keys (auto-generated on first boot if absent) ------------
const keys = buildKeyMaterial(
  process.env.JWT_PRIVATE_KEY_PATH || './keys/jwt_private.pem',
  process.env.JWT_PUBLIC_KEY_PATH || './keys/jwt_public.pem'
);

const config = {
  port: int('PORT', 8080),
  host: process.env.HOST || '127.0.0.1',

  // RS256 asymmetric keys. `jwtSecret` (HS256) is retained only as a legacy
  // fallback for the /api/verify path and is optional now.
  jwtPrivatePem: keys.privatePem,
  jwtPublicPem: keys.publicPem,
  jwtPublicJwk: keys.publicJwk,
  jwtKid: keys.kid,
  jwtSecret: process.env.JWT_SECRET || '',

  subscriptionPriceCents: int('SUBSCRIPTION_PRICE_CENTS', 500),
  subscriptionCurrency: process.env.SUBSCRIPTION_CURRENCY || 'EUR',
  subscriptionTtlDays: int('SUBSCRIPTION_TTL_DAYS', 30),

  freeMessagesPerContact: int('FREE_MESSAGES_PER_CONTACT', 20),

  // --- Stripe (real payment gateway) ----------------------------------------
  // All optional. When STRIPE_SECRET_KEY + STRIPE_PRICE_ID are set the payment
  // module switches from the built-in mock to real Stripe Checkout; otherwise
  // it stays fully mock so dev + tests run with no keys and no network.
  stripeSecretKey: process.env.STRIPE_SECRET_KEY || '',
  stripeWebhookSecret: process.env.STRIPE_WEBHOOK_SECRET || '',
  stripePriceId: process.env.STRIPE_PRICE_ID || '',
  stripeSuccessUrl:
    process.env.STRIPE_SUCCESS_URL || 'http://localhost:8080/subscribe/success',
  stripeCancelUrl:
    process.env.STRIPE_CANCEL_URL || 'http://localhost:8080/subscribe/cancel',

  // --- ICE / TURN for NAT traversal -----------------------------------------
  stunUrls: list('STUN_URLS').length
    ? list('STUN_URLS')
    : ['stun:stun.l.google.com:19302'],
  turnUrls: list('TURN_URLS'), // e.g. turn:turn.example.com:3478?transport=udp
  turnSecret: process.env.TURN_SECRET || '', // coturn `use-auth-secret` shared secret
  turnTtlSeconds: int('TURN_TTL_SECONDS', 24 * 60 * 60),

  corsOrigins: list('CORS_ORIGINS').length ? list('CORS_ORIGINS') : ['*'],
};

// True only when we have enough to actually talk to Stripe. Everything else in
// the codebase gates real-vs-mock on this single flag.
config.stripeEnabled = Boolean(config.stripeSecretKey && config.stripePriceId);

if (keys.generated) {
  // eslint-disable-next-line no-console
  console.log(`[config] RSA keypair ready (kid=${keys.kid}).`);
}

module.exports = config;
