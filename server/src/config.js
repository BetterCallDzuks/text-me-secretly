'use strict';

// Central config loader. All tunables come from the environment so the same
// build runs in dev and on a VPS without code changes.
require('dotenv').config();

function int(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const n = parseInt(raw, 10);
  return Number.isFinite(n) ? n : fallback;
}

const config = {
  port: int('PORT', 8080),
  host: process.env.HOST || '127.0.0.1',

  jwtSecret: process.env.JWT_SECRET || '',

  subscriptionPriceCents: int('SUBSCRIPTION_PRICE_CENTS', 500),
  subscriptionCurrency: process.env.SUBSCRIPTION_CURRENCY || 'EUR',
  subscriptionTtlDays: int('SUBSCRIPTION_TTL_DAYS', 30),

  freeMessagesPerContact: int('FREE_MESSAGES_PER_CONTACT', 20),

  corsOrigins: (process.env.CORS_ORIGINS || '*')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean),
};

// Fail fast: a missing/weak signing secret would let anyone forge a
// subscription proof, which is the one thing the server exists to prevent.
if (!config.jwtSecret || config.jwtSecret.length < 32) {
  // eslint-disable-next-line no-console
  console.error(
    '[config] FATAL: JWT_SECRET is missing or too short (need >= 32 chars). ' +
      'Generate one with: node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'hex\'))"'
  );
  process.exit(1);
}

module.exports = config;
