'use strict';

// Text Me Secretly — signaling + subscription server.
//
// Two responsibilities, nothing more:
//   1. WebSocket signaling to bootstrap P2P WebRTC connections.
//   2. A tiny REST API to sell a subscription and issue a signed proof token.
//
// It NEVER stores, processes, or relays message or media content.

const http = require('http');
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const config = require('./src/config');
const payment = require('./src/payment');
const subscription = require('./src/subscription');
const { attachSignaling } = require('./src/signaling');

const app = express();
app.use(express.json({ limit: '8kb' })); // tokens are tiny; cap the body hard.

app.use(
  cors({
    origin: config.corsOrigins.includes('*') ? true : config.corsOrigins,
  })
);

// Rate limit the money/token endpoints to blunt abuse.
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
});

const ANON_ID_RE = /^[A-Za-z0-9_-]{8,64}$/;

// --- Public config the client needs to render the paywall ------------------
app.get('/api/config', (req, res) => {
  res.json({
    freeMessagesPerContact: config.freeMessagesPerContact,
    priceCents: config.subscriptionPriceCents,
    currency: config.subscriptionCurrency,
    subscriptionTtlDays: config.subscriptionTtlDays,
  });
});

// --- Buy a subscription (mock) and receive a signed proof ------------------
// The client calls this after the (mocked) payment succeeds. The returned
// token is what the sender presents to a peer during the WebRTC handshake.
app.post('/api/subscribe', apiLimiter, (req, res) => {
  const anonId = req.body && req.body.anonId;
  if (typeof anonId !== 'string' || !ANON_ID_RE.test(anonId)) {
    return res.status(400).json({ error: 'invalid-anon-id' });
  }

  const checkout = payment.createCheckout(anonId, config.subscriptionTtlDays);
  if (!checkout.paid) {
    // Real PSP path: return checkoutUrl and let a webhook flip the state.
    return res.status(402).json({ error: 'payment-required', checkout });
  }

  const { token, expiresAt } = subscription.issueToken(anonId, checkout.expiresAt);
  res.json({ token, expiresAt, plan: 'premium-monthly' });
});

// --- Re-issue a fresh token for an already-paid anon ID --------------------
app.post('/api/token', apiLimiter, (req, res) => {
  const anonId = req.body && req.body.anonId;
  if (typeof anonId !== 'string' || !ANON_ID_RE.test(anonId)) {
    return res.status(400).json({ error: 'invalid-anon-id' });
  }
  const until = payment.paidUntil(anonId);
  if (!until) return res.status(403).json({ error: 'no-active-subscription' });
  const { token, expiresAt } = subscription.issueToken(anonId, until);
  res.json({ token, expiresAt });
});

// --- Verify a peer's token (used by the RECEIVER in the HS256 demo) --------
// In an RS256 hardened build the receiver verifies locally with the public key
// and this endpoint is unnecessary. See README "Hardening".
app.post('/api/verify', apiLimiter, (req, res) => {
  const { token, expectAnonId } = req.body || {};
  if (typeof token !== 'string') {
    return res.status(400).json({ error: 'missing-token' });
  }
  const result = subscription.verifyToken(token, expectAnonId);
  res.status(result.valid ? 200 : 401).json(result);
});

app.get('/api/health', (req, res) => res.json({ ok: true, ts: Date.now() }));

// --- HTTP + WebSocket on the same port -------------------------------------
const server = http.createServer(app);
const signaling = attachSignaling(server);

app.get('/api/stats', (req, res) => res.json(signaling.stats()));

server.listen(config.port, config.host, () => {
  // eslint-disable-next-line no-console
  console.log(
    `[tms] signaling+api listening on http://${config.host}:${config.port} ` +
      `(WS path /signal) — free msgs/contact: ${config.freeMessagesPerContact}`
  );
});

function shutdown(signal) {
  // eslint-disable-next-line no-console
  console.log(`[tms] ${signal} received, closing...`);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 5000).unref();
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

module.exports = { app, server };
