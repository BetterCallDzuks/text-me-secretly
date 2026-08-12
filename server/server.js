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
const turn = require('./src/turn');
const { attachSignaling } = require('./src/signaling');

const app = express();

// --- Stripe webhook (RAW body) ---------------------------------------------
// MUST be mounted BEFORE the global express.json() below: Stripe signature
// verification needs the exact bytes it signed, so this route gets the raw
// buffer and the JSON parser never touches it. No-op path in mock mode (Stripe
// simply never calls it).
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  if (!config.stripeEnabled) {
    return res.status(404).json({ error: 'stripe-not-enabled' });
  }
  const signature = req.headers['stripe-signature'];
  let event;
  try {
    event = payment.constructWebhookEvent(req.body, signature);
  } catch (err) {
    // Bad/missing signature, replayed, or malformed — reject.
    return res.status(400).json({ error: 'invalid-signature' });
  }

  // Apply the state transition (mark/extend/clear paid). Persisted in the
  // same in-memory store the mock uses — swap for a DB in production.
  const result = payment.handleStripeEvent(event);
  return res.status(200).json({ received: true, handled: result.handled });
});

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
app.post('/api/subscribe', apiLimiter, async (req, res) => {
  const anonId = req.body && req.body.anonId;
  if (typeof anonId !== 'string' || !ANON_ID_RE.test(anonId)) {
    return res.status(400).json({ error: 'invalid-anon-id' });
  }

  let checkout;
  try {
    checkout = await payment.createCheckout(anonId, config.subscriptionTtlDays);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('[tms] checkout creation failed:', err.message);
    return res.status(502).json({ error: 'checkout-failed' });
  }

  if (!checkout.paid) {
    // Stripe path: hand back the hosted checkout URL. The client opens it, pays,
    // and a webhook flips the paid state; the client then calls /api/token to
    // collect its RS256 proof. No token here — payment isn't confirmed yet.
    return res.status(200).json({
      paid: false,
      provider: checkout.provider,
      checkoutUrl: checkout.checkoutUrl,
    });
  }

  // Mock path: auto-paid, so issue the proof token immediately (today's shape).
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

// --- Public signing key: clients verify peer tokens OFFLINE with this -------
// Served as a JWK so the browser can import it via SubtleCrypto. The private
// key never leaves the server.
app.get('/api/pubkey', (req, res) => {
  res.set('Cache-Control', 'public, max-age=3600');
  res.json({ alg: 'RS256', kid: config.jwtKid, jwk: config.jwtPublicJwk });
});

// --- Verify a peer's token (FALLBACK) --------------------------------------
// The client's default is offline verification with /api/pubkey. This endpoint
// stays for clients that cannot import the key, and for diagnostics.
app.post('/api/verify', apiLimiter, (req, res) => {
  const { token, expectAnonId } = req.body || {};
  if (typeof token !== 'string') {
    return res.status(400).json({ error: 'missing-token' });
  }
  const result = subscription.verifyToken(token, expectAnonId);
  res.status(result.valid ? 200 : 401).json(result);
});

// --- ICE servers (STUN + ephemeral TURN credentials) -----------------------
// Called by the client just before opening a peer connection so TURN can relay
// when direct P2P fails behind symmetric NAT. TURN only ever carries encrypted
// media.
app.post('/api/turn', apiLimiter, (req, res) => {
  const anonId = req.body && req.body.anonId;
  const safeId = typeof anonId === 'string' && ANON_ID_RE.test(anonId) ? anonId : undefined;
  res.json(turn.iceServers(safeId));
});

app.get('/api/health', (req, res) => res.json({ ok: true, ts: Date.now() }));

// --- TURN diagnostics (secret-free, safe to expose to ops/clients) ---------
app.get('/api/turn/health', (req, res) => res.json(turn.status()));

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

  // TURN startup self-test — log a clear one-liner, never crash on misconfig.
  const ts = turn.status();
  /* eslint-disable no-console */
  if (ts.misconfigured) {
    console.warn('[tms] TURN: half-configured — set BOTH TURN_URLS and TURN_SECRET, or neither');
  } else if (ts.turnConfigured) {
    const st = turn.selfTest();
    if (st.ok) {
      console.log(`[tms] TURN: configured, credential self-test ok (ttl=${ts.ttlSeconds}s)`);
    } else {
      console.warn(`[tms] TURN: configured but self-test FAILED (${st.reason})`);
    }
  } else {
    console.log('[tms] TURN: not configured (STUN-only)');
  }
  /* eslint-enable no-console */
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
