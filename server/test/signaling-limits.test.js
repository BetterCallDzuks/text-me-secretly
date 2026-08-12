'use strict';

// Exercises the abuse/DoS hardening in the signaling relay with real ws clients:
//   - a normal client is unaffected (still registers + routes verbatim),
//   - the per-connection message rate limit throttles a burst,
//   - the per-IP concurrent-connection cap rejects the excess socket.
//
// Each concern spins up its own server with tuned limits so the tests are
// isolated and deterministic (all clients come from 127.0.0.1).

const os = require('os');
const path = require('path');
const fs = require('fs');
const http = require('http');
const { test } = require('node:test');
const assert = require('node:assert/strict');
const WebSocket = require('ws');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tms-sig-limits-'));
process.env.JWT_PRIVATE_KEY_PATH = path.join(tmp, 'priv.pem');
process.env.JWT_PUBLIC_KEY_PATH = path.join(tmp, 'pub.pem');

const { attachSignaling } = require('../src/signaling');

function withTimeout(promise, ms, label) {
  return Promise.race([
    promise,
    new Promise((_, rej) => setTimeout(() => rej(new Error(`timeout: ${label}`)), ms)),
  ]);
}

const delay = (ms) => new Promise((r) => setTimeout(r, ms));

// Start an isolated signaling server with the given limit overrides.
async function startServer(options) {
  const server = http.createServer();
  const sig = attachSignaling(server, options);
  await new Promise((res) => server.listen(0, '127.0.0.1', res));
  const url = `ws://127.0.0.1:${server.address().port}/signal`;
  const close = async () => {
    await new Promise((res) => sig.wss.close(res)); // clears the liveness interval
    await new Promise((res) => server.close(res));
  };
  return { url, sig, close };
}

function makeClient(url) {
  const ws = new WebSocket(url);
  const queue = [];
  const waiters = [];
  ws.received = []; // every parsed inbound message, for absence/count checks
  ws.on('message', (raw) => {
    const msg = JSON.parse(raw.toString());
    ws.received.push(msg);
    const waiter = waiters.shift();
    if (waiter) waiter(msg);
    else queue.push(msg);
  });
  ws.next = (label = 'message') =>
    withTimeout(
      queue.length ? Promise.resolve(queue.shift()) : new Promise((res) => waiters.push(res)),
      2000,
      label
    );
  ws.sendJson = (o) => ws.send(JSON.stringify(o));
  ws.opened = new Promise((res, rej) => {
    ws.once('open', res);
    ws.once('error', rej);
  });
  return ws;
}

async function register(url, id) {
  const ws = makeClient(url);
  await ws.opened;
  ws.sendJson({ type: 'register', from: id });
  const ack = await ws.next('registered');
  assert.deepEqual(ack, { type: 'registered', from: id });
  return ws;
}

test('a normal client is unaffected: registers and routes verbatim', async () => {
  const { url, close } = await startServer({}); // real default limits
  try {
    const a = await register(url, 'OK-SENDER-01');
    const b = await register(url, 'OK-TARGET-01');

    const offer = {
      type: 'offer',
      from: 'OK-SENDER-01',
      to: 'OK-TARGET-01',
      sdp: { s: 'v=0\r\n…' },
    };
    a.sendJson(offer);
    assert.deepEqual(await b.next('offer'), offer); // forwarded untouched

    a.close();
    b.close();
  } finally {
    await close();
  }
});

test('the per-connection rate limit throttles a burst (extra frames dropped)', async () => {
  const RATE_MAX = 10;
  const { url, close } = await startServer({
    rateLimitMax: RATE_MAX,
    rateLimitWindowMs: 60_000, // one window, won't roll during the test
    maxConnsPerIp: 100, // don't let the IP cap interfere here
  });
  try {
    const a = await register(url, 'RL-SENDER-01'); // register = a's message #1
    const b = await register(url, 'RL-TARGET-01');

    // Fire well past the budget in one burst. The register already used slot 1,
    // so offers fill slots 2..RATE_MAX (RATE_MAX-1 routed), then the rest drop.
    const burst = 15;
    for (let i = 0; i < burst; i++) {
      a.sendJson({ type: 'offer', from: 'RL-SENDER-01', to: 'RL-TARGET-01', sdp: { i } });
    }

    // The sender is told once (and only once) that it was throttled.
    assert.deepEqual(await a.next('rate-limited'), { type: 'error', reason: 'rate-limited' });

    await delay(200); // let all routed offers settle at b
    const routed = b.received.filter((m) => m.type === 'offer');
    assert.equal(routed.length, RATE_MAX - 1, 'only in-budget offers are routed');
    // And the sender is not spammed with repeated errors.
    const errs = a.received.filter((m) => m.type === 'error' && m.reason === 'rate-limited');
    assert.equal(errs.length, 1, 'rate-limited warning is sent at most once per window');

    a.close();
    b.close();
  } finally {
    await close();
  }
});

test('the per-IP connection cap rejects connections beyond the limit', async () => {
  const CAP = 3;
  const { url, close } = await startServer({ maxConnsPerIp: CAP });
  try {
    // Open exactly CAP connections successfully.
    const accepted = [];
    for (let i = 0; i < CAP; i++) {
      const ws = makeClient(url);
      await ws.opened;
      accepted.push(ws);
    }

    // The next one from the same host (127.0.0.1) must be refused and closed
    // with the "try again later" code.
    const excess = makeClient(url);
    await excess.opened;
    const closeCode = await withTimeout(
      new Promise((res) => excess.once('close', (code) => res(code))),
      2000,
      'excess-close'
    );
    assert.equal(closeCode, 1013, 'excess connection closed with 1013 (try again later)');

    // A slot frees up when an accepted socket closes: a fresh one now succeeds.
    accepted[0].close();
    await delay(150);
    const reopened = await register(url, 'CAP-REOPEN-01');
    reopened.close();

    for (const ws of accepted.slice(1)) ws.close();
  } finally {
    await close();
  }
});
