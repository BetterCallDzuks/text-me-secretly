'use strict';

// Exercises the real WebSocket signaling relay end-to-end with real ws clients:
// registration, point-to-point routing (verbatim, content-blind), and the error
// paths (bad id, not-registered, unavailable, displaced).

// Keys land in a temp dir (config is loaded transitively via signaling? no —
// signaling has no config dep, but keep the env hygienic for any transitive load).
const os = require('os');
const path = require('path');
const fs = require('fs');
const http = require('http');
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const WebSocket = require('ws');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tms-sig-'));
process.env.JWT_PRIVATE_KEY_PATH = path.join(tmp, 'priv.pem');
process.env.JWT_PUBLIC_KEY_PATH = path.join(tmp, 'pub.pem');

const { attachSignaling } = require('../src/signaling');

let server;
let sig;
let url;

before(async () => {
  server = http.createServer();
  sig = attachSignaling(server);
  await new Promise((res) => server.listen(0, '127.0.0.1', res));
  url = `ws://127.0.0.1:${server.address().port}/signal`;
});

after(async () => {
  await new Promise((res) => sig.wss.close(res)); // clears the liveness interval
  await new Promise((res) => server.close(res));
});

function withTimeout(promise, ms, label) {
  return Promise.race([
    promise,
    new Promise((_, rej) => setTimeout(() => rej(new Error(`timeout: ${label}`)), ms)),
  ]);
}

function makeClient() {
  const ws = new WebSocket(url);
  const queue = [];
  const waiters = [];
  ws.on('message', (raw) => {
    const msg = JSON.parse(raw.toString());
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

async function register(id) {
  const ws = makeClient();
  await ws.opened;
  ws.sendJson({ type: 'register', from: id });
  const ack = await ws.next('registered');
  assert.deepEqual(ack, { type: 'registered', from: id });
  return ws;
}

test('registration acknowledges the self-chosen id', async () => {
  const a = await register('PEER-AAAA1111');
  a.close();
});

test('an invalid anonId is rejected with bad-id', async () => {
  const ws = makeClient();
  await ws.opened;
  ws.sendJson({ type: 'register', from: 'short' }); // < 8 chars
  assert.deepEqual(await ws.next('bad-id'), { type: 'error', reason: 'bad-id' });
  ws.close();
});

test('offers are routed verbatim to the target peer', async () => {
  const a = await register('ROUTE-A-0001');
  const b = await register('ROUTE-B-0002');

  const offer = { type: 'offer', from: 'ROUTE-A-0001', to: 'ROUTE-B-0002', sdp: { s: 'v=0\r\n…' } };
  a.sendJson(offer);
  assert.deepEqual(await b.next('offer'), offer); // forwarded untouched, incl. sdp

  a.close();
  b.close();
});

test('routing before registration is refused (not-registered)', async () => {
  const ws = makeClient();
  await ws.opened;
  ws.sendJson({ type: 'offer', from: 'NOPE-0001', to: 'SOMEONE-0002', sdp: {} });
  assert.deepEqual(await ws.next('not-registered'), { type: 'error', reason: 'not-registered' });
  ws.close();
});

test('a from that does not match the socket is refused', async () => {
  const a = await register('SPOOF-A-0001');
  a.sendJson({ type: 'offer', from: 'SOMEONE-ELSE-1', to: 'X', sdp: {} });
  assert.deepEqual(await a.next('spoof'), { type: 'error', reason: 'not-registered' });
  a.close();
});

test('messaging an offline peer returns unavailable', async () => {
  const a = await register('LONELY-A-0001');
  a.sendJson({ type: 'offer', from: 'LONELY-A-0001', to: 'GHOST-0002', sdp: {} });
  assert.deepEqual(await a.next('unavailable'), { type: 'unavailable', to: 'GHOST-0002' });
  a.close();
});

test('re-registering an id displaces the older socket', async () => {
  const first = await register('DUP-ID-00001');
  const second = makeClient();
  await second.opened;
  second.sendJson({ type: 'register', from: 'DUP-ID-00001' });

  assert.deepEqual(await first.next('displaced'), { type: 'displaced' });
  assert.deepEqual(await second.next('registered'), { type: 'registered', from: 'DUP-ID-00001' });

  first.close();
  second.close();
});

test('unknown message types are ignored (no relay of arbitrary content)', async () => {
  const ws = makeClient();
  await ws.opened;
  ws.sendJson({ type: 'chat', from: 'X', body: 'should be ignored' }); // not an allowed type
  ws.sendJson({ type: 'register', from: 'IGNORE-TEST-1' });
  // If 'chat' had produced any reply it would arrive first; the first message
  // being 'registered' proves it was dropped.
  assert.deepEqual(await ws.next('registered'), { type: 'registered', from: 'IGNORE-TEST-1' });
  ws.close();
});

test('a disconnected peer is removed from the routing map', async () => {
  const a = await register('GONE-A-0001');
  const b = await register('GONE-B-0002');

  b.close();
  await new Promise((r) => setTimeout(r, 100)); // let the close propagate

  a.sendJson({ type: 'offer', from: 'GONE-A-0001', to: 'GONE-B-0002', sdp: {} });
  assert.deepEqual(await a.next('unavailable'), { type: 'unavailable', to: 'GONE-B-0002' });
  a.close();
});
