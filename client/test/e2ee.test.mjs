import './_setup.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { E2EESession } from '../www/js/e2ee.js';
import { makeIdentity, linkedPeers } from './helpers.mjs';

function established(session) {
  return new Promise((res) => session.addEventListener('established', () => res()));
}
function nextEvent(session, name) {
  return new Promise((res) => session.addEventListener(name, (e) => res(e.detail)));
}

test('Noise XX handshake establishes and encrypts text both ways', async () => {
  const A = await makeIdentity();
  const B = await makeIdentity();
  const { a, b } = linkedPeers();

  const sa = new E2EESession(a, A, B.id, true);
  const sb = new E2EESession(b, B, A.id, false);

  const bText = nextEvent(sb, 'frame');
  const aChunk = nextEvent(sa, 'chunk');

  await Promise.all([sa.start(), sb.start()]);
  await Promise.all([established(sa), established(sb)]);

  await sa.sendJson({ t: 'text', body: 'hello over noise xx' });
  assert.equal((await bText).body, 'hello over noise xx');

  await sb.sendChunk(new Uint8Array([9, 8, 7, 6]));
  const chunk = await aChunk;
  assert.deepEqual([...chunk], [9, 8, 7, 6]);
});

test('a tampered ciphertext is rejected (Poly1305) and not rendered', async () => {
  const A = await makeIdentity();
  const B = await makeIdentity();
  const { a, b } = linkedPeers();
  const sa = new E2EESession(a, A, B.id, true);
  const sb = new E2EESession(b, B, A.id, false);
  await Promise.all([sa.start(), sb.start()]);
  await established(sb);

  let rendered = false;
  sb.addEventListener('frame', () => {
    rendered = true;
  });
  // Flip a byte in the next transport ciphertext before it reaches b.
  a.tamper = (buf) => {
    const u = new Uint8Array(buf);
    if (u[0] === 0x01) u[u.length - 1] ^= 0xff;
    b.dispatchEvent(new CustomEvent('data', { detail: u.buffer }));
    return false;
  };
  await sa.sendJson({ t: 'text', body: 'tampered' });
  await new Promise((r) => setTimeout(r, 30));
  assert.equal(rendered, false);
});

test('an identity-mismatch (MITM) is detected and dropped', async () => {
  const A = await makeIdentity();
  const B = await makeIdentity();
  const C = await makeIdentity();
  const { a, b } = linkedPeers();

  // a dials B.id, but the peer actually presents identity C.
  const sa = new E2EESession(a, A, B.id, true);
  const sc = new E2EESession(b, C, A.id, false);

  const insecure = new Promise((res) =>
    sa.addEventListener('insecure', (e) => res(e.detail.reason))
  );
  await Promise.all([sa.start(), sc.start()]);
  assert.equal(await insecure, 'identity-mismatch');
  assert.equal(sa.established, false);
});
