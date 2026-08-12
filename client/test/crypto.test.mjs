import './_setup.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as nodeSign } from 'node:crypto';

import {
  base32,
  sha256,
  fingerprintOfRawKey,
  bytesToB64,
  b64ToBytes,
  importRs256VerifyKey,
  verifyJwtRs256,
} from '../www/js/crypto.js';

const b64u = (buf) =>
  Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// Craft a real RS256 JWT with node:crypto (no jsonwebtoken dependency here).
function makeRs256Jwt(privatePem, kid, claims) {
  const header = b64u(Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid })));
  const payload = b64u(Buffer.from(JSON.stringify(claims)));
  const signingInput = `${header}.${payload}`;
  const sig = nodeSign('sha256', Buffer.from(signingInput), privatePem); // PKCS1 v1.5
  return `${signingInput}.${b64u(sig)}`;
}

test('base32 + fingerprint are deterministic', async () => {
  const bytes = new Uint8Array(32).map((_, i) => (i * 7 + 3) & 255);
  assert.equal(base32(await sha256(bytes)), base32(await sha256(bytes)));
  const fp = await fingerprintOfRawKey(bytes);
  assert.match(fp, /^[A-Z2-7]{20}$/);
  assert.equal(fp, await fingerprintOfRawKey(bytes));
});

test('base64 round-trips', () => {
  const bytes = new Uint8Array([0, 1, 2, 250, 251, 255, 128, 64]);
  assert.deepEqual([...b64ToBytes(bytesToB64(bytes))], [...bytes]);
});

test('verifyJwtRs256 accepts valid tokens and rejects tampered/expired/wrong-sub', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const jwk = publicKey.export({ format: 'jwk' });
  jwk.kid = 'test-kid';
  const key = await importRs256VerifyKey(jwk);

  const now = Math.floor(Date.now() / 1000);
  const base = {
    sub: 'ABCDEFGH23456789JKLM',
    scope: 'subscription',
    iss: 'text-me-secretly',
    aud: 'tms-peers',
    exp: now + 3600,
  };
  const opts = { issuer: 'text-me-secretly', audience: 'tms-peers' };

  const good = makeRs256Jwt(privatePem, 'test-kid', base);
  const claims = await verifyJwtRs256(good, key, { ...opts, expectSub: base.sub });
  assert.equal(claims && claims.sub, base.sub);

  // wrong expected sub
  assert.equal(await verifyJwtRs256(good, key, { ...opts, expectSub: 'SOMEONEELSE00000' }), null);
  // wrong audience
  assert.equal(
    await verifyJwtRs256(good, key, { issuer: 'text-me-secretly', audience: 'nope' }),
    null
  );
  // expired
  const expired = makeRs256Jwt(privatePem, 'test-kid', { ...base, exp: now - 10 });
  assert.equal(await verifyJwtRs256(expired, key, opts), null);
  // tampered signature
  assert.equal(await verifyJwtRs256(good.slice(0, -4) + 'AAAA', key, opts), null);
});
