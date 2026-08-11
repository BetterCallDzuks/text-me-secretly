'use strict';

// Point the RSA keypair at a throwaway temp dir before loading config (which
// generates the keypair on first require).
const os = require('os');
const path = require('path');
const fs = require('fs');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tms-sub-'));
process.env.JWT_PRIVATE_KEY_PATH = path.join(tmp, 'priv.pem');
process.env.JWT_PUBLIC_KEY_PATH = path.join(tmp, 'pub.pem');

const { test } = require('node:test');
const assert = require('node:assert/strict');
const subscription = require('../src/subscription');

const ANON = 'ABCDEFGH23456789JKLM';

test('issued RS256 token verifies for the right anonId', () => {
  const { token } = subscription.issueToken(ANON, Date.now() + 60_000);
  const res = subscription.verifyToken(token, ANON);
  assert.equal(res.valid, true);
  assert.equal(res.claims.sub, ANON);
  assert.equal(res.claims.scope, 'subscription');
});

test('token is rejected for a different anonId (no lending)', () => {
  const { token } = subscription.issueToken(ANON, Date.now() + 60_000);
  const res = subscription.verifyToken(token, 'SOMEONEELSE000000000');
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'sub-mismatch');
});

test('a garbage token is rejected', () => {
  assert.equal(subscription.verifyToken('not.a.jwt', ANON).valid, false);
});
