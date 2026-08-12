'use strict';

// STUN-only case. config.js reads the environment once at module load and
// caches it, so this assertion needs its own process/file with no TURN env
// set — separate from turn.test.js (which sets TURN_URLS + TURN_SECRET).

const os = require('os');
const path = require('path');
const fs = require('fs');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tms-turn-health-'));
process.env.JWT_PRIVATE_KEY_PATH = path.join(tmp, 'priv.pem');
process.env.JWT_PUBLIC_KEY_PATH = path.join(tmp, 'pub.pem');
process.env.STUN_URLS = 'stun:stun.example.com:3478';
// Deliberately NO TURN_URLS / TURN_SECRET — STUN-only deployment.
delete process.env.TURN_URLS;
delete process.env.TURN_SECRET;

const { test } = require('node:test');
const assert = require('node:assert/strict');
const turn = require('../src/turn');

test('status() reports STUN-only: not configured, not misconfigured', () => {
  const s = turn.status();
  assert.equal(s.turnConfigured, false);
  assert.equal(s.misconfigured, false);
  assert.equal(s.stunCount, 1);
  assert.equal(s.turnCount, 0);
});

test('selfTest() returns not-configured (never throws) when STUN-only', () => {
  const st = turn.selfTest();
  assert.equal(st.ok, false);
  assert.equal(st.reason, 'not-configured');
});
