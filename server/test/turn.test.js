'use strict';

const os = require('os');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tms-turn-'));
process.env.JWT_PRIVATE_KEY_PATH = path.join(tmp, 'priv.pem');
process.env.JWT_PUBLIC_KEY_PATH = path.join(tmp, 'pub.pem');
process.env.STUN_URLS = 'stun:stun.example.com:3478';
process.env.TURN_URLS = 'turn:turn.example.com:3478?transport=udp';
process.env.TURN_SECRET = 'shared-secret-for-tests';
process.env.TURN_TTL_SECONDS = '3600';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const turn = require('../src/turn');

const ANON = 'ABCDEFGH23456789JKLM';

test('ice list includes STUN and TURN with coturn-valid ephemeral credentials', () => {
  const { iceServers, ttl } = turn.iceServers(ANON);
  assert.equal(ttl, 3600);

  const stun = iceServers.find((s) => String(s.urls).includes('stun:'));
  assert.ok(stun, 'has STUN');

  const t = iceServers.find((s) => Array.isArray(s.urls) && String(s.urls[0]).startsWith('turn'));
  assert.ok(t, 'has TURN');

  // username = "<unix-expiry>:<anonId>"
  assert.match(t.username, new RegExp(`^\\d+:${ANON}$`));

  // credential must equal base64(HMAC-SHA1(secret, username)) — what coturn checks.
  const expected = crypto
    .createHmac('sha1', 'shared-secret-for-tests')
    .update(t.username)
    .digest('base64');
  assert.equal(t.credential, expected);
});

test('status() reports configured with correct counts and no secrets', () => {
  const s = turn.status();
  assert.equal(s.turnConfigured, true);
  assert.equal(s.misconfigured, false);
  assert.equal(s.stunCount, 1);
  assert.equal(s.turnCount, 1);
  assert.equal(s.ttlSeconds, 3600);

  // Defense against accidental leakage: no value equals the secret or a
  // freshly generated credential.
  const { iceServers } = turn.iceServers(ANON);
  const cred = iceServers.find((x) => x.credential).credential;
  for (const v of Object.values(s)) {
    assert.notEqual(v, 'shared-secret-for-tests');
    assert.notEqual(v, cred);
  }
  // And no username/credential/secret keys at all.
  assert.deepEqual(
    Object.keys(s).sort(),
    ['misconfigured', 'stunCount', 'ttlSeconds', 'turnConfigured', 'turnCount']
  );
});

test('selfTest() returns { ok: true } when TURN is configured', () => {
  const st = turn.selfTest();
  assert.equal(st.ok, true);
  assert.equal(st.reason, undefined);

  // The generated TURN entry must carry username + credential.
  const { iceServers } = turn.iceServers('probe1234abcd');
  const t = iceServers.find((x) => x.username && x.credential);
  assert.ok(t, 'TURN entry has username + credential');
});
