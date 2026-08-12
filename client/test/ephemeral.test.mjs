import './_setup.mjs';
import { test, mock } from 'node:test';
import assert from 'node:assert/strict';

// Node ships Blob but NOT URL.createObjectURL / revokeObjectURL. Shim them with
// a counter-based fake so we can assert the view-once burn behaviour: each
// create hands out a distinct blob:mock/<n> url, and every revoke is recorded.
let urlCounter = 0;
const revoked = [];
globalThis.URL.createObjectURL = () => `blob:mock/${++urlCounter}`;
globalThis.URL.revokeObjectURL = (url) => revoked.push(url);

const {
  TEXT_TTL_MS,
  trackText,
  remainingLabel,
  stashMedia,
  consumeMedia,
  burnMedia,
  purgeAll,
} = await import('../www/js/ephemeral.js');

// A DOM-less stand-in for a chat bubble element. `parentNode` must be truthy
// for the sweeper to call remove() (it guards on entry.el.parentNode).
function fakeEl() {
  const el = { parentNode: {}, removeCalls: 0 };
  el.remove = () => {
    el.removeCalls++;
    el.parentNode = null;
  };
  return el;
}

// After a trackText test the module holds a live (mocked) sweeper interval.
// Drain it so the module nulls its singleton before we reset the timer mock,
// keeping tests isolated and leaving no real interval to linger.
function drainSweeper() {
  purgeAll();
  mock.timers.tick(60_000); // one sweep sees an empty registry → clears itself
}

test('trackText returns createdAt + TEXT_TTL_MS', () => {
  mock.timers.enable({ apis: ['setInterval', 'Date'] });
  try {
    const created = 1_700_000_000_000;
    mock.timers.setTime(created);
    const expiresAt = trackText('t1', fakeEl(), created);
    assert.equal(expiresAt, created + TEXT_TTL_MS);
    drainSweeper();
  } finally {
    mock.timers.reset();
  }
});

test('remainingLabel formats a known expiry', () => {
  mock.timers.enable({ apis: ['Date'] });
  try {
    const now = 1_700_000_000_000;
    mock.timers.setTime(now);
    assert.equal(remainingLabel(now + 12 * 3600_000), 'deletes in 12h 0m');
    assert.equal(remainingLabel(now + 11 * 3600_000 + 59 * 60_000), 'deletes in 11h 59m');
    // Already past → clamped to zero, never negative.
    assert.equal(remainingLabel(now - 5_000), 'deletes in 0h 0m');
  } finally {
    mock.timers.reset();
  }
});

test('the 60s sweeper removes an expired text bubble', () => {
  mock.timers.enable({ apis: ['setInterval', 'Date'] });
  try {
    // "now" sits past the TTL for a bubble created at t=0, so it is due.
    mock.timers.setTime(TEXT_TTL_MS + 60_000);
    const el = fakeEl();
    trackText('t2', el, 0);
    assert.equal(el.removeCalls, 0, 'not removed before a sweep runs');
    mock.timers.tick(60_000); // fire the interval → sweep
    assert.equal(el.removeCalls, 1, 'expired bubble removed exactly once');
    drainSweeper();
  } finally {
    mock.timers.reset();
  }
});

test('the sweeper leaves a not-yet-expired bubble alone', () => {
  mock.timers.enable({ apis: ['setInterval', 'Date'] });
  try {
    mock.timers.setTime(1_000_000);
    const el = fakeEl();
    trackText('t3', el, 1_000_000); // expires 12h from now
    mock.timers.tick(60_000);
    assert.equal(el.removeCalls, 0, 'live bubble survives the sweep');
    drainSweeper();
  } finally {
    mock.timers.reset();
  }
});

test('view-once: consumeMedia yields a url, burnMedia revokes it and drops the bytes', () => {
  revoked.length = 0;
  const blob = new Blob([new Uint8Array([1, 2, 3])], { type: 'image/png' });
  stashMedia('m1', blob);

  const url = consumeMedia('m1');
  assert.match(url, /^blob:mock\/\d+$/, 'first render hands out an object url');

  burnMedia('m1');
  assert.ok(revoked.includes(url), 'burn revoked the object url');
  assert.equal(consumeMedia('m1'), null, 'bytes are gone — no second render');
});

test('consumeMedia on an unknown id returns null', () => {
  assert.equal(consumeMedia('does-not-exist'), null);
});

test('purgeAll burns all stashed media and revokes outstanding urls', () => {
  revoked.length = 0;
  stashMedia('p1', new Blob([new Uint8Array([9])], { type: 'image/png' }));
  stashMedia('p2', new Blob([new Uint8Array([8])], { type: 'image/png' }));

  // Consume p1 so it has an outstanding object url that purge must revoke.
  const p1Url = consumeMedia('p1');

  purgeAll();

  assert.ok(revoked.includes(p1Url), 'purge revoked the outstanding url');
  assert.equal(consumeMedia('p1'), null, 'p1 bytes gone after purge');
  assert.equal(consumeMedia('p2'), null, 'p2 bytes gone after purge');
});

test('purgeAll removes tracked text bubbles', () => {
  mock.timers.enable({ apis: ['setInterval', 'Date'] });
  try {
    mock.timers.setTime(1_000_000);
    const el = fakeEl();
    trackText('p3', el, 1_000_000); // nowhere near expiry
    purgeAll();
    assert.equal(el.removeCalls, 1, 'purge removed the bubble regardless of TTL');
    mock.timers.tick(60_000); // let the module null its swept-clean interval
  } finally {
    mock.timers.reset();
  }
});
