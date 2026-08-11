import './_setup.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  getIdentity,
  getMnemonic,
  restoreFromMnemonic,
  setPassphrase,
} from '../www/js/identity.js';

const ID_RE = /^[A-Z2-7]{20}$/;

test('first run mints a 12-word phrase and a fingerprint id', async () => {
  const me = await getIdentity();
  assert.match(me.id, ID_RE);
  assert.equal((await getMnemonic()).split(' ').length, 12);
  assert.equal(me.hasPassphrase, false);
});

test('a passphrase changes the id deterministically and restores exactly', async () => {
  const before = await getIdentity();
  const phrase = before.mnemonic;

  const withPass = await setPassphrase('correct horse battery staple');
  assert.notEqual(withPass.id, before.id);
  assert.equal(withPass.hasPassphrase, true);

  // Same phrase + passphrase reproduces the same id.
  const restored = await restoreFromMnemonic(phrase, 'correct horse battery staple');
  assert.equal(restored.id, withPass.id);

  // Empty passphrase returns to the original (passphrase-less) id.
  const noPass = await restoreFromMnemonic(phrase, '');
  assert.equal(noPass.id, before.id);
  assert.equal(noPass.hasPassphrase, false);
});

test('an invalid recovery phrase is rejected', async () => {
  await assert.rejects(() => restoreFromMnemonic('not a valid mnemonic phrase zzz', ''));
});
