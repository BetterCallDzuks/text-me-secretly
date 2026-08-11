import './_setup.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  generateMnemonic,
  validateMnemonic,
  mnemonicToSeed32,
} from '../www/js/vendor/mnemonic.js';
import { curve, ready } from '../www/js/vendor/noise-xx.js';
import { fingerprintOfRawKey } from '../www/js/crypto.js';

async function idFor(phrase, pass = '') {
  await ready;
  const kp = curve.generateSeedKeyPair(mnemonicToSeed32(phrase, pass));
  return fingerprintOfRawKey(new Uint8Array(kp.publicKey));
}

test('generates and validates 12-word mnemonics', () => {
  const m = generateMnemonic();
  assert.equal(m.split(' ').length, 12);
  assert.equal(validateMnemonic(m), true);
  assert.equal(validateMnemonic('clearly not a valid bip39 phrase'), false);
});

test('derivation is deterministic and passphrase/casing sensitive', async () => {
  const m = generateMnemonic();
  const id = await idFor(m);

  assert.equal(await idFor(m), id, 'same phrase → same id');
  assert.equal(await idFor(m, ''), id, 'empty passphrase == no passphrase');
  assert.equal(await idFor(m.toUpperCase().replace(/ /g, '   ')), id, 'normalised');
  assert.notEqual(await idFor(m, 'x'), id, 'passphrase changes id');
  assert.notEqual(await idFor(generateMnemonic()), id, 'different phrase differs');
});
