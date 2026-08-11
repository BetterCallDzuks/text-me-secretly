// helpers.mjs — shared test utilities: a fake data-channel wire between two
// peers, and identity construction. Import _setup.mjs before this.

import { curve, ready } from '../www/js/vendor/noise-xx.js';
import { fingerprintOfRawKey } from '../www/js/crypto.js';

export { ready };

/** A fresh random identity ({ id, keyPair }) usable by E2EESession. */
export async function makeIdentity() {
  await ready;
  const keyPair = curve.generateKeyPair();
  const id = await fingerprintOfRawKey(new Uint8Array(keyPair.publicKey));
  return { id, keyPair };
}

function fakePeer() {
  const p = new EventTarget();
  p.initiator = false;
  p.tamper = null; // optional (buf) => false to swallow, or mutate + redeliver
  p.sendBinary = (buf) => {
    if (p.tamper && p.tamper(buf) === false) return true;
    p._other.dispatchEvent(new CustomEvent('data', { detail: buf }));
    return true;
  };
  p.sendJson = () => true;
  return p;
}

/** Two peers whose sendBinary delivers to the other's 'data' event. */
export function linkedPeers() {
  const a = fakePeer();
  const b = fakePeer();
  a._other = b;
  b._other = a;
  a.initiator = true;
  return { a, b };
}
