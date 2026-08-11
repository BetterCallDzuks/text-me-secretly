'use strict';

// keys.js — RSA keypair management for RS256 subscription tokens.
//
// RS256 lets the server sign tokens with a PRIVATE key while clients verify
// them with the PUBLIC key. That is what makes *offline* peer verification
// possible: a receiver checks a sender's token locally with the public key and
// never has to call the server (no metadata leak, no round-trip).
//
// On first boot, if the key files don't exist, we generate a 2048-bit RSA
// keypair and write them next to the server. The private key never leaves the
// box; the public key is served at /api/pubkey.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function loadOrCreate(privPath, pubPath) {
  const absPriv = path.resolve(privPath);
  const absPub = path.resolve(pubPath);

  if (fs.existsSync(absPriv) && fs.existsSync(absPub)) {
    return {
      privatePem: fs.readFileSync(absPriv, 'utf8'),
      publicPem: fs.readFileSync(absPub, 'utf8'),
      generated: false,
    };
  }

  // eslint-disable-next-line no-console
  console.log('[keys] No RSA keypair found — generating a 2048-bit keypair…');
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  fs.mkdirSync(path.dirname(absPriv), { recursive: true });
  fs.mkdirSync(path.dirname(absPub), { recursive: true });
  // Private key gets tight permissions.
  fs.writeFileSync(absPriv, privateKey, { mode: 0o600 });
  fs.writeFileSync(absPub, publicKey, { mode: 0o644 });

  return { privatePem: privateKey, publicPem: publicKey, generated: true };
}

/**
 * Build the key material the rest of the app needs: PEMs plus the public key as
 * a JWK (what browsers import via SubtleCrypto for offline verification).
 */
function buildKeyMaterial(privPath, pubPath) {
  const { privatePem, publicPem, generated } = loadOrCreate(privPath, pubPath);

  const pubKeyObj = crypto.createPublicKey(publicPem);
  const jwk = pubKeyObj.export({ format: 'jwk' });

  // A stable key id = first 16 hex of SHA-256 over the DER SPKI. Lets clients
  // pin a specific key and detect rotation.
  const der = pubKeyObj.export({ type: 'spki', format: 'der' });
  const kid = crypto.createHash('sha256').update(der).digest('hex').slice(0, 16);

  jwk.kid = kid;
  jwk.alg = 'RS256';
  jwk.use = 'sig';

  return { privatePem, publicPem, publicJwk: jwk, kid, generated };
}

module.exports = { buildKeyMaterial };
