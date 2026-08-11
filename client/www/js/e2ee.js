// e2ee.js — end-to-end encryption layer over the P2P data channel.
//
// WebRTC already encrypts the channel in transit (DTLS), but that terminates at
// each device's WebRTC stack. This layer adds application-level E2EE with:
//
//   * Authentication — bound to the long-term identity key whose fingerprint IS
//     the peer's anonId, so a signaling-server MITM (swapping keys) is detected.
//   * Forward secrecy — a fresh ephemeral ECDH keypair per session; compromising
//     an identity key later does not decrypt past sessions.
//
// Handshake (Noise-inspired, both peers send simultaneously on channel open):
//
//   hs = { t:'hs', v:1, idPub, ephPub, nonce }   (sent as plaintext JSON)
//
//   On receiving the peer's hs:
//     1. Verify fingerprint(peer.idPub) === peerId          (authenticate id)
//     2. ss_static = ECDH(myIdentityPriv, peerIdPub)        (mutual auth)
//     3. ss_eph    = ECDH(myEphemeralPriv, peerEphPub)      (forward secrecy)
//     4. ikm  = ss_static || ss_eph
//        salt = nonce(loId) || nonce(hiId)                  (canonical order)
//        k_lo = HKDF(ikm, salt, "…|k-lo")  → key the lo-id peer SENDS with
//        k_hi = HKDF(ikm, salt, "…|k-hi")  → key the hi-id peer SENDS with
//
// After that, every frame is AES-256-GCM sealed (fresh random IV each) and sent
// as binary. A 1-byte tag inside the plaintext distinguishes a JSON frame (0x01)
// from a raw media chunk (0x02).
//
// NOTE: This is a pragmatic, readable handshake — not a formally verified
// protocol. For production, adopt an audited library implementing full Noise
// (e.g. XX) or the Signal protocol.

import {
  generateEcdhKeypair,
  exportEcdhPublicJwk,
  importEcdhPublicJwk,
  ecdhSharedSecret,
  fingerprintOfPublicKey,
  hkdf,
  importAesGcmKey,
  aesGcmEncrypt,
  aesGcmDecrypt,
  concatBytes,
  bytesToB64u,
  b64uToBytes,
  utf8,
} from './crypto.js';

const TAG_JSON = 0x01;
const TAG_CHUNK = 0x02;
const INFO_BASE = 'tms-e2ee-v1';

export class E2EESession extends EventTarget {
  /**
   * @param {PeerConnection} peer
   * @param {{id:string, keypair:{privateKey:CryptoKey, publicKey:CryptoKey}, pubJwk:object}} identity
   * @param {string} peerId
   */
  constructor(peer, identity, peerId) {
    super();
    this.peer = peer;
    this.identity = identity;
    this.peerId = peerId;

    this.established = false;
    this.failed = false;

    this._eph = null; // ephemeral keypair
    this._myNonce = null;
    this._sendKey = null;
    this._recvKey = null;

    // Gate incoming handling until start() has prepared our ephemeral + nonce.
    this._ready = new Promise((res) => (this._readyResolve = res));
    // Serialize incoming messages so async decryption preserves channel order.
    this._recvChain = Promise.resolve();

    peer.addEventListener('data', (ev) => {
      const data = ev.detail;
      this._recvChain = this._recvChain.then(() => this._handleIncoming(data));
    });
  }

  /** Generate our ephemeral key + nonce and send our handshake frame. */
  async start() {
    this._eph = await generateEcdhKeypair(true);
    this._myNonce = crypto.getRandomValues(new Uint8Array(16));
    const ephPub = await exportEcdhPublicJwk(this._eph.publicKey);

    this._readyResolve();

    this.peer.sendJson({
      t: 'hs',
      v: 1,
      idPub: this.identity.pubJwk,
      ephPub,
      nonce: bytesToB64u(this._myNonce),
    });
  }

  async _handleIncoming(data) {
    if (this.failed) return;

    if (typeof data === 'string') {
      let msg;
      try {
        msg = JSON.parse(data);
      } catch {
        return;
      }
      if (msg.t === 'hs' && !this.established) {
        await this._ready; // ensure our ephemeral/nonce exist
        await this._onHandshake(msg);
      }
      return;
    }

    // Binary: an encrypted frame. Only valid once keys are established.
    if (!this.established) return;
    await this._decryptAndEmit(data);
  }

  async _onHandshake(msg) {
    try {
      const peerIdPub = await importEcdhPublicJwk(msg.idPub);
      const peerEphPub = await importEcdhPublicJwk(msg.ephPub);

      // 1. Authenticate: the identity key must hash to the id we're talking to.
      const fp = await fingerprintOfPublicKey(peerIdPub);
      if (fp !== this.peerId) {
        this._fail('identity-mismatch');
        return;
      }

      // 2 + 3. Mutual-auth secret + forward-secret secret.
      const ssStatic = await ecdhSharedSecret(this.identity.keypair.privateKey, peerIdPub);
      const ssEph = await ecdhSharedSecret(this._eph.privateKey, peerEphPub);
      const ikm = concatBytes(ssStatic, ssEph);

      // Canonical ordering so both sides derive identical salt + info.
      const peerNonce = b64uToBytes(msg.nonce);
      const iAmLo = this.identity.id < this.peerId;
      const loId = iAmLo ? this.identity.id : this.peerId;
      const hiId = iAmLo ? this.peerId : this.identity.id;
      const loNonce = iAmLo ? this._myNonce : peerNonce;
      const hiNonce = iAmLo ? peerNonce : this._myNonce;

      const salt = concatBytes(loNonce, hiNonce);
      const info = `${INFO_BASE}|${loId}|${hiId}`;

      const kLoRaw = await hkdf(ikm, salt, `${info}|k-lo`, 32);
      const kHiRaw = await hkdf(ikm, salt, `${info}|k-hi`, 32);

      // Each side SENDS with its own key, RECEIVES with the peer's.
      const myRaw = iAmLo ? kLoRaw : kHiRaw;
      const peerRaw = iAmLo ? kHiRaw : kLoRaw;
      this._sendKey = await importAesGcmKey(myRaw);
      this._recvKey = await importAesGcmKey(peerRaw);

      this.established = true;
      this.dispatchEvent(
        new CustomEvent('established', { detail: { peerId: this.peerId, verified: true } })
      );
    } catch (err) {
      this._fail('handshake-error');
    }
  }

  _fail(reason) {
    this.failed = true;
    this.dispatchEvent(new CustomEvent('insecure', { detail: { reason } }));
  }

  async _decryptAndEmit(data) {
    try {
      const pt = await aesGcmDecrypt(this._recvKey, data);
      if (pt.length < 1) return;
      const tag = pt[0];
      const payload = pt.subarray(1);
      if (tag === TAG_JSON) {
        const obj = JSON.parse(utf8.decode(payload));
        this.dispatchEvent(new CustomEvent('frame', { detail: obj }));
      } else if (tag === TAG_CHUNK) {
        // Copy out of the subarray view so downstream owns a standalone buffer.
        this.dispatchEvent(new CustomEvent('chunk', { detail: new Uint8Array(payload) }));
      }
    } catch {
      // A GCM auth failure means tampering or a key desync — drop it.
    }
  }

  // ---- Transport API consumed by messaging.js ------------------------------

  /** Encrypt and send a JSON frame. Returns true if it went out. */
  async sendJson(obj) {
    if (!this.established) return false;
    const plaintext = concatBytes(new Uint8Array([TAG_JSON]), utf8.encode(JSON.stringify(obj)));
    const env = await aesGcmEncrypt(this._sendKey, plaintext);
    return this.peer.sendBinary(env.buffer);
  }

  /** Encrypt and send a raw media chunk. */
  async sendChunk(u8) {
    if (!this.established) return false;
    const plaintext = concatBytes(new Uint8Array([TAG_CHUNK]), u8);
    const env = await aesGcmEncrypt(this._sendKey, plaintext);
    return this.peer.sendBinary(env.buffer);
  }

  destroy() {
    this._sendKey = null;
    this._recvKey = null;
    this._eph = null;
    this._myNonce = null;
  }
}
