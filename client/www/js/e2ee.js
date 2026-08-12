// e2ee.js — end-to-end encryption via an audited Noise XX handshake.
//
// The hand-rolled ECDH/HKDF/AES-GCM handshake this file used to contain has been
// replaced by the Noise Protocol Framework's XX pattern, implemented by
// noise-handshake (Holepunch — the same library that powers the Keet P2P
// messenger), bundled at www/js/vendor/noise-xx.js. Suite:
//
//     Noise_XX_25519_ChaChaPoly_BLAKE2b
//
// Why XX: it is the mutual-authentication pattern where neither party knows the
// other's static key in advance — exactly our case (anonymous peers who only
// exchanged an anonId). Both static keys are transmitted and authenticated
// during the handshake, and XX provides forward secrecy from its ephemeral keys.
//
// Identity binding (our addition): after the handshake, each side checks that
// the peer's Noise static key (`hs.rs`) fingerprints to the anonId it dialed
// (see identity.js). A signaling-server MITM that swaps keys is thus detected.
//
// Wire framing (all binary): a 1-byte outer prefix marks each message —
//   0x00 = Noise handshake message
//   0x01 = Noise transport message (ciphertext)
// Inside a decrypted transport message, a 1-byte tag marks the payload —
//   0x01 = JSON frame, 0x02 = raw media chunk.

import { Noise, ready as cryptoReady } from './vendor/noise-xx.js';
import { fingerprintOfRawKey, utf8 } from './crypto.js';

const PREFIX_HANDSHAKE = 0x00;
const PREFIX_TRANSPORT = 0x01;
const TAG_JSON = 0x01;
const TAG_CHUNK = 0x02;

// Prologue is mixed into the handshake hash; both peers must use the same value.
const PROLOGUE = utf8.encode('tms-noise-xx-v1');

function framed(prefix, body) {
  const out = new Uint8Array(1 + body.length);
  out[0] = prefix;
  out.set(body, 1);
  return out;
}

export class E2EESession extends EventTarget {
  /**
   * @param {PeerConnection} peer
   * @param {{id:string, keyPair:{publicKey:Uint8Array, secretKey:Uint8Array}}} identity
   * @param {string} peerId
   * @param {boolean} initiator  the WebRTC initiator drives the XX handshake
   */
  constructor(peer, identity, peerId, initiator) {
    super();
    this.peer = peer;
    this.identity = identity;
    this.peerId = peerId;
    this.initiator = !!initiator;

    this.established = false;
    this.failed = false;
    this.hs = null;

    // Serialize incoming messages so the async finalize step can't be raced by
    // a transport message that arrives immediately after the final handshake msg.
    this._recvChain = Promise.resolve();
    peer.addEventListener('data', (ev) => {
      const data = ev.detail;
      this._recvChain = this._recvChain.then(() => this._handleIncoming(data));
    });
  }

  /** Initialise the Noise state and, if initiator, send the first message. */
  async start() {
    await cryptoReady; // ensure libsodium WASM is initialised
    this.hs = new Noise('XX', this.initiator, this.identity.keyPair);
    this.hs.initialise(PROLOGUE);
    if (this.initiator) {
      this.peer.sendBinary(framed(PREFIX_HANDSHAKE, this.hs.send()).buffer);
    }
  }

  async _handleIncoming(data) {
    if (this.failed || !(data instanceof ArrayBuffer)) return;
    const u8 = new Uint8Array(data);
    if (u8.length < 1) return;
    const prefix = u8[0];
    const body = u8.subarray(1);

    if (prefix === PREFIX_HANDSHAKE) return this._onHandshake(body);
    if (prefix === PREFIX_TRANSPORT) return this._onTransport(body);
  }

  _onHandshake(body) {
    if (this.established || this.failed) return;
    try {
      this.hs.recv(body);
    } catch {
      return this._fail('handshake-error');
    }
    // Send our next handshake message if the pattern isn't finished yet.
    if (!this.hs.complete) {
      try {
        this.peer.sendBinary(framed(PREFIX_HANDSHAKE, this.hs.send()).buffer);
      } catch {
        return this._fail('handshake-error');
      }
    }
    if (this.hs.complete) return this._finalize();
  }

  async _finalize() {
    // Authenticate: the peer's Noise static key must fingerprint to its anonId.
    try {
      const fp = await fingerprintOfRawKey(new Uint8Array(this.hs.rs));
      if (fp !== this.peerId) return this._fail('identity-mismatch');
    } catch {
      return this._fail('handshake-error');
    }
    this.established = true;
    this.dispatchEvent(
      new CustomEvent('established', { detail: { peerId: this.peerId, verified: true } })
    );
  }

  _onTransport(body) {
    if (!this.established) return;
    let pt;
    try {
      pt = this.hs.decrypt(body);
    } catch {
      // ChaCha/Poly auth failure => tampering or desync. Drop it.
      return;
    }
    const bytes = pt instanceof Uint8Array ? pt : new Uint8Array(pt);
    if (bytes.length < 1) return;
    const tag = bytes[0];
    const payload = bytes.subarray(1);
    if (tag === TAG_JSON) {
      try {
        this.dispatchEvent(new CustomEvent('frame', { detail: JSON.parse(utf8.decode(payload)) }));
      } catch {
        /* malformed frame */
      }
    } else if (tag === TAG_CHUNK) {
      this.dispatchEvent(new CustomEvent('chunk', { detail: new Uint8Array(payload) }));
    }
  }

  _fail(reason) {
    if (this.failed) return;
    this.failed = true;
    this.dispatchEvent(new CustomEvent('insecure', { detail: { reason } }));
  }

  // ---- Transport API consumed by messaging.js ------------------------------

  _seal(tag, payload) {
    const plaintext = new Uint8Array(1 + payload.length);
    plaintext[0] = tag;
    plaintext.set(payload, 1);
    const ct = this.hs.encrypt(plaintext);
    const ctBytes = ct instanceof Uint8Array ? ct : new Uint8Array(ct);
    return this.peer.sendBinary(framed(PREFIX_TRANSPORT, ctBytes).buffer);
  }

  /** Encrypt and send a JSON frame. Returns true if it went out. */
  async sendJson(obj) {
    if (!this.established) return false;
    return this._seal(TAG_JSON, utf8.encode(JSON.stringify(obj)));
  }

  /** Encrypt and send a raw media chunk. */
  async sendChunk(u8) {
    if (!this.established) return false;
    return this._seal(TAG_CHUNK, u8);
  }

  destroy() {
    this.hs = null;
  }
}
