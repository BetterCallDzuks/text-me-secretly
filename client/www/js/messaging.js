// messaging.js — the app-level protocol, carried over the ENCRYPTED transport.
//
// Every frame below is sealed by the E2EE session (see e2ee.js) before it
// touches the data channel; this module never sees ciphertext and never sends
// plaintext. The `transport` it is given exposes:
//   transport.sendJson(obj)  -> Promise<bool>   (encrypted JSON frame)
//   transport.sendChunk(u8)  -> Promise<bool>   (encrypted media chunk)
//   events: 'frame' (decrypted object), 'chunk' (decrypted Uint8Array)
//
// Frame types (all JSON except raw media chunks):
//   { t:'text',       id, ts, body, token? }
//   { t:'media-meta', id, ts, mime, kind, size, chunks, token? }
//   <binary chunk>  x N   (ordered; belong to the most recent media-meta)
//   { t:'media-end',  id }
//   { t:'gate',       reason }        // "I can't accept this, you must subscribe"
//
// Freemium enforcement (see subscription.js for the counting model):
//   * Before SENDING, if the contact is out of free messages, we require a
//     local subscription token and attach it to the frame.
//   * On RECEIVE, if the contact is out of free messages, we require a valid
//     token on the frame (verified against the sender's anonId) before we
//     render. Otherwise we drop it and reply with a 'gate' frame.

import {
  bumpCount,
  getCount,
  freeLimit,
  isWithinFreeTier,
  getToken,
  verifyPeerToken,
} from './subscription.js';
import { trackText, remainingLabel, stashMedia, consumeMedia, burnMedia } from './ephemeral.js';

const CHUNK_SIZE = 16 * 1024; // 16 KiB — safe for SCTP data channels.

export class Messaging extends EventTarget {
  /**
   * @param {E2EESession} transport  encrypted transport (sendJson/sendChunk + 'frame'/'chunk')
   * @param {string} myId
   * @param {string} peerId
   */
  constructor(transport, myId, peerId) {
    super();
    this.transport = transport;
    this.myId = myId;
    this.peerId = peerId;
    this._incomingMedia = null; // { id, mime, kind, received:[], size }

    transport.addEventListener('frame', (ev) => this._onFrame(ev.detail));
    transport.addEventListener('chunk', (ev) => this._onChunk(ev.detail));
  }

  // ---- Outgoing ------------------------------------------------------------

  /**
   * Send a text message. Returns { sent, gated }.
   * gated=true means the free tier is exhausted and no valid token is held —
   * the caller should show the paywall.
   */
  async sendText(body) {
    const gate = await this._gateOutgoing();
    if (gate.blocked) return { sent: false, gated: true };

    const frame = {
      t: 'text',
      id: rid(),
      ts: Date.now(),
      body,
      ...(gate.token ? { token: gate.token } : {}),
    };
    const ok = await this.transport.sendJson(frame);
    if (ok) {
      await this._afterSend();
      this._emitLocalText(frame, true);
    }
    return { sent: ok, gated: false };
  }

  /**
   * Send a view-once media file (image/video/audio Blob).
   */
  async sendMedia(blob, kind) {
    const gate = await this._gateOutgoing();
    if (gate.blocked) return { sent: false, gated: true };

    const id = rid();
    const buf = new Uint8Array(await blob.arrayBuffer());
    const chunks = Math.ceil(buf.length / CHUNK_SIZE) || 1;

    await this.transport.sendJson({
      t: 'media-meta',
      id,
      ts: Date.now(),
      mime: blob.type || 'application/octet-stream',
      kind, // 'image' | 'video' | 'voice'
      size: buf.length,
      chunks,
      ...(gate.token ? { token: gate.token } : {}),
    });

    for (let i = 0; i < chunks; i++) {
      // Await each so encryption + ordering are preserved on the wire.
      await this.transport.sendChunk(buf.subarray(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE));
    }
    await this.transport.sendJson({ t: 'media-end', id });

    await this._afterSend();
    // Sender side: we do NOT keep the media either (view-once is mutual).
    this.dispatchEvent(
      new CustomEvent('message', {
        detail: { mine: true, kind: 'media', mediaKind: kind, id, viewOnce: true },
      })
    );
    return { sent: true, gated: false };
  }

  /**
   * Decide whether an outgoing message is allowed and what token to attach.
   * Returns { blocked, token }.
   */
  async _gateOutgoing() {
    if (await isWithinFreeTier(this.peerId)) return { blocked: false, token: null };
    const token = await getToken();
    if (!token) return { blocked: true, token: null };
    return { blocked: false, token };
  }

  async _afterSend() {
    const n = await bumpCount(this.peerId);
    this.dispatchEvent(new CustomEvent('count', { detail: { count: n, limit: freeLimit() } }));
  }

  // ---- Incoming (already decrypted by the transport) -----------------------

  /** A decrypted media chunk belonging to the in-flight transfer. */
  _onChunk(u8) {
    if (this._incomingMedia) this._incomingMedia.received.push(u8);
  }

  /** A decrypted JSON frame. */
  _onFrame(frame) {
    switch (frame.t) {
      case 'text':
        return this._onText(frame);
      case 'media-meta':
        return this._onMediaMeta(frame);
      case 'media-end':
        return this._onMediaEnd(frame);
      case 'gate':
        return this.dispatchEvent(new CustomEvent('gated', { detail: frame }));
    }
  }

  async _onText(frame) {
    if (!(await this._acceptIncoming(frame))) return;
    await this._afterReceive();
    this._emitLocalText(frame, false);
  }

  _emitLocalText(frame, mine) {
    this.dispatchEvent(
      new CustomEvent('message', {
        detail: {
          mine,
          kind: 'text',
          id: frame.id,
          body: frame.body,
          ts: frame.ts,
          track: (el) => {
            const exp = trackText(frame.id, el, frame.ts);
            return remainingLabel(exp);
          },
        },
      })
    );
  }

  async _onMediaMeta(frame) {
    if (!(await this._acceptIncoming(frame))) {
      // Still must consume the incoming chunks to keep the stream aligned;
      // mark a discard sink.
      this._incomingMedia = { id: frame.id, discard: true, received: [] };
      return;
    }
    this._incomingMedia = {
      id: frame.id,
      mime: frame.mime,
      kind: frame.kind,
      size: frame.size,
      received: [],
      discard: false,
    };
    await this._afterReceive();
  }

  _onMediaEnd(frame) {
    const m = this._incomingMedia;
    this._incomingMedia = null;
    if (!m || m.id !== frame.id || m.discard) return;

    const blob = new Blob(m.received, { type: m.mime });
    stashMedia(m.id, blob);
    // Emit a placeholder bubble; bytes are revealed once on tap, then burned.
    this.dispatchEvent(
      new CustomEvent('message', {
        detail: {
          mine: false,
          kind: 'media',
          mediaKind: m.kind,
          id: m.id,
          viewOnce: true,
          reveal: () => consumeMedia(m.id),
          burn: () => burnMedia(m.id),
        },
      })
    );
  }

  /**
   * Gatekeeper for incoming frames: enforce the per-contact free limit and
   * verify a subscription token once it is exceeded.
   */
  async _acceptIncoming(frame) {
    if (await isWithinFreeTier(this.peerId)) return true;

    const ok = await verifyPeerToken(frame.token, this.peerId);
    if (!ok) {
      // Tell the sender why we dropped it so their UI can show the paywall.
      this.transport.sendJson({ t: 'gate', reason: 'subscription-required' });
      this.dispatchEvent(new CustomEvent('blocked-incoming', { detail: { from: this.peerId } }));
      return false;
    }
    return true;
  }

  async _afterReceive() {
    const n = await bumpCount(this.peerId);
    this.dispatchEvent(new CustomEvent('count', { detail: { count: n, limit: freeLimit() } }));
  }

  async currentCount() {
    return getCount(this.peerId);
  }
}

function rid() {
  const b = new Uint8Array(12);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}
