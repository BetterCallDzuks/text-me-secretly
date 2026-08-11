// webrtc.js — direct P2P transport via RTCPeerConnection + a single ordered,
// reliable RTCDataChannel. All chat traffic (text + chunked media) rides this
// channel and NEVER touches the server after the handshake completes.

const RTC_CONFIG = {
  iceServers: [
    // Public STUN for NAT traversal. Add a TURN server for symmetric-NAT
    // fallback in production (still relays only opaque encrypted media, but
    // most privacy setups run their own TURN).
    { urls: 'stun:stun.l.google.com:19302' },
  ],
};

export class PeerConnection extends EventTarget {
  constructor(signaling, peerId, { initiator }) {
    super();
    this.signaling = signaling;
    this.peerId = peerId;
    this.initiator = initiator;
    this.pc = new RTCPeerConnection(RTC_CONFIG);
    this.channel = null;

    this.pc.addEventListener('icecandidate', (ev) => {
      if (ev.candidate) this.signaling.sendIce(this.peerId, ev.candidate);
    });

    this.pc.addEventListener('connectionstatechange', () => {
      this.dispatchEvent(
        new CustomEvent('state', { detail: this.pc.connectionState })
      );
    });

    if (initiator) {
      this._setupChannel(this.pc.createDataChannel('tms', { ordered: true }));
    } else {
      this.pc.addEventListener('datachannel', (ev) => this._setupChannel(ev.channel));
    }
  }

  _setupChannel(ch) {
    this.channel = ch;
    ch.binaryType = 'arraybuffer';
    ch.addEventListener('open', () =>
      this.dispatchEvent(new Event('channelopen'))
    );
    ch.addEventListener('close', () =>
      this.dispatchEvent(new Event('channelclose'))
    );
    ch.addEventListener('message', (ev) =>
      this.dispatchEvent(new CustomEvent('data', { detail: ev.data }))
    );
  }

  async start() {
    if (!this.initiator) return;
    const offer = await this.pc.createOffer();
    await this.pc.setLocalDescription(offer);
    this.signaling.sendOffer(this.peerId, offer);
  }

  async onOffer(sdp) {
    await this.pc.setRemoteDescription(new RTCSessionDescription(sdp));
    const answer = await this.pc.createAnswer();
    await this.pc.setLocalDescription(answer);
    this.signaling.sendAnswer(this.peerId, answer);
  }

  async onAnswer(sdp) {
    await this.pc.setRemoteDescription(new RTCSessionDescription(sdp));
  }

  async onIce(candidate) {
    try {
      await this.pc.addIceCandidate(new RTCIceCandidate(candidate));
    } catch {
      /* ignore late/duplicate candidates */
    }
  }

  /** Send a UTF-8 JSON control/text frame. */
  sendJson(obj) {
    if (this.channel && this.channel.readyState === 'open') {
      this.channel.send(JSON.stringify(obj));
      return true;
    }
    return false;
  }

  /** Send a raw binary chunk (media). */
  sendBinary(buf) {
    if (this.channel && this.channel.readyState === 'open') {
      this.channel.send(buf);
      return true;
    }
    return false;
  }

  get connected() {
    return this.channel && this.channel.readyState === 'open';
  }

  close() {
    try {
      if (this.channel) this.channel.close();
      this.pc.close();
    } catch {
      /* ignore */
    }
  }
}

export { RTC_CONFIG };
