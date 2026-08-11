// signaling.js — WebSocket client to the signaling server.
//
// Carries ONLY WebRTC setup traffic (register / offer / answer / ice / bye).
// Never carries message content.

export class Signaling extends EventTarget {
  constructor(url) {
    super();
    this.url = url;
    this.ws = null;
    this.myId = null;
    this._shouldReconnect = false;
    this._backoff = 1000;
  }

  connect(myId) {
    this.myId = myId;
    this._shouldReconnect = true;
    this._open();
  }

  _open() {
    this.ws = new WebSocket(this.url);

    this.ws.addEventListener('open', () => {
      this._backoff = 1000;
      this._send({ type: 'register', from: this.myId });
      this.dispatchEvent(new Event('open'));
    });

    this.ws.addEventListener('message', (ev) => {
      let msg;
      try {
        msg = JSON.parse(ev.data);
      } catch {
        return;
      }
      this.dispatchEvent(new CustomEvent('signal', { detail: msg }));
    });

    this.ws.addEventListener('close', () => {
      this.dispatchEvent(new Event('close'));
      if (this._shouldReconnect) {
        setTimeout(() => this._open(), this._backoff);
        this._backoff = Math.min(this._backoff * 2, 15000);
      }
    });

    this.ws.addEventListener('error', () => {
      this.dispatchEvent(new Event('error'));
    });
  }

  _send(obj) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(obj));
    }
  }

  sendOffer(to, sdp) {
    this._send({ type: 'offer', from: this.myId, to, sdp });
  }
  sendAnswer(to, sdp) {
    this._send({ type: 'answer', from: this.myId, to, sdp });
  }
  sendIce(to, candidate) {
    this._send({ type: 'ice', from: this.myId, to, candidate });
  }
  sendBye(to) {
    this._send({ type: 'bye', from: this.myId, to });
  }

  /** Hard disconnect — used by the VPN gate to sever the server link. */
  disconnect() {
    this._shouldReconnect = false;
    if (this.ws) {
      try {
        this.ws.close();
      } catch {
        /* ignore */
      }
      this.ws = null;
    }
  }
}
