'use strict';

// WebRTC signaling relay.
//
// The ONLY job here is to forward SDP offers/answers and ICE candidates between
// two anonymous peers so they can open a direct RTCDataChannel. Once the P2P
// channel is up, no message content ever passes through this server.
//
// Privacy rules enforced in code:
//   - We never inspect, log, or persist SDP/ICE payloads' contents.
//   - We keep only an in-memory anonId -> socket map for live routing.
//   - The map entry is deleted the instant a socket closes.

const { WebSocketServer } = require('ws');
const crypto = require('crypto');

// anonId -> ws
const peers = new Map();

const ALLOWED_TYPES = new Set([
  'register', // { type, from }              -> announce presence
  'offer', // { type, from, to, sdp }        -> forwarded verbatim
  'answer', // { type, from, to, sdp }       -> forwarded verbatim
  'ice', // { type, from, to, candidate }    -> forwarded verbatim
  'bye', // { type, from, to }               -> hang up
]);

function safeSend(ws, obj) {
  if (ws && ws.readyState === ws.OPEN) {
    ws.send(JSON.stringify(obj));
  }
}

function attachSignaling(server) {
  const wss = new WebSocketServer({ server, path: '/signal' });

  wss.on('connection', (ws) => {
    ws.anonId = null;
    ws.isAlive = true;
    ws.on('pong', () => {
      ws.isAlive = true;
    });

    ws.on('message', (raw) => {
      let msg;
      try {
        msg = JSON.parse(raw.toString());
      } catch {
        return; // ignore non-JSON noise
      }
      if (!msg || !ALLOWED_TYPES.has(msg.type)) return;

      if (msg.type === 'register') {
        // Basic anonId shape check; the server assigns nothing and trusts the
        // client's self-chosen random ID (identity is anonymous by design).
        if (typeof msg.from !== 'string' || !/^[A-Za-z0-9_-]{8,64}$/.test(msg.from)) {
          return safeSend(ws, { type: 'error', reason: 'bad-id' });
        }
        // Evict any stale socket holding the same id.
        const prev = peers.get(msg.from);
        if (prev && prev !== ws) safeSend(prev, { type: 'displaced' });
        ws.anonId = msg.from;
        peers.set(msg.from, ws);
        return safeSend(ws, { type: 'registered', from: msg.from });
      }

      // All other types are point-to-point routing. Sender must be registered.
      if (!ws.anonId || msg.from !== ws.anonId) {
        return safeSend(ws, { type: 'error', reason: 'not-registered' });
      }
      if (typeof msg.to !== 'string') return;

      const target = peers.get(msg.to);
      if (!target) {
        return safeSend(ws, { type: 'unavailable', to: msg.to });
      }

      // Forward verbatim. We do NOT read sdp/candidate contents.
      safeSend(target, msg);
    });

    ws.on('close', () => {
      if (ws.anonId && peers.get(ws.anonId) === ws) {
        peers.delete(ws.anonId);
      }
    });
  });

  // Liveness sweep: drop half-open sockets so the peer map stays accurate.
  const interval = setInterval(() => {
    wss.clients.forEach((ws) => {
      if (ws.isAlive === false) return ws.terminate();
      ws.isAlive = false;
      try {
        ws.ping();
      } catch {
        /* ignore */
      }
    });
  }, 30000);

  wss.on('close', () => clearInterval(interval));

  return {
    wss,
    stats: () => ({ connectedPeers: peers.size }),
    // Used by tests only.
    _peers: peers,
    _rid: () => crypto.randomBytes(4).toString('hex'),
  };
}

module.exports = { attachSignaling };
