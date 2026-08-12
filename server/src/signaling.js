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
//
// Abuse hardening (content-blind — we only count frames, never read them):
//   - a hard per-frame size cap (oversized frames are dropped by `ws`),
//   - a per-IP concurrent-connection cap,
//   - a per-connection message rate limit.

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

// --- Abuse / DoS limits (all tunable; override via attachSignaling opts) -----
// SDP/ICE payloads are tiny (a few KiB at most); anything larger is not a
// legitimate signaling frame, so we let `ws` drop oversized frames outright
// (which closes the connection). 64 KiB is comfortably above any real frame.
const MAX_PAYLOAD_BYTES = 64 * 1024; // 64 KiB hard cap per WS frame

// A single host needs only a handful of live signaling sockets (one per active
// tab/device). Cap concurrent connections per remote IP to blunt connection
// floods; excess sockets are closed immediately with "try again later".
const MAX_CONNS_PER_IP = 20;
const CLOSE_TRY_AGAIN = 1013; // WS close code: "try again later"

// Per-connection message rate limit (fixed rolling window). Legitimate
// signaling is bursty-but-small (a few offer/answer/ice frames per call), so
// 60 messages / 10s sits well above normal use while capping floods. Frames
// over the limit are dropped (not routed) for the remainder of the window.
const RATE_LIMIT_MAX = 60; // messages ...
const RATE_LIMIT_WINDOW_MS = 10_000; // ... per this window

function safeSend(ws, obj) {
  if (ws && ws.readyState === ws.OPEN) {
    ws.send(JSON.stringify(obj));
  }
}

function attachSignaling(server, options = {}) {
  // Limits default to the named constants above; tests may override them.
  const maxPayload = options.maxPayload || MAX_PAYLOAD_BYTES;
  const maxConnsPerIp = options.maxConnsPerIp || MAX_CONNS_PER_IP;
  const rateLimitMax = options.rateLimitMax || RATE_LIMIT_MAX;
  const rateLimitWindowMs = options.rateLimitWindowMs || RATE_LIMIT_WINDOW_MS;

  const wss = new WebSocketServer({ server, path: '/signal', maxPayload });

  // remoteAddress -> live connection count. Local to this server instance so
  // counts can never leak between separate servers in the same process.
  const ipConns = new Map();

  // Release an IP slot exactly once per socket, even on an abnormal close.
  function releaseIp(ws) {
    const ip = ws._ipCounted;
    if (!ip) return;
    ws._ipCounted = null;
    const n = (ipConns.get(ip) || 1) - 1;
    if (n <= 0) ipConns.delete(ip);
    else ipConns.set(ip, n);
  }

  // Fixed-window per-connection rate check. Returns true if the frame may be
  // processed, false if it should be dropped (over the limit for this window).
  function rateLimitOk(ws) {
    const now = Date.now();
    if (now - ws._rlStart >= rateLimitWindowMs) {
      ws._rlStart = now;
      ws._rlCount = 0;
      ws._rlNotified = false;
    }
    ws._rlCount += 1;
    if (ws._rlCount > rateLimitMax) {
      // Warn once per window so we don't amplify a flood back at the client.
      if (!ws._rlNotified) {
        ws._rlNotified = true;
        safeSend(ws, { type: 'error', reason: 'rate-limited' });
      }
      return false;
    }
    return true;
  }

  wss.on('connection', (ws, req) => {
    // Per-IP concurrent-connection cap. `req.socket.remoteAddress` is the
    // relay's only view of the peer; we count it, never anything about content.
    const ip = (req && req.socket && req.socket.remoteAddress) || 'unknown';
    const current = ipConns.get(ip) || 0;
    if (current >= maxConnsPerIp) {
      // Refuse without counting this socket toward the cap.
      safeSend(ws, { type: 'error', reason: 'too-many-connections' });
      ws.close(CLOSE_TRY_AGAIN, 'try again later');
      return;
    }
    ipConns.set(ip, current + 1);
    ws._ipCounted = ip; // remember so close/error decrements exactly once

    ws.anonId = null;
    ws.isAlive = true;
    // Rate-limit window state.
    ws._rlStart = Date.now();
    ws._rlCount = 0;
    ws._rlNotified = false;

    ws.on('pong', () => {
      ws.isAlive = true;
    });

    ws.on('message', (raw) => {
      // Count every inbound frame against the per-connection budget first.
      if (!rateLimitOk(ws)) return; // over budget: drop, do not route

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

    // Decrement the per-IP count on any terminal event. `releaseIp` is
    // idempotent, so overlapping close/error can't double-decrement or leak.
    ws.on('close', () => {
      releaseIp(ws);
      if (ws.anonId && peers.get(ws.anonId) === ws) {
        peers.delete(ws.anonId);
      }
    });
    ws.on('error', () => releaseIp(ws));
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
    stats: () => ({
      connectedPeers: peers.size,
      connections: wss.clients.size,
      uniqueIps: ipConns.size,
    }),
    // Used by tests only.
    _peers: peers,
    _rid: () => crypto.randomBytes(4).toString('hex'),
  };
}

module.exports = { attachSignaling };
