# Text Me Secretly

A privacy-first, peer-to-peer 1-on-1 messenger. Text and media flow **directly
between two devices** over a WebRTC data channel. The backend is deliberately
tiny: it brokers the initial handshake and sells subscriptions — it **never
stores, processes, or relays a single message or media byte**.

- **Identity:** anonymous **and self-certifying**. Each device generates a
  long-term ECDH identity keypair on first run; the anonId is the key's
  fingerprint (`base32(sha256(spki))[:20]`). No emails, no accounts, no
  server-side user table.
- **End-to-end encrypted:** every message and media chunk is sealed with
  AES-256-GCM under keys from an authenticated ECDH handshake (forward secrecy),
  on top of WebRTC's transport encryption.
- **Ephemeral:** text has a 12-hour local TTL and auto-deletes; media is
  **view-once** (rendered exactly once, then the bytes are burned).
- **Freemium:** 20 free messages **per new contact**, then a €5/month
  subscription is required — enforced locally on both peers with an RS256
  server-signed proof token that peers verify **offline**.
- **VPN-gated:** the UI is blocked and the signaling socket is cut whenever no
  VPN is detected, via a custom native Capacitor plugin.
- **NAT-resilient:** STUN + ephemeral-credential TURN fallback so connections
  succeed behind symmetric NAT (TURN relays only E2EE ciphertext).

---

## 1. Message counting & subscription verification

### Why counting has to be local

The server cannot count messages because it never sees them — after the WebRTC
handshake, all traffic is a direct encrypted (DTLS-SRTP/SCTP) channel between the
two phones. So counting lives entirely on the clients.

### The counting model (`client/www/js/subscription.js`)

- Each client keeps a **durable per-contact counter**: `{ contactId: count }`
  in Capacitor Preferences (device) / localStorage (dev).
- **Both** the sender and the receiver increment their own counter for the same
  conversation. Symmetric counting means the limit holds even if one side runs a
  patched client — the honest side independently stops at 20.
- `isWithinFreeTier(contactId)` is simply `count < FREE_MESSAGES_PER_CONTACT`.

### The gate (`client/www/js/messaging.js`)

```
                 ┌─────────────── SENDER ───────────────┐
 user hits send → within free tier?  ── yes ──► send frame (no token)
                          │ no
                          ▼
                  hold a valid token? ── no ──► show paywall, DON'T send
                          │ yes
                          ▼
                  attach token to frame ──► send

                 ┌─────────────── RECEIVER ─────────────┐
 frame arrives → within free tier?  ── yes ──► render + increment
                          │ no
                          ▼
                  verify frame.token for sender's anonId
                          │
              valid ──────┴────── invalid
                │                    │
             render            drop + reply {t:'gate'}  → sender shows paywall
```

### The proof token (RS256, verified offline)

- After a (mocked) payment, the client calls `POST /api/subscribe` with its
  `anonId`. The server issues a **JWT signed with an RSA private key (RS256)**
  asserting *"the holder of this anonId has an active subscription until `exp`"*
  (`server/src/subscription.js`). It contains **no contact list and no message
  data** — just `sub` (the anonId), `scope`, and expiry.
- The token binds to the subscriber's `anonId`. The receiver checks the token's
  `sub` equals the sender's channel ID, which stops a paid user from lending
  their token to someone else on a different connection.
- One subscription unlocks *all* of the subscriber's contacts; the **other**
  party still has their own independent 20-message free tier until they too
  subscribe. (This is the intended business rule: either party paying keeps the
  conversation open from their side.)

### Verification is offline (RS256)

The server signs with a **private** key that never leaves the box; the client
fetches the **public** key once from `GET /api/pubkey` (a JWK), caches it, and
imports it via SubtleCrypto. Every peer token is then verified **fully offline**
with `crypto.subtle.verify` — no `/api/verify` round-trip, no metadata leak at
verification time. `/api/verify` remains only as a fallback for a client that
cannot obtain the key (e.g. first run while offline).

- **Key management:** `server/src/keys.js` auto-generates a 2048-bit RSA keypair
  on first boot (written to `server/keys/`, git-ignored) and exposes a `kid`.
- **Key pinning:** set `EXPECTED_JWT_KID` in `client/www/js/config.js` to reject
  any public key whose `kid` differs (defends against a swapped key). Default is
  trust-on-first-use.
- **Tested:** valid tokens verify; wrong-`sub`, tampered-signature, and
  wrong-audience tokens are all rejected offline.

---

## 1b. End-to-end encryption (`client/www/js/e2ee.js`)

WebRTC encrypts the data channel in transit (DTLS), but that terminates inside
each device's WebRTC stack. On top of it we run an application-level E2EE layer:

- **Authenticated handshake:** on channel open, both peers exchange their
  long-term identity public key + a fresh **ephemeral** ECDH key. Each peer
  checks `fingerprint(peer identity key) === peerId` — because the anonId *is*
  that fingerprint, a signaling-server MITM that swaps keys is detected and the
  connection is dropped.
- **Key agreement:** the session key mixes two ECDH secrets —
  `ss_static = ECDH(myIdentity, peerIdentity)` (mutual authentication) and
  `ss_eph = ECDH(myEphemeral, peerEphemeral)` (**forward secrecy**) — through
  HKDF-SHA256. Separate send/receive keys are derived per direction (ordered by
  anonId) so each direction has its own AES-GCM key.
- **AEAD:** every frame and media chunk is sealed with **AES-256-GCM**, fresh
  random 96-bit IV each, a 1-byte type tag distinguishing JSON frames from media
  chunks. Incoming messages are processed through a serial queue so async
  decryption preserves channel order.
- **Tested:** two simulated peers establish, exchange encrypted text and media
  both ways, and an identity-mismatch (MITM) attempt is rejected.

Curve choice: P-256 (universally supported in mobile WebViews). X25519 is a
drop-in where the WebView supports it — change the `namedCurve`/algorithm in
`crypto.js`. This is a pragmatic, readable handshake, **not** a formally verified
protocol; for launch, adopt an audited Noise (XX) or Signal-protocol library.

---

## 1c. NAT traversal: TURN with ephemeral credentials

- `GET`/`POST /api/turn` returns an ICE server list: STUN always, plus TURN when
  `TURN_URLS` + `TURN_SECRET` are configured. Credentials are **short-lived**,
  computed with coturn's `use-auth-secret` scheme
  (`username = "<expiry>:<anonId>"`, `credential = base64(HMAC-SHA1(secret,
  username))`), so the TURN server needs no user database and passwords expire.
- The client fetches this list at session start and passes it to
  `RTCPeerConnection`. TURN only ever relays already-E2EE-encrypted media, so a
  relay operator learns nothing.
- See **[docs/coturn.md](docs/coturn.md)** for the coturn setup on the VPS.

---

## 2. VPN detection (custom Capacitor native plugin)

Location: `plugins/vpn-detector/`. JS API:

```ts
VpnDetector.isVpnActive(): Promise<{ active: boolean; interfaces?: string[] }>
VpnDetector.startMonitoring(): Promise<void>   // emits 'vpnStatusChanged'
VpnDetector.stopMonitoring(): Promise<void>
```

- **Android** (`android/.../VpnDetectorPlugin.kt`): checks
  `NetworkCapabilities.TRANSPORT_VPN` across all active networks, plus a
  secondary scan of live `tun*/ppp*/ipsec*/utun*` interfaces. Live updates come
  from a `ConnectivityManager.NetworkCallback`. Requires
  `ACCESS_NETWORK_STATE`.
- **iOS** (`ios/Plugin/VpnDetectorPlugin.swift`): iOS exposes no "is VPN on"
  API, so it uses two App Store-safe heuristics — the `__SCOPED__` keys of
  `CFNetworkCopySystemProxySettings()` and a `getifaddrs()` scan for up
  `utun/tap/tun/ppp/ipsec` interfaces. Live updates via
  `SCNetworkReachability`.
- **Web** (`src/web.ts`): a browser can't read interfaces, so it **fails closed**
  (reports inactive). Set `window.__TMS_DEV_ALLOW_NO_VPN__ = true` to bypass
  while developing the UI in a desktop browser.

The gate (`client/www/js/vpn.js` + `app.js`) reacts on every change: if no VPN,
it **purges ephemeral data, closes the P2P connection, disconnects signaling,
and covers the UI** with a blocking overlay. Detection is both event-driven and
polled every 4s as a safety net.

> Note: interface-based detection is a strong deterrent, not an unforgeable
> guarantee — a rooted/jailbroken device can spoof interfaces. It reliably
> enforces the *product* requirement ("don't run without a VPN") for normal
> users.

---

## 3. Directory structure

```
text-me-secretly/
├── README.md                     # this file (spec + explanation)
├── .gitignore
├── scripts/
│   └── deploy.sh                 # PM2 setup/update for an Ubuntu VPS (no Docker)
│
├── docs/
│   └── coturn.md                 # TURN server setup on the VPS (no Docker)
│
├── server/                       # Minimal backend
│   ├── package.json
│   ├── .env.example
│   ├── ecosystem.config.js       # PM2 process definition
│   ├── server.js                 # Express REST + ws signaling on one port
│   └── src/
│       ├── config.js             # env loader + RSA key/TURN config
│       ├── keys.js               # RSA keypair auto-gen + public JWK (RS256)
│       ├── signaling.js          # WebRTC signaling relay (no content inspection)
│       ├── subscription.js       # RS256 JWT issue/verify
│       ├── turn.js               # ephemeral TURN credentials (coturn REST)
│       └── payment.js            # MOCK payment gateway (swap for Stripe here)
│
├── plugins/
│   └── vpn-detector/             # Custom Capacitor plugin
│       ├── package.json
│       ├── VpnDetector.podspec
│       ├── tsconfig.json
│       ├── src/                  # TS bridge (definitions/index/web)
│       ├── android/              # Kotlin plugin + manifest + build.gradle
│       └── ios/Plugin/           # Swift plugin + ObjC registration
│
└── client/                       # Vanilla JS app, wrapped by Capacitor
    ├── package.json
    ├── capacitor.config.json
    └── www/
        ├── index.html
        ├── css/style.css
        └── js/
            ├── config.js         # signaling + API endpoints + key-pin (edit for your VPS)
            ├── app.js            # bootstrap + UI wiring + VPN gate + E2EE handshake
            ├── identity.js       # self-certifying identity keypair + anonId fingerprint
            ├── crypto.js         # Web Crypto: ECDH, HKDF, AES-GCM, RS256 verify
            ├── e2ee.js           # authenticated E2EE handshake + session cipher
            ├── storage.js        # Preferences/localStorage KV (no message bodies)
            ├── signaling.js      # WebSocket signaling client
            ├── webrtc.js         # RTCPeerConnection + data channel (STUN/TURN)
            ├── messaging.js      # protocol, counting, freemium gate, chunked media
            ├── ephemeral.js      # 12h text TTL sweeper + view-once media vault
            ├── subscription.js   # counters + token cache + offline RS256 verify
            └── vpn.js            # native plugin wrapper + change events
```

---

## 4. Backend (Node.js: `ws` signaling + Express auth)

See `server/`. Key endpoints (`server/server.js`):

| Method + path        | Purpose                                                        |
| -------------------- | -------------------------------------------------------------- |
| `WS /signal`         | Register an anonId; relay `offer`/`answer`/`ice`/`bye` verbatim |
| `GET /api/config`    | Public: free limit, price, currency (renders the paywall)      |
| `POST /api/subscribe`| Mock-pay for an anonId, return an RS256 signed proof token     |
| `POST /api/token`    | Re-issue a token for an already-paid anonId                    |
| `GET /api/pubkey`    | RSA public key (JWK) for **offline** peer-token verification   |
| `POST /api/verify`   | Verify a peer's token (fallback path only)                     |
| `POST /api/turn`     | ICE servers: STUN + ephemeral TURN credentials                 |
| `GET /api/health`    | Liveness                                                       |

The signaling relay keeps only an **in-memory `anonId → socket` map**, deleted on
disconnect, and forwards SDP/ICE without reading their contents. The mock
payment store lives in memory too — replace `server/src/payment.js` with a real
Stripe integration (webhook flips the paid flag) without touching anything else.

**Run locally:**

```bash
cd server
cp .env.example .env
npm install
npm start          # http + ws on :8080; RSA keypair auto-generates on first boot
```

No secret to paste: the server generates its RS256 keypair into `server/keys/`
on first boot (git-ignored). Set `TURN_URLS`/`TURN_SECRET` in `.env` only if you
run a TURN server (see `docs/coturn.md`); otherwise it serves STUN-only.

---

## 5. Client core logic (Vanilla JS)

See `client/www/js/`. Highlights:

- **`crypto.js` / `e2ee.js`** — the E2EE layer (see §1b): authenticated ECDH
  handshake, HKDF, per-direction AES-256-GCM. Chat opens only after the
  handshake verifies the peer's identity.
- **`webrtc.js`** — one ordered/reliable `RTCDataChannel` named `tms`. ICE
  servers (STUN + ephemeral TURN) are fetched from the backend at session start.
- **`messaging.js`** — runs over the encrypted transport: JSON frames for
  text/control, 16 KiB media chunks (bracketed by `media-meta` / `media-end`),
  each sealed before it hits the wire. Applies the freemium gate on both send
  and receive.
- **`ephemeral.js`** — text lives **in memory only** with an `expiresAt`; a
  1-minute sweeper removes expired bubbles (12h is the max lifetime, not a
  promise it survives that long). Media is stashed as a Blob and **burned on
  first render** — `URL.revokeObjectURL` + dropping the bytes — so it can never
  be viewed twice.
- **`app.js`** — enforces the VPN gate first, then identity, config, signaling,
  dialing, chat UI, and the paywall.

**Run the web build locally** (desktop browser, dev bypass on):

```bash
cd client/www
# serve statically, e.g.:
python3 -m http.server 5173
# then in the browser console before it boots is too late; instead set it in config
# or open devtools and run:  window.__TMS_DEV_ALLOW_NO_VPN__ = true; location.reload()
```

Edit `client/www/js/config.js` to point at your server (`ws://localhost:8080/signal`
and `http://localhost:8080` for local dev; `wss://` + `https://` in production).

**Wrap as a native app:**

```bash
cd client
npm install
npx cap add android      # and/or: npx cap add ios
npx cap sync
npx cap open android     # build/run from Android Studio / Xcode
```

The `vpn-detector` plugin is linked via `"vpn-detector": "file:../plugins/vpn-detector"`
and picked up automatically by `cap sync`.

---

## 6. Deployment (PM2 on Ubuntu, no Docker)

`scripts/deploy.sh` handles both first-time setup and updates:

```bash
# On the VPS, after cloning the repo to ~/text-me-secretly:
./scripts/deploy.sh setup     # installs Node 20, PM2, deps, creates .env, starts (RSA keys auto-gen on boot)
./scripts/deploy.sh update    # git pull + npm ci + pm2 reload
./scripts/deploy.sh status    # pm2 status
./scripts/deploy.sh logs      # tail logs
```

Put **nginx or Caddy** in front to terminate TLS and proxy both HTTP and the
WebSocket upgrade to `127.0.0.1:8080` (the server binds to localhost by
default). Example nginx location:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
}
```

---

## Security & privacy notes (read before shipping)

Implemented in this branch:

- **Application-level E2EE** over the data channel (§1b): authenticated ECDH
  handshake with forward secrecy, identity keys pinned to anonIds, AES-256-GCM.
- **RS256 offline token verification** (§1): peers verify subscription proofs
  with the server's public key, no round-trip.
- **TURN with ephemeral credentials** (§1c) for symmetric-NAT fallback.

Still required before a real launch:

- **Get the crypto audited.** The handshake in `e2ee.js` is pragmatic and
  readable, not formally verified. Adopt an audited Noise (XX) or Signal-protocol
  implementation, and add a user-visible **safety-number** comparison flow.
- Consider **X25519** in place of P-256 where the WebView supports it.
- **Pin the signing key** (`EXPECTED_JWT_KID`) and plan RSA key rotation.
- The VPN check deters, but cannot cryptographically prove, a VPN on a
  compromised device.
- Never commit `server/.env` or `server/keys/` (both git-ignored). The RSA
  private key must stay on the server only.
```
