# Text Me Secretly

A privacy-first, peer-to-peer 1-on-1 messenger. Text and media flow **directly
between two devices** over a WebRTC data channel. The backend is deliberately
tiny: it brokers the initial handshake and sells subscriptions — it **never
stores, processes, or relays a single message or media byte**.

- **Identity:** anonymous. Each device mints a random 20-char ID on first run,
  stored locally. No emails, no accounts, no server-side user table.
- **Ephemeral:** text has a 12-hour local TTL and auto-deletes; media is
  **view-once** (rendered exactly once, then the bytes are burned).
- **Freemium:** 20 free messages **per new contact**, then a €5/month
  subscription is required — enforced locally on both peers with a server-signed
  proof token.
- **VPN-gated:** the UI is blocked and the signaling socket is cut whenever no
  VPN is detected, via a custom native Capacitor plugin.

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

### The proof token

- After a (mocked) payment, the client calls `POST /api/subscribe` with its
  `anonId`. The server issues a **JWT signed with `JWT_SECRET`** asserting
  *"the holder of this anonId has an active subscription until `exp`"*
  (`server/src/subscription.js`). It contains **no contact list and no message
  data** — just `sub` (the anonId), `scope`, and expiry.
- The token binds to the subscriber's `anonId`. The receiver checks the token's
  `sub` equals the sender's channel ID, which stops a paid user from lending
  their token to someone else on a different connection.
- One subscription unlocks *all* of the subscriber's contacts; the **other**
  party still has their own independent 20-message free tier until they too
  subscribe. (This is the intended business rule: either party paying keeps the
  conversation open from their side.)

### Verification: HS256 demo vs. RS256 hardening

This foundation uses **HS256** (shared secret). Because the receiver must not
hold the signing secret (that would let them forge tokens), the receiver
verifies by calling `POST /api/verify`. That's simple but adds a server
round-trip and a light metadata touch at verification time.

**Production hardening (recommended):** switch the server to **RS256**. Sign
with a private key kept only on the server; ship the **public** key inside the
app. Then the receiver verifies the token **fully offline** with the public key —
zero server contact, no metadata leak. The switch is localized to
`subscription.js` (server) and `verifyPeerToken` (client). See the inline notes
in both files.

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
├── server/                       # Minimal backend
│   ├── package.json
│   ├── .env.example
│   ├── ecosystem.config.js       # PM2 process definition
│   ├── server.js                 # Express REST + ws signaling on one port
│   └── src/
│       ├── config.js             # env loader, fails fast on weak JWT secret
│       ├── signaling.js          # WebRTC signaling relay (no content inspection)
│       ├── subscription.js       # JWT issue/verify (HS256 now, RS256-ready)
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
            ├── config.js         # signaling + API endpoints (edit for your VPS)
            ├── app.js            # bootstrap + UI wiring + VPN gate control
            ├── identity.js       # anonymous persistent ID
            ├── storage.js        # Preferences/localStorage KV (no message bodies)
            ├── signaling.js      # WebSocket signaling client
            ├── webrtc.js         # RTCPeerConnection + data channel
            ├── messaging.js      # protocol, counting, freemium gate, chunked media
            ├── ephemeral.js      # 12h text TTL sweeper + view-once media vault
            ├── subscription.js   # per-contact counters + token cache + purchase
            └── vpn.js            # native plugin wrapper + change events
```

---

## 4. Backend (Node.js: `ws` signaling + Express auth)

See `server/`. Key endpoints (`server/server.js`):

| Method + path        | Purpose                                                        |
| -------------------- | -------------------------------------------------------------- |
| `WS /signal`         | Register an anonId; relay `offer`/`answer`/`ice`/`bye` verbatim |
| `GET /api/config`    | Public: free limit, price, currency (renders the paywall)      |
| `POST /api/subscribe`| Mock-pay for an anonId, return a signed proof token            |
| `POST /api/token`    | Re-issue a token for an already-paid anonId                    |
| `POST /api/verify`   | Verify a peer's token (HS256 demo path)                        |
| `GET /api/health`    | Liveness                                                       |

The signaling relay keeps only an **in-memory `anonId → socket` map**, deleted on
disconnect, and forwards SDP/ICE without reading their contents. The mock
payment store lives in memory too — replace `server/src/payment.js` with a real
Stripe integration (webhook flips the paid flag) without touching anything else.

**Run locally:**

```bash
cd server
cp .env.example .env
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"  # paste into JWT_SECRET
npm install
npm start          # http + ws on :8080
```

---

## 5. Client core logic (Vanilla JS)

See `client/www/js/`. Highlights:

- **`webrtc.js`** — one ordered/reliable `RTCDataChannel` named `tms`. STUN is
  configured; add a TURN server for symmetric-NAT fallback.
- **`messaging.js`** — JSON frames for text/control, raw 16 KiB binary chunks for
  media (bracketed by `media-meta` / `media-end`). Applies the freemium gate on
  both send and receive.
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
./scripts/deploy.sh setup     # installs Node 20, PM2, deps, generates .env + JWT secret, starts
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

- **This is a foundation, not an audited product.** WebRTC already encrypts the
  data channel in transit (DTLS), but for at-rest and true end-to-end guarantees
  you should add an application-layer E2EE handshake (e.g. X25519 + libsodium)
  over the data channel and pin peer keys to anonIds.
- Move token verification to **RS256** so receivers verify **offline** (section 1).
- The VPN check deters, but cannot cryptographically prove, a VPN on a
  compromised device.
- Never commit `server/.env`. The server refuses to boot with a weak
  `JWT_SECRET`.
```
