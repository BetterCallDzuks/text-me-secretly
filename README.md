# Text Me Secretly

A privacy-first, peer-to-peer 1-on-1 messenger. Text and media flow **directly
between two devices** over a WebRTC data channel. The backend is deliberately
tiny: it brokers the initial handshake and sells subscriptions — it **never
stores, processes, or relays a single message or media byte**.

- **Identity:** anonymous, **self-certifying, and recoverable**. The identity
  keypair (Noise X25519 static key) is derived deterministically from a **BIP39
  recovery phrase** — the phrase is your login/backup, and its **public-key
  fingerprint** (`base32(sha256(pub))[:20]`) is the anonId you share so people
  can add you. No emails, no accounts, no server-side user table.
- **End-to-end encrypted:** an audited **Noise XX** handshake
  (`Noise_XX_25519_ChaChaPoly_BLAKE2b`) authenticates both peers and seals every
  message and media chunk, on top of WebRTC's transport encryption.
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

## 1b. End-to-end encryption — Noise XX (`client/www/js/e2ee.js`)

WebRTC encrypts the data channel in transit (DTLS), but that terminates inside
each device's WebRTC stack. On top of it we run application-level E2EE using the
**Noise Protocol Framework's XX pattern**, implemented by the audited
[`noise-handshake`](https://github.com/holepunchto/noise-handshake) library
(Holepunch — the same Noise implementation that powers the **Keet** P2P
messenger). Suite:

```
Noise_XX_25519_ChaChaPoly_BLAKE2b
```

- **Why XX:** it is the mutual-authentication pattern for peers who *don't* know
  each other's static key in advance — exactly our case (anonymous peers who only
  exchanged an anonId). Both static keys are transmitted and cryptographically
  authenticated during the 3-message handshake, and XX's ephemeral keys give
  **forward secrecy**.
- **Identity binding (our layer):** the identity keypair is now the Noise
  **static** key (X25519), and the anonId is its fingerprint
  (`base32(sha256(pub))[:20]`). After the handshake each side checks that the
  peer's learned static key (`hs.rs`) fingerprints to the anonId it dialed — so a
  signaling-server MITM that swaps keys is detected and the connection dropped.
- **Transport:** after the handshake, `noise-handshake` provides the split
  cipher states; every frame and media chunk is sealed with ChaCha20-Poly1305
  (nonces + rekeying managed by the library). A 1-byte outer prefix marks
  handshake vs transport messages; a 1-byte inner tag marks JSON frame vs media
  chunk.
- **Tested:** two peers complete the XX handshake, exchange encrypted text and
  media both ways, a tampered ciphertext is rejected by Poly1305, and an
  identity-mismatch (MITM) attempt is rejected.

**Build note:** the vendored crypto libraries are the *only* part of the client
with a build step. `npm run build:vendor` bundles `client/build/*.mjs` (via
esbuild) into two committed, self-contained ES modules under
`client/www/js/vendor/` (`noise-xx.js`, `mnemonic.js`), so the app still loads
buildless. Everything else stays vanilla JS.

**In-browser primitive:** the Noise bundle uses `sodium-javascript` (a pure-JS
port of libsodium) for the WebView. The Noise *protocol* implementation is
production-grade; the further hardening step is to back it with the official
audited **libsodium WASM** build.

---

## 1b′. Identity & recovery phrase (`client/www/js/identity.js`)

The identity is wallet-style — a keypair you can back up and restore, with no
account server:

- **Public key = contact address.** Its fingerprint is the anonId
  (`base32(sha256(pub))[:20]`); you share it so people can add you. It is also
  the Noise static-key fingerprint used for the MITM check above, so the anonId
  doubles as a **safety number** for out-of-band verification.
- **Private key = recovery phrase (login/backup).** On first run the app mints a
  **12-word BIP39 mnemonic** (via the audited `@scure/bip39`) and derives the
  X25519 static keypair deterministically from it:
  `mnemonic (+ passphrase) → BIP39 seed → SHA-256(domain-tagged) → curve.generateSeedKeyPair`.
  Entering the same phrase on any device restores the same keypair and the same
  anonId — that's login. The derived keypair is persisted locally, so normal
  launches never prompt for the passphrase.
- **Optional passphrase (second factor).** A BIP39 "25th word": with a passphrase
  set, the written phrase *alone* can't restore the account. It is **never
  stored**, and because it changes the derived keypair it changes the anonId —
  so setting/removing it is switching to a different address (the UI says so).
  An empty passphrase reproduces the original derivation, so existing identities
  are unchanged.
- **Safety number.** The anonId *is* the identity-key fingerprint, so the chat
  header shows a **🔒 verified** bar; tapping it reveals both peers' safety
  numbers (grouped for reading aloud). If both devices show the same pair,
  there's no one in the middle.
- **UI:** the 🔑 account panel shows the shareable ID, reveals the recovery
  phrase for backup (with a "never share this" warning), lets you add/remove a
  passphrase, and accepts a phrase (+ optional passphrase) to restore/log in
  (re-registering signaling under the restored id). A first-run prompt nudges
  the user to save the phrase.
- **Tested:** a phrase deterministically yields the same anonId; a passphrase
  changes it deterministically and restores exactly; an empty passphrase equals
  the passphrase-less derivation; the keypair persists and reloads without the
  passphrase; and mnemonic-derived identities complete a real Noise XX handshake.

> Security note: the recovery phrase (plus passphrase, if set) is the master
> secret. Whoever holds it can restore the account and read its *future* messages
> (past messages stay protected by Noise's forward secrecy) — the standard
> mnemonic-wallet trade-off, surfaced in the UI.

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
    ├── package.json              # + build:vendor scripts (esbuild) & crypto dev deps
    ├── capacitor.config.json
    ├── build/                    # bundle entries (the only client build step)
    │   ├── noise-entry.mjs       # re-exports Noise XX
    │   └── mnemonic-entry.mjs    # re-exports BIP39 mnemonic helpers
    └── www/
        ├── index.html
        ├── css/style.css
        └── js/
            ├── config.js         # signaling + API endpoints + key-pin (edit for your VPS)
            ├── app.js            # bootstrap + UI + VPN gate + Noise handshake + account panel
            ├── identity.js       # mnemonic-derived X25519 keypair; backup/restore
            ├── crypto.js         # Web Crypto: base32/sha256, fingerprint, RS256 verify
            ├── e2ee.js           # drives the Noise XX handshake + transport framing
            ├── vendor/
            │   ├── noise-xx.js   # GENERATED: noise-handshake + sodium-javascript
            │   └── mnemonic.js   # GENERATED: @scure/bip39 + @noble/hashes
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

- **`e2ee.js` / `vendor/noise-xx.js`** — the E2EE layer (see §1b): drives the
  audited **Noise XX** handshake and seals every frame with ChaCha20-Poly1305.
  Chat opens only after the handshake verifies the peer's identity.
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

The vendored crypto bundles (`www/js/vendor/*.js`) are committed, so the app
runs without a build step. To regenerate them after bumping a pinned library:

```bash
cd client && npm install && npm run build:vendor
```

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

Implemented:

- **Application-level E2EE via Noise XX** (§1b): the audited `noise-handshake`
  library (`Noise_XX_25519_ChaChaPoly_BLAKE2b`), with static keys bound to
  anonIds so a key-swap MITM is detected. Forward secrecy from XX ephemerals.
- **RS256 offline token verification** (§1): peers verify subscription proofs
  with the server's public key, no round-trip.
- **TURN with ephemeral credentials** (§1c) for symmetric-NAT fallback.
- **Recoverable identity** (§1b′): BIP39 recovery phrase (+ optional passphrase)
  → deterministic X25519 keypair; public-key fingerprint is the shareable anonId.
- **Safety-number verification** (§1b′): the chat header shows a verified bar
  revealing both peers' identity-key fingerprints for out-of-band comparison.

Still required before a real launch:

- **Back Noise with the audited libsodium WASM.** The Noise *protocol* impl is
  production-grade (powers Keet), but the in-browser primitive is
  `sodium-javascript` (a pure-JS port). Swap in the official libsodium WASM
  backend, and get the full integration reviewed.
- **Pin the signing key** (`EXPECTED_JWT_KID`) and plan RSA key rotation.
- The VPN check deters, but cannot cryptographically prove, a VPN on a
  compromised device.
- Never commit `server/.env` or `server/keys/` (both git-ignored). The RSA
  private key must stay on the server only.
```
