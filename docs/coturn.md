# TURN server (coturn) on an Ubuntu VPS — no Docker

Text Me Secretly connects peers directly with WebRTC. Behind **symmetric NAT**
(common on mobile carriers) a direct path can't be found, and the connection
needs a TURN relay to succeed. TURN only ever forwards the **already
end-to-end-encrypted** media, so the relay operator sees ciphertext.

The app server issues **short-lived** TURN credentials using coturn's
`use-auth-secret` (a.k.a. TURN REST) scheme, so coturn needs no user database
and passwords expire automatically. The app server and coturn share only one
secret.

## 1. Install coturn

```bash
sudo apt-get update
sudo apt-get install -y coturn
# Enable the service
sudo sed -i 's/^#TURNSERVER_ENABLED=1/TURNSERVER_ENABLED=1/' /etc/default/coturn
```

## 2. Generate a shared secret

Use the SAME value in both coturn and the app server's `.env` (`TURN_SECRET`):

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## 3. Configure `/etc/turnserver.conf`

Replace `turn.your-host.example` and `YOUR_PUBLIC_IP`, and paste the secret:

```conf
# Listen
listening-port=3478
tls-listening-port=5349

# Public address of this VPS
listening-ip=0.0.0.0
external-ip=YOUR_PUBLIC_IP

# Realm (your domain)
realm=turn.your-host.example
server-name=turn.your-host.example

# Ephemeral credentials (TURN REST / use-auth-secret).
# MUST equal TURN_SECRET in the app server's .env.
use-auth-secret
static-auth-secret=PASTE_THE_SAME_SECRET_HERE

# TLS (reuse your Let's Encrypt cert; see step 5)
cert=/etc/letsencrypt/live/turn.your-host.example/fullchain.pem
pkey=/etc/letsencrypt/live/turn.your-host.example/privkey.pem

# Relay port range — open these in the firewall too
min-port=49152
max-port=65535

# Hardening
no-cli
no-multicast-peers
fingerprint
# Refuse relaying to private ranges (SSRF hygiene)
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=192.168.0.0-192.168.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
```

## 4. Firewall

```bash
sudo ufw allow 3478/tcp
sudo ufw allow 3478/udp
sudo ufw allow 5349/tcp
sudo ufw allow 5349/udp
sudo ufw allow 49152:65535/udp
```

## 5. TLS certificate (turns:)

```bash
sudo apt-get install -y certbot
sudo certbot certonly --standalone -d turn.your-host.example
# Let coturn read the cert (simplest: run coturn as a user in the ssl-cert group,
# or copy the certs to a coturn-readable path on renewal via a deploy hook).
```

## 6. Start coturn

```bash
sudo systemctl enable coturn
sudo systemctl restart coturn
sudo systemctl status coturn --no-pager
```

## 7. Point the app server at it

In `server/.env`:

```env
TURN_URLS=turn:turn.your-host.example:3478?transport=udp,turns:turn.your-host.example:5349?transport=tcp
TURN_SECRET=PASTE_THE_SAME_SECRET_HERE
TURN_TTL_SECONDS=86400
```

Reload the app server (`./scripts/deploy.sh update`). Now `POST /api/turn`
returns TURN entries with fresh credentials, and clients pick them up
automatically at session start.

## 8. Verify

- App server: `curl -s -X POST https://your-host.example/api/turn -H 'content-type: application/json' -d '{}' | jq`
  should list a `turn:`/`turns:` server with a `username` like `1699999999` and a
  base64 `credential`.
- End-to-end: use the [Trickle ICE test page](https://webrtc.github.io/samples/src/content/peerconnection/trickle-ice/)
  with your TURN URL + those credentials and confirm a `relay` candidate appears.
