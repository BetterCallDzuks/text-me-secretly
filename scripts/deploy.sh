#!/usr/bin/env bash
#
# deploy.sh — first-time setup AND update for the Text Me Secretly backend on a
# bare Ubuntu VPS. No Docker. Manages the process with PM2.
#
# Usage:
#   ./scripts/deploy.sh setup     # one-time: install deps, node, pm2, env
#   ./scripts/deploy.sh update    # pull latest, install, reload with zero-ish downtime
#   ./scripts/deploy.sh logs      # tail the server logs
#   ./scripts/deploy.sh status    # pm2 status
#
# Assumes this repo is cloned at $APP_DIR and the server lives in ./server.

set -euo pipefail

APP_DIR="${APP_DIR:-$HOME/text-me-secretly}"
SERVER_DIR="$APP_DIR/server"
NODE_MAJOR="${NODE_MAJOR:-20}"
PM2_APP_NAME="tms-server"

log() { printf '\033[0;32m[deploy]\033[0m %s\n' "$*"; }
err() { printf '\033[0;31m[deploy:error]\033[0m %s\n' "$*" >&2; }

ensure_node() {
  if command -v node >/dev/null 2>&1 && node -e 'process.exit(process.versions.node.split(".")[0] >= 18 ? 0 : 1)'; then
    log "Node $(node -v) already present."
    return
  fi
  log "Installing Node.js ${NODE_MAJOR}.x via NodeSource…"
  curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | sudo -E bash -
  sudo apt-get install -y nodejs
}

ensure_pm2() {
  if ! command -v pm2 >/dev/null 2>&1; then
    log "Installing PM2 globally…"
    sudo npm install -g pm2
  fi
}

ensure_env() {
  if [[ ! -f "$SERVER_DIR/.env" ]]; then
    log "No .env found — creating from .env.example (EDIT IT, then re-run)."
    cp "$SERVER_DIR/.env.example" "$SERVER_DIR/.env"
    # Auto-generate a strong JWT secret so the server can boot.
    local secret
    secret="$(node -e "console.log(require('crypto').randomBytes(48).toString('hex'))")"
    # Replace the placeholder secret line in-place.
    sed -i "s|^JWT_SECRET=.*|JWT_SECRET=${secret}|" "$SERVER_DIR/.env"
    log "Generated a random JWT_SECRET in server/.env."
  fi
}

cmd_setup() {
  ensure_node
  ensure_pm2
  log "Installing server dependencies…"
  (cd "$SERVER_DIR" && npm ci --omit=dev || npm install --omit=dev)
  ensure_env
  log "Starting under PM2…"
  (cd "$SERVER_DIR" && pm2 start ecosystem.config.js)
  pm2 save
  log "Enabling PM2 startup on boot (follow any printed instructions)…"
  pm2 startup systemd -u "$USER" --hp "$HOME" || true
  log "Setup complete. Put nginx/caddy in front to terminate TLS -> :${PORT:-8080}."
}

cmd_update() {
  log "Pulling latest…"
  (cd "$APP_DIR" && git pull --ff-only)
  log "Installing server dependencies…"
  (cd "$SERVER_DIR" && npm ci --omit=dev || npm install --omit=dev)
  ensure_env
  log "Reloading PM2 process…"
  (cd "$SERVER_DIR" && pm2 reload ecosystem.config.js) || (cd "$SERVER_DIR" && pm2 start ecosystem.config.js)
  pm2 save
  log "Update complete."
}

cmd_logs() { pm2 logs "$PM2_APP_NAME"; }
cmd_status() { pm2 status; }

case "${1:-}" in
  setup) cmd_setup ;;
  update) cmd_update ;;
  logs) cmd_logs ;;
  status) cmd_status ;;
  *)
    err "Unknown command: ${1:-<none>}"
    echo "Usage: $0 {setup|update|logs|status}"
    exit 1
    ;;
esac
