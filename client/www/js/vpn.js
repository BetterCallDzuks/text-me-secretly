// vpn.js — hard VPN gate.
//
// The app must not function without a VPN. This module wraps the native
// VpnDetector plugin, polls + listens for changes, and exposes a simple
// "onChange(active)" so the bootstrap can lock the UI and cut the signaling
// socket the instant a tunnel drops.

let VpnDetector = null;
try {
  ({ VpnDetector } = await import('vpn-detector'));
} catch {
  VpnDetector = null;
}

const listeners = new Set();
let lastActive = null;
let pollTimer = null;

async function check() {
  if (!VpnDetector) {
    // No plugin (plain browser). Honor the dev bypass flag, else fail closed.
    const bypass = typeof window !== 'undefined' && window.__TMS_DEV_ALLOW_NO_VPN__ === true;
    return bypass;
  }
  try {
    const { active } = await VpnDetector.isVpnActive();
    return !!active;
  } catch {
    return false; // fail closed
  }
}

function emit(active) {
  if (active === lastActive) return;
  lastActive = active;
  for (const fn of listeners) fn(active);
}

export const vpnGate = {
  onChange(fn) {
    listeners.add(fn);
    if (lastActive !== null) fn(lastActive);
    return () => listeners.delete(fn);
  },

  async isActive() {
    return check();
  },

  /** Begin native monitoring + a belt-and-braces poll. */
  async start() {
    const active = await check();
    emit(active);

    if (VpnDetector) {
      try {
        await VpnDetector.startMonitoring();
        await VpnDetector.addListener('vpnStatusChanged', (s) => emit(!!s.active));
      } catch {
        /* fall back to polling only */
      }
    }

    // Poll every 4s as a safety net (some OS callbacks are unreliable).
    if (!pollTimer) {
      pollTimer = setInterval(async () => emit(await check()), 4000);
    }
  },

  async stop() {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
    if (VpnDetector) {
      try {
        await VpnDetector.stopMonitoring();
      } catch {
        /* ignore */
      }
    }
  },
};
