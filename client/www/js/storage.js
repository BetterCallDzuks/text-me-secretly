// storage.js — thin key/value wrapper.
//
// Uses Capacitor Preferences on device (survives app restarts, stored in the
// app's private sandbox) and falls back to localStorage in a plain browser for
// development. Values are JSON-encoded.
//
// IMPORTANT: message BODIES are never written here. This holds only durable app
// state: the anon ID, per-contact counters, and the subscription token. Message
// text lives in an in-memory + TTL-swept cache (see ephemeral.js), and media is
// never persisted at all (view-once).

let Preferences = null;
try {
  // Available only inside the Capacitor runtime.
  ({ Preferences } = await import('@capacitor/preferences'));
} catch {
  Preferences = null;
}

export const store = {
  async get(key) {
    if (Preferences) {
      const { value } = await Preferences.get({ key });
      return value == null ? null : safeParse(value);
    }
    const raw = localStorage.getItem(key);
    return raw == null ? null : safeParse(raw);
  },

  async set(key, value) {
    const raw = JSON.stringify(value);
    if (Preferences) return Preferences.set({ key, value: raw });
    localStorage.setItem(key, raw);
  },

  async remove(key) {
    if (Preferences) return Preferences.remove({ key });
    localStorage.removeItem(key);
  },
};

function safeParse(raw) {
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}
