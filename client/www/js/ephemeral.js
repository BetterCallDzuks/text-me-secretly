// ephemeral.js — the two ephemerality rules live here.
//
//   1. TEXT: 12-hour local TTL. Text is kept ONLY in memory with an expiry
//      timestamp. A sweeper purges expired entries and removes their bubbles.
//      Because it is never written to durable storage, killing the app also
//      drops it — the 12h TTL is the *maximum* lifetime, not a guarantee it
//      lives that long.
//
//   2. MEDIA: view-once. Media bytes are held as an in-memory Blob keyed by a
//      message id. The instant they are rendered, revoke() is called, the Blob
//      URL is revoked, and the bytes are dropped from the map. There is no
//      second render.

export const TEXT_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours

// id -> { expiresAt, el } for text bubbles under TTL.
const textRegistry = new Map();
// id -> { blob, objectUrl } for undisplayed view-once media.
const mediaVault = new Map();

let sweeper = null;

/** Register a text message so it auto-deletes at `expiresAt`. */
export function trackText(id, el, createdAt = Date.now()) {
  const expiresAt = createdAt + TEXT_TTL_MS;
  textRegistry.set(id, { expiresAt, el });
  ensureSweeper();
  return expiresAt;
}

/** Human-friendly remaining time, e.g. "11h 59m". */
export function remainingLabel(expiresAt) {
  const ms = Math.max(0, expiresAt - Date.now());
  const h = Math.floor(ms / 3600000);
  const m = Math.floor((ms % 3600000) / 60000);
  return `deletes in ${h}h ${m}m`;
}

function ensureSweeper() {
  if (sweeper) return;
  sweeper = setInterval(sweep, 60 * 1000);
}

function sweep() {
  const now = Date.now();
  for (const [id, entry] of textRegistry) {
    if (entry.expiresAt <= now) {
      if (entry.el && entry.el.parentNode) entry.el.remove();
      textRegistry.delete(id);
    }
  }
  if (textRegistry.size === 0 && sweeper) {
    clearInterval(sweeper);
    sweeper = null;
  }
}

/** Stash incoming view-once media until it is rendered exactly once. */
export function stashMedia(id, blob) {
  mediaVault.set(id, { blob, objectUrl: null });
}

/**
 * Consume a view-once media item: returns an object URL for a single render and
 * IMMEDIATELY schedules its destruction. Returns null if already consumed.
 */
export function consumeMedia(id) {
  const entry = mediaVault.get(id);
  if (!entry) return null;
  const objectUrl = URL.createObjectURL(entry.blob);
  entry.objectUrl = objectUrl;
  return objectUrl;
}

/** Burn a media item after its single render (revoke URL + drop bytes). */
export function burnMedia(id) {
  const entry = mediaVault.get(id);
  if (!entry) return;
  if (entry.objectUrl) URL.revokeObjectURL(entry.objectUrl);
  // Best-effort: drop references so GC can reclaim the bytes.
  entry.blob = null;
  mediaVault.delete(id);
}

/** Wipe everything (called when the VPN drops or the app blurs to background). */
export function purgeAll() {
  for (const [id] of mediaVault) burnMedia(id);
  for (const [, entry] of textRegistry) {
    if (entry.el && entry.el.parentNode) entry.el.remove();
  }
  textRegistry.clear();
}
