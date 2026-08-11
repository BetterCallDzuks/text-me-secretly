// _setup.mjs — browser-global shims so the client's ES modules (written for a
// Capacitor WebView) load under Node's test runner. Import this FIRST in every
// client test file; its side effects run before the modules under test load.

if (typeof globalThis.self === 'undefined') globalThis.self = globalThis;
if (typeof globalThis.window === 'undefined') globalThis.window = globalThis;

if (typeof globalThis.CustomEvent === 'undefined') {
  globalThis.CustomEvent = class extends Event {
    constructor(type, opts = {}) {
      super(type, opts);
      this.detail = opts && opts.detail;
    }
  };
}

if (typeof globalThis.localStorage === 'undefined') {
  const m = new Map();
  globalThis.localStorage = {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
    removeItem: (k) => m.delete(k),
    clear: () => m.clear(),
  };
}
