// run.mjs — real end-to-end test.
//
// Proves the whole stack works in an actual browser, not just unit tests:
// boots two isolated Chromium peers against the REAL signaling+API server, lets
// them discover each other's anonId, open a real WebRTC data channel, run the
// Noise XX handshake (on libsodium WASM), and exchange messages that must
// decrypt and render on the other side.
//
// Run: npm run test:e2e   (uses the preinstalled Chromium)

import { chromium } from 'playwright';
import { spawn } from 'node:child_process';
import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLIENT_DIR = path.resolve(__dirname, '..');
const REPO_DIR = path.resolve(CLIENT_DIR, '..');
const WWW_DIR = path.join(CLIENT_DIR, 'www');
const CHROME =
  process.env.TMS_CHROME || '/opt/pw-browsers/chromium-1194/chrome-linux/chrome';

const MIME = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.mjs': 'text/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
};

function freePort() {
  return new Promise((res, rej) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => res(port));
    });
    s.on('error', rej);
  });
}

function staticServer(dir, port) {
  const server = http.createServer((req, res) => {
    const urlPath = decodeURIComponent(req.url.split('?')[0]);
    let file = path.join(dir, urlPath === '/' ? 'index.html' : urlPath);
    if (!file.startsWith(dir)) return res.writeHead(403).end();
    fs.readFile(file, (err, data) => {
      if (err) return res.writeHead(404).end('not found');
      res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
      res.end(data);
    });
  });
  return new Promise((resolve) => server.listen(port, '127.0.0.1', () => resolve(server)));
}

async function waitForHealth(base, timeoutMs = 10000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`${base}/api/health`);
      if (r.ok) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error('signaling server did not become healthy');
}

const log = (...a) => console.log('[e2e]', ...a);
let failures = 0;
function check(name, cond) {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${name}`);
  if (!cond) failures++;
}

async function main() {
  const apiPort = await freePort();
  const staticPort = await freePort();
  const apiBase = `http://127.0.0.1:${apiPort}`;
  const wsUrl = `ws://127.0.0.1:${apiPort}/signal`;

  // 1. Spawn the REAL signaling + API server (keys land in a temp dir).
  const keyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tms-e2e-'));
  const server = spawn('node', ['server.js'], {
    cwd: path.join(REPO_DIR, 'server'),
    env: {
      ...process.env,
      PORT: String(apiPort),
      HOST: '127.0.0.1',
      JWT_PRIVATE_KEY_PATH: path.join(keyDir, 'priv.pem'),
      JWT_PUBLIC_KEY_PATH: path.join(keyDir, 'pub.pem'),
      CORS_ORIGINS: '*',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  server.stderr.on('data', (d) => process.stderr.write(`[server] ${d}`));
  await waitForHealth(apiBase);
  log('signaling server up on', apiBase);

  // 2. Serve the client app.
  const staticSrv = await staticServer(WWW_DIR, staticPort);
  const appUrl = `http://127.0.0.1:${staticPort}/`;
  log('app served at', appUrl);

  // 3. Launch Chromium. Flags: no-sandbox (container/root) and expose real host
  //    ICE candidates so two local contexts can actually connect. Use the
  //    preinstalled browser when present; otherwise fall back to Playwright's
  //    managed browser (e.g. after `npx playwright install chromium` in CI).
  const launchOpts = {
    headless: true,
    args: [
      '--no-sandbox',
      '--disable-features=WebRtcHideLocalIpsWithMdns',
      '--force-webrtc-ip-handling-policy=default_public_and_private_interfaces',
    ],
  };
  if (fs.existsSync(CHROME)) launchOpts.executablePath = CHROME;
  const browser = await chromium.launch(launchOpts);

  async function openPeer(label) {
    const ctx = await browser.newContext(); // isolated storage => distinct identity
    const page = await ctx.newPage();
    page.on('console', (m) => {
      if (m.type() === 'error') console.error(`[${label} console] ${m.text()}`);
    });
    // Pass the VPN gate (web fallback) and skip the first-run backup overlay.
    await page.addInitScript(() => {
      window.__TMS_DEV_ALLOW_NO_VPN__ = true;
      try {
        localStorage.setItem('CapacitorStorage.tms.backupPrompted', 'true');
      } catch {}
    });
    // Point the app at our local server.
    await page.route('**/js/config.js', (route) =>
      route.fulfill({
        contentType: 'text/javascript',
        body: `export const CONFIG = { SIGNALING_URL: ${JSON.stringify(wsUrl)}, API_BASE: ${JSON.stringify(apiBase)}, EXPECTED_JWT_KID: null };`,
      })
    );
    await page.goto(appUrl);
    // App visible (VPN gate passed) and identity minted.
    await page.waitForSelector('#app:not(.hidden)', { timeout: 15000 });
    await page.waitForFunction(
      () => {
        const el = document.getElementById('my-id');
        return el && /^[A-Z2-7]{20}$/.test(el.textContent.trim());
      },
      { timeout: 15000 }
    );
    // Wait until signaling has connected + registered.
    await page.waitForFunction(
      () => (document.getElementById('conn-status')?.textContent || '').includes('Signaling connected'),
      { timeout: 15000 }
    );
    // Dismiss the account overlay if it happens to be open.
    if (await page.locator('#account:not(.hidden)').count()) {
      await page.click('#acct-close').catch(() => {});
    }
    const id = (await page.textContent('#my-id')).trim();
    return { ctx, page, id };
  }

  const A = await openPeer('A');
  const B = await openPeer('B');
  log('peer A id:', A.id);
  log('peer B id:', B.id);
  check('two peers minted distinct anonIds', A.id !== B.id);

  // 4. A dials B; both should reach the encrypted chat.
  await A.page.fill('#peer-id', B.id);
  await A.page.click('#connect-btn');

  await A.page.waitForSelector('#chat:not(.hidden)', { timeout: 25000 });
  await B.page.waitForSelector('#chat:not(.hidden)', { timeout: 25000 });
  log('P2P data channel + Noise XX handshake complete on both peers');
  check('A shows the verified (E2EE) safety bar', await A.page.locator('#safety-bar').isVisible());

  // 5. A -> B message must decrypt + render on B.
  const msgAB = 'hello from A ' + Date.now();
  await A.page.fill('#msg-input', msgAB);
  await A.page.click('#send-btn');
  await B.page.waitForFunction(
    (t) => document.getElementById('messages')?.textContent.includes(t),
    msgAB,
    { timeout: 15000 }
  );
  check('B received & rendered A’s encrypted message', true);

  // 6. B -> A the other direction.
  const msgBA = 'reply from B ' + Date.now();
  await B.page.fill('#msg-input', msgBA);
  await B.page.click('#send-btn');
  await A.page.waitForFunction(
    (t) => document.getElementById('messages')?.textContent.includes(t),
    msgBA,
    { timeout: 15000 }
  );
  check('A received & rendered B’s encrypted message', true);

  // Cleanup.
  await browser.close();
  staticSrv.close();
  server.kill('SIGTERM');

  console.log(failures === 0 ? '\ne2e: ALL PASSED' : `\ne2e: ${failures} FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('[e2e] fatal:', err);
  process.exit(1);
});
