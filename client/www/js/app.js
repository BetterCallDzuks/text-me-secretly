// app.js — bootstrap + UI wiring.
//
// Order of operations:
//   1. Enforce the VPN gate. Nothing else runs until a VPN is active. If it
//      drops at any time, we purge ephemeral data, cut signaling, and re-lock.
//   2. Mint/load the anonymous ID and pull public server config.
//   3. Connect signaling, let the user dial a peer, open the P2P channel.
//   4. Run the freemium-gated messaging protocol.

import { CONFIG } from './config.js';
import { getIdentity, getMnemonic, restoreFromMnemonic } from './identity.js';
import { vpnGate } from './vpn.js';
import { Signaling } from './signaling.js';
import { PeerConnection } from './webrtc.js';
import { E2EESession } from './e2ee.js';
import { Messaging } from './messaging.js';
import { purgeAll } from './ephemeral.js';
import { store } from './storage.js';
import {
  setServerConfig,
  setApiBase,
  subscribe,
  freeLimit,
  getCount,
  preloadVerifyKey,
} from './subscription.js';

const $ = (id) => document.getElementById(id);

const ui = {
  gate: $('vpn-gate'),
  gateMsg: $('vpn-gate-msg'),
  gateRecheck: $('vpn-recheck'),
  app: $('app'),
  myId: $('my-id'),
  vpnBadge: $('vpn-badge'),
  peerId: $('peer-id'),
  connectBtn: $('connect-btn'),
  connStatus: $('conn-status'),
  chat: $('chat'),
  peerLabel: $('peer-label'),
  quota: $('quota'),
  messages: $('messages'),
  msgInput: $('msg-input'),
  sendBtn: $('send-btn'),
  attachBtn: $('attach-btn'),
  fileInput: $('file-input'),
  paywall: $('paywall'),
  paywallMsg: $('paywall-msg'),
  paywallSubscribe: $('paywall-subscribe'),
  paywallClose: $('paywall-close'),
  accountBtn: $('account-btn'),
  account: $('account'),
  acctId: $('acct-id'),
  acctCopyId: $('acct-copy-id'),
  acctPhrase: $('acct-phrase'),
  acctReveal: $('acct-reveal'),
  acctCopyPhrase: $('acct-copy-phrase'),
  acctRestoreInput: $('acct-restore-input'),
  acctRestore: $('acct-restore'),
  acctMsg: $('acct-msg'),
  acctClose: $('acct-close'),
};

const state = {
  identity: null,
  myId: null,
  vpnActive: false,
  signaling: null,
  iceServers: null,
  peer: null,
  session: null,
  messaging: null,
  peerId: null,
};

// --- VPN gate ---------------------------------------------------------------

function lockForVpn() {
  ui.gate.classList.add('overlay--block');
  ui.gate.classList.remove('hidden');
  ui.app.classList.add('hidden');
  ui.gateMsg.textContent =
    'No VPN detected. Connect to your VPN to use Text Me Secretly.';
  ui.gateRecheck.classList.remove('hidden');
  ui.vpnBadge.className = 'badge badge--bad';

  // Sever everything the moment the tunnel is gone.
  purgeAll();
  if (state.signaling) state.signaling.disconnect();
  if (state.session) state.session.destroy();
  if (state.peer) state.peer.close();
  state.session = null;
  state.peer = null;
  state.messaging = null;
}

function unlockFromVpn() {
  ui.gate.classList.add('hidden');
  ui.gate.classList.remove('overlay--block');
  ui.app.classList.remove('hidden');
  ui.vpnBadge.className = 'badge badge--ok';
  startSession();
}

// --- Session ----------------------------------------------------------------

let sessionStarted = false;
async function startSession() {
  if (sessionStarted) {
    // Re-establish signaling after a VPN blip.
    if (state.signaling) state.signaling.connect(state.myId);
    return;
  }
  sessionStarted = true;

  ui.myId.textContent = state.myId;

  // Pull public config (free limit, price) — non-fatal if offline.
  try {
    const res = await fetch(`${CONFIG.API_BASE}/api/config`);
    if (res.ok) setServerConfig(await res.json());
  } catch {
    /* use defaults */
  }
  ui.paywallMsg.textContent = `You've used your ${freeLimit()} free messages with this contact. Subscribe to continue.`;

  // Warm the offline token-verification key and fetch ICE servers (STUN+TURN).
  preloadVerifyKey();
  state.iceServers = await fetchIceServers();

  state.signaling = new Signaling(CONFIG.SIGNALING_URL);
  state.signaling.addEventListener('open', () => {
    ui.connStatus.textContent = 'Signaling connected. Enter a contact ID.';
  });
  state.signaling.addEventListener('close', () => {
    ui.connStatus.textContent = 'Signaling disconnected.';
  });
  state.signaling.addEventListener('signal', (ev) => handleSignal(ev.detail));
  state.signaling.connect(state.myId);

  // First-run: nudge the user to back up their recovery phrase exactly once.
  if (!(await store.get('tms.backupPrompted'))) {
    await store.set('tms.backupPrompted', true);
    openAccount();
    ui.acctMsg.textContent = 'Welcome! Save your recovery phrase — it is the only way to restore this account.';
  }
}

async function handleSignal(msg) {
  switch (msg.type) {
    case 'offer':
      await acceptIncomingCall(msg.from, msg.sdp);
      break;
    case 'answer':
      if (state.peer) await state.peer.onAnswer(msg.sdp);
      break;
    case 'ice':
      if (state.peer) await state.peer.onIce(msg.candidate);
      break;
    case 'bye':
      teardownPeer('Peer hung up.');
      break;
    case 'unavailable':
      ui.connStatus.textContent = `Contact ${msg.to} is offline.`;
      break;
  }
}

// --- Peer connection --------------------------------------------------------

/** Fetch STUN + ephemeral TURN servers from the backend (best-effort). */
async function fetchIceServers() {
  try {
    const res = await fetch(`${CONFIG.API_BASE}/api/turn`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ anonId: state.myId }),
    });
    if (res.ok) return (await res.json()).iceServers;
  } catch {
    /* fall back to the client's built-in STUN default */
  }
  return null;
}

async function dial(peerId) {
  state.peerId = peerId;
  state.peer = new PeerConnection(state.signaling, peerId, {
    initiator: true,
    iceServers: state.iceServers,
  });
  wirePeer();
  await state.peer.start();
  ui.connStatus.textContent = `Calling ${peerId}…`;
}

async function acceptIncomingCall(peerId, sdp) {
  state.peerId = peerId;
  ui.peerId.value = peerId;
  state.peer = new PeerConnection(state.signaling, peerId, {
    initiator: false,
    iceServers: state.iceServers,
  });
  wirePeer();
  await state.peer.onOffer(sdp);
  ui.connStatus.textContent = `Incoming from ${peerId}…`;
}

function wirePeer() {
  state.peer.addEventListener('channelopen', async () => {
    // Run the E2EE handshake BEFORE any messaging. Chat opens only once the
    // channel is authenticated and keyed.
    ui.connStatus.textContent = 'Securing channel (Noise XX handshake)…';
    state.session = new E2EESession(
      state.peer,
      state.identity,
      state.peerId,
      state.peer.initiator
    );
    state.session.addEventListener('established', () => {
      state.messaging = new Messaging(state.session, state.myId, state.peerId);
      wireMessaging();
      openChatUI();
    });
    state.session.addEventListener('insecure', (ev) => {
      teardownPeer(`⚠ Handshake failed (${ev.detail.reason}) — possible MITM. Disconnected.`);
    });
    await state.session.start();
  });
  state.peer.addEventListener('channelclose', () => teardownPeer('Channel closed.'));
  state.peer.addEventListener('state', (ev) => {
    if (['failed', 'disconnected', 'closed'].includes(ev.detail)) {
      teardownPeer(`Connection ${ev.detail}.`);
    }
  });
}

function teardownPeer(reason) {
  if (state.session) state.session.destroy();
  if (state.peer) state.peer.close();
  state.session = null;
  state.peer = null;
  state.messaging = null;
  ui.chat.classList.add('hidden');
  ui.connStatus.textContent = reason || 'Disconnected.';
}

// --- Chat UI ----------------------------------------------------------------

async function openChatUI() {
  ui.chat.classList.remove('hidden');
  ui.peerLabel.textContent = state.peerId;
  ui.connStatus.textContent = 'Connected (P2P · end-to-end encrypted).';
  await refreshQuota();
  systemBubble(
    '🔒 End-to-end encrypted & identity-verified. Text auto-deletes after 12h; media is view-once.'
  );
}

function wireMessaging() {
  state.messaging.addEventListener('message', (ev) => renderMessage(ev.detail));
  state.messaging.addEventListener('count', () => refreshQuota());
  state.messaging.addEventListener('gated', () => showPaywall());
  state.messaging.addEventListener('blocked-incoming', () =>
    systemBubble('A message was blocked: contact must subscribe to continue.')
  );
}

async function refreshQuota() {
  const n = await getCount(state.peerId);
  const limit = freeLimit();
  ui.quota.textContent = `${Math.min(n, limit)} / ${limit}`;
  ui.quota.classList.toggle('quota--warn', n >= limit);
}

function renderMessage(m) {
  if (m.kind === 'text') {
    const el = bubble(m.mine ? 'me' : 'them', m.body);
    if (m.track) {
      const ttl = m.track(el);
      const meta = document.createElement('span');
      meta.className = 'bubble__ttl';
      meta.textContent = ttl;
      el.appendChild(meta);
    }
    scrollDown();
  } else if (m.kind === 'media') {
    renderMediaBubble(m);
  }
}

function renderMediaBubble(m) {
  const el = bubble(m.mine ? 'me' : 'them', '');
  el.classList.add('bubble--media');
  if (m.mine) {
    el.textContent = `📤 ${m.mediaKind} sent · view-once`;
    ui.messages.appendChild(el);
    scrollDown();
    return;
  }
  el.textContent = `👁 Tap to view once (${m.mediaKind})`;
  el.addEventListener(
    'click',
    () => {
      const url = m.reveal();
      if (!url) {
        el.textContent = '⋯ already viewed';
        return;
      }
      el.textContent = '';
      const node = buildMediaNode(m.mediaKind, url);
      el.appendChild(node);
      // Burn on first render: revoke + drop bytes. No second view.
      const burnNow = () => m.burn();
      if (m.mediaKind === 'image') {
        // Give the image a beat to paint, then it stays only as pixels on
        // screen; the underlying bytes are released.
        node.addEventListener('load', () => setTimeout(burnNow, 50));
      } else {
        node.addEventListener('ended', burnNow);
        setTimeout(burnNow, 100); // release source bytes; element keeps playing buffer
      }
      const note = document.createElement('span');
      note.className = 'bubble__ttl';
      note.textContent = 'view-once · not stored';
      el.appendChild(note);
    },
    { once: true }
  );
  ui.messages.appendChild(el);
  scrollDown();
}

function buildMediaNode(kind, url) {
  if (kind === 'image') {
    const img = document.createElement('img');
    img.className = 'bubble__media-view';
    img.src = url;
    return img;
  }
  if (kind === 'video') {
    const v = document.createElement('video');
    v.className = 'bubble__media-view';
    v.src = url;
    v.controls = true;
    v.autoplay = true;
    return v;
  }
  const a = document.createElement('audio');
  a.src = url;
  a.controls = true;
  a.autoplay = true;
  return a;
}

function bubble(who, text) {
  const el = document.createElement('div');
  el.className = `bubble bubble--${who}`;
  if (text) el.textContent = text;
  if (who !== 'system') ui.messages.appendChild(el);
  return el;
}

function systemBubble(text) {
  const el = document.createElement('div');
  el.className = 'bubble bubble--system';
  el.textContent = text;
  ui.messages.appendChild(el);
  scrollDown();
}

function scrollDown() {
  ui.messages.scrollTop = ui.messages.scrollHeight;
}

// --- Paywall ----------------------------------------------------------------

function showPaywall() {
  ui.paywall.classList.remove('hidden');
}

async function doSubscribe() {
  ui.paywallSubscribe.disabled = true;
  ui.paywallSubscribe.textContent = 'Processing…';
  try {
    await subscribe(state.myId);
    ui.paywall.classList.add('hidden');
    systemBubble('Subscription active. You can keep chatting.');
  } catch (e) {
    ui.paywallMsg.textContent = 'Payment failed. Please try again.';
  } finally {
    ui.paywallSubscribe.disabled = false;
    ui.paywallSubscribe.textContent = 'Subscribe · €5/mo';
  }
}

// --- Account / recovery phrase ----------------------------------------------

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

function openAccount() {
  ui.acctId.textContent = state.myId;
  // Reset the phrase to its hidden state each time the panel opens.
  ui.acctPhrase.textContent = 'tap “Reveal” to show your 12-word recovery phrase';
  ui.acctPhrase.classList.add('phrase--hidden');
  ui.acctReveal.classList.remove('hidden');
  ui.acctCopyPhrase.classList.add('hidden');
  ui.acctRestoreInput.value = '';
  ui.acctMsg.textContent = '';
  ui.account.classList.remove('hidden');
}

async function revealPhrase() {
  const phrase = await getMnemonic();
  ui.acctPhrase.textContent = phrase;
  ui.acctPhrase.classList.remove('phrase--hidden');
  ui.acctReveal.classList.add('hidden');
  ui.acctCopyPhrase.classList.remove('hidden');
}

async function doRestore() {
  const phrase = ui.acctRestoreInput.value.trim();
  if (!phrase) return;
  ui.acctRestore.disabled = true;
  ui.acctMsg.textContent = 'Restoring…';
  try {
    const identity = await restoreFromMnemonic(phrase);
    // Switch the live identity over and re-register signaling under the new id.
    state.identity = identity;
    state.myId = identity.id;
    ui.myId.textContent = identity.id;
    ui.acctId.textContent = identity.id;
    teardownPeer('Identity restored.');
    if (state.signaling) {
      state.signaling.disconnect();
      state.signaling.connect(state.myId);
    }
    ui.acctMsg.textContent = 'Restored. You are now logged in as this ID.';
    ui.acctRestoreInput.value = '';
  } catch {
    ui.acctMsg.textContent = 'That is not a valid 12-word recovery phrase.';
  } finally {
    ui.acctRestore.disabled = false;
  }
}

ui.accountBtn.addEventListener('click', openAccount);
ui.acctClose.addEventListener('click', () => ui.account.classList.add('hidden'));
ui.acctReveal.addEventListener('click', revealPhrase);
ui.acctCopyId.addEventListener('click', () => copyToClipboard(state.myId));
ui.acctCopyPhrase.addEventListener('click', async () => {
  const phrase = await getMnemonic();
  const ok = await copyToClipboard(phrase);
  ui.acctCopyPhrase.textContent = ok ? 'Copied' : 'Copy failed';
  setTimeout(() => (ui.acctCopyPhrase.textContent = 'Copy'), 1500);
});
ui.acctRestore.addEventListener('click', doRestore);

// --- Event listeners --------------------------------------------------------

ui.connectBtn.addEventListener('click', async () => {
  const peerId = ui.peerId.value.trim();
  if (!/^[A-Za-z0-9_-]{8,64}$/.test(peerId)) {
    ui.connStatus.textContent = 'Enter a valid contact ID.';
    return;
  }
  if (peerId === state.myId) {
    ui.connStatus.textContent = "That's your own ID.";
    return;
  }
  await dial(peerId);
});

ui.sendBtn.addEventListener('click', sendCurrentText);
ui.msgInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') sendCurrentText();
});

async function sendCurrentText() {
  const body = ui.msgInput.value.trim();
  if (!body || !state.messaging) return;
  const res = await state.messaging.sendText(body);
  if (res.gated) return showPaywall();
  if (res.sent) ui.msgInput.value = '';
}

ui.attachBtn.addEventListener('click', () => ui.fileInput.click());
ui.fileInput.addEventListener('change', async () => {
  const file = ui.fileInput.files && ui.fileInput.files[0];
  ui.fileInput.value = '';
  if (!file || !state.messaging) return;
  const kind = file.type.startsWith('image')
    ? 'image'
    : file.type.startsWith('video')
      ? 'video'
      : 'voice';
  const res = await state.messaging.sendMedia(file, kind);
  if (res.gated) showPaywall();
});

ui.paywallSubscribe.addEventListener('click', doSubscribe);
ui.paywallClose.addEventListener('click', () => ui.paywall.classList.add('hidden'));
ui.gateRecheck.addEventListener('click', async () => {
  ui.gateMsg.textContent = 'Checking…';
  const active = await vpnGate.isActive();
  if (active) unlockFromVpn();
  else lockForVpn();
});

// --- Boot -------------------------------------------------------------------

(async function boot() {
  setApiBase(CONFIG.API_BASE);
  state.identity = await getIdentity();
  state.myId = state.identity.id;

  vpnGate.onChange((active) => {
    state.vpnActive = active;
    if (active) unlockFromVpn();
    else lockForVpn();
  });
  await vpnGate.start();
})();
