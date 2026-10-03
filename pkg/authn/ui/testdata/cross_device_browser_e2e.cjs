// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
// A dependency-free CDP consumer. The Go fixture owns Chrome and the TLS portal.
const assert = require("node:assert/strict");
const [endpoint, encoded] = process.argv.slice(2);
const config = JSON.parse(encoded);
const { origin } = config;
const password = require("node:fs").readFileSync(0, "utf8");
const socket = new WebSocket(endpoint);
const pending = new Map();
let sequence = 0;
let stage = "connect";
const beginDiagnostics = [];

socket.addEventListener("message", ({ data }) => {
  const message = JSON.parse(data);
  if (message.method === 'Network.requestWillBeSent' && message.params.request.url.endsWith('/cross-device/begin')) {
    beginDiagnostics.push({ origin: message.params.request.headers.Origin || 'absent', method: message.params.request.method });
  }
  if (message.method === 'Network.responseReceived' && message.params.response.url.endsWith('/cross-device/begin')) beginDiagnostics.push({ status: message.params.response.status });
  if (!message.id) return;
  const request = pending.get(message.id);
  if (!request) return;
  pending.delete(message.id);
  clearTimeout(request.timer);
  if (message.error) request.reject(new Error("browser protocol command failed"));
  else request.resolve(message.result);
});
function command(method, params = {}, sessionId) {
  return new Promise((resolve, reject) => {
    const id = ++sequence;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error("browser command timed out")); }, 25000);
    pending.set(id, { resolve, reject, timer });
    socket.send(JSON.stringify({ id, method, params, sessionId }));
  });
}
async function evaluate(page, fn, args) {
  const result = await command("Runtime.evaluate", {
    expression: `(${fn.toString()})(${JSON.stringify(args)})`, awaitPromise: true, returnByValue: true
  }, page);
  if (result.exceptionDetails) throw new Error("browser evaluation failed: " + (result.exceptionDetails.exception?.description || "unknown exception"));
  return result.result.value;
}
async function waitFor(fn) {
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    if (await fn()) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error("browser condition timed out");
}
async function page(contextId) {
  const target = await command("Target.createTarget", { url: "about:blank", browserContextId: contextId });
  const { sessionId } = await command("Target.attachToTarget", { targetId: target.targetId, flatten: true });
  await command("Page.enable", {}, sessionId);
  await command("Network.enable", {}, sessionId);
  await command("Runtime.enable", {}, sessionId);
  return sessionId;
}
async function navigate(page, path, sessionClient = false) {
  const result = await command("Page.navigate", { url: origin + path }, page);
  if (result.errorText) throw new Error("portal navigation failed");
  await waitFor(() => evaluate(page, (url) => location.href === url && document.readyState === "complete", origin + path));
  if (sessionClient) await waitFor(() => evaluate(page, () => !!window.AuthCrunchSession));
}

(async () => {
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', () => reject(new Error('browser socket failed')), { once: true });
  });
  const contexts = [];
  try {
    const first = await command('Target.createBrowserContext'); contexts.push(first.browserContextId);
    const second = await command('Target.createBrowserContext'); contexts.push(second.browserContextId);
    const requester = await page(first.browserContextId);
    const approver = await page(second.browserContextId);
    // Exercise the real fetch/abort protocol without the newer static helpers,
    // as on embedded browsers that have AbortController but lack these methods.
    await command('Page.addScriptToEvaluateOnNewDocument', { source: `
      Object.defineProperty(AbortSignal, 'any', { value: undefined });
      Object.defineProperty(AbortSignal, 'timeout', { value: undefined });
    ` }, requester);
    stage = 'visible login link';
    await navigate(requester, '/auth/login');
    const visibleLink = () => evaluate(requester, () => {
      const link = document.querySelector('#cross-device-link a');
      return link && link.getClientRects().length > 0;
    });
    assert.ok(await visibleLink(), 'single-realm login hid the cross-device action');
    stage = 'request on a narrow screen';
    await command('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 1, mobile: true }, requester);
    await evaluate(requester, () => document.querySelector('#cross-device-link a').click());
    await waitFor(() => evaluate(requester, () => document.getElementById('cross-device-details')?.hidden === false));
    assert.ok(await evaluate(requester, () => !AbortSignal.any && !AbortSignal.timeout), 'compatibility fixture retained static abort helpers');
    const interaction = await evaluate(requester, () => ({
      link: document.getElementById('cross-device-link').value,
      code: document.getElementById('cross-device-code').textContent,
      qr: document.getElementById('cross-device-qr').complete && document.getElementById('cross-device-qr').naturalWidth === 256,
      fits: document.documentElement.scrollWidth <= window.innerWidth,
    }));
    assert.ok(interaction.qr, 'QR code did not render');
    assert.ok(interaction.fits, 'request page overflowed the phone viewport');
    assert.ok(interaction.link.startsWith(origin + '/auth/cross-device/activate?code='));
    assert.equal((await command('Storage.getCookies', { browserContextId: first.browserContextId })).cookies.some(c => c.name === 'AUTHP_ACCESS_TOKEN'), false);
    stage = 'activate on isolated second device';
    await navigate(approver, interaction.link.slice(origin.length));
    assert.equal(await evaluate(approver, () => document.getElementById('cross-device-code').textContent), interaction.code);
    stage = 'fresh login form';
    await evaluate(approver, () => document.querySelector('form button').click());
    await waitFor(() => evaluate(approver, () => location.pathname === '/auth/login' && document.readyState === 'complete'));
    stage = 'username submission';
    await evaluate(approver, () => { document.getElementById('username').value = 'alice'; document.querySelector('#loginform form').requestSubmit(); });
    await waitFor(() => evaluate(approver, () => !!document.querySelector('input[name="secret"]')));
    stage = 'password verification';
    await evaluate(approver, password => {
      const input = document.querySelector('input[name="secret"]'); input.value = password; input.form.requestSubmit();
    }, password);
    await waitFor(() => evaluate(approver, () => location.pathname === '/auth/cross-device/confirm' && document.readyState === 'complete'));
    assert.equal(await evaluate(approver, () => document.getElementById('cross-device-code').textContent), interaction.code);
    // At least one real scheduled poll observes pending before explicit approval.
    await new Promise(resolve => setTimeout(resolve, 2200));
    assert.equal((await command('Storage.getCookies', { browserContextId: first.browserContextId })).cookies.some(c => c.name === 'AUTHP_ACCESS_TOKEN'), false);
    stage = 'explicit approval and requester polling';
    await evaluate(approver, () => document.querySelector('button[value="approve"]').click());
    await waitFor(() => evaluate(requester, () => location.pathname === '/auth/portal' && document.readyState === 'complete'));
    const requesterCookies = (await command('Storage.getCookies', { browserContextId: first.browserContextId })).cookies;
    const approverCookies = (await command('Storage.getCookies', { browserContextId: second.browserContextId })).cookies;
    for (const name of ['AUTHP_ACCESS_TOKEN', 'AUTHP_REFRESH_TOKEN', 'AUTHP_OIDC_SESSION_ID']) {
      const own = requesterCookies.find(c => c.name === name);
      const remote = approverCookies.find(c => c.name === name);
      assert.ok(own && remote && own.value !== remote.value, 'devices did not receive independent ' + name);
      assert.ok(own.secure && own.httpOnly, 'requester credential is not secure/HttpOnly');
    }
    assert.ok(!approverCookies.some(c => c.name === '__Secure-DEVICE'), 'approval cookie was not deleted');
    stage = 'cancel stops polling';
    await navigate(requester, '/auth/cross-device');
    await waitFor(() => evaluate(requester, () => document.getElementById('cross-device-details')?.hidden === false));
    await evaluate(requester, () => document.getElementById('cross-device-cancel').click());
    await waitFor(() => evaluate(requester, () => document.getElementById('cross-device-status')?.textContent === 'Sign-in cancelled.'));
    assert.equal(await evaluate(requester, () => document.getElementById('cross-device-details').hidden), true);
    stage = 'navigation ends the visible request';
    await navigate(requester, '/auth/cross-device');
    await waitFor(() => evaluate(requester, () => document.getElementById('cross-device-details')?.hidden === false));
    const abandoned = await evaluate(requester, () => {
      // Observe the actual pagehide event after the production listener. Store
      // only display state; capabilities must never enter browser storage.
      window.addEventListener('pagehide', () => sessionStorage.setItem('cross-device-left', JSON.stringify({
        hidden: document.getElementById('cross-device-details').hidden,
        status: document.getElementById('cross-device-status').textContent,
      })), { once: true });
      return document.getElementById('cross-device-link').value;
    });
    await navigate(requester, '/auth/portal');
    const left = await evaluate(requester, () => JSON.parse(sessionStorage.getItem('cross-device-left')));
    assert.equal(left.hidden, true);
    assert.match(left.status, /ended/);
    stage = 'back navigation never revives a stopped request';
    await evaluate(requester, () => history.back());
    await waitFor(() => evaluate(requester, previous => {
      if (location.pathname !== '/auth/cross-device' || document.readyState !== 'complete') return false;
      const details = document.getElementById('cross-device-details');
      if (!details) return false;
      // Chrome may restore a cached document or fetch a new no-store page.
      // A restored document is terminal; a fresh one gets a new capability.
      return details.hidden
        ? document.getElementById('cross-device-status').textContent.includes('ended')
        : document.getElementById('cross-device-link').value !== previous;
    }, abandoned));
    process.stdout.write(JSON.stringify({ passed: true }));
  } finally {
    for (const browserContextId of contexts) await command('Target.disposeBrowserContext', { browserContextId });
    socket.close();
  }
})().catch(error => { console.error('Stage: ' + stage + '\n' + error.message + '\n' + JSON.stringify(beginDiagnostics)); socket.close(); process.exitCode = 1; });
