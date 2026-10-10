// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
// A dependency-free CDP consumer. The Go fixture owns Chrome and the TLS portal.
const assert = require("node:assert/strict");
const fs = require('node:fs');
const path = require('node:path');
const [endpoint, encoded] = process.argv.slice(2);
const config = JSON.parse(encoded);
const { origin } = config;
const password = fs.readFileSync(0, "utf8");
const screenshotDir = process.env.AUTHCRUNCH_CROSS_DEVICE_SCREENSHOT_DIR;
const socket = new WebSocket(endpoint);
const pending = new Map();
let sequence = 0;
let stage = "connect";
const beginDiagnostics = [];
const scriptErrors = [];

socket.addEventListener("message", ({ data }) => {
  const message = JSON.parse(data);
  if (message.method === 'Runtime.exceptionThrown') {
    const details = message.params.exceptionDetails;
    scriptErrors.push({ text: details.text, line: details.lineNumber });
  }
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

async function capture(page, name) {
  if (!screenshotDir) return;
  await evaluate(page, async () => { await document.fonts.ready; });
  const { cssContentSize } = await command('Page.getLayoutMetrics', {}, page);
  const { data } = await command('Page.captureScreenshot', {
    format: 'png', captureBeyondViewport: true,
    clip: { x: 0, y: 0, width: cssContentSize.width, height: cssContentSize.height, scale: 1 },
  }, page);
  fs.mkdirSync(screenshotDir, { recursive: true });
  fs.writeFileSync(path.join(screenshotDir, name + '.png'), Buffer.from(data, 'base64'));
}

async function copyStatusRegion(page) {
  const { root } = await command('DOM.getDocument', {}, page);
  const { nodeId } = await command('DOM.querySelector', { nodeId: root.nodeId, selector: '#cross-device-copy-status' }, page);
  const { nodes } = await command('Accessibility.getPartialAXTree', { nodeId, fetchRelatives: false }, page);
  const region = nodes[0];
  assert.ok(region && !region.ignored, 'copy feedback must be exposed before its message changes');
  assert.equal(region.role.value, 'status');
  assert.equal(region.properties.find(p => p.name === 'live')?.value.value, 'polite');
  assert.equal(region.properties.find(p => p.name === 'atomic')?.value.value, true);
  return region.backendDOMNodeId;
}

async function layout(page, name, title, matchingCode = '') {
  const expectedButtons = {
    '01-request': ['Copy link', 'Cancel'],
    '04-continue': ['Continue'],
    '05-approve': ['Approve', 'Deny'],
  }[name] || [];
  for (const width of [320, 390, 639, 640, 768, 1280]) {
    await command('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: width < 640 }, page);
    const result = await evaluate(page, async () => {
      await document.fonts.ready;
      const visible = el => el && el.getClientRects().length > 0;
      const rect = el => { const r = el.getBoundingClientRect(); return { x: r.x, y: r.y, width: r.width, height: r.height, right: r.right, bottom: r.bottom }; };
      const main = document.querySelector('main');
      const code = document.getElementById('cross-device-code');
      const panel = document.querySelector('.cross-device-code-panel');
      const qr = document.getElementById('cross-device-qr');
      const buttons = [...document.querySelectorAll('.cross-device-actions button')].filter(visible);
      const bounds = rect(main);
      const style = getComputedStyle(main);
      const left = bounds.x + parseFloat(style.borderLeftWidth) + parseFloat(style.paddingLeft);
      const right = bounds.right - parseFloat(style.borderRightWidth) - parseFloat(style.paddingRight);
      const controlsFit = [...main.querySelectorAll('button, textarea, .cross-device-code-panel')].filter(visible).every(el => {
        const r = rect(el); return r.x >= left && r.right <= right && el.scrollWidth <= el.clientWidth;
      });
      return {
        title: document.querySelector('h1').textContent, documentTitle: document.title,
        fits: document.documentElement.scrollWidth <= innerWidth && controlsFit,
        code: visible(code) ? { value: code.textContent, size: parseFloat(getComputedStyle(code).fontSize), centered: Math.abs(rect(code).x + rect(code).width / 2 - (rect(panel).x + rect(panel).width / 2)) < 1 } : null,
        qr: visible(qr) ? { loaded: qr.complete && qr.naturalWidth === 256, centered: Math.abs(rect(qr).x + rect(qr).width / 2 - (bounds.x + bounds.width / 2)) < 1 } : null,
        buttons: buttons.map(el => ({ ...rect(el), label: el.textContent })),
        rawLinkVisible: visible(document.getElementById('cross-device-link')),
        controlsHeight: document.getElementById('cross-device-controls')?.getBoundingClientRect().height,
      };
    });
    assert.equal(result.title, title, name + ' heading');
    assert.ok(result.documentTitle.endsWith(title), name + ' browser title');
    assert.ok(result.fits, `${name} overflowed its content area at ${width}px`);
    if (matchingCode) {
      assert.equal(result.code?.value, matchingCode);
      assert.ok(result.code.size >= 28 && result.code.centered, 'matching code is not prominent and centered');
    }
    if (result.qr) assert.ok(result.qr.loaded && result.qr.centered, 'QR is not loaded and centered');
    if (name === '01-request') {
      assert.ok(result.qr, 'request page must show its QR code');
      assert.equal(result.rawLinkVisible, false, 'raw link should be hidden until manual copy is needed');
      assert.equal(result.controlsHeight, result.buttons[0]?.height, 'empty feedback must not add a blank row');
    }
    assert.deepEqual(result.buttons.map(b => b.label), expectedButtons, `${name} visible actions at ${width}px`);
    if (result.buttons.length === 2) {
      const [first, second] = result.buttons;
      assert.equal(first.y, second.y, 'actions are not aligned');
      assert.ok(Math.abs(first.width - second.width) < 1, 'actions have unequal widths');
      assert.ok(second.x - first.right >= 12, 'actions need a visible gap');
      assert.equal(first.height, second.height);
    }
    if (width === 390 || width === 1280 || (name === '01-request' && width === 320)) {
      await capture(page, name + (width === 1280 ? '-desktop' : width === 320 ? '-small-phone' : '-phone'));
    }
  }
  await command('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 1, mobile: true }, page);
}

async function signIn(approver) {
  await evaluate(approver, () => document.querySelector('form button').click());
  await waitFor(() => evaluate(approver, () => location.pathname === '/auth/login' && document.readyState === 'complete'));
  await evaluate(approver, () => { document.getElementById('username').value = 'alice'; document.querySelector('#loginform form').requestSubmit(); });
  await waitFor(() => evaluate(approver, () => !!document.querySelector('input[name="secret"]')));
  await evaluate(approver, password => {
    const input = document.querySelector('input[name="secret"]'); input.value = password; input.form.requestSubmit();
  }, password);
  await waitFor(() => evaluate(approver, () => location.pathname === '/auth/cross-device/confirm' && document.readyState === 'complete'));
}

async function legacyJourney(requester, approver, contextId) {
  stage = 'legacy theme manual copy';
  await navigate(requester, '/auth/cross-device');
  await waitFor(() => evaluate(requester, () => document.getElementById('cross-device-details')?.hidden === false));
  assert.ok(await evaluate(requester, () => ['controls', 'recovery', 'copy-status', 'link-fallback'].every(id => !document.getElementById('cross-device-' + id))));
  await command('Page.bringToFront', {}, requester);
  await command('Browser.grantPermissions', { origin, browserContextId: contextId, permissions: [] });
  await evaluate(requester, () => document.getElementById('cross-device-copy').click());
  await waitFor(() => evaluate(requester, () => document.activeElement.id === 'cross-device-link'));
  assert.ok(await evaluate(requester, () => {
    const link = document.getElementById('cross-device-link');
    return link.selectionStart === 0 && link.selectionEnd === link.value.length;
  }));
  stage = 'legacy theme cancellation';
  await evaluate(requester, () => document.getElementById('cross-device-cancel').click());
  await waitFor(() => evaluate(requester, () => document.getElementById('cross-device-cancel').disabled));
  assert.ok(await evaluate(requester, () => document.getElementById('cross-device-details').hidden && document.getElementById('cross-device-cancel').getClientRects().length === 0));
  assert.equal(await evaluate(requester, () => document.title), 'Legacy portal - Sign-in cancelled');
  assert.equal(await evaluate(requester, () => document.activeElement.id), 'cross-device-title');
  stage = 'legacy theme fresh login and approval';
  await navigate(requester, '/auth/cross-device?redirect_url=' + encodeURIComponent(origin + '/auth/portal?requester=legacy'));
  await waitFor(() => evaluate(requester, () => document.getElementById('cross-device-details')?.hidden === false));
  const link = await evaluate(requester, () => document.getElementById('cross-device-link').value);
  assert.equal((await command('Storage.getCookies', { browserContextId: contextId })).cookies.some(c => c.name === 'AUTHP_ACCESS_TOKEN'), false);
  await navigate(approver, link.slice(origin.length));
  await signIn(approver);
  await evaluate(approver, () => document.querySelector('button[value="approve"]').click());
  await waitFor(() => evaluate(requester, () => location.pathname === '/auth/portal' && location.search.startsWith('?requester=') && document.readyState === 'complete'));
  assert.ok((await command('Storage.getCookies', { browserContextId: contextId })).cookies.some(c => c.name === 'AUTHP_ACCESS_TOKEN'));
  assert.deepEqual(scriptErrors, [], 'legacy theme raised an unhandled client error');
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
    if (config.theme === 'legacy') {
      await legacyJourney(requester, approver, first.browserContextId);
      process.stdout.write(JSON.stringify({ passed: true }));
      return;
    }
    stage = 'visible login link';
    await navigate(requester, '/auth/login?redirect_url=' + encodeURIComponent(origin + '/auth/portal?requester=basic'));
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
    await layout(requester, '01-request', 'Sign in on another device', interaction.code);
    stage = 'copy feedback accessibility before interaction';
    const copyStatusNode = await copyStatusRegion(requester);
    stage = 'copy link with clipboard permission';
    await command('Page.bringToFront', {}, requester);
    await command('Browser.grantPermissions', { origin, browserContextId: first.browserContextId, permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite'] });
    await evaluate(requester, () => document.getElementById('cross-device-copy').click());
    await waitFor(() => evaluate(requester, () => document.getElementById('cross-device-copy-status').textContent.startsWith('Link copied')));
    assert.equal(await copyStatusRegion(requester), copyStatusNode, 'copy must update the existing live region');
    assert.equal(await evaluate(requester, () => {
      const feedback = document.getElementById('cross-device-copy-status').getBoundingClientRect();
      const actions = document.querySelector('.cross-device-actions').getBoundingClientRect();
      return feedback.top - actions.bottom;
    }), 24, 'copy feedback needs the same spacing as the rest of the flow');
    assert.equal(await evaluate(requester, () => navigator.clipboard.readText()), interaction.link);
    assert.equal(await evaluate(requester, () => document.getElementById('cross-device-link-fallback').hidden), true);
    await capture(requester, '02-link-copied-phone');
    stage = 'delayed clipboard denial preserves keyboard focus';
    await command('Browser.grantPermissions', { origin, browserContextId: first.browserContextId, permissions: [] });
    await evaluate(requester, () => {
      // Delay delivery of a real permission denial until the user has tabbed
      // onward. Keep the native clipboard call and restore it before continuing.
      const original = navigator.clipboard.writeText;
      let release;
      const gate = new Promise(resolve => { release = resolve; });
      window.releaseClipboardDenial = () => {
        navigator.clipboard.writeText = original;
        delete window.releaseClipboardDenial;
        release();
      };
      navigator.clipboard.writeText = async function(value) {
        try { return await original.call(this, value); }
        catch (error) { await gate; throw error; }
      };
      const copy = document.getElementById('cross-device-copy'); copy.focus(); copy.click();
    });
    await command('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 }, requester);
    await command('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 }, requester);
    assert.equal(await evaluate(requester, () => document.activeElement.id), 'cross-device-cancel');
    await evaluate(requester, () => window.releaseClipboardDenial());
    await waitFor(() => evaluate(requester, () => document.getElementById('cross-device-link-fallback').hidden === false));
    assert.equal(await evaluate(requester, () => document.activeElement.id), 'cross-device-cancel', 'delayed denial stole keyboard focus');
    assert.doesNotMatch(await evaluate(requester, () => document.getElementById('cross-device-copy-status').textContent), /selected/);
    await capture(requester, '03-delayed-copy-keyboard-phone');
    stage = 'manual-copy fallback after clipboard denial';
    await evaluate(requester, () => {
      const copy = document.getElementById('cross-device-copy'); copy.focus(); copy.click();
    });
    await waitFor(() => evaluate(requester, () => document.activeElement.id === 'cross-device-link'));
    assert.ok(await evaluate(requester, () => {
      const link = document.getElementById('cross-device-link');
      return document.activeElement === link && link.selectionStart === 0 && link.selectionEnd === link.value.length && link.scrollWidth <= link.clientWidth;
    }), 'manual copy must reveal, focus, and select a wrapping link');
    await capture(requester, '03-manual-copy-phone');
    assert.equal((await command('Storage.getCookies', { browserContextId: first.browserContextId })).cookies.some(c => c.name === 'AUTHP_ACCESS_TOKEN'), false);
    stage = 'activate on isolated second device';
    await navigate(approver, interaction.link.slice(origin.length));
    assert.equal(await evaluate(approver, () => document.getElementById('cross-device-code').textContent), interaction.code);
    await layout(approver, '04-continue', 'Sign in to continue', interaction.code);
    assert.equal(await evaluate(approver, () => document.querySelector('form button').textContent), 'Continue');
    stage = 'fresh login form';
    await signIn(approver);
    assert.equal(await evaluate(approver, () => document.getElementById('cross-device-code').textContent), interaction.code);
    await layout(approver, '05-approve', 'Approve sign in', interaction.code);
    // Real keyboard navigation must reach both independent decisions.
    await evaluate(approver, () => document.querySelector('h1').focus());
    await command('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 }, approver);
    await command('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 }, approver);
    assert.ok(await evaluate(approver, () => document.activeElement.value === 'approve' && getComputedStyle(document.activeElement).outlineStyle !== 'none'));
    await capture(approver, '05-approve-keyboard-phone');
    await command('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 }, approver);
    await command('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 }, approver);
    assert.equal(await evaluate(approver, () => document.activeElement.value), 'deny');
    // At least one real scheduled poll observes pending before explicit approval.
    await new Promise(resolve => setTimeout(resolve, 2200));
    assert.equal((await command('Storage.getCookies', { browserContextId: first.browserContextId })).cookies.some(c => c.name === 'AUTHP_ACCESS_TOKEN'), false);
    stage = 'explicit approval and requester polling';
    await evaluate(approver, () => document.querySelector('button[value="approve"]').click());
    await waitFor(() => evaluate(requester, () => location.pathname === '/auth/portal' && location.search.startsWith('?requester=') && document.readyState === 'complete'));
    await layout(approver, '06-approved', 'Sign-in approved');
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
    await waitFor(() => evaluate(requester, () => document.getElementById('cross-device-title')?.textContent === 'Sign-in cancelled'));
    assert.equal(await evaluate(requester, () => document.getElementById('cross-device-details').hidden), true);
    assert.ok(await evaluate(requester, () => document.getElementById('cross-device-cancel').hidden && !document.getElementById('cross-device-recovery').hidden));
    assert.equal(await evaluate(requester, () => document.activeElement.id), 'cross-device-title');
    await evaluate(requester, () => document.activeElement.blur());
    await layout(requester, '07-cancelled', 'Sign-in cancelled');
    stage = 'start again after cancellation';
    await evaluate(requester, () => document.querySelector('#cross-device-recovery a').click());
    await waitFor(() => evaluate(requester, () => document.getElementById('cross-device-details')?.hidden === false));
    stage = 'deny a new request';
    const deniedLink = await evaluate(requester, () => document.getElementById('cross-device-link').value);
    await navigate(approver, deniedLink.slice(origin.length));
    await signIn(approver);
    await evaluate(approver, () => document.querySelector('button[value="deny"]').click());
    await waitFor(() => evaluate(approver, () => document.querySelector('h1')?.textContent === 'Sign-in denied'));
    await layout(approver, '08-denied', 'Sign-in denied');
    await waitFor(() => evaluate(requester, () => document.getElementById('cross-device-title')?.textContent === 'Sign-in unavailable'));
    await layout(requester, '09-unavailable', 'Sign-in unavailable');
    stage = 'expired request recovery';
    await navigate(requester, '/auth/cross-device');
    await waitFor(() => evaluate(requester, () => document.getElementById('cross-device-details')?.hidden === false));
    // Advance the client clock after admission; retain the real poll timer and
    // production expiry transition instead of substituting screenshot markup.
    await evaluate(requester, () => {
      document.getElementById('cross-device-copy').focus();
      const now = Date.now(); Date.now = () => now + 300001;
    });
    await waitFor(() => evaluate(requester, () => document.getElementById('cross-device-title')?.textContent === 'Sign-in link expired'));
    assert.equal(await evaluate(requester, () => document.activeElement.id), 'cross-device-title', 'expiry left focus on a hidden control');
    await evaluate(requester, () => document.activeElement.blur());
    await layout(requester, '10-expired', 'Sign-in link expired');
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
    assert.deepEqual(scriptErrors, [], 'browser journey raised an unhandled client error');
    process.stdout.write(JSON.stringify({ passed: true }));
  } finally {
    for (const browserContextId of contexts) await command('Target.disposeBrowserContext', { browserContextId });
    socket.close();
  }
})().catch(error => { console.error('Stage: ' + stage + '\n' + error.message + '\n' + JSON.stringify(beginDiagnostics)); socket.close(); process.exitCode = 1; });
