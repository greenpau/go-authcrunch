// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
// Real shipped bundles and portal APIs; no intercepted network responses.
const assert = require('node:assert/strict');
const config = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
const socket = new WebSocket(process.argv[2]);
const pending = new Map();
let sequence = 0;
let responses = [];
let exceptions = 0;
socket.addEventListener('message', ({ data }) => {
  const message = JSON.parse(data);
  if (message.method === 'Network.responseReceived') responses.push(message.params.response);
  if (message.method === 'Runtime.exceptionThrown') exceptions++;
  const call = pending.get(message.id);
  if (!call) return;
  pending.delete(message.id);
  clearTimeout(call.timer);
  if (message.error) call.reject(new Error(message.error.message));
  else call.resolve(message.result);
});
function command(method, params = {}, sessionId) {
  return new Promise((resolve, reject) => {
    const id = ++sequence;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error('browser command timed out')); }, 15000);
    pending.set(id, { resolve, reject, timer });
    socket.send(JSON.stringify({ id, method, params, sessionId }));
  });
}
async function evaluate(tab, fn, args) {
  const result = await command('Runtime.evaluate', { expression: `(${fn.toString()})(${JSON.stringify(args)})`, returnByValue: true, awaitPromise: true }, tab);
  if (result.exceptionDetails) throw new Error('browser evaluation failed');
  return result.result.value;
}
async function eventually(tab, fn, args, label) {
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    try { if (await evaluate(tab, fn, args)) return; }
    catch (error) { if (!/Execution context was destroyed|Cannot find context|Inspected target navigated/.test(error.message)) throw error; }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  const state = await evaluate(tab, () => ({ path: location.pathname, heading: document.querySelector('main h1')?.textContent, alert: document.querySelector('[role=alert]')?.textContent?.slice(0, 200) }));
  throw new Error('browser checkpoint failed: ' + label + ' ' + JSON.stringify(state));
}
(async () => {
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', () => reject(new Error('browser socket failed')), { once: true });
  });
  try {
    const { browserContextId } = await command('Target.createBrowserContext');
    const { targetId } = await command('Target.createTarget', { url: 'about:blank', browserContextId });
    const { sessionId: tab } = await command('Target.attachToTarget', { targetId, flatten: true });
    for (const method of ['Page.enable', 'Network.enable', 'Runtime.enable']) await command(method, {}, tab);
    await command('Network.setCookies', { cookies: config.cookies }, tab);
    const applications = [
      { slug: 'profile', page: 'info', heading: 'alice', endpoint: '/api/profile', text: 'alice@example.test' },
      { slug: 'operator', page: 'users', heading: 'Users', endpoint: '/api/server/users', text: 'alice' },
      { slug: 'documents', page: 'vault', heading: 'Vault', endpoint: '/api/documents/bootstrap', text: 'Create a recovery key' },
    ];
    const selected = config.apps || applications.map((app) => app.slug);
    assert.ok(selected.length && selected.every((slug) => applications.some((app) => app.slug === slug)), 'invalid browser app selection');
    for (const app of applications.filter((app) => selected.includes(app.slug))) {
      responses = [];
      const base = config.issuer + '/' + app.slug + '/';
      await command('Page.navigate', { url: base + app.page + '?mount-test=1#kept' }, tab);
      await eventually(tab, (app) => document.querySelector('main h1')?.textContent === app.heading &&
        document.querySelector('main')?.innerText.includes(app.text), app, app.slug + ' real data');
      assert.equal(await evaluate(tab, () => document.querySelector('base').href), base);
      assert.equal(await evaluate(tab, () => location.hash), '#kept');
      assert.ok(responses.some((response) => response.url === config.issuer + app.endpoint && response.status === 200), app.slug + ' API did not use portal mount');
      assert.ok(responses.some((response) => response.url.startsWith(base + 'assets/') && response.url.endsWith('.js') && response.status === 200), app.slug + ' bundled JavaScript did not load');
      assert.ok(responses.some((response) => response.url.startsWith(base + 'i18n/') && response.status === 200), app.slug + ' translations did not load');
      assert.equal(responses.some((response) => response.status >= 400 && !(app.slug === 'documents' && response.status === 404 && response.url === config.issuer + '/api/documents/keys/fetch')), false, app.slug + ' requested a failed resource');
      assert.equal(await evaluate(tab, async () => { await document.fonts.ready; return document.fonts.check('400 16px Inter'); }), true);
      await command('Page.reload', {}, tab);
      await eventually(tab, (app) => document.querySelector('main h1')?.textContent === app.heading &&
        document.querySelector('main')?.innerText.includes(app.text), app, app.slug + ' deep link reload');
      // Follow the actual React menu link without replacing the document.
      await evaluate(tab, () => {
        window.__appMountNavigation = true;
        document.querySelector('button[aria-label^="Account menu:"]').dispatchEvent(
          new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true }));
      });
      await eventually(tab, () => [...document.querySelectorAll('[role="menuitem"][href]')].some((link) => link.href.endsWith('/preferences')), undefined, app.slug + ' account menu');
      await evaluate(tab, () => [...document.querySelectorAll('[role="menuitem"][href]')].find((link) => link.href.endsWith('/preferences')).click());
      await eventually(tab, () => document.querySelector('main h1')?.textContent === 'Preferences', undefined, app.slug + ' preferences');
      assert.equal(await evaluate(tab, () => window.__appMountNavigation), true, 'React navigation replaced the document');
      assert.equal(await evaluate(tab, () => location.href), base + 'preferences');
      await command('Page.reload', {}, tab);
      await eventually(tab, () => document.querySelector('main h1')?.textContent === 'Preferences', undefined, app.slug + ' preferences reload');

    }
    assert.equal(exceptions, 0, 'shipped apps raised uncaught browser exceptions');
    process.stdout.write(JSON.stringify({ passed: true }));
  } finally {
    await command('Browser.close').catch(() => {});
    socket.close();
  }
})().catch((error) => { process.stderr.write(error.message + '\n'); process.exitCode = 1; });
