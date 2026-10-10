// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../core/js/cross_device.js'), 'utf8');
const flush = () => new Promise(resolve => setImmediate(resolve));

function environment(responses, clipboard = async () => { throw new Error('denied'); }, abortSignal = AbortSignal, options = {}) {
  const elements = new Map();
  const document = {
    title: options.title || 'Test portal - Sign in on another device',
    currentScript: { dataset: { base: '/tenant/auth', returnUrl: options.returnURL || '', i18n: JSON.stringify(options.messages || {}) } },
    getElementById: id => elements.get(id) || null,
    activeElement: null,
  };
  for (const id of ['title', 'status', 'details', 'controls', 'cancel', 'copy', 'copy-status', 'link', 'link-fallback', 'qr', 'code', 'recovery']) elements.set('cross-device-' + id, {
    hidden: true, disabled: false, textContent: '', value: '', events: {},
    addEventListener(name, fn) { this.events[name] = fn; },
    focus() { this.focused = true; document.activeElement = this; }, select() { this.selected = true; },
    contains(target) {
      for (let node = target; node; node = node.parentElement) if (node === this) return true;
      return false;
    },
  });
  elements.get('cross-device-title').textContent = 'Sign in on another device';
  elements.get('cross-device-controls').hidden = false;
  elements.get('cross-device-copy-status').hidden = false;
  elements.get('cross-device-cancel').hidden = false;
  elements.get('cross-device-copy').disabled = true;
  for (const id of ['copy', 'cancel', 'link-fallback']) elements.get('cross-device-' + id).parentElement = elements.get('cross-device-controls');
  elements.get('cross-device-link').parentElement = elements.get('cross-device-link-fallback');
  if (options.legacy) {
    for (const id of ['controls', 'recovery', 'copy-status', 'link-fallback']) elements.delete('cross-device-' + id);
    for (const id of ['copy', 'link']) elements.get('cross-device-' + id).parentElement = elements.get('cross-device-details');
    elements.get('cross-device-cancel').parentElement = null;
  }
  if (options.omitHeading) elements.delete('cross-device-title');
  const timers = new Map(); const requests = []; const navigations = []; const events = {};
  let now = 1000; let seq = 0;
  const context = {
    document,
    window: { addEventListener: (name, fn) => { events[name] = fn; }, location: { assign: next => navigations.push(next) } },
    navigator: { clipboard: { writeText: clipboard } },
    URLSearchParams, AbortController, AbortSignal: abortSignal, Date: { now: () => now },
    setTimeout: (fn, delay) => { timers.set(++seq, { fn, delay }); return seq; },
    clearTimeout: id => timers.delete(id),
    fetch: async (url, options) => {
      requests.push({ url, options, body: Object.fromEntries(options.body) });
      const response = responses.shift();
      if (typeof response === 'function') return response(options);
      if (response instanceof Error) throw response;
      const status = typeof response.status === 'number' ? response.status : 200;
      return { ok: status < 400, status, json: async () => response.body || response };
    },
  };
  vm.runInNewContext(source, context);
  return { elements, document: context.document, requests, navigations, timers, events, advance: value => { now += value; }, tick: async () => {
    const [id, timer] = timers.entries().next().value; timers.delete(id); await timer.fn(); await flush();
  } };
}
const interaction = () => ({ code: 'activation', secret: 'requester-only', verification_uri: 'https://portal.test/tenant/auth/cross-device/activate?code=activation', display_code: 'ABCD-EFGH', qr: 'data:image/png;base64,test', expires_in: 300, interval: 2 });

test('copy is unavailable until a sign-in link is ready', async () => {
  let resolve, copied = false;
  const starting = new Promise(done => { resolve = done; });
  const e = environment([() => starting], async () => { copied = true; }); await flush();
  assert.equal(e.elements.get('cross-device-copy').disabled, true);
  await e.elements.get('cross-device-copy').events.click();
  assert.equal(copied, false);
  resolve({ ok: true, status: 200, json: async () => interaction() });
  await flush();
  assert.equal(e.elements.get('cross-device-copy').disabled, false);
  assert.equal(e.elements.get('cross-device-controls').hidden, false);
});

test('login and cancellation work without AbortSignal static helpers', async () => {
  for (const helpers of [{}, { timeout: AbortSignal.timeout }]) {
    const e = environment([interaction(), { status: 'approved', next: '/tenant/auth/portal' }], undefined, helpers);
    await flush();
    assert.equal(e.elements.get('cross-device-details').hidden, false);
    await e.tick();
    assert.deepEqual(e.navigations, ['/tenant/auth/portal']);
    const cancelled = environment([interaction(), { status: 'cancelled' }], undefined, helpers);
    await flush();
    await cancelled.elements.get('cross-device-cancel').events.click();
    assert.ok(cancelled.requests[1].url.endsWith('/cancel'));
    assert.equal(cancelled.timers.size, 0);
  }
});

test('polls serially, keeps capabilities out of URLs, and navigates only after approval', async () => {
  const e = environment([interaction(), { status: 'pending' }, { status: 429, body: { status: 'slow_down' } }, { status: 'approved', next: '/tenant/auth/portal' }]);
  await flush();
  assert.equal(e.elements.get('cross-device-details').hidden, false);
  assert.equal(e.timers.size, 1);
  assert.equal([...e.timers.values()][0].delay, 2000);
  await e.tick(); await e.tick();
  assert.equal(e.navigations.length, 0);
  await e.tick();
  assert.deepEqual(e.navigations, ['/tenant/auth/portal']);
  assert.equal(e.timers.size, 0);
  for (const request of e.requests) {
    assert.ok(!request.url.includes('requester-only'));
    assert.equal(request.options.credentials, 'same-origin');
    assert.equal(request.options.cache, 'no-store');
  }
  assert.equal(e.requests[1].body.secret, 'requester-only');
});

test('denial and network failure stop polling without navigation', async () => {
  for (const failure of [{ status: 410, body: { status: 'unavailable' } }, new Error('offline')]) {
    const e = environment([interaction(), failure]); await flush(); await e.tick();
    assert.equal(e.timers.size, 0); assert.equal(e.navigations.length, 0);
    assert.equal(e.elements.get('cross-device-details').hidden, true);
    assert.match(e.elements.get('cross-device-status').textContent, /no longer available/);
  }
});

test('expiry, explicit cancellation, and navigation stop future polls', async () => {
  const expired = environment([interaction()]); await flush(); expired.advance(300000); await expired.tick();
  assert.equal(expired.requests.length, 1); assert.equal(expired.timers.size, 0);
  assert.match(expired.elements.get('cross-device-status').textContent, /expired/);
  const cancelled = environment([interaction(), { status: 'cancelled' }]); await flush();
  await cancelled.elements.get('cross-device-cancel').events.click();
  assert.ok(cancelled.requests[1].url.endsWith('/cancel')); assert.equal(cancelled.timers.size, 0);
  const navigated = environment([interaction(), waitForAbort]); await flush();
  const polling = navigated.tick(); await flush(); navigated.events.pagehide(); await polling;
  assert.equal(navigated.timers.size, 0); assert.equal(navigated.requests[1].options.signal.aborted, true);
  assert.equal(navigated.elements.get('cross-device-details').hidden, true);
  assert.equal(navigated.elements.get('cross-device-cancel').disabled, true);
  assert.match(navigated.elements.get('cross-device-status').textContent, /ended/);
});

test('copy fallback selects the visible activation link', async () => {
  const e = environment([interaction()]); await flush();
  assert.equal(e.elements.get('cross-device-link-fallback').hidden, true);
  const status = e.elements.get('cross-device-status').textContent;
  await e.elements.get('cross-device-copy').events.click();
  const input = e.elements.get('cross-device-link');
  assert.equal(e.elements.get('cross-device-link-fallback').hidden, false);
  assert.equal(e.elements.get('cross-device-copy-status').hidden, false);
  assert.equal(e.elements.get('cross-device-status').textContent, status);
  assert.equal(input.selected, true); assert.equal(input.focused, true);
  assert.ok(!input.value.includes('requester-only'));
});

test('successful copy keeps the raw link hidden and preserves the waiting status', async () => {
  let copied;
  const e = environment([interaction()], async value => { copied = value; }); await flush();
  const status = e.elements.get('cross-device-status').textContent;
  await e.elements.get('cross-device-copy').events.click();
  assert.equal(copied, interaction().verification_uri);
  assert.equal(e.elements.get('cross-device-link-fallback').hidden, true);
  assert.match(e.elements.get('cross-device-copy-status').textContent, /Link copied/);
  assert.equal(e.elements.get('cross-device-status').textContent, status);
});

test('delayed clipboard denial preserves focus when the user has moved on', async () => {
  for (const legacy of [false, true]) {
    let reject;
    const clipboard = new Promise((_, fail) => { reject = fail; });
    const e = environment([interaction()], () => clipboard, undefined, { legacy }); await flush();
    e.elements.get('cross-device-copy').focus();
    const copying = e.elements.get('cross-device-copy').events.click();
    const cancel = e.elements.get('cross-device-cancel'); cancel.focus();
    reject(new Error('denied'));
    await copying;
    assert.equal(e.document.activeElement, cancel, 'delayed denial must not steal keyboard focus');
    assert.notEqual(e.elements.get('cross-device-link').selected, true);
    const feedback = e.elements.get('cross-device-copy-status') || e.elements.get('cross-device-status');
    assert.doesNotMatch(feedback.textContent, /selected/, 'feedback must not claim an unselected link is selected');
    if (!legacy) assert.equal(e.elements.get('cross-device-link-fallback').hidden, false);
  }
});

test('terminal pages have a matching title, useful recovery, and no stale cancel action', async () => {
  const e = environment([interaction(), { status: 'cancelled' }]); await flush();
  await e.elements.get('cross-device-cancel').events.click();
  assert.equal(e.elements.get('cross-device-title').textContent, 'Sign-in cancelled');
  assert.equal(e.document.title, 'Test portal - Sign-in cancelled');
  assert.equal(e.elements.get('cross-device-title').focused, true);
  assert.equal(e.elements.get('cross-device-cancel').hidden, true);
  assert.equal(e.elements.get('cross-device-controls').hidden, true);
  assert.equal(e.elements.get('cross-device-recovery').hidden, false);
  const expired = environment([interaction()]); await flush(); expired.advance(300000); await expired.tick();
  assert.equal(expired.elements.get('cross-device-title').textContent, 'Sign-in link expired');
  assert.equal(expired.elements.get('cross-device-recovery').hidden, false);
  assert.notEqual(expired.elements.get('cross-device-title').focused, true);
  const approved = environment([interaction(), { status: 'approved', next: '/portal' }]); await flush(); await approved.tick();
  assert.equal(approved.elements.get('cross-device-recovery').hidden, true);
});

test('older filesystem templates can copy, cancel, and finish without the new wrappers', async () => {
  const e = environment([interaction(), { status: 'cancelled' }], undefined, undefined, { legacy: true }); await flush();
  await e.elements.get('cross-device-copy').events.click();
  assert.equal(e.elements.get('cross-device-link').selected, true);
  await e.elements.get('cross-device-cancel').events.click();
  assert.equal(e.elements.get('cross-device-details').hidden, true);
  assert.equal(e.elements.get('cross-device-cancel').disabled, true);
  assert.ok(e.requests[1].url.endsWith('/cancel'));
  const approved = environment([interaction(), { status: 'approved', next: '/portal' }], undefined, undefined, { legacy: true }); await flush(); await approved.tick();
  assert.deepEqual(approved.navigations, ['/portal']);
});

test('expiry relocates focus only when it would otherwise hide the focused control', async () => {
  const e = environment([interaction()]); await flush();
  e.elements.get('cross-device-copy').focus();
  e.advance(300000); await e.tick();
  assert.equal(e.document.activeElement, e.elements.get('cross-device-title'));
  const outside = environment([interaction()]); await flush();
  const back = { id: 'back-to-sign-in' }; outside.document.activeElement = back;
  outside.advance(300000); await outside.tick();
  assert.equal(outside.document.activeElement, back);
});

test('terminal titles preserve a custom document title that differs from its heading', async () => {
  const e = environment([interaction(), { status: 'cancelled' }], undefined, undefined, { title: 'Acme portal' }); await flush();
  await e.elements.get('cross-device-cancel').events.click();
  assert.equal(e.document.title, 'Acme portal - Sign-in cancelled');
});

test('custom themes without the optional heading retain terminal feedback and focus', async () => {
  const e = environment([interaction(), { status: 'cancelled' }], undefined, undefined, { legacy: true, omitHeading: true, title: 'Acme portal' }); await flush();
  await e.elements.get('cross-device-cancel').events.click();
  assert.equal(e.document.title, 'Acme portal - Sign-in cancelled');
  assert.equal(e.document.activeElement, e.elements.get('cross-device-status'));
  assert.equal(e.document.activeElement.tabIndex, -1);
  assert.ok(e.requests[1].url.endsWith('/cancel'));
});

test('a late poll response cannot override cancellation', async () => {
  let resolve;
  const waiting = new Promise(done => { resolve = done; });
  const e = environment([interaction(), () => waiting, { status: 'cancelled' }]); await flush();
  const poll = e.tick(); await flush();
  await e.elements.get('cross-device-cancel').events.click();
  resolve({ ok: true, status: 200, json: async () => ({ status: 'approved', next: '/portal' }) });
  await poll;
  assert.equal(e.navigations.length, 0); assert.equal(e.timers.size, 0);
  assert.equal(e.elements.get('cross-device-status').textContent, 'This sign-in request has been cancelled. Start again when you’re ready.');
});

test('a late clipboard response cannot overwrite a terminal status', async () => {
  for (const rejected of [false, true]) {
    let resolve, reject;
    const clipboard = new Promise((done, fail) => { resolve = done; reject = fail; });
    const e = environment([interaction(), { status: 'cancelled' }], () => clipboard); await flush();
    const copying = e.elements.get('cross-device-copy').events.click();
    await e.elements.get('cross-device-cancel').events.click();
    if (rejected) reject(new Error('denied')); else resolve();
    await copying;
    assert.equal(e.elements.get('cross-device-status').textContent, 'This sign-in request has been cancelled. Start again when you’re ready.');
    assert.equal(e.elements.get('cross-device-copy-status').textContent, '');
    assert.equal(e.elements.get('cross-device-link-fallback').hidden, true);
    assert.equal(e.elements.get('cross-device-controls').hidden, true);
    assert.notEqual(e.elements.get('cross-device-link').selected, true);
  }
});

function waitForAbort(options) {
  return new Promise((_, reject) => {
    const fail = () => reject(new Error('aborted'));
    if (options.signal.aborted) fail();
    else options.signal.addEventListener('abort', fail, { once: true });
  });
}

test('deadlines bound both fetch and response body without retrying', async () => {
  for (const response of [waitForAbort, options => ({ ok: true, status: 200, json: () => waitForAbort(options) })]) {
    const e = environment([response]); await flush();
    assert.equal([...e.timers.values()][0].delay, 10000);
    await e.tick();
    assert.equal(e.requests[0].options.signal.aborted, true);
    assert.equal(e.requests.length, 1);
    assert.equal(e.timers.size, 0);
    assert.match(e.elements.get('cross-device-status').textContent, /Unable to start/);
  }
  const e = environment([interaction(), waitForAbort]); await flush();
  const polling = e.tick(); await flush();
  await e.tick(); await polling;
  assert.equal(e.requests.length, 2);
  assert.equal(e.timers.size, 0);
  assert.match(e.elements.get('cross-device-status').textContent, /no longer available/);
});

test('cancellation aborts an in-flight poll but gets its own bounded request', async () => {
  const e = environment([interaction(), waitForAbort, waitForAbort]); await flush();
  const polling = e.tick(); await flush();
  const cancelling = e.elements.get('cross-device-cancel').events.click();
  await polling; await flush();
  assert.equal(e.requests[1].options.signal.aborted, true);
  assert.equal(e.requests[2].options.signal.aborted, false);
  assert.equal(e.timers.size, 1);
  assert.equal([...e.timers.values()][0].delay, 5000);
  await e.tick(); await cancelling;
  assert.equal(e.requests[2].options.signal.aborted, true);
  assert.equal(e.timers.size, 0);
  assert.equal(e.elements.get('cross-device-status').textContent, 'This sign-in request has been cancelled. Start again when you’re ready.');
});

test('a late start response after cancellation is cancelled without reviving the page', async () => {
  let resolve;
  const response = new Promise(done => { resolve = done; });
  const e = environment([() => response, { status: 'cancelled' }]); await flush();
  await e.elements.get('cross-device-cancel').events.click();
  resolve({ ok: true, status: 200, json: async () => interaction() });
  await flush();
  assert.ok(e.requests[1].url.endsWith('/cancel'));
  assert.equal(e.requests[1].body.secret, 'requester-only');
  assert.equal(e.elements.get('cross-device-details').hidden, true);
  assert.equal(e.elements.get('cross-device-status').textContent, 'This sign-in request has been cancelled. Start again when you’re ready.');
  assert.equal(e.timers.size, 0);
});

test('localized dynamic states keep protocol values and matching codes unchanged', async () => {
  const messages = {
    cross_device_waiting: 'En attente d’approbation.', cross_device_copied: '<copié> & prêt',
    cross_device_cancelled_title: 'Connexion annulée', cross_device_cancelled: 'Recommencez quand vous le souhaitez.',
  };
  const e = environment([interaction(), { status: 'cancelled' }], async () => {}, AbortSignal, { messages });
  await flush();
  assert.equal(e.elements.get('cross-device-status').textContent, messages.cross_device_waiting);
  assert.equal(e.elements.get('cross-device-code').textContent, 'ABCD-EFGH');
  await e.elements.get('cross-device-copy').events.click();
  assert.equal(e.elements.get('cross-device-copy-status').textContent, messages.cross_device_copied);
  await e.elements.get('cross-device-cancel').events.click();
  assert.equal(e.elements.get('cross-device-title').textContent, messages.cross_device_cancelled_title);
  assert.ok(e.document.title.endsWith(messages.cross_device_cancelled_title));
  assert.equal(e.elements.get('cross-device-status').textContent, messages.cross_device_cancelled);
  assert.ok(e.requests[1].url.endsWith('/cancel'));
});

test('only start carries the requester destination; approval link and polling do not', async () => {
  const returnURL = 'https://app.test/document?x=one%26two';
  const e = environment([interaction(), { status: 'approved', next: returnURL }], undefined, undefined, { returnURL });
  await flush();
  assert.equal(e.requests[0].url, '/tenant/auth/cross-device/start?redirect_url=' + encodeURIComponent(returnURL));
  assert.equal(e.elements.get('cross-device-link').value, interaction().verification_uri);
  await e.tick();
  assert.equal(e.requests[1].url, '/tenant/auth/cross-device/poll');
  assert.deepEqual(e.navigations, [returnURL]);
});
