// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const source = fs.readFileSync(path.join(__dirname, "../core/js/refresh.js"), "utf8");
const storageKey = "authcrunch-session:/auth";

function environment() {
  const storage = new Map();
  const listeners = [];
  let queue = Promise.resolve();
  let locked = false;
  let calls = 0;
  let lookups = 0;
  const shared = {
    session: "sid", expires: 1, authenticated: true,
    localStorage: {
      getItem: (key) => storage.get(key) || null,
      setItem: (key, value) => {
        assert.equal(locked, true, "session metadata changed outside the Web Lock");
        storage.set(key, value);
      }
    },
    locks: {
      request: (_key, fn) => {
        const result = queue.then(async () => {
          locked = true;
          try { return await fn(); } finally { locked = false; }
        });
        queue = result.catch(() => {});
        return result;
      }
    },
    access: async () => ({ ok: shared.authenticated, status: shared.authenticated ? 200 : 401,
      json: async () => ({ authenticated: true, sid: shared.session, exp: shared.expires }) }),
    exchange: async (url, options) => {
      if (url.endsWith("/logout")) {
        shared.authenticated = false;
        return { ok: true, json: async () => ({ logged_out: true }) };
      }
      if (options.headers["X-Authcrunch-Refresh-Session"] !== shared.session) return { ok: false, status: 401 };
      shared.expires = Math.floor(Date.now()/1000)+300;
      shared.authenticated = true;
      return { ok: true, json: async () => ({
        session_id: shared.session, access_expires_at: shared.expires,
        session_expires_at: Math.floor(Date.now()/1000)+3600,
        access_token: "must-not-persist", refresh_token: "must-not-persist"
      }) };
    },
    fetch: async (url, options) => {
      assert.equal(options.credentials, "same-origin");
      if (url.endsWith("/whoami?probe=true")) {
        assert.equal(options.headers.Accept, "application/json");
        return shared.access();
      }
      assert.equal(options.method, "POST");
      assert.equal(options.headers["X-Authcrunch-Refresh"], "1");
      assert.equal(options.body, "{}");
      if (url.endsWith("/refresh_session")) {
        lookups++;
        return { ok: true, json: async () => ({ session_id: shared.session }) };
      }
      calls++;
      if (!url.endsWith("/logout")) assert.ok(options.headers["X-Authcrunch-Refresh-Session"], "rotation omitted its session precondition");
      return shared.exchange(url, options);
    },
    tab(overrides = {}) {
      const window = {
        addEventListener: (name, fn) => { if (name === "storage") listeners.push(fn); },
        dispatchEvent() {}, location: { assign() {}, replace() {} }
      };
      const context = {
        window,
        document: { currentScript: { dataset: { base: "/auth", session: "sid", expires: "1", action: "refresh" } }, getElementById: () => null },
        navigator: { locks: shared.locks }, localStorage: shared.localStorage,
        fetch: (...args) => shared.fetch(...args), setTimeout: () => 1, clearTimeout() {}, CustomEvent: class {}, ...overrides
      };
      vm.runInNewContext(source, context);
      return window.AuthCrunchSession;
    },
    staleTab() {
      return shared.tab({ document: { currentScript: { dataset: { base: "/auth", session: "old-html-session", expires: "1" } }, getElementById: () => null } });
    },
    storageEvent() { for (const fn of listeners) fn({ key: storageKey }); },
    idle: () => queue,
    get calls() { return calls; },
    get lookups() { return lookups; },
    get state() { return JSON.parse(storage.get(storageKey) || "null"); },
    set state(value) { storage.set(storageKey, JSON.stringify(value)); }
  };
  return shared;
}

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

test("single page and multiple tabs refresh once", async () => {
  const env = environment();
  const first = env.tab(), second = env.tab();
  await Promise.all([first.refresh(), first.refresh(), second.refresh()]);
  assert.equal(env.calls, 1);
  assert.equal(env.state.session_id, "sid");
  assert.equal(env.state.access_token, undefined);
  assert.equal(env.state.refresh_token, undefined);
});

test("logout and refresh share the same lock", async () => {
  const env = environment();
  const first = env.tab(), second = env.tab();
  await Promise.all([first.refresh(), second.logout()]);
  assert.equal(env.calls, 2);
  assert.equal(env.state.blocked, true);
  assert.equal(env.state.session_id, "sid");
  await assert.rejects(first.refresh(), /sign in again/);
  assert.equal(env.calls, 2);
});

test("interrupted rotation is not retried across tabs or reload", async () => {
  const env = environment();
  env.exchange = async () => { throw new Error("network interrupted"); };
  const first = env.tab();
  await assert.rejects(first.refresh(), /interrupted/);
  assert.equal(env.state.pending, true);
  env.exchange = async () => { assert.fail("uncertain credential retried"); };
  await assert.rejects(env.tab().refresh(), /sign in again/);
  assert.equal(env.lookups, 0);
});

test("malformed success response remains uncertain", async () => {
  const env = environment();
  env.exchange = async () => ({ ok: true, json: async () => { throw new Error("incomplete response"); } });
  await assert.rejects(env.tab().refresh(), /incomplete/);
  assert.equal(env.state.pending, true);
});

test("a mismatched response cannot switch the pending session", async () => {
  const env = environment();
  env.exchange = async () => ({ ok: true, json: async () => ({ session_id: "different", access_expires_at: 100, session_expires_at: 200 }) });
  await assert.rejects(env.tab().refresh(), /incomplete/);
  assert.equal(env.state.pending, true);
  assert.equal(env.state.session_id, "sid");
});

for (const field of ["pending", "blocked"]) {
  test(`stale HTML cannot erase ${field} for a different session`, async () => {
    const env = environment();
    env.session = "current-session";
    env.state = { session_id: env.session, [field]: true };
    await assert.rejects(env.staleTab().refresh(), /sign in again/);
    assert.deepEqual(env.state, { session_id: env.session, [field]: true });
    assert.equal(env.calls, 0);
    assert.equal(env.lookups, 0);
  });
}

test("delayed bootstrap waits for an in-flight malformed rotation", async () => {
  const env = environment();
  const entered = deferred(), response = deferred();
  env.session = "new-session";
  env.exchange = async () => { entered.resolve(); return response.promise; };
  const first = env.tab().refresh();
  await entered.promise;
  const stale = env.staleTab();
  assert.equal(env.state.pending, true);
  assert.equal(env.state.session_id, "new-session");
  response.resolve({ ok: true, json: async () => { throw new Error("lost response body"); } });
  await assert.rejects(first, /lost response/);
  await assert.rejects(stale.refresh(), /sign in again/);
  assert.equal(env.state.pending, true);
  assert.equal(env.calls, 1);
  assert.equal(env.lookups, 0);
});

for (const notify of [false, true]) {
  test(`a completed new login restores tabs with storage event=${notify}`, async () => {
    const env = environment();
    env.state = { session_id: "sid", pending: true };
    const old = env.tab();
    await assert.rejects(old.refresh(), /sign in again/);
    env.session = "fresh-login";
    env.expires = Math.floor(Date.now()/1000)+300;
    const fresh = env.staleTab(); // Even this document's stale ID is irrelevant.
    await fresh.refresh();
    assert.equal(env.state.session_id, "fresh-login");
    assert.equal(env.state.pending, undefined);
    assert.equal(env.calls, 0);
    if (notify) env.storageEvent();
    await old.refresh(true);
    assert.equal(env.calls, 1);
    assert.equal(env.state.session_id, "fresh-login");
  });
}

test("a concurrent login cannot redirect an old pending request to its family", async () => {
  const env = environment();
  const exchange = env.exchange;
  env.exchange = (url, options) => {
    env.session = "new-login";
    env.expires = Math.floor(Date.now()/1000)+300;
    return exchange(url, options);
  };
  await assert.rejects(env.tab().refresh(), /sign in again/);
  assert.equal(env.state.session_id, "sid");
  assert.equal(env.state.blocked, true);
  assert.equal(env.calls, 1);
  await env.staleTab().refresh();
  assert.equal(env.state.session_id, "new-login");
  assert.equal(env.state.blocked, undefined);
  assert.equal(env.calls, 1);
});

test("initial expired access obtains the family ID without a rotation", async () => {
  const env = environment();
  env.authenticated = false;
  const client = env.tab();
  await env.idle();
  assert.equal(env.lookups, 1);
  assert.equal(env.calls, 0);
  assert.equal(env.state.session_id, "sid");
  await client.refresh();
  assert.equal(env.calls, 1);
});

test("expired access cannot trigger a lookup of an uncertain credential", async () => {
  const env = environment();
  env.authenticated = false;
  env.state = { session_id: "sid", pending: true };
  const client = env.tab();
  await assert.rejects(client.refresh(), /sign in again/);
  assert.equal(env.lookups, 0);
  assert.equal(env.calls, 0);
  await client.logout();
  assert.equal(env.calls, 1);
  assert.equal(env.state.blocked, true);
  assert.equal(env.state.session_id, "sid");
});

test("an uncertain state without a session ID cannot be relabeled", async () => {
  const env = environment();
  env.state = { pending: true };
  await assert.rejects(env.tab().refresh(), /sign in again/);
  assert.deepEqual(env.state, { pending: true });
  assert.equal(env.calls, 0);
});

test("signed access expiry replaces stale metadata and malformed storage cannot rotate", async () => {
  const env = environment();
  env.state = { session_id: "sid", access_expires_at: "invalid" };
  const client = env.tab();
  await env.idle();
  assert.equal(env.state.access_expires_at, env.expires);
  env.state = { session_id: "sid", access_expires_at: "invalid" };
  await assert.rejects(client.refresh(true), /sign in again/);
  assert.equal(env.calls, 0);
});

test("missing cross-tab coordination fails closed", async () => {
  const env = environment();
  const client = env.tab({ navigator: {} });
  await assert.rejects(client.refresh(), /signing in again/);
  assert.equal(env.calls, 0);
});

test("blocked storage fails closed", async () => {
  const env = environment();
  const client = env.tab({ localStorage: { getItem() { throw new Error("storage disabled"); } } });
  await assert.rejects(client.refresh(), /storage disabled/);
  assert.equal(env.calls, 0);
});
