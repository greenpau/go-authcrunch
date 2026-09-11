// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const source = fs.readFileSync(path.join(__dirname, "../core/js/refresh.js"), "utf8");

function environment() {
  const storage = new Map();
  let queue = Promise.resolve();
  let calls = 0;
  const shared = {
    localStorage: {
      getItem: (key) => storage.get(key) || null,
      setItem: (key, value) => storage.set(key, value)
    },
    locks: {
      request: (_key, fn) => {
        const result = queue.then(fn);
        queue = result.catch(() => {});
        return result;
      }
    },
    fetch: async (url, options) => {
      calls++;
      assert.equal(options.method, "POST");
      assert.equal(options.credentials, "same-origin");
      assert.equal(options.headers["X-Authcrunch-Refresh"], "1");
      assert.equal(options.body, "{}");
      return { ok: true, json: async () => url.endsWith("/logout") ? { logged_out: true } : {
        session_id: "sid", access_expires_at: Math.floor(Date.now()/1000)+300,
        session_expires_at: Math.floor(Date.now()/1000)+3600,
        // Never persist credentials, even if a server accidentally includes them.
        access_token: "must-not-persist", refresh_token: "must-not-persist"
      }};
    },
    tab(overrides = {}) {
      const window = { addEventListener() {}, dispatchEvent() {}, location: { assign() {}, replace() {} } };
      const context = { window, document: { currentScript: { dataset: { base: "/auth", session: "sid", expires: "1", action: "refresh" } }, getElementById: () => null }, navigator: { locks: shared.locks }, localStorage: shared.localStorage, fetch: (...args) => shared.fetch(...args), setTimeout: () => 1, clearTimeout() {}, CustomEvent: class {}, ...overrides };
      vm.runInNewContext(source, context);
      return window.AuthCrunchSession;
    },
    get calls() { return calls; },
    get state() { return JSON.parse(storage.get("authcrunch-session:/auth")); }
  };
  return shared;
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
  await assert.rejects(first.refresh(), /sign in again/);
  assert.equal(env.calls, 2);
});

test("interrupted rotation is not retried across tabs or reload", async () => {
  const env = environment();
  env.fetch = async () => { throw new Error("network interrupted"); };
  const first = env.tab();
  await assert.rejects(first.refresh(), /interrupted/);
  assert.equal(env.state.pending, true);
  env.fetch = async () => { assert.fail("uncertain credential retried"); };
  await assert.rejects(env.tab().refresh(), /sign in again/);
});

test("malformed success response remains uncertain", async () => {
  const env = environment();
  env.fetch = async () => ({ ok: true, json: async () => { throw new Error("incomplete response"); } });
  await assert.rejects(env.tab().refresh(), /incomplete/);
  assert.equal(env.state.pending, true);
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
