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

socket.addEventListener("message", ({ data }) => {
  const message = JSON.parse(data);
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
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", () => reject(new Error("browser socket failed")), { once: true });
  });
  try {
    const { browserContextId } = await command("Target.createBrowserContext");
    const tab = await page(browserContextId);
    await navigate(tab, "/_test/blank");
    const cookieNames = async () => {
      const { cookies } = await command("Storage.getCookies", { browserContextId });
      // Only names leave this helper; failures never print session values.
      return cookies.map((cookie) => cookie.name);
    };
    const protectedStatus = (path = "/auth/protected") => evaluate(tab, async (path) => {
      const response = await fetch(path, { headers: { Accept: "application/json" }, redirect: "manual", cache: "no-store" });
      return response.status;
    }, path);
    stage = "unauthenticated gatekeeper";
    assert.notEqual(await protectedStatus(), 204);
    stage = "HTML login";
    await evaluate(tab, async ({ base, password }) => {
      const start = await fetch(base + "/login", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "text/html" }, body: new URLSearchParams({ username: "alice", realm: "local" }) });
      const sandbox = new URL(start.url);
      if (!sandbox.pathname.includes("/sandbox/")) throw new Error("login did not enter sandbox: HTTP " + start.status + ", type " + start.headers.get("Content-Type"));
      const finish = await fetch(sandbox, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "text/html" }, body: new URLSearchParams({ secret: password }) });
      if (!finish.ok) throw new Error("password checkpoint failed");
    }, { base: config.base, password });
    let names = await cookieNames();
    assert.ok(names.includes(config.access), "login did not store the access cookie");
    assert.ok(!names.includes(config.sandbox), "login retained the sandbox cookie");
    assert.ok(names.includes(config.session), "login did not store the session cookie");
    assert.equal(await protectedStatus(), 204);
    stage = "portal routes after login";
    const routes = await evaluate(tab, async (base) => {
      const results = [];
      for (const path of ["/beacon?format=json", "/qrcode/login", "/favicon.ico", "/apps/mobile-access"]) {
        const response = await fetch(base + path, { redirect: "manual", cache: "no-store" });
        results.push(response.status);
      }
      const profile = await fetch(base + "/api/profile", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ kind: "fetch_user_info" })
      });
      results.push(profile.status);
      return results;
    }, config.base);
    assert.deepEqual(routes, [200, 200, 200, 200, 200], "valid portal routes rejected after login");
    if (config.scoped) assert.notEqual(await protectedStatus("/outside/protected"), 204);
    if (config.reserved) {
      stage = "old deletion negative control";
      await evaluate(tab, async () => { await fetch("/_test/old-delete"); });
      names = await cookieNames();
      assert.ok(names.includes(config.access), "browser accepted old access deletion");
      assert.ok(names.includes(config.session), "browser accepted old session deletion");
      assert.equal(await protectedStatus(), 204);
    }
    stage = "production logout";
    await evaluate(tab, async (base) => { await fetch(base + "/logout", { redirect: "manual" }); }, config.base);
    names = await cookieNames();
    assert.ok(!names.includes(config.access), "logout retained the access cookie");
    assert.ok(!names.includes(config.session), "logout retained the session cookie");
    assert.notEqual(await protectedStatus(), 204);
    process.stdout.write(JSON.stringify({ passed: true }));
  } finally {
    await command("Browser.close").catch(() => {});
    socket.close();
  }
})().catch((error) => { process.stderr.write(stage + ": " + error.message + "\n"); process.exitCode = 1; });
