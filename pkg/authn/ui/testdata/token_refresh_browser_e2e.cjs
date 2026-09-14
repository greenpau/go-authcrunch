// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
// A dependency-free CDP consumer. The Go fixture owns Chrome and the TLS portal.
const assert = require("node:assert/strict");
const [endpoint, origin] = process.argv.slice(2);
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
async function login(page, username) {
  return evaluate(page, async ({ username, password }) => {
    const send = async (body) => {
      const response = await fetch("/auth/login", { method: "POST", headers: { "Content-Type": "application/json", "Accept": "application/json" }, body: JSON.stringify(body) });
      if (!response.ok) throw new Error("fixture login rejected");
      return response.json();
    };
    const request = { username, realm: "local" };
    const challenge = await send(request);
    const result = await send({ ...request, sandbox_id: challenge.sandbox_id, sandbox_secret: challenge.sandbox_secret, challenge_kind: challenge.next_challenge, challenge_response: password });
    if (!result.authenticated || !result.session_id || result.access_token || result.refresh_token) throw new Error("browser login did not return session-only metadata");
    return result.session_id;
  }, { username, password });
}
async function control(page, operation) {
  return evaluate(page, async (operation) => {
    const response = await fetch("/_test/" + operation, { method: operation === "status" ? "GET" : "POST", cache: "no-store" });
    return operation === "status" ? response.json() : response.ok;
  }, operation);
}
const state = (page) => evaluate(page, () => JSON.parse(localStorage.getItem("authcrunch-session:/auth")));
const refresh = (page, force = false) => evaluate(page, async (force) => {
  try { const result = await AuthCrunchSession.refresh(force); return { ok: true, session: result.session_id }; }
  catch (_) { return { ok: false }; }
}, force);

(async () => {
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", () => reject(new Error("browser socket failed")), { once: true });
  });
  try {
    const { browserContextId } = await command("Target.createBrowserContext");
    const first = await page(browserContextId), stale = await page(browserContextId);
    stage = "initial login";
    await navigate(first, "/auth/login?fresh=1");
    const original = await login(first, "alice");
    await navigate(first, "/auth/portal", true);
    assert.deepEqual(await refresh(first), { ok: true, session: original });
    stage = "deferred old HTML";
    const delayedNavigation = command("Page.navigate", { url: origin + "/auth/portal?deferred=1" }, stale);
    await waitFor(async () => (await control(first, "status")).stale_rendered);
    stage = "account replacement";
    const replacement = await login(first, "bob");
    assert.notEqual(replacement, original);
    await navigate(first, "/auth/portal", true);
    assert.deepEqual(await refresh(first), { ok: true, session: replacement });
    stage = "lost committed response";
    await control(first, "cut");
    assert.deepEqual(await refresh(first, true), { ok: false });
    const uncertain = await state(first);
    assert.equal(uncertain.session_id, replacement);
    assert.equal(uncertain.pending, true);
    assert.equal((await control(first, "status")).rotations, 1);
    stage = "stale document initialization";
    await control(first, "release");
    await delayedNavigation;
    await waitFor(() => evaluate(stale, () => !!window.AuthCrunchSession));
    assert.deepEqual(await refresh(stale, true), { ok: false });
    assert.deepEqual(await state(stale), uncertain);
    assert.equal((await control(first, "status")).rotations, 1);
    stage = "fresh login recovery";
    const fresh = await login(first, "alice");
    assert.notEqual(fresh, replacement);
    await navigate(first, "/auth/portal", true);
    assert.deepEqual(await refresh(first), { ok: true, session: fresh });
    // Real storage events revive the older tab's rejected bootstrap.
    await waitFor(async () => (await state(stale)).session_id === fresh);
    assert.deepEqual(await refresh(stale, true), { ok: true, session: fresh });
    const healthy = await state(first);
    assert.equal(healthy.pending, undefined);
    assert.equal(healthy.access_token, undefined);
    assert.equal(healthy.refresh_token, undefined);
    const identity = await evaluate(stale, async () => {
      const response = await fetch("/auth/whoami?probe=true", { headers: { "Accept": "application/json" } });
      const result = await response.json();
      return { authenticated: result.authenticated, username: result.sub };
    });
    assert.deepEqual(identity, { authenticated: true, username: "alice" });
    stage = "logout across tabs";
    assert.equal(await evaluate(stale, async () => (await AuthCrunchSession.logout()).logged_out), true);
    assert.deepEqual(await refresh(first, true), { ok: false });
    assert.equal((await state(first)).blocked, true);
    const final = await control(first, "status");
    assert.equal(final.rotations, 2);
    process.stdout.write(JSON.stringify({ passed: true, rotations: final.rotations }) + "\n");
  } finally {
    await command("Browser.close").catch(() => {});
    socket.close();
    for (const request of pending.values()) clearTimeout(request.timer);
  }
})().catch((error) => {
  // Assertions contain only session identifiers/metadata; never dump login or
  // CDP response objects, cookies, configured passwords, or credential bodies.
  process.stderr.write(stage + ": " + error.message + "\n");
  process.exitCode = 1;
  socket.close();
});
