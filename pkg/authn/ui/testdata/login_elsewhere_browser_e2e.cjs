// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
// A dependency-free CDP consumer. The Go fixture owns Chrome and the TLS portal.
const assert = require("node:assert/strict");
const [endpoint, encoded] = process.argv.slice(2);
const config = JSON.parse(encoded);
const password = require("node:fs").readFileSync(0, "utf8");
const socket = new WebSocket(endpoint);
const pending = new Map();
// Probe requests to whoami, by the page session that sent them.
const probes = new Map();
let sequence = 0;
let stage = "connect";

socket.addEventListener("message", ({ data }) => {
  const message = JSON.parse(data);
  if (message.method === "Network.requestWillBeSent" && new URL(message.params.request.url).pathname === "/whoami") {
    probes.set(message.sessionId, (probes.get(message.sessionId) || 0) + 1);
  }
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
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error("browser command timed out"));
    }, 25000);
    pending.set(id, { resolve, reject, timer });
    socket.send(JSON.stringify({ id, method, params, sessionId }));
  });
}
async function evaluate(page, fn, args) {
  const result = await command("Runtime.evaluate", {
    expression: `(${fn.toString()})(${JSON.stringify(args)})`, awaitPromise: true, returnByValue: true
  }, page);
  if (result.exceptionDetails) {
    throw new Error("browser evaluation failed: " + (result.exceptionDetails.exception?.description || "unknown exception"));
  }
  return result.result.value;
}
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function waitFor(fn) {
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    if (await fn()) return;
    await sleep(50);
  }
  throw new Error("browser condition timed out");
}
async function page(contextId) {
  const target = await command("Target.createTarget", { url: "about:blank", browserContextId: contextId });
  const { sessionId } = await command("Target.attachToTarget", { targetId: target.targetId, flatten: true });
  await command("Page.enable", {}, sessionId);
  await command("Runtime.enable", {}, sessionId);
  await command("Network.enable", {}, sessionId);
  return sessionId;
}
const href = (tab) => evaluate(tab, () => document.readyState === "complete" ? location.href : "");

(async () => {
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", () => reject(new Error("browser socket failed")), { once: true });
  });
  try {
    const { browserContextId } = await command("Target.createBrowserContext");
    const login = config.origin + "/login";
    const destination = config.origin + "/_test/tab/waiting?view=one%26two";
    const tabs = {};
    stage = "open login pages";
    for (const [name, url] of [
      ["signing", login + "?redirect_url=" + encodeURIComponent(config.origin + "/_test/tab/signing")],
      ["waiting", login + "?redirect_url=" + encodeURIComponent(destination)],
      ["bare", login],
      ["fresh", login + "?fresh=1"],
    ]) {
      tabs[name] = await page(browserContextId);
      const navigation = await command("Page.navigate", { url }, tabs[name]);
      if (navigation.errorText) throw new Error(name + " tab navigation failed");
      await waitFor(async () => (await href(tabs[name])) === url);
    }

    // A tab in the background does not ask; switching to it does.
    stage = "signed-out probe";
    assert.equal(await evaluate(tabs.waiting, () => document.visibilityState), "hidden");
    // Outlast the page's five-second interval, so its visibility guard is what
    // keeps the background tab quiet.
    await sleep(5500);
    assert.equal(probes.get(tabs.waiting) || 0, 0, "a background tab asked the portal");
    await command("Page.bringToFront", {}, tabs.waiting);
    await waitFor(() => probes.get(tabs.waiting) > 0);
    await sleep(500);
    assert.equal(await href(tabs.waiting), login + "?redirect_url=" + encodeURIComponent(destination),
      "a signed-out browser left the login page");

    stage = "sign in from another tab";
    await command("Page.bringToFront", {}, tabs.signing);
    await evaluate(tabs.signing, async ({ origin, password }) => {
      const start = await fetch(origin + "/login", {
        method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "text/html" },
        body: new URLSearchParams({ username: "alice", realm: "local" })
      });
      const sandbox = new URL(start.url);
      if (!sandbox.pathname.includes("/sandbox/")) throw new Error("login did not enter sandbox");
      const finish = await fetch(sandbox, {
        method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "text/html" },
        body: new URLSearchParams({ secret: password })
      });
      if (!finish.ok) throw new Error("password checkpoint failed");
    }, { origin: config.origin, password });

    // A fresh login must be completed on its own page: a session from another
    // tab is not evidence of it, so that page does not even ask.
    stage = "fresh login stays";
    await command("Page.bringToFront", {}, tabs.fresh);
    await sleep(1000);
    assert.equal(probes.get(tabs.fresh) || 0, 0, "a fresh login page asked the portal");
    assert.equal(await href(tabs.fresh), login + "?fresh=1", "a fresh login page left");

    // The user only switches back to the waiting tabs: their own script must
    // notice the login, without a reload.
    stage = "waiting tab leaves for its own destination";
    await command("Page.bringToFront", {}, tabs.waiting);
    await waitFor(async () => (await href(tabs.waiting)) === destination);
    stage = "tab without a destination leaves for the portal";
    await command("Page.bringToFront", {}, tabs.bare);
    await waitFor(async () => (await href(tabs.bare)) === config.origin + "/portal");
    process.stdout.write(JSON.stringify({ passed: true }));
  } finally {
    await command("Browser.close").catch(() => {});
    socket.close();
  }
})().catch((error) => {
  process.stderr.write(stage + ": " + error.message + "\n");
  process.exitCode = 1;
});
