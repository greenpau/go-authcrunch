// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
// A dependency-free CDP consumer. The Go fixture owns Chrome and the TLS portal.
const assert = require("node:assert/strict");
const [endpoint, encoded] = process.argv.slice(2);
const config = JSON.parse(encoded);
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
  await command("Network.enable", {}, sessionId);
  return sessionId;
}

(async () => {
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", () => reject(new Error("browser socket failed")), { once: true });
  });
  try {
    const { browserContextId } = await command("Target.createBrowserContext");
    const tab = await page(browserContextId);
    const cookieNames = async () => {
      const { cookies } = await command("Storage.getCookies", { browserContextId });
      return cookies.map((cookie) => cookie.name);
    };
    const hasCookie = async (name) => (await cookieNames()).includes(name);
    const issueReferer = () => evaluate(tab, async ({ origin, returnURL }) => {
      const response = await fetch(origin + "/login?redirect_url=" + encodeURIComponent(returnURL), {
        redirect: "manual", cache: "no-store"
      });
      return response.status;
    }, { origin: config.origin, returnURL: config.return_url });
    const setReferer = async (value) => {
      const result = await command("Network.setCookie", {
        name: config.referer, value, url: config.origin + "/portal", path: "/", secure: true, httpOnly: true
      }, tab);
      assert.equal(result.success, true, "Chrome rejected the synthetic referer state");
    };
    const consumePortal = () => evaluate(tab, async (origin) => {
      const response = await fetch(origin + "/portal", { redirect: "manual", cache: "no-store" });
      return response.status;
    }, config.origin);

    stage = "portal origin";
    const navigation = await command("Page.navigate", { url: config.origin + "/_test/referer-cleanup/blank" }, tab);
    if (navigation.errorText) throw new Error("portal navigation failed");
    await waitFor(() => evaluate(tab, (origin) => location.origin === origin && document.readyState === "complete", config.origin));

    stage = "secure sentinel";
    await evaluate(tab, async (origin) => { await fetch(origin + "/_test/referer-cleanup/sentinel"); }, config.origin);
    assert.equal(await hasCookie(config.sentinel), true, "browser did not store the unrelated sentinel");

    stage = "referer issuance";
    assert.equal(await issueReferer(), 200, "unauthenticated login page did not issue referer cookie");
    assert.equal(await hasCookie(config.referer), true, "Chrome rejected the root __Host- referer cookie");

    stage = "invalid deletion negative control";
    await evaluate(tab, async (origin) => { await fetch(origin + "/_test/referer-cleanup/old-delete"); }, config.origin);
    assert.equal(await hasCookie(config.referer), true, "Chrome accepted __Host- deletion without Secure");

    stage = "successful login grant cleanup";
    await evaluate(tab, async ({ origin, password }) => {
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
    await waitFor(async () => !(await hasCookie(config.referer)));
    assert.equal(await hasCookie(config.sentinel), true, "login cleanup removed the unrelated sentinel");

    stage = "authenticated trusted portal cleanup";
    await issueReferer();
    assert.equal(await hasCookie(config.referer), true, "authenticated browser did not store trusted referer cookie");
    await consumePortal();
    assert.equal(await hasCookie(config.referer), false, "trusted portal redirect retained referer cookie");

    for (const [label, value] of [
      ["untrusted", "https://evil.example.test/return"],
      ["malformed", "http://[::1"]
    ]) {
      stage = "authenticated " + label + " portal cleanup";
      await setReferer(value);
      assert.equal(await hasCookie(config.referer), true, "browser did not store " + label + " referer state");
      assert.equal(await consumePortal(), 200, "portal did not render after ignoring " + label + " referer");
      assert.equal(await hasCookie(config.referer), false, "portal retained " + label + " referer state");
    }
    assert.equal(await hasCookie(config.sentinel), true, "portal cleanup removed the unrelated sentinel");
    process.stdout.write(JSON.stringify({ passed: true }));
  } finally {
    await command("Browser.close").catch(() => {});
    socket.close();
  }
})().catch((error) => {
  process.stderr.write(stage + ": " + error.message + "\n");
  process.exitCode = 1;
});
