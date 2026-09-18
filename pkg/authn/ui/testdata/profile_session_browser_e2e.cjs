// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
// Run the embedded profile application against the Go fixture's TLS portal.
const assert = require("node:assert/strict");
const config = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
const socket = new WebSocket(process.argv[2]);
const pending = new Map();
let sequence = 0;
let rejectedProfile = false;
let recoveryNavigation = false;

socket.addEventListener("message", ({ data }) => {
  const message = JSON.parse(data);
  if (message.method === "Network.responseReceived") {
    const response = message.params.response;
    if (response.url === config.issuer + "/api/profile" && response.status === 401) rejectedProfile = true;
  }
  if (message.method === "Network.requestWillBeSent" &&
      message.params.type === "Document" && message.params.request.url === config.issuer + "/api/refresh_token") {
    recoveryNavigation = true;
  }
  const request = pending.get(message.id);
  if (!request) return;
  pending.delete(message.id);
  clearTimeout(request.timer);
  if (message.error) request.reject(new Error(message.error.message));
  else request.resolve(message.result);
});
function command(method, params = {}, sessionId) {
  return new Promise((resolve, reject) => {
    const id = ++sequence;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error("browser command timed out")); }, 15000);
    pending.set(id, { resolve, reject, timer });
    socket.send(JSON.stringify({ id, method, params, sessionId }));
  });
}
async function evaluate(tab, fn, args) {
  const result = await command("Runtime.evaluate", {
    expression: `(${fn.toString()})(${JSON.stringify(args)})`, awaitPromise: true, returnByValue: true
  }, tab);
  if (result.exceptionDetails) throw new Error("browser evaluation failed");
  return result.result.value;
}
async function waitFor(fn) {
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    try {
      if (await fn()) return;
    } catch (error) {
      if (!/Execution context was destroyed|Cannot find context/.test(error.message)) throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error("profile recovery did not reach the login form");
}

(async () => {
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", () => reject(new Error("browser socket failed")), { once: true });
  });
  try {
    const { browserContextId } = await command("Target.createBrowserContext");
    const { targetId } = await command("Target.createTarget", { url: "about:blank", browserContextId });
    const { sessionId: tab } = await command("Target.attachToTarget", { targetId, flatten: true });
    await command("Page.enable", {}, tab);
    await command("Runtime.enable", {}, tab);
    await command("Network.enable", {}, tab);
    await command("Network.setCookies", { cookies: config.cookies }, tab);
    await command("Page.navigate", { url: config.issuer + "/portal" }, tab);
    await waitFor(() => evaluate(tab, (issuer) => location.href === issuer + "/portal" && document.readyState === "complete", config.issuer));
    await command("Page.navigate", { url: config.issuer + "/profile/" }, tab);
    await waitFor(() => evaluate(tab, (issuer) => location.href === issuer + "/login?fresh=1" && !!document.querySelector("#username"), config.issuer));
    assert.ok(rejectedProfile, "the shipped profile app did not observe the revoked session");
    assert.ok(recoveryNavigation, "the shipped profile app did not follow its recovery route");
    const { cookies } = await command("Storage.getCookies", { browserContextId });
    assert.ok(!cookies.some((cookie) => cookie.name === "AUTHP_ACCESS_TOKEN"), "fresh login retained stale access");
    assert.equal(cookies.some((cookie) => cookie.name === "AUTHP_REFRESH_TOKEN"), config.cookies.some((cookie) => cookie.name === "AUTHP_REFRESH_TOKEN"), "fresh login discarded refresh before replacement");
    await evaluate(tab, () => {
      document.querySelector("#username").value = "alice";
      document.querySelector("#realm").value = "local";
      document.querySelector("#username").form.submit();
    });
    await waitFor(() => evaluate(tab, () => location.pathname.includes("/sandbox/") && document.readyState === "complete"));
    process.stdout.write(JSON.stringify({ passed: true }));
  } finally {
    await command("Browser.close").catch(() => {});
    socket.close();
  }
})().catch((error) => { process.stderr.write(error.message + "\n"); process.exitCode = 1; });
