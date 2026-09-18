// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
const assert = require("node:assert/strict");
const [endpoint, encoded] = process.argv.slice(2);
const config = JSON.parse(encoded);
const socket = new WebSocket(endpoint);
const pending = new Map();
const statuses = new Map();
const callbacks = new Map();
let sequence = 0;
let stage = "startup";

socket.addEventListener("message", ({ data }) => {
  const message = JSON.parse(data);
  if (!message.id) {
    if (message.method === "Network.responseReceived" && message.params.type === "Document") {
      statuses.set(message.sessionId, { url: message.params.response.url, status: message.params.response.status });
      if (message.params.response.url.includes("/auth/saml/upstream")) callbacks.set(message.sessionId, { url: message.params.response.url, status: message.params.response.status });
    }
    return;
  }
  const request = pending.get(message.id);
  if (!request) return;
  pending.delete(message.id); clearTimeout(request.timer);
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
async function evaluate(page, expression) {
  const result = await command("Runtime.evaluate", { expression, returnByValue: true }, page);
  if (result.exceptionDetails) throw new Error("browser evaluation failed");
  return result.result.value;
}
async function makePage(disableJS = false) {
  const { browserContextId } = await command("Target.createBrowserContext");
  const target = await command("Target.createTarget", { url: "about:blank", browserContextId });
  const { sessionId } = await command("Target.attachToTarget", { targetId: target.targetId, flatten: true });
  await command("Page.enable", {}, sessionId); await command("Runtime.enable", {}, sessionId); await command("Network.enable", {}, sessionId);
  if (disableJS) await command("Emulation.setScriptExecutionDisabled", { value: true }, sessionId);
  return sessionId;
}
async function navigate(page, url) {
  statuses.delete(page);
  callbacks.delete(page);
  const result = await command("Page.navigate", { url }, page);
  if (result.errorText) throw new Error("navigation failed");
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
	const callback = callbacks.get(page);
	if (callback) return callback;
	const latest = statuses.get(page);
	if (latest && (latest.url.endsWith("/auth/portal") || (latest.url.includes("/auth/saml/upstream") && latest.status >= 400))) return latest;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  throw new Error(stage + ": SAML navigation timed out at " + JSON.stringify(statuses.get(page)));
}

(async () => {
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", () => reject(new Error("browser socket failed")), { once: true });
  });
  try {
    stage = "valid cross-site POST";
    const valid = await makePage();
    const success = await navigate(valid, config.portal + "/auth/saml/upstream");
    assert.equal(success.status, 200, "cross-site SAML POST did not authenticate");

    stage = "foreign browser setup";
    const initiator = await makePage(true);
    await command("Page.navigate", { url: config.portal + "/auth/saml/upstream" }, initiator);
    let idpURL = "";
    const deadline = Date.now() + 20000;
    while (Date.now() < deadline) {
      idpURL = await evaluate(initiator, "location.href");
      if (idpURL.includes("/sso")) break;
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert.ok(idpURL.includes("/sso"), "initiation did not reach the IdP");
    stage = "foreign browser callback";
    const foreign = await makePage();
    const rejected = await navigate(foreign, idpURL);
    assert.equal(rejected.status, 401, "a different browser completed SAML state");
    process.stdout.write(JSON.stringify({ passed: true }));
  } finally {
    await command("Browser.close").catch(() => {}); socket.close();
  }
})().catch(error => { process.stderr.write(error.message + "\n"); process.exitCode = 1; });
