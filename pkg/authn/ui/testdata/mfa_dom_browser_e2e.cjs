// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
const assert = require("node:assert/strict");
const [endpoint, origin] = process.argv.slice(2);
const socket = new WebSocket(endpoint);
const pending = new Map();
let sequence = 0;

socket.addEventListener("message", ({ data }) => {
  const message = JSON.parse(data);
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
    const timer = setTimeout(() => reject(new Error("browser command timed out")), 20000);
    pending.set(id, { resolve, reject, timer });
    socket.send(JSON.stringify({ id, method, params, sessionId }));
  });
}
async function evaluate(page, fn, args) {
  const result = await command("Runtime.evaluate", {
    expression: `(${fn.toString()})(${JSON.stringify(args)})`, awaitPromise: true, returnByValue: true,
  }, page);
  if (result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description || "browser evaluation failed");
  return result.result.value;
}
async function waitFor(page, fn) {
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    if (await evaluate(page, fn)) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error("browser condition timed out");
}

(async () => {
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", reject, { once: true });
  });
  try {
    for (const script of ["mfa_add_app.js", "sandbox_mfa_add_app.js"]) {
      const { browserContextId } = await command("Target.createBrowserContext");
      const target = await command("Target.createTarget", { url: `${origin}/fixture?script=${script}`, browserContextId });
      const attached = await command("Target.attachToTarget", { targetId: target.targetId, flatten: true });
      await command("Page.enable", {}, attached.sessionId);
      await command("Runtime.enable", {}, attached.sessionId);
      await waitFor(attached.sessionId, () => document.readyState === "complete" &&
        typeof updateQRCode === "function" && typeof M !== "undefined" &&
        typeof M.getHashElement === "function");
      const result = await evaluate(attached.sessionId, () => {
        document.getElementById("label").value = "Ops <b>Team</b> & QA";
        document.getElementById("email").value = "member+fixture@example.test?mode=full";
        document.getElementById("digits").value = "6&extra=text";
        document.getElementById("period").value = "30#tail";
        updateQRCode();
        const link = document.querySelector("#mfa-no-camera-link a");
        const image = document.querySelector("#mfa-qr-code-image img");
        const fragment = document.getElementById("panel[fixture]\\value");
        const tabs = M.Tabs.init(document.querySelector(".tabs"));
        return {
          href: link.getAttribute("href"), src: image.src,
          bold: document.querySelectorAll("#mfa-no-camera-link b, #mfa-qr-code-image b").length,
          fragment: M.getHashElement("#panel%5Bfixture%5D%5Cvalue") === fragment,
          escaped: document.querySelector(M.escapeHash("#panel%5Bfixture%5D%5Cvalue")) === fragment,
          selected: tabs.$content[0] === fragment && fragment.classList.contains("active"),
          invalid: M.getHashElement("#bad%ZZ") === null,
        };
      });
      assert.match(result.href, /^otpauth:\/\/totp\/Ops%20%3Cb%3ETeam%3C%2Fb%3E%20%26%20QA:/);
      assert.match(result.href, /digits=6%26extra%3Dtext&period=30%23tail$/);
      assert.match(result.src, new RegExp(`^${origin.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/barcode/`));
      assert.equal(result.bold, 0);
      assert.equal(result.fragment, true);
      assert.equal(result.escaped, true);
      assert.equal(result.selected, true);
      assert.equal(result.invalid, true);
      await command("Target.disposeBrowserContext", { browserContextId });
    }
    const { browserContextId } = await command("Target.createBrowserContext");
    const target = await command("Target.createTarget", { url: `${origin}/sandbox`, browserContextId });
    const attached = await command("Target.attachToTarget", { targetId: target.targetId, flatten: true });
    await command("Runtime.enable", {}, attached.sessionId);
    await waitFor(attached.sessionId, () => document.readyState === "complete" && typeof updateQRCode === "function");
    const portal = await evaluate(attached.sessionId, () => {
      document.getElementById("label").value = "Ops & QA";
      document.getElementById("email").value = "member+fixture@example.test";
      updateQRCode();
      return {
        href: document.querySelector("#mfa-no-camera-link a").getAttribute("href"),
        src: document.querySelector("#mfa-qr-code-image img").src,
        form: document.querySelector("form.mfa-add-app-form") !== null,
      };
    });
    assert.equal(portal.form, true);
    assert.match(portal.href, /^otpauth:\/\/totp\/Ops%20%26%20QA:/);
    assert.match(portal.src, new RegExp(`^${origin.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/sandbox/fixture/mfa-app-barcode/`));
    await command("Target.disposeBrowserContext", { browserContextId });
    process.stdout.write(JSON.stringify({ passed: true }) + "\n");
  } finally {
    await command("Browser.close").catch(() => {});
    socket.close();
  }
})().catch((error) => {
  process.stderr.write(error.message + "\n");
  process.exitCode = 1;
  socket.close();
});
