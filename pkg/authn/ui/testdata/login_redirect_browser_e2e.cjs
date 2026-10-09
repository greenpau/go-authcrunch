// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
// The Go fixture owns Chrome and the real TLS portal; no DOM simulation is used.
const [endpoint, origin] = process.argv.slice(2);
const password = require("node:fs").readFileSync(0, "utf8");
const socket = new WebSocket(endpoint);
const pending = new Map();
let sequence = 0;
let stage = "connect";

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
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error("browser command timed out"));
    }, 15000);
    pending.set(id, { resolve, reject, timer });
    socket.send(JSON.stringify({ id, method, params, sessionId }));
  });
}

async function evaluate(sessionId, fn, args) {
  const result = await command("Runtime.evaluate", {
    expression: `(${fn.toString()})(${JSON.stringify(args)})`,
    awaitPromise: true, returnByValue: true,
  }, sessionId);
  if (result.exceptionDetails) throw new Error("browser evaluation failed");
  return result.result.value;
}

(async () => {
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", () => reject(new Error("browser socket failed")), { once: true });
  });
  try {
    const { browserContextId } = await command("Target.createBrowserContext");
    const { targetId } = await command("Target.createTarget", { url: "about:blank", browserContextId });
    const { sessionId } = await command("Target.attachToTarget", { targetId, flatten: true });
    await command("Page.enable", {}, sessionId);
    await command("Runtime.enable", {}, sessionId);
    // A fixture-owned page stays idle while fetch follows production redirects.
    // It cannot run the login page's cross-tab watcher during the assertions.
    const blank = origin + "/_test/blank";
    await command("Page.navigate", { url: blank }, sessionId);
    const deadline = Date.now() + 15000;
    while (!await evaluate(sessionId, (url) => document.readyState === "complete" && location.href === url, blank)) {
      if (Date.now() > deadline) throw new Error("fixture page did not load");
      await new Promise((resolve) => setTimeout(resolve, 50));
    }

    stage = "password login";
    await evaluate(sessionId, async ({ origin, password }) => {
      const headers = { "Content-Type": "application/x-www-form-urlencoded", Accept: "text/html" };
      const start = await fetch(origin + "/login", {
        method: "POST", headers, signal: AbortSignal.timeout(10000),
        body: new URLSearchParams({ username: "alice", realm: "local" }),
      });
      if (!start.ok || !new URL(start.url).pathname.startsWith("/sandbox/")) {
        throw new Error("login did not enter a sandbox");
      }
      await start.body?.cancel();
      const finish = await fetch(start.url, {
        method: "POST", headers, signal: AbortSignal.timeout(10000),
        body: new URLSearchParams({ secret: password }),
      });
      if (!finish.ok || finish.url !== origin + "/portal") throw new Error("password login did not reach portal");
      await finish.body?.cancel();
    }, { origin, password });

    stage = "redirect boundary";
    const cases = await evaluate(sessionId, async ({ origin }) => {
      const cases = [];
      for (const method of ["GET", "POST"]) {
        for (const input of [
          { name: "allowed", path: "/_test/allowed/safe", allowed: true },
          { name: "allowed_escaped_path_query", path: "/_test/allowed/a%2Fb?x=one%26two&x=three+four", allowed: true },
          { name: "outside", path: "/_test/outside" },
          { name: "literal_dot_segments", path: "/_test/allowed/../outside" },
          { name: "encoded_dot_segments", path: "/_test/allowed/%2e%2e/outside" },
          { name: "mixed_dot_segments", path: "/_test/allowed/.%2e/outside" },
        ]) {
          const target = origin + input.path;
          const response = await fetch(origin + "/login?redirect_url=" + encodeURIComponent(target), {
            method, headers: { Accept: "text/html" }, redirect: "follow", signal: AbortSignal.timeout(10000),
          });
          cases.push({
            name: method + "/" + input.name, target, actual: response.url,
            expected: input.allowed ? target : "", status: response.status,
          });
          await response.body?.cancel();
        }
      }
      return cases;
    }, { origin });
    // Exactly one JSON document, including on a future implementation where all
    // cases pass. Go reports each regression as a separate named subtest.
    process.stdout.write(JSON.stringify({ cases }));
  } finally {
    await command("Browser.close").catch(() => {});
    socket.close();
  }
})().catch((error) => {
  process.stderr.write(stage + ": " + error.message + "\n");
  process.exitCode = 1;
});
