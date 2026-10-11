// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
const [endpoint, origin, base] = process.argv.slice(2);
const tokens = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
const endpoints = {
  "bootstrap": {
    "method": "GET",
    "path": "/api/documents/bootstrap",
    "body": false
  },
  "key.fetch": {
    "method": "GET",
    "path": "/api/documents/keys/fetch",
    "body": false
  },
  "key.register": {
    "method": "PUT",
    "path": "/api/documents/keys/register",
    "body": true
  },
  "file.allocate": {
    "method": "POST",
    "path": "/api/documents/files/allocate",
    "body": true
  },
  "file.manifest": {
    "method": "PUT",
    "path": "/api/documents/file/{id}/manifest",
    "body": true
  },
  "chunk.put": {
    "method": "PUT",
    "path": "/api/documents/file/{id}/chunk/{idx}/put",
    "body": true
  },
  "file.commit": {
    "method": "POST",
    "path": "/api/documents/file/{id}/commit",
    "body": false
  },
  "file.list": {
    "method": "GET",
    "path": "/api/documents/files",
    "body": false
  },
  "file.fetch": {
    "method": "GET",
    "path": "/api/documents/file/{id}/fetch",
    "body": false
  },
  "chunk.fetch": {
    "method": "GET",
    "path": "/api/documents/file/{id}/chunk/{idx}/fetch",
    "body": false
  },
  "key.lookup": {
    "method": "GET",
    "path": "/api/documents/key/{user_id}/lookup",
    "body": false
  },
  "share.put": {
    "method": "PUT",
    "path": "/api/documents/file/{id}/share/{user_id}/put",
    "body": true
  },
  "share.list": {
    "method": "GET",
    "path": "/api/documents/file/{id}/share/list",
    "body": false
  },
  "share.delete": {
    "method": "DELETE",
    "path": "/api/documents/file/{id}/share/{user_id}/delete",
    "body": false
  },
  "file.delete": {
    "method": "DELETE",
    "path": "/api/documents/file/{id}/delete",
    "body": false
  },
  "key.reset": {
    "method": "POST",
    "path": "/api/documents/keys/reset",
    "body": true
  }
};
const socket = new WebSocket(endpoint);
let sequence = 0;
const pending = new Map();
const documentRequests = [];
socket.addEventListener("message", ({ data }) => {
  const result = JSON.parse(data), entry = pending.get(result.id);
  if (result.method === "Network.requestWillBeSent" && result.params.request.url.includes("/api/documents")) documentRequests.push(result.params.request);
  if (!entry) return;
  pending.delete(result.id); clearTimeout(entry.timer);
  if (result.error) entry.reject(new Error("Chrome command failed: " + result.error.message));
  else entry.resolve(result.result);
});
function command(method, params = {}, sessionId) {
  return new Promise((resolve, reject) => {
    const id = ++sequence;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error("Chrome command timed out")); }, 45000);
    pending.set(id, { resolve, reject, timer });
    socket.send(JSON.stringify({ id, method, params, sessionId }));
  });
}
async function evaluate(page, fn, args) {
  const result = await command("Runtime.evaluate", { expression: `(${fn.toString()})(${JSON.stringify(args)})`, awaitPromise: true, returnByValue: true }, page);
  if (result.exceptionDetails) throw new Error("Documents browser evaluation failed: " + (result.exceptionDetails.exception?.description || "unknown"));
  return result.result.value;
}
async function journey({ origin, base, tokens, endpoints }) {
  const c = await import(origin + "/_documents_test/crypto.mjs");
  const assert = (condition, step) => { if (!condition) throw new Error(step); };
  const reject = async (fn, step) => { let failed = false; try { await fn(); } catch { failed = true; } assert(failed, step); };
  const captured = [];
  async function request(token, operation, payload = {}, status = 200) {
    const endpoint = endpoints[operation];
    const fields = { ...payload };
    let path = endpoint.path.replace(/\{([^}]+)\}/g, (_, name) => {
      const value = fields[name]; delete fields[name]; return encodeURIComponent(value);
    });
    if (operation === "file.list" && fields.after !== undefined) {
      path += "?after=" + encodeURIComponent(fields.after); delete fields.after;
    }
    const headers = { Authorization: "Bearer " + token };
    const data = endpoint.body ? JSON.stringify(fields) : undefined;
    if (endpoint.body) headers["Content-Type"] = "application/json";
    else assert(Object.keys(fields).length === 0, "unexpected request body");
    const url = origin + base + path;
    captured.push(url + (data || ""));
    const response = await fetch(url, { method:endpoint.method, headers, body:data, credentials:"omit" });
    assert(response.status === status, operation + " HTTP " + response.status);
    assert(response.headers.get("Cache-Control") === "no-store", "response cache policy");
    assert(response.headers.get("Content-Type") === "application/json", "JSON response message");
    const message = await response.json();
    if (status !== 200) return message;
    assert(message && typeof message === "object" && !("operation" in message) && !("result" in message), "response must contain direct resource fields");
    if (["key.register", "key.reset", "file.manifest", "chunk.put", "file.commit", "share.put", "share.delete", "file.delete"].includes(operation)) assert(message.success === true && Object.keys(message).length === 1, "mutation confirmation");
    return message;
  }
  const a = await request(tokens.alice, "bootstrap"), b = await request(tokens.bob, "bootstrap");
  assert(a.user_id !== b.user_id, "identity isolation");
  const alice = await c.enroll(a), bob = await c.enroll(b);
  await request(tokens.alice, "key.register", {key:alice.registration});
  await request(tokens.bob, "key.register", {key:bob.registration});
  const fileBytes = new Uint8Array(c.chunkSize + 53);
  fileBytes.fill(91);
  const marker = "Private file body invisible to TLS inspection";
  fileBytes.set(new TextEncoder().encode(marker));
  const metadata = { name: "sensitive-budget-2026.txt", type: "text/plain", size: fileBytes.length };
  const file = await request(tokens.alice, "file.allocate", c.describeSize(fileBytes.length));
  const upload = await c.prepareUpload(a, file, alice.registration, metadata);
  await request(tokens.alice, "file.manifest", {id:file.id, manifest:upload.manifest});
  await request(tokens.bob, "file.fetch", {id:file.id}, 404);
  await request(tokens.alice, "file.commit", {id:file.id}, 409);
  const encrypted = [];
  for (let i = 0; i < file.chunks; i++) {
    const input = fileBytes.slice(i * c.chunkSize, (i + 1) * c.chunkSize);
    const work = upload.encryptChunk(i, input);
    input.fill(0); // A worker can release its plaintext buffer immediately.
    await reject(() => upload.encryptChunk(i, input), "concurrent nonce reuse accepted");
    encrypted[i] = await work;
    await request(tokens.alice, "chunk.put", {id:file.id, idx:i, ciphertext:c.encode(encrypted[i])});
    await request(tokens.alice, "chunk.put", {id:file.id, idx:i, ciphertext:c.encode(encrypted[i])});
  }
  upload.dispose();
  await request(tokens.alice, "file.commit", {id:file.id});
  const stored = await request(tokens.alice, "file.fetch", {id:file.id});
  const vault = await request(tokens.alice, "key.fetch");
  const ownerPrivate = await c.unlock(a, vault, alice.recoveryKey);
  const documentKey = await c.unwrapKey(a, stored, vault, ownerPrivate);
  assert((await c.decryptMetadata(a, stored, documentKey)).name === metadata.name, "owner metadata decrypt");
  const recipient = await request(tokens.alice, "key.lookup", {user_id:b.user_id});
  assert(!recipient.vault, "recipient vault disclosure");
  // The app verifies this fingerprint against the recipient's share code.
  assert(recipient.key_id === bob.registration.key_id, "recipient fingerprint");
  const wrappingInput = documentKey.slice(), recipientSnapshot = {...recipient};
  const wrapping = c.wrapKey(a, stored, recipientSnapshot, wrappingInput);
  wrappingInput.fill(0);
  recipientSnapshot.public_key = "changed after starting wrap";
  const envelope = await wrapping;
  await request(tokens.alice, "share.put", {id:file.id, user_id:b.user_id, envelope});
  const shared = await request(tokens.bob, "file.fetch", {id:file.id});
  const recipientPrivate = await c.unlock(b, bob.registration, bob.recoveryKey);
  const recipientKey = await c.unwrapKey(b, shared, bob.registration, recipientPrivate);
  const recovered = new Uint8Array(fileBytes.length);
  for (let i = 0; i < shared.chunks; i++) {
    const chunk = await request(tokens.bob, "chunk.fetch", {id:file.id, idx:i});
    const cipher = c.decode(chunk.ciphertext, 16, c.chunkSize+16);
    recovered.set(await c.decryptChunk(b, shared, recipientKey, i, cipher), i * c.chunkSize);
  }
  assert(recovered.every((v, i) => v === fileBytes[i]), "recipient download mismatch");
  await request(tokens.charlie, "file.fetch", {id:file.id}, 404);
  const corrupt = encrypted[0].slice(); corrupt[0] ^= 1;
  await reject(() => c.decryptChunk(b, shared, recipientKey, 0, corrupt), "tampered ciphertext accepted");
  await reject(() => c.unlock(b, bob.registration, alice.recoveryKey), "wrong recovery secret accepted");
  const foreign = { ...b, portal_id: c.encode(new Uint8Array(32).fill(77)) };
  await reject(() => c.unwrapKey(foreign, shared, bob.registration, recipientPrivate), "foreign portal envelope accepted");
  await request(tokens.alice, "share.delete", {id:file.id, user_id:b.user_id});
  await request(tokens.bob, "chunk.fetch", {id:file.id, idx:0}, 404);
  assert(captured.every(value => !value.includes(metadata.name) && !value.includes(marker) && !value.includes(alice.recoveryKey) && !value.includes(bob.recoveryKey) && !value.includes(c.encode(documentKey))), "plaintext or secret in API traffic");
  documentKey.fill(0); recipientKey.fill(0);
  return { passed: true, chunks: shared.chunks };
}
(async () => {
  await new Promise((resolve, reject) => { socket.addEventListener("open", resolve, { once: true }); socket.addEventListener("error", reject, { once: true }); });
  const target = await command("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await command("Target.attachToTarget", { targetId: target.targetId, flatten: true });
  await command("Page.enable", {}, sessionId);
  await command("Network.enable", {}, sessionId);
  const navigation = await command("Page.navigate", { url: origin + "/_documents_test/" }, sessionId);
  if (navigation.errorText) throw new Error("Documents fixture navigation failed");
  const deadline = Date.now() + 15000;
  let ready = false;
  while (Date.now() < deadline) {
    try { ready = await evaluate(sessionId, () => document.readyState === "complete" && document.title === "Documents browser fixture"); }
    catch (error) { if (!/Execution context was destroyed|Cannot find context/.test(error.message)) throw error; }
    if (ready) break;
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  if (!ready) throw new Error("Documents fixture did not load");
  // The Go fixture completed the real HTML login and supplied its existing
  // server-cached session. Verify the React cookie transport in Chrome without
  // exposing that HttpOnly cookie through application JavaScript.
  const installed = await command("Network.setCookie", { name: "AUTHP_ACCESS_TOKEN", value: tokens.alice, url: origin, path: "/", secure: true, httpOnly: true, sameSite: "Lax" }, sessionId);
  if (!installed.success) throw new Error("Documents browser cookie installation failed");
  const cookieStatus = await evaluate(sessionId, async ({ base }) => {
    if (document.cookie.includes("AUTHP_ACCESS_TOKEN")) throw new Error("Session cookie exposed to JavaScript");
    return (await fetch(base + "/api/documents/bootstrap", { method:"GET", credentials: "same-origin" })).status;
  }, { base });
  if (cookieStatus !== 200) throw new Error("Documents cookie transport HTTP " + cookieStatus);
  await command("Network.clearBrowserCookies", {}, sessionId);
  const result = await evaluate(sessionId, journey, { origin, base, tokens, endpoints });
  if (documentRequests.length < 20 || !documentRequests.every(r => {
    const url = new URL(r.url);
    const route = Object.values(endpoints).find(endpoint => {
      const pattern = endpoint.path.replace(/\{[^}]+\}/g, "[^/]+");
      return new RegExp("^"+base+pattern+"$").test(url.pathname);
    });
    if (!route || r.method !== route.method || url.origin !== origin || url.search) return false;
    if (!route.body) return !r.postData;
    const body = JSON.parse(r.postData);
    return !("operation" in body) && !("payload" in body) && !("id" in body) && !("idx" in body);
  })) throw new Error("Documents network requests used an unexpected method, resource path or body");
  process.stdout.write(JSON.stringify(result));
  socket.close();
})().catch(error => { process.stderr.write(error.message + "\n"); socket.close(); process.exitCode = 1; });
