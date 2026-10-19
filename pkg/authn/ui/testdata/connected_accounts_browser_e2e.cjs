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
let latestStatus = 0;

socket.addEventListener("message", ({ data }) => {
  const message = JSON.parse(data);
  if (!message.id) { if(message.method==="Network.responseReceived"&&message.params.type==="Document")latestStatus=message.params.response.status;return; }
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
  await command("Network.enable", {}, sessionId);
  return sessionId;
}

async function navigate(session, path) {
  await command("Page.navigate", {url: origin + path}, session);
}
(async () => {
 await new Promise((resolve,reject) => {socket.addEventListener("open",resolve,{once:true});socket.addEventListener("error",()=>reject(new Error("browser socket failed")),{once:true});});
 try {
  const {browserContextId}=await command("Target.createBrowserContext");
  const tab=await page(browserContextId);
  stage="external sign-in";
  await navigate(tab,"/auth/oauth2/upstream");
  await waitFor(()=>evaluate(tab,()=>location.pathname==="/auth/portal"));
  stage="connection page";
  await navigate(tab,"/auth/connected-accounts");
  await waitFor(()=>evaluate(tab,()=>Boolean(document.querySelector('input[name="action"][value="start"]'))));
  for(const width of [1280,375]) {
   await command("Emulation.setDeviceMetricsOverride",{width,height:900,deviceScaleFactor:1,mobile:width<500},tab);
   assert.equal(await evaluate(tab,()=>document.documentElement.scrollWidth<=innerWidth),true,"connection page overflows viewport");
   const shot=await command("Page.captureScreenshot",{format:"png"},tab);
   const fs=require("node:fs");fs.mkdirSync(config.screenshots,{recursive:true});fs.writeFileSync(require("node:path").join(config.screenshots,`connected-accounts-${width}.png`),Buffer.from(shot.data,"base64"));
  }
  stage="fresh local sign-in";
  await evaluate(tab,()=>document.querySelector("form").requestSubmit());
  await waitFor(()=>evaluate(tab,()=>location.pathname==="/auth/login"&&Boolean(document.querySelector('input[name="username"]'))));
  assert.equal(await evaluate(tab,()=>new URL(location.href).searchParams.get("fresh")),"1");
  await evaluate(tab,()=>{document.querySelector('input[name="username"]').value="keymember";const realm=document.querySelector('[name="realm"]');if(realm)realm.value="local";document.querySelector('input[name="username"]').form.requestSubmit();});
  stage="local password";
  await waitFor(()=>evaluate(tab,()=>Boolean(document.querySelector('input[name="secret"]'))));
  await evaluate(tab,(secret)=>{const input=document.querySelector('input[name="secret"]');input.value=secret;input.form.requestSubmit();},password);
  stage="confirmation";
  await waitFor(()=>evaluate(tab,()=>Boolean(document.querySelector('button[name="action"][value="connect"]'))));
  assert.equal(await evaluate(tab,()=>document.body.textContent.includes("keymember")),true);
  await evaluate(tab,()=>document.querySelector('button[name="action"][value="connect"]').click());
  await waitFor(()=>evaluate(tab,()=>Boolean(document.querySelector('[role="status"]'))));
  assert.equal(await evaluate(tab,()=>document.querySelector('[role="status"]').textContent.includes("Account connected")),true);
  stage="connected identity login";
  await navigate(tab,"/auth/oauth2/upstream");
  await waitFor(()=>evaluate(tab,()=>location.pathname==="/auth/portal"));
  await navigate(tab,"/auth/connected-accounts");
  await waitFor(()=>evaluate(tab,()=>Boolean(document.querySelector("li"))));
  assert.equal(await evaluate(tab,()=>document.body.textContent.includes("keymember")&&document.querySelector("li").textContent.includes("upstream")),true);
  process.stdout.write(JSON.stringify({passed:true}));
 } finally {await command("Browser.close").catch(()=>{});socket.close();}
})().catch(error=>{process.stderr.write(stage+" (HTTP "+latestStatus+"): "+error.message+"\n");process.exitCode=1;});
