// Copyright 2026 Paul Greenberg greenpau@outlook.com
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const directory = new URL("../../openapi/", import.meta.url);
const source = await readFile(new URL("scalar.js", directory), "utf8");
const html = await readFile(new URL("index.html", directory), "utf8");
const spec = { openapi: "3.1.1", tags: [{ name: "Login" }, { name: "Admin" }], paths: {} };
const storageKey = "authcrunch.openapi.portal-server";
const portalSpec = () => ({ ...spec, servers: [{ url: "{origin}{portalBasePath}", variables: {
  origin: { default: "https://auth.myfiosgateway.com:8443" }, portalBasePath: { default: "/auth" },
} }] });

function bootstrap({ protocol = "https:", response = spec, status = 200, renderError, noAPI = false,
  stored, storageError = false, portalField = true, renderErrorAfter = Infinity } = {}) {
  const elements = [];
  const rendered = [];
  const fetched = [];
  const storage = new Map(stored === undefined ? [] : [[storageKey, stored]]);
  let destroyed = 0;
  let script;
  const element = (tag) => ({
    tag,
    children: [],
    events: {},
    append(...children) { this.children.push(...children); },
    replaceChildren(...children) { this.children = children; },
    addEventListener(name, callback) { this.events[name] = callback; },
  });
  const app = element("main");
  const context = {
    URL, Date, Map, structuredClone, console: { error() {} },
    window: { location: { protocol, href: `${protocol}//docs.example.test/nested/reference/` }, localStorage: {
      getItem(key) { if (storageError) throw new Error("blocked"); return storage.get(key) ?? null; },
      setItem(key, value) { if (storageError) throw new Error("full"); storage.set(key, value); },
    } },
    document: {
      getElementById: (id) => id === "app" ? app : portalField && id.endsWith("-portalBasePath") ? {} : null,
      createElement(tag) { const node = element(tag); elements.push(node); return node; },
      head: { append(node) { script = node; } },
    },
    fetch: async (url, options) => {
      fetched.push({ url, options });
      return { ok: status === 200, status, json: async () => response };
    },
    Scalar: noAPI ? {} : { createApiReference: async (selector, config) => {
      if (renderError || rendered.length >= renderErrorAfter) throw new Error("render failed");
      rendered.push({ selector, config });
      return { getConfiguration: () => config, destroy: () => { destroyed++; } };
    } },
  };
  vm.runInNewContext(source, context);
  return { app, elements, rendered, fetched, script, storage, get destroyed() { return destroyed; } };
}

test("shell cache key matches the bootstrap bytes", () => {
  const digest = createHash("sha256").update(source).digest("hex").slice(0, 12);
  assert.ok(html.includes(`./scalar.js?v=${digest}`));
  assert.ok(html.includes('id="app"'));
});

test("loads pinned viewer and fresh content beneath a nested mount", async () => {
  const env = bootstrap();
  assert.equal(env.script.src, "https://cdn.jsdelivr.net/npm/@scalar/api-reference@1.67.0/dist/browser/standalone.js");
  assert.match(env.script.integrity, /^sha384-[A-Za-z0-9+/]{64}$/);
  assert.equal(env.script.crossOrigin, "anonymous");
  assert.equal(env.script.referrerPolicy, "no-referrer");
  await env.script.events.load();
  assert.equal(env.fetched.length, 1);
  assert.equal(env.fetched[0].url.pathname, "/nested/reference/generated/openapi.json");
  assert.ok(env.fetched[0].url.searchParams.get("v"));
  assert.equal(env.fetched[0].options.cache, "no-store");
  assert.equal(env.fetched[0].options.credentials, "omit");
  const { selector, config } = env.rendered[0];
  assert.equal(selector, "#app");
  assert.equal(config.content, spec);
  assert.equal(config.url, undefined);
  assert.equal(config.proxyUrl, undefined);
  assert.equal(config.persistAuth, false);
  assert.equal(config.telemetry, false);
  assert.equal(config.agent.disabled, true);
  assert.equal(config.mcp.disabled, true);
  assert.equal(config.showDeveloperTools, "never");
  assert.deepEqual(JSON.parse(JSON.stringify(config.defaultHttpClient)), { targetKey: "shell", clientKey: "curl" });
  assert.deepEqual(JSON.parse(JSON.stringify(config.hiddenClients)), {
    c: true, clojure: true, csharp: true, dart: true, fsharp: true,
    go: true, http: true, java: true, js: true, julia: true, kotlin: true,
    node: true, objc: true, ocaml: true, php: true,
    powershell: false, python: ["aiohttp", "httpx_async", "httpx_sync"],
    r: true, ruby: true, rust: true, shell: ["httpie", "wget"], swift: true,
  });
  assert.ok(config.tagsSorter({ name: "Login" }, { name: "Admin" }) < 0);
});

for (const [name, options] of Object.entries({
  "missing JSON": { status: 404 },
  "malformed spec": { response: {} },
  "missing Scalar API": { noAPI: true },
  "rejected rendering": { renderError: true },
})) {
  test(`${name} produces a visible error`, async () => {
    const env = bootstrap(options);
    await env.script.events.load();
    assert.equal(env.app.children[0].className, "scalar-load-error");
    assert.equal(env.app.children[0].children[0].textContent, "API reference unavailable");
    assert.equal(env.rendered.length, 0);
  });
}

test("CDN/SRI failure and file URLs fail visibly", () => {
  const env = bootstrap();
  env.script.events.error(new Error("blocked"));
  assert.equal(env.app.children[0].className, "scalar-load-error");
  const file = bootstrap({ protocol: "file:" });
  assert.equal(file.script, undefined);
  assert.equal(file.fetched.length, 0);
  assert.ok(file.app.children[0].children[1].textContent.includes("make serve-openapi"));
});

test("restores only portal server values, including an empty mount", async () => {
  const response = portalSpec();
  const env = bootstrap({ response, stored: JSON.stringify({ origin: "http://localhost:9443", portalBasePath: "", token: "never-copy" }) });
  await env.script.events.load();
  assert.equal(response.servers[0].variables.origin.default, "http://localhost:9443");
  assert.equal(response.servers[0].variables.portalBasePath.default, "");
  assert.equal(response.servers[0].url, "{origin}");
  assert.equal(response.servers[0].variables.token, undefined);
  assert.equal(env.rendered[0].config.persistAuth, false);
});

test("saves portal edits immediately and restores them on the next load", async () => {
  const env = bootstrap({ response: portalSpec() });
  await env.script.events.load();
  const change = (id, value, event = "input") => env.app.events[event]({ target: { tagName: "INPUT", id, value } });
  change("scalar-refs-0-11-origin", "https://login.example.test:9443");
  change("scalar-refs-0-11-portalBasePath", "/portal");
  assert.deepEqual(JSON.parse(env.storage.get(storageKey)), { origin: "https://login.example.test:9443", portalBasePath: "/portal" });
  const reload = bootstrap({ response: portalSpec(), stored: env.storage.get(storageKey) });
  await reload.script.events.load();
  assert.equal(reload.rendered[0].config.content.servers[0].variables.portalBasePath.default, "/portal");
  change("scalar-refs-0-11-portalBasePath", "", "change");
  change("scalar-refs-0-11-authorization", "never-save");
  change("scalar-refs-0-11-origin", "https://user:password@example.test");
  assert.deepEqual(JSON.parse(env.storage.get(storageKey)), { origin: "https://login.example.test:9443", portalBasePath: "" });
});

test("malformed, unsafe and unavailable storage does not stop rendering", async () => {
  for (const stored of ["{", "null", "[]", "42", JSON.stringify({ origin: 42, portalBasePath: false }),
    JSON.stringify({ origin: "javascript:alert(1)", portalBasePath: "//other.test" }),
    JSON.stringify({ origin: "https://user:password@example.test", portalBasePath: "/path?token=secret" }),
    JSON.stringify({ origin: "https://example.test/path", portalBasePath: "/path#fragment" }),
    JSON.stringify({ origin: "https://example.test\\path", portalBasePath: "/a b" }),
    JSON.stringify({ origin: "https://[", portalBasePath: "x".repeat(2049) })]) {
    const response = portalSpec();
    const env = bootstrap({ response, stored });
    await env.script.events.load();
    assert.equal(env.rendered.length, 1, stored);
    assert.deepEqual(response, portalSpec(), stored);
  }
  const env = bootstrap({ response: portalSpec(), storageError: true });
  await env.script.events.load();
  env.app.events.input({ target: { tagName: "INPUT", id: "scalar-refs-0-11-origin", value: "https://example.test" } });
  assert.equal(env.rendered.length, 1);
  assert.equal(env.storage.size, 0);
});

test("unrelated origin fields without a portal mount cannot overwrite deployment settings", async () => {
  const env = bootstrap({ response: portalSpec(), portalField: false });
  await env.script.events.load();
  env.app.events.input({ target: { tagName: "INPUT", id: "scalar-refs-0-11-origin", value: "https://app.example.test" } });
  env.app.events.input({ target: { tagName: "TEXTAREA", id: "scalar-refs-0-11-portalBasePath", value: "/app" } });
  assert.equal(env.storage.size, 0);
});

test("committing root/non-root mounts refreshes the template without resetting other settings", async () => {
  const env = bootstrap({ response: portalSpec() });
  await env.script.events.load();
  const edit = (value, type) => env.app.events[type]({ type, target: {
    tagName: "INPUT", id: "scalar-refs-0-11-portalBasePath", value,
  } });
  await edit("", "input");
  assert.equal(env.rendered.length, 1, "typing must not remount the focused field");
  await edit("", "change");
  assert.equal(env.rendered[1].config.content.servers[0].url, "{origin}");
  await edit("/", "input");
  await edit("/portal", "change");
  assert.equal(env.rendered[2].config.content.servers[0].url, "{origin}{portalBasePath}");
  assert.equal(env.rendered[2].config.content.servers[0].variables.portalBasePath.default, "/portal");
  assert.equal(env.rendered[2].config.persistAuth, false);
  await edit("/other", "change");
  assert.equal(env.rendered.length, 3, "ordinary edits use Scalar's native variable handling");
  assert.equal(env.destroyed, 2);
});

test("a template refresh failure is visible and retains the saved mount", async () => {
  const env = bootstrap({ response: portalSpec(), renderErrorAfter: 1 });
  await env.script.events.load();
  await env.app.events.change({ type: "change", target: {
    tagName: "INPUT", id: "scalar-refs-0-11-portalBasePath", value: "",
  } });
  assert.equal(env.app.children[0].className, "scalar-load-error");
  assert.equal(JSON.parse(env.storage.get(storageKey)).portalBasePath, "");
});
