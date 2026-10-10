// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const source = fs.readFileSync(path.join(__dirname, "../core/js/login.js"), "utf8");

function environment(view, page = {}) {
  const elements = new Map();
  const listeners = new Map();
  const document = {
    activeElement: null,
    currentScript: page.dataset ? { dataset: page.dataset } : null,
    visibilityState: page.visibility || "visible",
    getElementById: (id) => elements.get(id) || null,
    createElement: (tag) => element(tag),
    addEventListener: (name, callback) => listeners.set(name, callback),
  };
  function element(id, classes = []) {
    const names = new Set(classes);
    const node = {
      id, dataset: {}, children: [], attributes: {}, value: "",
      classList: { add: (name) => names.add(name), remove: (name) => names.delete(name), contains: (name) => names.has(name) },
      setAttribute(name, value) { this.attributes[name] = value; },
      appendChild(child) { this.children.push(child); },
      replaceChildren(...children) { this.children = children; },
      getClientRects() { return names.has("hidden") ? [] : [{}]; },
      querySelector() { return document.getElementById(id === "loginform" ? "username" : "provider"); },
      focus() { document.activeElement = node; },
    };
    elements.set(id, node);
    return node;
  }
  element("qr", ["hidden"]);
  element("qrcode");
  element("bookmarks", ["hidden", "sm:block"]);
  element("show-qrcode").setAttribute("aria-expanded", "false");
  element("close-qrcode");
  if (view !== "external") {
    element("loginform", view === "providers" ? ["hidden"] : []);
    element("username").value = "saved-user";
    element("realm").value = "engineering";
  }
  if (view !== "single") {
    element("authenticators", view === "selected" ? ["hidden"] : []);
    element("provider");
  }
  const windowListeners = new Map();
  const intervals = [];
  const replaced = [];
  const context = {
    document, console,
    fetch: page.fetch,
    setInterval: (callback, delay) => intervals.push({ callback, delay }),
    window: {
      addEventListener: (name, callback) => windowListeners.set(name, callback),
      location: { replace: (target) => replaced.push(target) },
    },
  };
  vm.runInNewContext(source, context);
  return { ...context, elements, listeners, windowListeners, intervals, replaced };
}

for (const view of ["providers", "selected", "single", "external"]) {
  test(`QR view restores ${view} login state without clearing fields`, () => {
    const { showQRCode, hideQRCode, document, elements } = environment(view);
    const panels = ["loginform", "authenticators"].map((id) => elements.get(id)).filter(Boolean);
    const hidden = panels.map((panel) => panel.classList.contains("hidden"));
    showQRCode("/tenant/auth/qrcode/login.png");
    assert.ok(panels.every((panel) => panel.classList.contains("hidden")), "login items remain visible");
    assert.equal(elements.get("qr").classList.contains("hidden"), false);
    assert.equal(elements.get("show-qrcode").attributes["aria-expanded"], "true");
    assert.equal(document.activeElement.id, "close-qrcode");
    const image = elements.get("qrcode").children[0];
    assert.equal(image.src, "/tenant/auth/qrcode/login.png");
    assert.ok(image.alt);
    // A repeated open must not duplicate images or overwrite the saved view.
    showQRCode("/tenant/auth/qrcode/login.png");
    assert.equal(elements.get("qrcode").children.length, 1);
    hideQRCode();
    hideQRCode();
    assert.deepEqual(panels.map((panel) => panel.classList.contains("hidden")), hidden);
    assert.equal(elements.get("qr").classList.contains("hidden"), true);
    assert.equal(elements.get("qrcode").children.length, 0);
    assert.equal(elements.get("show-qrcode").attributes["aria-expanded"], "false");
    assert.equal(document.activeElement.id, "show-qrcode");
    if (view !== "external") {
      assert.equal(elements.get("username").value, "saved-user");
      assert.equal(elements.get("realm").value, "engineering");
    }
    showQRCode("/tenant/auth/qrcode/login.png");
    hideQRCode();
    assert.deepEqual(panels.map((panel) => panel.classList.contains("hidden")), hidden);
  });
}

test("closing after a narrow resize focuses the restored login control", () => {
  for (const view of ["providers", "single"]) {
    const { showQRCode, hideQRCode, document, elements } = environment(view);
    showQRCode("/auth/qrcode/login.png");
    elements.get("show-qrcode").getClientRects = () => [];
    hideQRCode();
    assert.equal(document.activeElement.id, view === "single" ? "username" : "provider");
  }
});

test("Escape closes the QR view and is otherwise inert", () => {
  const { showQRCode, document, elements, listeners } = environment("single");
  elements.get("username").focus();
  const keydown = listeners.get("keydown");
  keydown({ key: "Escape" });
  assert.equal(document.activeElement.id, "username");
  showQRCode("/auth/qrcode/login.png");
  keydown({ key: "Tab" });
  assert.equal(elements.get("qr").classList.contains("hidden"), false);
  keydown({ key: "Escape" });
  assert.equal(elements.get("qr").classList.contains("hidden"), true);
  assert.equal(document.activeElement.id, "show-qrcode");
});

test("QR image uses the portal's localized accessible name", () => {
  const { showQRCode, elements } = environment("single");
  elements.get("qrcode").dataset.qrAlt = "رمز QR";
  showQRCode("/auth/qrcode/login.png");
  assert.equal(elements.get("qrcode").children[0].alt, "رمز QR");
});

// A tab left on the login page while the user signs in from another tab must
// leave for its own destination once the browser is signed in, without a second
// login. It asks the portal only while the tab is in view.
// status is the probe's answer: 200 signed in, 401 signed out, and 403 signed
// in with an account this portal does not admit.
function signInElsewhere(status, visibility = "visible") {
  const probes = [];
  const fetch = async (url, options) => {
    probes.push({ url, options });
    return { ok: status === 200, status };
  };
  return { probes, ...environment("single", {
    dataset: { whoami: "/auth/whoami?probe=login", returnUrl: "https://app.example.test/tab/b?x=1" },
    fetch, visibility,
  }) };
}

const settle = () => new Promise((resolve) => setImmediate(resolve));

test("a signed-in browser sends the waiting tab to its own destination", async () => {
  for (const trigger of ["visibilitychange", "focus", "interval"]) {
    const env = signInElsewhere(200);
    if (trigger === "visibilitychange") env.listeners.get("visibilitychange")();
    if (trigger === "focus") env.windowListeners.get("focus")();
    if (trigger === "interval") env.intervals[0].callback();
    await settle();
    assert.deepEqual(env.replaced, ["https://app.example.test/tab/b?x=1"], trigger);
    assert.equal(env.probes.length, 1, trigger);
    assert.equal(env.probes[0].url, "/auth/whoami?probe=login");
    assert.equal(env.probes[0].options.headers.Accept, "application/json");
    // A followed redirect would turn a signed-out answer into a 200 login page.
    assert.equal(env.probes[0].options.redirect, "manual");
    assert.equal(env.probes[0].options.cache, "no-store");
    assert.equal(env.probes[0].options.credentials, "same-origin");
  }
});

test("a signed-out browser stays on the login page", async () => {
  const env = signInElsewhere(401);
  env.windowListeners.get("focus")();
  // A check still waiting for its answer absorbs the next one.
  env.intervals[0].callback();
  await settle();
  env.intervals[0].callback();
  await settle();
  assert.equal(env.probes.length, 2);
  assert.deepEqual(env.replaced, []);
});

test("a tab out of view does not ask the portal", async () => {
  const env = signInElsewhere(200, "hidden");
  env.intervals[0].callback();
  env.listeners.get("visibilitychange")();
  await settle();
  assert.equal(env.probes.length, 0);
  assert.deepEqual(env.replaced, []);
  assert.ok(env.intervals[0].delay >= 2000, "polls no faster than every two seconds");
});

test("an account this portal does not admit stops the watch", async () => {
  const env = signInElsewhere(403);
  env.intervals[0].callback();
  await settle();
  env.windowListeners.get("focus")();
  env.listeners.get("visibilitychange")();
  env.intervals[0].callback();
  await settle();
  assert.equal(env.probes.length, 1);
  assert.deepEqual(env.replaced, []);
});

test("a login page without a destination does not watch", () => {
  const env = environment("single", { fetch: async () => ({ ok: true }) });
  assert.equal(env.intervals.length, 0);
  assert.equal(env.listeners.has("visibilitychange"), false);
});

test("realm registration navigation keeps the page destination", () => {
  const destination = "https://app.test/return?x=one%26two";
  for (const value of [destination, ""]) {
    const e = environment("providers", { dataset: { loginDestination: value, returnUrl: "/auth/portal?redirect_url=" } });
    for (const id of ["user_actions", "user_register_link", "forgot_username_link", "contact_support_link"]) {
      const node = e.document.createElement(id);
      const anchor = { href: "" };
      node.getElementsByTagName = () => [anchor];
    }
    e.showLoginForm("staff", "yes", "no", "no", "/auth/");
    const link = new URL(e.elements.get("user_register_link").getElementsByTagName("a")[0].href, "https://portal.test");
    assert.equal(link.pathname, "/auth/register/staff");
    assert.equal(link.searchParams.get("redirect_url"), value);
    assert.equal(e.elements.get("realm").value, "staff");
  }
});
