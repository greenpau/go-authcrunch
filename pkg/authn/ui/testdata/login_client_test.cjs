// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const source = fs.readFileSync(path.join(__dirname, "../core/js/login.js"), "utf8");

function environment(view) {
  const elements = new Map();
  const listeners = new Map();
  const document = {
    activeElement: null,
    getElementById: (id) => elements.get(id) || null,
    createElement: (tag) => element(tag),
    addEventListener: (name, callback) => listeners.set(name, callback),
  };
  function element(id, classes = []) {
    const names = new Set(classes);
    const node = {
      id, children: [], attributes: {}, value: "",
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
  const context = { document, console };
  vm.runInNewContext(source, context);
  return { ...context, elements, listeners };
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
