// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

for (const scriptName of ["mfa_add_app.js", "sandbox_mfa_add_app.js"]) {
  test(`${scriptName} encodes DOM values and confines the barcode endpoint`, () => {
    const values = {
      label: "Team & <Admin>", email: "user+qa@example.test?view=full",
      secret: "fixture secret", digits: "6&mode=wide", period: "30#tail",
      barcode_uri: "/auth/mfa-app-barcode?size=200",
    };
    const oldImage = { nodeName: "IMG" };
    const link = { href: "" };
    const imageDiv = {
      childNodes: [null, oldImage], replacement: null,
      insertBefore(node, current) { assert.equal(current, oldImage); this.replacement = node; },
      removeChild(node) { assert.equal(node, oldImage); },
    };
    const elements = Object.fromEntries(Object.entries(values).map(([id, value]) => [id, { value }]));
    elements["mfa-no-camera-link"] = { childNodes: [null, link] };
    elements["mfa-qr-code-image"] = imageDiv;
    const context = {
      URL, encodeURIComponent, btoa, console,
      window: { location: { origin: "https://portal.example.test" } },
      document: {
        addEventListener() {}, getElementById(id) { return elements[id]; },
        createElement(name) {
          return { nodeName: name.toUpperCase(), attributes: {}, setAttribute(key, value) { this.attributes[key] = value; } };
        },
      },
    };
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, "../core/js", scriptName), "utf8"), context);
    context.updateQRCode();
    assert.match(link.href, /^otpauth:\/\/totp\/Team%20%26%20%3CAdmin%3E:user%2Bqa%40example\.test%3Fview%3Dfull\?/);
    assert.match(link.href, /digits=6%26mode%3Dwide&period=30%23tail$/);
    assert.equal(imageDiv.replacement.nodeName, "IMG");
    assert.match(imageDiv.replacement.attributes.src, /^https:\/\/portal\.example\.test\/auth\/mfa-app-barcode\//);
    assert.match(imageDiv.replacement.attributes.src, /\.png\?size=200$/);
    assert.equal(imageDiv.replacement.children, undefined);

    elements.barcode_uri.value = "https://elsewhere.example.test/barcode";
    imageDiv.replacement = null;
    link.href = "";
    context.updateQRCode();
    assert.equal(imageDiv.replacement, null);
  });
}
