// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
// A dependency-free CDP consumer. The Go fixture owns Chrome and the TLS portal.
const assert = require("node:assert/strict");
const [endpoint, encoded] = process.argv.slice(2);
const config = JSON.parse(encoded);
const fs = require("node:fs");
const path = require("node:path");
const password = require("node:fs").readFileSync(0, "utf8");
const socket = new WebSocket(endpoint);
const pending = new Map();
let sequence = 0;
let stage = "connect";

socket.addEventListener("message", ({ data }) => {
  const message = JSON.parse(data);
  if (!message.id) return;
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
  return sessionId;
}

async function navigate(tab, url, selector) {
  await evaluate(tab, () => { window.oidcTestNavigating = true; });
  const result = await command("Page.navigate", { url }, tab);
  if (result.errorText) throw new Error("navigation failed");
  await waitFor(() => evaluate(tab, (selector) => !window.oidcTestNavigating && document.readyState === "complete" && !!document.querySelector(selector), selector));
}
async function click(tab, selector) {
  const point = await evaluate(tab, (selector) => {
    const element = document.querySelector(selector);
    if (!element) throw new Error("missing action");
    element.scrollIntoView({ block: "center" });
    const box = element.getBoundingClientRect();
    return { x: box.x + box.width / 2, y: box.y + box.height / 2 };
  }, selector);
  await command("Input.dispatchMouseEvent", { type: "mousePressed", button: "left", clickCount: 1, ...point }, tab);
  await command("Input.dispatchMouseEvent", { type: "mouseReleased", button: "left", clickCount: 1, ...point }, tab);
}
async function screenshot(tab, name) {
  const { data } = await command("Page.captureScreenshot", { format: "png", captureBeyondViewport: true }, tab);
  fs.writeFileSync(path.join(config.screenshots, name + ".png"), Buffer.from(data, "base64"), { mode: 0o600 });
}
async function selectLocalRealm(tab) {
  const selector = await evaluate(tab, () => {
    const choices = document.getElementById("authenticators");
    if (!choices || !choices.getClientRects().length) return null;
    const links = [...choices.querySelectorAll("a")];
    const index = links.findIndex((link) => link.textContent.trim().toLowerCase() === "local");
    if (index < 0) throw new Error("local realm option missing");
    return `#authenticators > div:nth-child(${index + 1}) a`;
  });
  if (selector) await click(tab, selector);
}
async function checkQRCode(tab, capture) {
  const snapshot = () => evaluate(tab, () => ({
    panels: ["loginform", "authenticators"].map((id) => {
      const panel = document.getElementById(id);
      return panel ? panel.getClientRects().length > 0 : null;
    }),
    username: document.getElementById("username")?.value,
    realm: document.getElementById("realm")?.value,
  }));
  const before = await snapshot();
  const checkOpen = async () => {
    await evaluate(tab, async () => { await document.querySelector("#qrcode img").decode(); });
    const state = await evaluate(tab, () => {
      const qr = document.getElementById("qr"), image = qr.querySelector("img");
      const close = document.getElementById("close-qrcode");
      const imageBox = image.getBoundingClientRect(), closeBox = close.getBoundingClientRect();
      return {
        inCard: !!qr.closest(".app-container"), images: qr.querySelectorAll("img").length,
        loginHidden: ["loginform", "authenticators"].every((id) => !document.getElementById(id)?.getClientRects().length),
        expanded: document.getElementById("show-qrcode").getAttribute("aria-expanded"),
        closeLabel: close.textContent.trim(), focus: document.activeElement.id,
        gap: closeBox.top - imageBox.bottom, imageWidth: imageBox.width,
        square: Math.abs(imageBox.width - imageBox.height) < 1,
        imagePath: new URL(image.src).pathname,
      };
    });
    assert.equal(state.inCard, true, "QR code must replace the login items inside the card");
    assert.equal(state.loginHidden, true, "login items remain visible behind the QR code");
    assert.equal(state.images, 1, "reopening duplicates the QR image");
    assert.equal(state.expanded, "true");
    assert.equal(state.closeLabel, "Close QR Code");
    assert.equal(state.focus, "close-qrcode");
    assert.ok(state.gap >= 24 && state.imageWidth >= 180 && state.square, "QR code and close control have poor proportions");
    assert.equal(state.imagePath, new URL(config.issuer).pathname + "/qrcode/login.png");
    await checkLayout(tab);
  };
  const checkClosed = async (mobile = false) => {
    assert.deepEqual(await snapshot(), before, "closing QR code changes the previous login view or fields");
    assert.equal(await evaluate(tab, () => {
      return !document.getElementById("qr").getClientRects().length &&
        !document.querySelector("#qrcode img") &&
        document.getElementById("show-qrcode").getAttribute("aria-expanded") === "false";
    }), true, "QR view did not close completely");
    assert.equal(await evaluate(tab, (mobile) => {
      const focus = document.activeElement;
      return focus.getClientRects().length > 0 && (mobile ? !!focus.closest("#loginform, #authenticators") : focus.id === "show-qrcode");
    }, mobile), true, "focus was not restored to a visible login control");
  };
  await click(tab, "#show-qrcode");
  await checkOpen();
  await screenshot(tab, capture + "-desktop");
  await click(tab, "#qrcode img");
  await checkClosed();
  // The focused bookmark must work with a keyboard as well as a pointer.
  await command("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, text: "\r" }, tab);
  await command("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 }, tab);
  await checkOpen();
  await command("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, text: "\r" }, tab);
  await command("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 }, tab);
  await checkClosed();
  await click(tab, "#show-qrcode");
  await command("Emulation.setDeviceMetricsOverride", { width: 320, height: 800, deviceScaleFactor: 1, mobile: true }, tab);
  await checkOpen();
  await screenshot(tab, capture + "-mobile");
  await click(tab, "#close-qrcode");
  await checkClosed(true);
  await command("Emulation.setDeviceMetricsOverride", { width: 1280, height: 960, deviceScaleFactor: 1, mobile: false }, tab);
  await click(tab, "#show-qrcode");
  await command("Input.dispatchKeyEvent", { type: "keyDown", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 }, tab);
  await command("Input.dispatchKeyEvent", { type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 }, tab);
  await checkClosed();
}
async function checkRowInteraction(tab, selector, capture) {
  await command("Input.dispatchMouseEvent", { type: "mouseMoved", x: 0, y: 0 }, tab);
  const measure = () => evaluate(tab, (selector) => {
    const row = document.querySelector(selector);
    row.scrollIntoView({ block: "center" });
    const bounds = (node) => {
      const b = node.getBoundingClientRect();
      return { x: b.x, y: b.y, width: b.width, height: b.height };
    };
    // Normalize CSS Color 4 and rgb() values through the browser's color parser.
    const canvas = document.createElement("canvas");
    canvas.width = canvas.height = 1;
    const context = canvas.getContext("2d");
    const luminance = (paint) => {
      context.fillStyle = paint;
      context.fillRect(0, 0, 1, 1);
      const channels = [...context.getImageData(0, 0, 1, 1).data].slice(0, 3).map((channel) => {
        const value = channel / 255;
        return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
      });
      return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
    };
    return { row: bounds(row), icon: bounds(row.firstElementChild), label: bounds(row.lastElementChild),
      border: getComputedStyle(row).borderColor, borderWidth: getComputedStyle(row).borderWidth,
      borderLuminance: luminance(getComputedStyle(row).borderTopColor),
      backgroundLuminance: luminance(getComputedStyle(row.lastElementChild).backgroundColor),
      background: getComputedStyle(row.lastElementChild).backgroundColor };
  }, selector);
  const normal = await measure();
  for (const part of ["icon", "label"]) {
    const rect = normal[part];
    await command("Input.dispatchMouseEvent", { type: "mouseMoved", x: rect.x + rect.width / 2, y: rect.y + rect.height / 2 }, tab);
    const hovered = await measure();
    assert.ok(hovered.backgroundLuminance < normal.backgroundLuminance, "hover must darken the item background");
    assert.ok(normal.backgroundLuminance - hovered.backgroundLuminance < 0.2, "hover background change is too strong");
    assert.ok(hovered.borderLuminance < hovered.backgroundLuminance && hovered.backgroundLuminance - hovered.borderLuminance < 0.25, "hover border must be a subtle darker surface tone");
    assert.notEqual(hovered.background, normal.background, "hover does not highlight the whole row");
    assert.deepEqual(hovered.row, normal.row, "hover shifts the row layout");
    assert.equal(hovered.borderWidth, normal.borderWidth, "hover changes border thickness");
  }
  await screenshot(tab, capture + "-hover");
  await command("Input.dispatchMouseEvent", { type: "mouseMoved", x: 0, y: 0 }, tab);
  // QR dismissal leaves focus on the last control. Tab can move into Chrome's
  // toolbar; script focus() cannot reliably restore visible keyboard focus.
  // Traverse the real tab order, including a possible trip through the toolbar.
  await command("Page.bringToFront", {}, tab);
  const tabLimit = await evaluate(tab, () => document.querySelectorAll('a[href], button, input, select, textarea, [tabindex]').length + 2);
  let focused = false;
  for (let attempt = 0; attempt < tabLimit; attempt++) {
    await command("Input.dispatchKeyEvent", { type: "keyDown", key: "Tab", code: "Tab", windowsVirtualKeyCode: 9 }, tab);
    await command("Input.dispatchKeyEvent", { type: "keyUp", key: "Tab", code: "Tab", windowsVirtualKeyCode: 9 }, tab);
    focused = await evaluate(tab, (selector) => document.hasFocus() && document.activeElement === document.querySelector(selector).closest("a"), selector);
    if (focused) break;
  }
  assert.equal(focused, true, "row link is not reachable with keyboard Tab navigation");
  const focus = await evaluate(tab, (selector) => {
    const row = document.querySelector(selector), link = row.closest("a");
    const style = getComputedStyle(link);
    return { visible: link.matches(":focus-visible"), outlineStyle: style.outlineStyle,
      outlineWidth: parseFloat(style.outlineWidth), display: style.display,
      radius: style.borderRadius, rowRadius: getComputedStyle(row).borderRadius };
  }, selector);
  assert.equal(focus.visible, true, "row link lacks keyboard focus styling");
  assert.notEqual(focus.outlineStyle, "none", "row link has no keyboard focus outline");
  assert.ok(focus.outlineWidth > 0, "row link has an invisible keyboard focus outline");
  assert.equal(focus.display, "block", "keyboard focus does not enclose the whole row");
  assert.equal(focus.radius, focus.rowRadius, "keyboard focus does not follow the rounded row");
  await screenshot(tab, capture + "-focus");
}
async function checkLongRow(tab, selector) {
  const original = await evaluate(tab, (selector) => {
    const label = document.querySelector(selector);
    const original = label.textContent;
    label.textContent = "LongWorkspaceApplicationName".repeat(5);
    return original;
  }, selector);
  await checkLayout(tab);
  await evaluate(tab, ({ selector, original }) => { document.querySelector(selector).textContent = original; }, { selector, original });
}
async function checkResponsiveShell(tab, capture) {
  for (const [width, height] of [[768, 1024], [640, 960], [639, 960], [430, 932]]) {
    await command("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: width < 640 }, tab);
    await checkLayout(tab);
    if (width === 768 || width === 430) await screenshot(tab, capture + (width === 768 ? "-tablet" : "-phone"));
  }
  await command("Emulation.setDeviceMetricsOverride", { width: 1280, height: 960, deviceScaleFactor: 1, mobile: false }, tab);
}
async function checkProportions(tab) {
  const layout = await evaluate(tab, () => {
    const visible = (element) => element.getClientRects().length > 0;
    const box = (element) => {
      const { left, right, top, bottom, width, height } = element.getBoundingClientRect();
      return { left, right, top, bottom, width, height, centerY: (top + bottom) / 2 };
    };
    const logo = document.querySelector(".logo-img");
    const applicationList = document.querySelector(".app-link-list");
    return {
      viewport: innerWidth,
      logo: logo && box(logo),
      applications: applicationList && {
        intro: box(applicationList.closest(".app-container").querySelector("p.app-inp-lbl")),
        firstRow: box(applicationList.querySelector(".app-portal-btn-box")),
      },
      rows: [...document.querySelectorAll(".app-login-btn-box, .app-portal-btn-box")].filter(visible).map((row) => {
        const label = row.querySelector("span");
        const icon = row.firstElementChild;
        return { row: box(row), label: box(label), icon: box(icon), font: parseFloat(getComputedStyle(label).fontSize), overflow: getComputedStyle(row).overflow, iconRadius: getComputedStyle(icon).borderTopLeftRadius };
      }),
      fields: [...document.querySelectorAll("label[for]")].filter(visible).map((label) => {
        const input = document.getElementById(label.htmlFor);
        return { label: box(label), input: box(input), font: parseFloat(getComputedStyle(label).fontSize), lineHeight: parseFloat(getComputedStyle(label).lineHeight), align: getComputedStyle(label).textAlign };
      }),
      actions: [...document.querySelectorAll(".app-form-actions")].filter(visible).map((row) => ({
        row: box(row), buttons: [...row.querySelectorAll("button")].map((button) => ({
          ...box(button), font: parseFloat(getComputedStyle(button).fontSize),
          label: button.querySelector("span") && box(button.querySelector("span")),
          icon: button.querySelector("i, svg") && box(button.querySelector("i, svg")),
        })),
        input: box(row.closest("form").querySelector('input:not([type="hidden"])')),
      })),
    };
  });
  if (layout.logo) assert.ok(layout.logo.width >= 96 && layout.logo.height >= 96, "portal logo is too small");
  if (layout.applications) {
    const { intro, firstRow } = layout.applications;
    assert.ok(firstRow.top - intro.bottom >= 24, "application links are crowded against their introduction");
  }
  for (const { row, label, icon, font, overflow, iconRadius } of layout.rows) {
    assert.ok(font >= (layout.viewport >= 640 ? 24 : 22), "navigation label is too small");
    assert.ok(Math.abs(label.centerY - row.centerY) <= 1.5, "navigation text is not vertically centered");
    assert.ok(Math.abs(icon.centerY - row.centerY) <= 1.5, "navigation icon is not vertically centered");
    assert.ok(icon.width >= 56 && icon.width <= 72, "navigation icon column is disproportionate");
    assert.ok(label.left - icon.right >= 16, "navigation text has insufficient inset");
    assert.equal(overflow, "hidden", "row backgrounds escape the rounded outline");
    assert.equal(iconRadius, "0px", "nested corner radius leaves a seam");
  }
  for (const { label, input, font, lineHeight, align } of layout.fields) {
    assert.ok(font >= 18 && lineHeight >= font * 1.4, "field label typography is cramped");
    assert.equal(align, "left", "field label must align with its input");
    assert.ok(Math.abs(label.left - input.left) <= 1, "field label and input have different insets");
    assert.ok(input.top - label.bottom >= 16, "field label is crowded against its input");
  }
  for (const { row, buttons, input } of layout.actions) {
    assert.ok(Math.abs(row.left - input.left) <= 1 && Math.abs(row.right - input.right) <= 1, "actions do not align with their input");
    assert.ok(row.top - input.bottom >= 20, "actions are crowded against their input");
    for (const button of buttons) {
      assert.ok(button.height >= 56 && button.font >= 18, "action padding or typography is too small");
      for (const part of [button.label, button.icon].filter(Boolean)) {
        assert.ok(Math.abs(part.centerY - button.centerY) <= 1.5, "action text and icon are not centered");
      }
    }
  }
}
async function checkLayout(tab) {
  // Inspect resting colors; hover behavior is covered by checkRowInteraction.
  await command("Input.dispatchMouseEvent", { type: "mouseMoved", x: 0, y: 0 }, tab);
  await evaluate(tab, async () => { await document.fonts.ready; });
  const view = await evaluate(tab, () => {
    const card = document.querySelector(".oidc-card, .app-container");
    const buttons = [...document.querySelectorAll(".oidc-button, .app-btn-pri, .app-btn-sec")].filter((button) => button.getClientRects().length);
    const primary = buttons.find((button) => button.matches(".oidc-button-primary, .app-btn-pri"));
    const logo = document.querySelector(".oidc-brand img, .logo-img");
    const banner = document.querySelector(".brand-banner");
    return {
      viewport: innerWidth,
      overflow: document.documentElement.scrollWidth > innerWidth,
      radius: getComputedStyle(card).borderRadius,
      border: getComputedStyle(card).borderTopWidth,
      shadow: getComputedStyle(card).boxShadow,
      surface: getComputedStyle(card).backgroundColor,
      font: getComputedStyle(document.body).fontFamily,
      primaryColor: getComputedStyle(primary || card).backgroundColor,
      hasPrimary: !!primary,
      banner: getComputedStyle(banner).backgroundImage,
      background: getComputedStyle(document.body).backgroundImage,
      bannerHeight: banner.getBoundingClientRect().height,
      bannerArtworkHeight: parseFloat(getComputedStyle(document.body).getPropertyValue("--brand-banner-height")),
      card: { left: card.getBoundingClientRect().left, right: card.getBoundingClientRect().right },
      buttons: buttons.map((button) => ({ width: button.getBoundingClientRect().width, height: button.getBoundingClientRect().height, left: button.getBoundingClientRect().left, right: button.getBoundingClientRect().right })),
      inputs: [...document.querySelectorAll('input:not([type="hidden"]), select, textarea')].filter((input) => input.getClientRects().length).map((input) => ({ left: input.getBoundingClientRect().left, right: input.getBoundingClientRect().right })),
      stylesLoaded: [...document.querySelectorAll('link[rel="stylesheet"]')].every((link) => !!link.sheet),
      logoLoaded: !logo || (logo.complete && logo.naturalWidth > 0),
      violations: window.oidcTestViolations || [],
      errors: window.oidcTestErrors || 0,
    };
  });
  assert.equal(view.overflow, false, "page overflows the viewport");
  if (view.viewport < 640) {
    assert.equal(view.radius, "0px", "phone page retains the floating card corners");
    assert.equal(view.border, "0px", "phone page retains the floating card border");
    assert.equal(view.shadow, "none", "phone page retains the floating card shadow");
    assert.equal(view.surface, "rgba(0, 0, 0, 0)", "phone page retains the floating card surface");
    assert.equal(view.bannerHeight, 0, "phone page retains the card ribbon");
    assert.ok(view.card.left >= 20 && view.card.left <= 28 && view.viewport - view.card.right >= 20 && view.viewport - view.card.right <= 28, "phone content has excessive or missing side gutters");
  } else {
    assert.equal(view.radius, "20px", "tablet/desktop card corners changed");
    assert.equal(view.border, "1px", "tablet/desktop card border changed");
    assert.notEqual(view.shadow, "none", "tablet/desktop card shadow missing");
    assert.notEqual(view.surface, "rgba(0, 0, 0, 0)", "tablet/desktop card surface missing");
    assert.ok(view.bannerHeight > 0, "tablet/desktop brand banner is not visible");
  }
  assert.ok(view.font.includes("Roboto"), "portal typography missing");
  assert.equal(view.stylesLoaded, true, "stylesheet blocked or missing");
  assert.equal(view.logoLoaded, true, "portal logo missing");
  assert.deepEqual(view.violations, [], "page has CSP violations");
  assert.equal(view.errors, 0, "page has JavaScript errors");
  assert.ok(view.banner.includes(config.bannerName), "banner customization missing");
  assert.ok(view.background.includes(config.backgroundName), "background customization missing");
  if (view.viewport >= 640 && config.bannerName === "banner.svg") {
    assert.ok(view.bannerArtworkHeight <= 12 && view.bannerHeight <= 24, "default card accent occupies too much header space");
  }
  if (view.hasPrimary) assert.equal(view.primaryColor, config.primaryColor, "brand action color missing");
  assert.equal(await evaluate(tab, () => {
    const icon = document.querySelector('link[type="image/svg+xml"]');
    const banner = getComputedStyle(document.querySelector('.brand-banner')).backgroundImage.match(/url\(["']?(.*?)["']?\)/);
    const background = getComputedStyle(document.body).backgroundImage.match(/url\(["']?(.*?)["']?\)/);
    const icons = [...document.querySelectorAll('link[rel~="icon"]')];
    if (!icon || !banner || !background || icons.length !== 1 || icons[0] !== icon || !icon.href.endsWith('.svg')) return false;
    window.oidcTestImages = [icon.href, banner[1], background[1]].map((src) => {
      const image = new Image();
      image.src = src;
      return image;
    });
    return true;
  }), true, "brand icon or banner URL missing");
  // Poll image state through CDP, including when page JavaScript is disabled.
  await waitFor(() => evaluate(tab, () => window.oidcTestImages.every((image) => image.complete)));
  assert.equal(await evaluate(tab, () => window.oidcTestImages.every((image) => image.naturalWidth > 0)), true, "brand icon or banner failed to load");
  for (const button of view.buttons) {
    assert.ok(button.height >= (view.viewport < 640 ? 56 : 44) && button.width >= 44, "action has a small touch target");
    assert.ok(button.left >= view.card.left && button.right <= view.card.right, "action extends beyond its card");
  }
  for (const input of view.inputs) {
    assert.ok(input.left >= view.card.left && input.right <= view.card.right, "input extends beyond its card");
  }
  await checkProportions(tab);
  return view;
}
(async () => {
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", () => reject(new Error("browser socket failed")), { once: true });
  });
  let tab;
  try {
    const { browserContextId } = await command("Target.createBrowserContext");
    tab = await page(browserContextId);
    await command("Page.addScriptToEvaluateOnNewDocument", { source: `window.oidcTestViolations = []; window.oidcTestErrors = 0; addEventListener('securitypolicyviolation', (event) => window.oidcTestViolations.push(event.effectiveDirective)); addEventListener('error', () => window.oidcTestErrors++);` }, tab);
    await command("Emulation.setDeviceMetricsOverride", { width: 1280, height: 960, deviceScaleFactor: 1, mobile: false }, tab);
    stage = "real password login";
    await navigate(tab, config.authorize, 'input[name="username"]');
    if (await evaluate(tab, () => !!document.querySelector("#authenticators"))) {
      await checkLayout(tab);
      await screenshot(tab, "providers-desktop");
      await checkResponsiveShell(tab, "providers");
      await checkQRCode(tab, "qr-providers");
      await command("Emulation.setDeviceMetricsOverride", { width: 1700, height: 900, deviceScaleFactor: 1, mobile: false }, tab);
      await checkLayout(tab);
      await screenshot(tab, "providers-wide");
      await command("Emulation.setDeviceMetricsOverride", { width: 1280, height: 960, deviceScaleFactor: 1, mobile: false }, tab);
      await checkRowInteraction(tab, ".app-login-btn-box", "providers");
      await command("Emulation.setDeviceMetricsOverride", { width: 320, height: 800, deviceScaleFactor: 1, mobile: true }, tab);
      await checkLayout(tab);
      await checkLongRow(tab, ".app-login-btn-txt span");
      await screenshot(tab, "providers-mobile");
      await selectLocalRealm(tab);
      await click(tab, '#loginform button[type="button"]');
      assert.equal(await evaluate(tab, () => document.getElementById("loginform").classList.contains("hidden") && !document.getElementById("authenticators").classList.contains("hidden")), true, "Back does not restore realm selection");
      await selectLocalRealm(tab);
      await command("Emulation.setDeviceMetricsOverride", { width: 1280, height: 960, deviceScaleFactor: 1, mobile: false }, tab);
    }
    await checkLayout(tab);
    await screenshot(tab, "login-desktop");
    await checkResponsiveShell(tab, "login");
    await evaluate(tab, () => { document.getElementById("username").value = "saved-username"; });
    await checkQRCode(tab, "qr-login");
    await command("Emulation.setDeviceMetricsOverride", { width: 360, height: 800, deviceScaleFactor: 1, mobile: true }, tab);
    await checkLayout(tab);
    await screenshot(tab, "login-mobile");
    await evaluate(tab, () => { document.querySelector('input[name="username"]').value = "alice"; });
    await click(tab, '#loginform button[type="submit"]');
    await waitFor(() => evaluate(tab, () => !!document.querySelector('input[name="secret"]') && document.readyState === "complete"));
    await command("Emulation.setDeviceMetricsOverride", { width: 1280, height: 960, deviceScaleFactor: 1, mobile: false }, tab);
    await checkLayout(tab);
    await screenshot(tab, "password-desktop");
    await command("Emulation.setDeviceMetricsOverride", { width: 320, height: 800, deviceScaleFactor: 1, mobile: true }, tab);
    await checkLayout(tab);
    await command("Emulation.setDeviceMetricsOverride", { width: 360, height: 800, deviceScaleFactor: 1, mobile: true }, tab);
    await checkLayout(tab);
    await screenshot(tab, "password-mobile");
    await evaluate(tab, (password) => { document.querySelector('input[name="secret"]').value = password; }, password);
    await click(tab, 'button[name="submit"]');
    await waitFor(() => evaluate(tab, () => !!document.querySelector('button[value="allow"]') && document.readyState === "complete"));
    stage = "desktop consent";
    await command("Emulation.setDeviceMetricsOverride", { width: 1280, height: 960, deviceScaleFactor: 1, mobile: false }, tab);
    await checkLayout(tab);
    await screenshot(tab, "consent-desktop");
    await checkResponsiveShell(tab, "consent");
    stage = "keyboard focus";
    await command("Input.dispatchKeyEvent", { type: "keyDown", key: "Tab", code: "Tab", windowsVirtualKeyCode: 9 }, tab);
    await command("Input.dispatchKeyEvent", { type: "keyUp", key: "Tab", code: "Tab", windowsVirtualKeyCode: 9 }, tab);
    assert.equal(await evaluate(tab, () => document.activeElement.classList.contains("oidc-button") && getComputedStyle(document.activeElement).outlineStyle !== "none"), true, "keyboard focus is not visible");
    stage = "mobile consent";
    await command("Emulation.setDeviceMetricsOverride", { width: 320, height: 800, deviceScaleFactor: 1, mobile: true }, tab);
    await checkLayout(tab);
    await command("Emulation.setDeviceMetricsOverride", { width: 360, height: 800, deviceScaleFactor: 1, mobile: true }, tab);
    await checkLayout(tab);
    await screenshot(tab, "consent-mobile");
    stage = "allow consent";
    await click(tab, 'button[value="allow"]');
    const callback = () => evaluate(tab, (url) => location.href.startsWith(url) && document.title === "Application callback", config.callback);
    await waitFor(callback);
    stage = "deny consent";
    await navigate(tab, config.authorize, 'button[value="deny"]');
    await click(tab, 'button[value="deny"]');
    await waitFor(callback);
    stage = "automatic form post";
    const formPost = new URL(config.authorize);
    formPost.searchParams.set("response_mode", "form_post");
    await navigate(tab, formPost.href, 'button[value="allow"]');
    await click(tab, 'button[value="allow"]');
    await waitFor(callback);
    stage = "manual form post with JavaScript disabled";
    await command("Emulation.setScriptExecutionDisabled", { value: true }, tab);
    await navigate(tab, formPost.href, 'button[value="allow"]');
    await click(tab, 'button[value="allow"]');
    await waitFor(() => evaluate(tab, () => !!document.getElementById("response") && document.readyState === "complete"));
    await checkLayout(tab);
    await screenshot(tab, "continuation-mobile");
    await click(tab, '#response button[type="submit"]');
    await waitFor(callback);
    await command("Emulation.setScriptExecutionDisabled", { value: false }, tab);
    stage = "extended permissions";
    const extended = new URL(config.authorize);
    extended.searchParams.set("scope", "openid profile email address phone offline_access");
    extended.searchParams.set("claims", JSON.stringify({ id_token: { given_name: null, acr: null } }));
    await navigate(tab, extended.href, 'button[value="allow"]');
    await checkLayout(tab);
    assert.equal(await evaluate(tab, () => document.body.textContent.includes("Continued access") && document.body.textContent.includes("Given name") && !document.body.textContent.includes("id_token:")), true, "permission descriptions are incomplete");
    await screenshot(tab, "permissions-mobile");
    // Layout resilience to unusually long administrator and identity labels.
    await evaluate(tab, () => {
      document.querySelector(".oidc-client").textContent = "LongApplicationName".repeat(14);
      document.querySelector(".oidc-username").textContent = "long-username-".repeat(20);
      document.querySelector(".oidc-brand span").textContent = "LongPortalBrand".repeat(14);
    });
    await command("Emulation.setDeviceMetricsOverride", { width: 320, height: 800, deviceScaleFactor: 1, mobile: true }, tab);
    await checkLayout(tab);
    await command("Emulation.setDeviceMetricsOverride", { width: 360, height: 800, deviceScaleFactor: 1, mobile: true }, tab);
    stage = "browser error";
    await navigate(tab, config.issuer + "/oidc/authorize?client_id=invalid&redirect_uri=https://unregistered.invalid/", '[role="alert"]');
    await checkLayout(tab);
    assert.equal(await evaluate(tab, () => document.querySelector("form") === null && document.getElementById("oidc-title").textContent === "Unable to continue"), true);
    await screenshot(tab, "error-mobile");

    // Use a separate browser session so logout cannot revoke the OIDC codes
    // that Go independently redeems after this driver completes.
    stage = "portal branding and logout";
    const portalContext = await command("Target.createBrowserContext");
    tab = await page(portalContext.browserContextId);
    await command("Page.addScriptToEvaluateOnNewDocument", { source: `window.oidcTestViolations = []; window.oidcTestErrors = 0; addEventListener('securitypolicyviolation', (event) => window.oidcTestViolations.push(event.effectiveDirective)); addEventListener('error', () => window.oidcTestErrors++);` }, tab);
    await command("Emulation.setDeviceMetricsOverride", { width: 360, height: 800, deviceScaleFactor: 1, mobile: true }, tab);
    await navigate(tab, config.issuer + "/login", 'input[name="username"]');
    await selectLocalRealm(tab);
    await evaluate(tab, () => { document.querySelector('input[name="username"]').value = "alice"; });
    await click(tab, '#loginform button[type="submit"]');
    await waitFor(() => evaluate(tab, () => !!document.querySelector('input[name="secret"]') && document.readyState === "complete"));
    await evaluate(tab, (password) => { document.querySelector('input[name="secret"]').value = password; }, password);
    await click(tab, 'button[name="submit"]');
    await waitFor(() => evaluate(tab, () => !!document.querySelector('.app-portal-btn-box') && document.readyState === "complete"));
    await command("Emulation.setDeviceMetricsOverride", { width: 1280, height: 960, deviceScaleFactor: 1, mobile: false }, tab);
    await checkLayout(tab);
    await screenshot(tab, "portal-desktop");
    await checkResponsiveShell(tab, "portal");
    await checkRowInteraction(tab, ".app-portal-btn-box", "portal");
    await command("Emulation.setDeviceMetricsOverride", { width: 320, height: 800, deviceScaleFactor: 1, mobile: true }, tab);
    await checkLongRow(tab, ".app-portal-btn-txt span");
    await command("Emulation.setDeviceMetricsOverride", { width: 360, height: 800, deviceScaleFactor: 1, mobile: true }, tab);
    await checkLayout(tab);
    await screenshot(tab, "portal-mobile");
    await navigate(tab, config.issuer + "/whoami", "pre");
    await checkLayout(tab);
    await navigate(tab, config.issuer + "/logout", "#session-logout");
    await checkLayout(tab);
    await screenshot(tab, "logout-mobile");
    await click(tab, "#session-logout");
    await waitFor(() => evaluate(tab, () => !!document.querySelector('input[name="username"]') && document.readyState === "complete"));

    stage = "MFA passcode form";
    await selectLocalRealm(tab);
    await evaluate(tab, () => { document.querySelector('input[name="username"]').value = "mfauser"; });
    await click(tab, '#loginform button[type="submit"]');
    await waitFor(() => evaluate(tab, () => !!document.querySelector('input[name="secret"]') && document.readyState === "complete"));
    await evaluate(tab, (password) => { document.querySelector('input[name="secret"]').value = password; }, password);
    await click(tab, 'button[name="submit"]');
    await waitFor(() => evaluate(tab, () => !!document.querySelector('input[name="passcode"]') && document.readyState === "complete"));
    await command("Emulation.setDeviceMetricsOverride", { width: 320, height: 800, deviceScaleFactor: 1, mobile: true }, tab);
    await checkLayout(tab);
    await command("Emulation.setDeviceMetricsOverride", { width: 360, height: 800, deviceScaleFactor: 1, mobile: true }, tab);
    await checkLayout(tab);
    await screenshot(tab, "mfa-mobile");
    // Independent TOTP calculation from the disposable fixture's raw secret.
    const counter = Buffer.alloc(8);
    counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
    const mac = require("node:crypto").createHmac("sha1", "0123456789abcdef0123456789abcdef").update(counter).digest();
    const passcode = String((mac.readUInt32BE(mac[mac.length - 1] & 15) & 0x7fffffff) % 1000000).padStart(6, "0");
    await evaluate(tab, (passcode) => { document.querySelector('input[name="passcode"]').value = passcode; }, passcode);
    await click(tab, 'button[name="submit"]');
    await waitFor(() => evaluate(tab, () => !!document.querySelector('.app-portal-btn-box') && document.readyState === "complete"));
    await checkLayout(tab);
    process.stdout.write(JSON.stringify({ passed: true }));
  } catch (error) {
    if (tab) {
      const details = await evaluate(tab, () => ({ path: location.pathname, title: document.title, violations: window.oidcTestViolations || [], errors: window.oidcTestErrors || 0 })).catch(() => ({}));
      process.stderr.write(JSON.stringify(details) + "\n");
      await screenshot(tab, "failure").catch(() => {});
    }
    throw error;
  } finally {
    await command("Browser.close").catch(() => {});
    socket.close();
  }
})().catch((error) => { process.stderr.write(stage + ": " + error.message + "\n"); process.exitCode = 1; });
