// Copyright 2026 Paul Greenberg greenpau@outlook.com
// SPDX-License-Identifier: Apache-2.0

// Exercise the real pinned Scalar bundle in Chrome through the public server.
// The CDN response is served from a SHA-384-verified cache; no npm install is used.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { once } from 'node:events';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const repository = fileURLToPath(new URL('../../../', import.meta.url));
const work = path.join(repository, 'tmp/openapi');
const bootstrap = await readFile(path.join(repository, 'assets/openapi/scalar.js'), 'utf8');
const bundleURL = bootstrap.match(/const BUNDLE_URL = "([^"]+)"/)[1];
const integrity = bootstrap.match(/sha384-[A-Za-z0-9+/=]+/)[0];
const digest = (data) => `sha384-${createHash('sha384').update(data).digest('base64')}`;

async function browserPath() {
  const candidates = process.env.AUTHCRUNCH_TEST_BROWSER
    ? [process.env.AUTHCRUNCH_TEST_BROWSER]
    : ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
      ...['google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser']
        .flatMap((name) => (process.env.PATH ?? '').split(path.delimiter).map((dir) => path.join(dir, name)))];
  for (const candidate of candidates) {
    try { await access(candidate); return candidate; } catch { /* next candidate */ }
  }
  throw new Error('Chrome is required; set AUTHCRUNCH_TEST_BROWSER to its executable');
}

async function eventually(fn, label) {
  const deadline = Date.now() + 45000;
  while (Date.now() < deadline) {
    const result = await fn();
    if (result) return result;
    await delay(100);
  }
  throw new Error(`Timed out: ${label}`);
}

function start(t, command, args) {
  const child = spawn(command, args, { cwd: repository, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  let failure;
  child.stdout.on('data', (data) => { output += data; });
  child.stderr.on('data', (data) => { output += data; });
  child.on('error', (error) => { failure = error; });
  t.after(async () => {
    if (!child.pid) return;
    const exited = once(child, 'exit').catch(() => {});
    try { process.kill(-child.pid, 'SIGTERM'); } catch { return; }
    await Promise.race([exited, delay(3000)]);
    try { process.kill(-child.pid, 'SIGKILL'); } catch { /* already exited */ }
  });
  return () => {
    if (failure) throw failure;
    if (child.exitCode !== null) throw new Error(`${command} stopped: ${output.slice(-2000)}`);
    return output;
  };
}

function protocol(ws) {
  let id = 0;
  const pending = new Map();
  const listeners = new Map();
  ws.addEventListener('message', ({ data }) => {
    const message = JSON.parse(data);
    if (message.id) {
      const request = pending.get(message.id);
      if (!request) return;
      clearTimeout(request.timer);
      pending.delete(message.id);
      if (message.error) request.reject(new Error(message.error.message));
      else request.resolve(message.result);
    } else {
      for (const listener of listeners.get(message.method) ?? []) listener(message);
    }
  });
  ws.addEventListener('close', () => {
    for (const request of pending.values()) {
      clearTimeout(request.timer);
      request.reject(new Error('Browser protocol closed'));
    }
    pending.clear();
  });
  return {
    on(method, listener) {
      listeners.set(method, [...(listeners.get(method) ?? []), listener]);
    },
    send(method, params = {}, sessionId) {
      return new Promise((resolve, reject) => {
        const requestID = ++id;
        const timer = setTimeout(() => { pending.delete(requestID); reject(new Error(`Browser timeout: ${method}`)); }, 15000);
        pending.set(requestID, { resolve, reject, timer });
        ws.send(JSON.stringify({ id: requestID, method, params, sessionId }));
      });
    },
  };
}

test('real Scalar renders every operation under the shared mount and restores deployment settings', { timeout: 180000 }, async (t) => {
  await mkdir(work, { recursive: true });
  const cache = path.join(work, 'scalar-bundle.js');
  let bundle;
  try { bundle = await readFile(cache); } catch { /* initial download */ }
  if (!bundle || digest(bundle) !== integrity) {
    const response = await fetch(bundleURL, { signal: AbortSignal.timeout(20000) });
    assert.equal(response.ok, true, 'pinned Scalar download failed');
    bundle = Buffer.from(await response.arrayBuffer());
    assert.equal(digest(bundle), integrity, 'pinned Scalar integrity mismatch');
    await writeFile(cache, bundle);
  }
  assert.equal(digest(bundle), integrity);
  const profile = await mkdtemp(path.join(work, 'chrome-'));
  // Cleanup hooks run in registration order: stop children before profile removal.
  const serverOutput = start(t, 'go', ['run', '-mod=readonly', './cmd/openapi', '-listen', '127.0.0.1:0', 'serve']);
  const address = await eventually(() => serverOutput().match(/OpenAPI reference: (http:\/\/[^ ]+)/)?.[1], 'reference server');
  const chromeOutput = start(t, await browserPath(), ['--headless=new', '--disable-gpu', '--no-first-run',
    '--no-default-browser-check', '--disable-background-networking', '--remote-debugging-port=0',
    `--user-data-dir=${profile}`, 'about:blank']);
  t.after(() => rm(profile, { recursive: true, force: true }));
  const endpoint = await eventually(async () => {
    chromeOutput();
    try {
      const [port, pathname] = (await readFile(path.join(profile, 'DevToolsActivePort'), 'utf8')).trim().split('\n');
      return `ws://127.0.0.1:${port}${pathname}`;
    } catch { return null; }
  }, 'Chrome DevTools');
  const ws = new WebSocket(endpoint);
  await once(ws, 'open');
  t.after(() => ws.close());
  const cdp = protocol(ws);
  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  const send = (method, params = {}) => cdp.send(method, params, sessionId);
  const errors = [];
  let intercepted = 0;
  cdp.on('Runtime.exceptionThrown', (message) => errors.push(message.params.exceptionDetails.text));
  cdp.on('Fetch.requestPaused', (message) => {
    if (message.sessionId !== sessionId) return;
    intercepted++;
    send('Fetch.fulfillRequest', { requestId: message.params.requestId, responseCode: 200,
      responseHeaders: [{ name: 'Content-Type', value: 'text/javascript' }, { name: 'Access-Control-Allow-Origin', value: '*' }],
      body: bundle.toString('base64') }).catch((error) => errors.push(error.message));
  });
  await send('Page.enable');
  await send('Runtime.enable');
  await send('Fetch.enable', { patterns: [{ urlPattern: bundleURL, requestStage: 'Request' }] });
  await send('Emulation.setDeviceMetricsOverride', { width: 1440, height: 1000, deviceScaleFactor: 1, mobile: false });
  await send('Page.navigate', { url: address });
  const evaluate = async (expression) => {
    const result = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    if (result.exceptionDetails) throw new Error(result.exceptionDetails.text);
    return result.result.value;
  };
  // Scalar renders multiple expanded models and scrolls after navigation.
  // Text elsewhere in the document does not prove the captured viewport shows it.
  const centerDescription = async (phrase) => {
    await eventually(() => evaluate(`(async () => {
      const node = Array.from(document.querySelectorAll('p')).find(n => n.textContent.includes(${JSON.stringify(phrase)}));
      if (!node) return false;
      node.scrollIntoView({behavior: 'instant', block: 'center'});
      await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
      const rect = node.getBoundingClientRect();
      return rect.height > 0 && rect.top >= 0 && rect.bottom <= innerHeight;
    })()`), `visible description: ${phrase}`);
  };
  await eventually(async () => evaluate(`document.querySelector('.scalar-api-reference') && document.body.innerText.includes('Open a realm registration form')`), 'Scalar operations');
  assert.equal(intercepted, 1, 'the verified pinned viewer must be loaded');
  assert.equal(await evaluate(`!!document.querySelector('.scalar-load-error')`), false);
  const visible = await evaluate('document.body.innerText');
  const version = (await readFile(path.join(repository, 'VERSION'), 'utf8')).trim();
  assert.ok(visible.split('\n').includes(`v${version}`), 'reference version differs from VERSION');
  assert.equal(await evaluate(`document.querySelector('input[id$="-origin"]').value`), 'https://auth.myfiosgateway.com:8443');
  assert.equal(await evaluate(`document.querySelector('[data-testid="client-picker"]').innerText.trim()`), 'Shell Curl');
  await eventually(() => evaluate(`/curl ['"]?https:\\/\\/auth\\.myfiosgateway\\.com:8443\\/auth\\//.test(document.body.innerText)`), 'default curl snippet');
  const clients = [
    ['powershell/webrequest', /Invoke-WebRequest\s+-/],
    ['powershell/restmethod', /Invoke-RestMethod\s+-/],
    ['python/python3', /http\.client\.HTTPSConnection\("auth\.myfiosgateway\.com:8443"\)/],
    ['python/requests', /requests\.(get|post)\(/],
    ['shell/curl', /curl ['"]?https:\/\/auth\.myfiosgateway\.com:8443\/auth\//],
  ];
  for (const [client, snippet] of clients) {
    await evaluate(`document.querySelector('[data-testid="client-picker"]').click()`);
    await eventually(() => evaluate(`document.querySelectorAll('[role="listbox"] [role="option"]').length === 5`), 'five allowed clients');
    const options = await evaluate(`Array.from(document.querySelectorAll('[role="listbox"] [role="option"]'), n => n.id.split('-').at(-1))`);
    assert.deepEqual(options.sort(), clients.map(([id]) => id).sort(), 'unexpected client menu');
    if (client === clients[0][0]) {
      assert.equal(await evaluate(`document.querySelector('[role="option"][aria-selected="true"]').innerText.trim()`), 'Curl');
    }
    await evaluate(`document.querySelector('[role="option"][id$="-${client}"]').click()`);
    await eventually(async () => snippet.test(await evaluate('document.body.innerText')), `${client} generated snippet`);
  }
  for (const label of ['AuthCrunch', 'Authentication Portal', 'Cross-Device Sign-In', 'External Authentication', 'Administration', 'OpenID Connect', 'Schemas']) {
    assert.ok(visible.includes(label), `missing reference section: ${label}`);
  }
  const groups = await evaluate(`Array.from(document.querySelectorAll('button[aria-expanded]'), n => n.textContent.trim())`);
  for (const obsolete of ['Authentication', 'Portal sessions', 'Browser', 'Cross-device', 'Federation', 'Direct OAuth']) {
    assert.ok(!groups.includes('Open Group - ' + obsolete) && !groups.includes('Close Group - ' + obsolete), `obsolete navigation group: ${obsolete}`);
  }
  assert.ok(await evaluate(`document.querySelectorAll('a[href*="tag/"]').length > 5`), 'operation navigation missing');
  assert.equal(await evaluate(`document.documentElement.scrollWidth <= innerWidth`), true, 'desktop reference overflows');
  const document = await (await fetch(`${address}generated/openapi.json`)).json();
  const workflowTags = ['Registration', 'Authentication Portal', 'External Authentication',
    'Cross-Device Sign-In', 'Profile', 'Discovery', 'OpenID Connect', 'Administration', 'System'];
  assert.deepEqual(document.tags.map(tag => tag.name), workflowTags, 'categories must follow the account and integration workflows');
  const operations = Object.entries(document.paths).flatMap(([url, item]) => Object.entries(item)
    .filter(([method]) => ['get', 'post', 'head', 'put', 'patch', 'delete', 'options', 'trace'].includes(method))
    .map(([method, operation]) => ({ url, method, ...operation })));
  const normalizeLabel = label => label.toLowerCase().trim().replace(/\s+/gu, ' ');
  assert.equal(new Set(operations.map(op => normalizeLabel(op.summary))).size, operations.length,
    'operation labels must be unique across the reference');
  const expandNavigation = () => evaluate(`Array.from(document.querySelectorAll('button[aria-expanded="false"]'))
    .filter(n => n.textContent.trim().startsWith('Open Group - ') && !n.textContent.includes('Schemas'))
    .forEach(n => n.click())`);
  await expandNavigation();
  const navigationGroups = await evaluate(`Array.from(document.querySelectorAll('button[aria-expanded]'),
    n => n.textContent.trim().replace(/^(Open|Close) Group - /, '')).filter(name => ${JSON.stringify(workflowTags)}.includes(name))`);
  assert.deepEqual(navigationGroups, workflowTags, 'Scalar reordered the workflow categories');
  const expectedNavigation = workflowTags.flatMap(tag => operations.filter(op => op.tags[0] === tag)
    .map(op => `${op.method.toUpperCase()}${op.url}`));
  const navigationOperations = await evaluate(`Array.from(document.querySelectorAll('a[href*="tag/"]'),
    n => decodeURIComponent(new URL(n.href).hash).match(/\\/(GET|POST|HEAD|PUT|PATCH|DELETE|OPTIONS|TRACE)(\\/.*)$/)?.slice(1).join(''))
    .filter(Boolean)`);
  assert.deepEqual(navigationOperations, expectedNavigation, 'Scalar reordered operations within a workflow');
  // Check the labels users actually see, independently of each link's method
  // and path; URLs alone cannot expose two indistinguishable menu entries.
  const renderedLabels = await evaluate(`Array.from(document.querySelectorAll('a[href*="tag/"]'))
    .filter(n => /\\/(GET|POST|HEAD|PUT|PATCH|DELETE|OPTIONS|TRACE)\\//.test(decodeURIComponent(new URL(n.href).hash)))
    .map(n => {
      // Scalar appends an HTTP method badge, including screen-reader text.
      // Exclude that badge so it cannot disguise duplicate summary labels.
      const label = n.cloneNode(true);
      const badge = label.querySelector('.sidebar-heading-type');
      if (!badge) throw new Error('Scalar operation link is missing its method badge');
      badge.remove();
      return label.textContent.trim().replace(/\\s+/gu, ' ');
    })`);
  const expectedLabels = workflowTags.flatMap(tag => operations.filter(op => op.tags[0] === tag).map(op => op.summary));
  assert.deepEqual(renderedLabels, expectedLabels, 'Scalar navigation must display the authored operation labels');
  assert.equal(new Set(renderedLabels.map(normalizeLabel)).size, operations.length, 'duplicate visible navigation labels');
  const workflowCapture = await send('Page.captureScreenshot', { format: 'png' });
  await writeFile(path.join(work, 'viewer-workflow-order.png'), Buffer.from(workflowCapture.data, 'base64'));
  const navigateOperation = async (operation) => {
    await expandNavigation();
    await eventually(() => evaluate(`(() => {
      const link = [...document.querySelectorAll('a[href*="tag/"]')].find(n =>
        n.textContent.includes(${JSON.stringify(operation.summary)}) &&
        decodeURIComponent(new URL(n.href).hash).endsWith(${JSON.stringify('/' + operation.method.toUpperCase() + operation.url)}));
      if (!link) return false;
      link.click(); return true;
    })()`), `navigation to ${operation.operationId}`);
  };
  const curlURLs = () => evaluate(`Array.from(document.querySelectorAll('pre'), n => n.textContent)
    .map(text => text.match(/^curl\\s+['"]?(https?:\\/\\/[^\\s'"]+)/)?.[1]).filter(Boolean)`);
  const checkOperationURL = async (operation, origin, mount) => {
    await navigateOperation(operation);
    const escape = (value) => value.replace(/[.*+?^$()|[\]\\]/g, '\\$&');
    const suffix = operation.url.split(/(\{[^}]+\})/).map(part => part.startsWith('{') ? '[^/\\s?]+?' : escape(part)).join('');
    const expected = new RegExp(`^${escape(origin + mount)}${suffix}(?:\\?|$)`);
    await eventually(async () => (await curlURLs()).some(url => expected.test(url)), `mounted URL for ${operation.method} ${operation.url}`);
    for (const url of await curlURLs()) {
      assert.ok(url.startsWith(origin + mount + '/') || url === origin + mount,
        `request snippet escaped the selected mount: ${url}`);
    }
  };
  // Visit every operation, including previously collapsed tags. A valid JSON
  // document and a login-only browser sample missed the OAuth server overrides.
  for (const operation of operations) {
    await checkOperationURL(operation, 'https://auth.myfiosgateway.com:8443', '/auth');
  }
  await navigateOperation(operations.find(op => op.operationId === 'whoami'));
  await eventually(() => evaluate(`(() => {
    const response = Array.from(document.querySelectorAll('button[aria-expanded="false"]'))
      .filter(n => /^200\\s+Authenticated\\./.test(n.textContent.trim())).at(-1);
    if (!response) return false;
    response.click(); return true;
  })()`), 'open claims response schema');
  await eventually(() => evaluate(`document.body.innerText.includes('Expiration time of the access token') &&
    document.body.innerText.includes('1970-01-01T00:00:00Z') &&
    document.body.innerText.includes('Time the access token was issued')`), 'claim meanings and time units');
  await centerDescription('Expiration time of the access token');
  const claimsScreenshot = await send('Page.captureScreenshot', { format: 'png' });
  await writeFile(path.join(work, 'viewer-claims.png'), Buffer.from(claimsScreenshot.data, 'base64'));
  await evaluate(`Array.from(document.querySelectorAll('button[aria-expanded="false"]'))
    .find(n => n.textContent.trim() === 'Open Group - Schemas')?.click()`);
  await eventually(() => evaluate(`(() => {
    const link = Array.from(document.querySelectorAll('a')).find(n => n.textContent.trim() === 'ProfileTOTPEnrollment');
    if (!link) return false;
    link.click(); return true;
  })()`), 'profile enrollment response model navigation');
  await eventually(() => evaluate(`document.body.innerText.includes('Standard padded Base64 of the UTF-8 otpauth URI')`), 'profile response encoding description');
  await centerDescription('Standard padded Base64 of the UTF-8 otpauth URI');
  const profileScreenshot = await send('Page.captureScreenshot', { format: 'png' });
  await writeFile(path.join(work, 'viewer-profile.png'), Buffer.from(profileScreenshot.data, 'base64'));
  await eventually(() => evaluate(`(() => {
    const link = Array.from(document.querySelectorAll('a')).find(n => n.textContent.trim() === 'LoginWebAuthnOptions');
    if (!link) return false;
    link.click(); return true;
  })()`), 'WebAuthn login options navigation');
  await eventually(() => evaluate(`(() => {
    const toggle = Array.from(document.querySelectorAll('button[aria-expanded="false"]'))
      .find(n => n.textContent.trim() === '{} credentials');
    if (!toggle) return false;
    toggle.click(); return true;
  })()`), 'expand WebAuthn credential properties');
  try {
    await eventually(() => evaluate(`document.body.innerText.includes('Browser request timeout in milliseconds') &&
      document.body.innerText.includes('Stored comma-separated transports string') &&
      document.body.innerText.includes('64 random ASCII letters/digits')`), 'login options units and encodings');
  } catch (error) {
    await writeFile(path.join(work, 'viewer-challenges-rendered.txt'), await evaluate('document.body.innerText'));
    await writeFile(path.join(work, 'viewer-challenges-controls.json'), JSON.stringify(await evaluate(`Array.from(document.querySelectorAll('button'), n => ({text: n.textContent, label: n.getAttribute('aria-label'), expanded: n.getAttribute('aria-expanded')}))`), null, 2));
    throw error;
  }
  await centerDescription('Stored comma-separated transports string');
  const challengesScreenshot = await send('Page.captureScreenshot', { format: 'png' });
  await writeFile(path.join(work, 'viewer-challenges.png'), Buffer.from(challengesScreenshot.data, 'base64'));
  for (const [name, phrases, artifact] of [
    ['OIDCRequestObjectHeader', ['forbidden even when null', 'none requires an empty signature segment', 'Request-supplied key material is forbidden'], 'viewer-request-header.png'],
    ['OIDCRequestObjectPayload', ['with fractional seconds accepted', 'neither validates its JSON type', 'exponent notation'], 'viewer-request-object.png'],
    ['SAMLCallback', ['Portal-generated one-use SAML transaction identifier', 'consumes valid browser-bound state before'], 'viewer-federation.png'],
    ['LocalAccountEmail', ['not ownership verification', 'single-label domain', 'Case is preserved'], 'viewer-account-email.png'],
    ['LocalRoleInput', ['Unicode whitespace trimming', 'Duplicate normalized', 'Empty components are accepted'], 'viewer-account-role.png'],
    ['AdminUserMutation', ['not a rollback guarantee', 'Generated password', 'HTTP 200'], 'viewer-admin-mutations.png'],
    ['OIDCRefreshScope', ['Omit this field to preserve', 'whitespace-only value fails', 'already established refresh family'], 'viewer-refresh-scope.png'],
    ['OIDCRevocationRequest', ['pre-rotation access token', 'spent refresh credential', 'not independent grants'], 'viewer-revocation.png'],
    ['JWKUnsignedInteger', ['minimal big-endian bytes', 'redundant final bits', 'not decimal strings'], 'viewer-key-integer.png'],
    ['PublicJWK', ['No private d.', 'Canonical output lengths', 'SHA-256 public-key thumbprint'], 'viewer-public-key.png'],
    ['PrivateJWK', ['secret signing material', '32-byte seed', 'fixed-width private scalar'], 'viewer-private-key.png'],
    ['OIDCJWKS', ['first configured key signs', 'Dedicated OIDC ID-token', 'configuration-derived kid'], 'viewer-oidc-keys.png'],
    ['LoginRequest', ['does not require EOF', 'last non-null', 'case-insensitive matching'], 'viewer-login-decoder.png'],
    ['LoginBlankField', ['Unicode whitespace trimming', 'U+FEFF'], 'viewer-login-blank.png'],
    ['BcryptHash', ['22-character salt', '31-character checksum', 'logarithmic work factor'], 'viewer-bcrypt-hash.png'],
    ['Argon2Hash', ['Memory multiplied by passes', 'canonical unpadded standard Base64', '65536 KiB'], 'viewer-argon2-hash.png'],
    ['IdentityPasswordRecord', ['Password purpose', 'logarithmic work factor', 'Argon2id v19'], 'viewer-password-record.png'],
    ['ProfileAPIKeyRecord', ['First 24 ASCII letters/digits', 'cost 10', 'stored bcrypt hash'], 'viewer-profile-api-key.png'],
    ['ProfileAddUserAppMultiFactorAuthenticator', ['No passcode is required or verified', 'Unknown fields such as algorithm or passcode', 'fresh login evidence'], 'viewer-totp-enrollment.png'],
    ['ProfileTestUserAppTokenPasscode', ['current and two preceding', 'does not consume', 'surrounding whitespace fails'], 'viewer-totp-diagnostic.png'],
    ['ProfilePublicKeyRecord', ['without zero padding', 'does not round-trip', 'inline SSH comment'], 'viewer-profile-public-key.png'],
    ['ProfileDeleteUserSshKey', ['owned ID without checking', 'never selects another'], 'viewer-profile-key-delete.png'],
    ['ProfileAddUserGpgKey', ['signing-capable primary key', 'does not enforce public-only packets', 'can skip unsupported'], 'viewer-profile-openpgp-input.png'],
  ]) {
    await eventually(() => evaluate(`(() => {
      const link = Array.from(document.querySelectorAll('a')).find(n => n.textContent.trim() === ${JSON.stringify(name)});
      if (!link) return false;
      link.click(); return true;
    })()`), `${name} navigation`);
    try {
      await eventually(() => evaluate(`${JSON.stringify(phrases)}.every(text => document.body.innerText.includes(text))`), `${name} field semantics`);
    } catch (error) {
      await writeFile(path.join(work, `${name}-rendered.txt`), await evaluate('document.body.innerText'));
      const failed = await send('Page.captureScreenshot', { format: 'png' });
      await writeFile(path.join(work, artifact), Buffer.from(failed.data, 'base64'));
      throw error;
    }
    await centerDescription(phrases[0]);
    const capture = await send('Page.captureScreenshot', { format: 'png' });
    await writeFile(path.join(work, artifact), Buffer.from(capture.data, 'base64'));
    if (name === 'ProfilePublicKeyRecord') {
      assert.ok(await evaluate(`(() => {
        const picker = Array.from(document.querySelectorAll('button'))
          .findLast(n => n.textContent.includes('SSH RSA record'));
        if (!picker) return false;
        picker.click(); return true;
      })()`), 'public-key category picker');
      await eventually(() => evaluate(`(() => {
        const option = Array.from(document.querySelectorAll('[role="option"]'))
          .find(n => n.textContent.includes('OpenPGP record'));
        if (!option) return false;
        option.click(); return true;
      })()`), 'OpenPGP record selection');
      await eventually(() => evaluate(`document.body.innerText.includes('Full primary-key fingerprint in lowercase hexadecimal') &&
        document.body.innerText.includes('not a full fingerprint')`), 'OpenPGP ID and fingerprint semantics');
      await centerDescription('Full primary-key fingerprint in lowercase hexadecimal');
      const pgp = await send('Page.captureScreenshot', { format: 'png' });
      await writeFile(path.join(work, 'viewer-profile-openpgp.png'), Buffer.from(pgp.data, 'base64'));
    }
  }
  const oauthOperations = operations.filter(op => ['directOAuthCallback', 'directOAuthLogout', 'externalOAuthLogin', 'externalOAuthCallback', 'externalOAuthLogout'].includes(op.operationId));
  assert.equal(oauthOperations.length, 5);
  await checkOperationURL(operations.find(op => op.operationId === 'directOAuthCallback'), 'https://auth.myfiosgateway.com:8443', '/auth');
  const screenshot = await send('Page.captureScreenshot', { format: 'png' });
  await writeFile(path.join(work, 'viewer.png'), Buffer.from(screenshot.data, 'base64'));
  const destination = await evaluate(`(() => {
    const link = [...document.querySelectorAll('a[href*="tag/"]')]
      .find((node) => node.textContent.includes('Authenticate with a challenge or API key'));
    if (!link) return null;
    const hash = new URL(link.href).hash;
    link.click();
    return hash;
  })()`);
  assert.ok(destination, 'login operation link missing');
  await eventually(async () => evaluate(`location.hash === ${JSON.stringify(destination)}`), 'operation navigation');
  await send('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
  try {
    await eventually(async () => evaluate('innerWidth === 390'), 'mobile viewport');
  } catch (error) {
    const layout = await evaluate(`({ width: innerWidth, scrollWidth: document.documentElement.scrollWidth,
      viewport: document.querySelector('meta[name="viewport"]')?.content,
      overflowing: [...document.querySelectorAll('body *')].filter(n => {
        const r = n.getBoundingClientRect();
        if (r.right <= 390 || r.width === 0) return false;
        for (let p = n.parentElement; p; p = p.parentElement) {
          if (['auto', 'scroll', 'hidden', 'clip'].includes(getComputedStyle(p).overflowX)
            && p.getBoundingClientRect().right <= 390) return false;
        }
        return true;
      }).map(n => { const r = n.getBoundingClientRect(); return { tag: n.tagName, class: n.className,
        left: r.left, right: r.right, width: r.width, text: n.children.length ? '' : n.textContent.slice(0, 80) }; }).slice(-60) })`);
    await writeFile(path.join(work, 'viewer-mobile-layout.json'), JSON.stringify(layout, null, 2));
    throw error;
  } finally {
    const mobileScreenshot = await send('Page.captureScreenshot', { format: 'png' });
    await writeFile(path.join(work, 'viewer-mobile.png'), Buffer.from(mobileScreenshot.data, 'base64'));
  }
  assert.equal(await evaluate('document.documentElement.scrollWidth <= innerWidth'), true, 'mobile reference overflows');

  await send('Emulation.setDeviceMetricsOverride', { width: 1440, height: 1000, deviceScaleFactor: 1, mobile: false });
  const storageKey = 'authcrunch.openapi.portal-server';
  const editVariable = async (name, value) => {
    await evaluate(`(() => { const input = document.querySelector('input[id$="-${name}"]'); input.focus(); input.select(); })()`);
    if (value) await send('Input.insertText', { text: value });
    else {
      await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Backspace', code: 'Backspace', windowsVirtualKeyCode: 8 });
      await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Backspace', code: 'Backspace', windowsVirtualKeyCode: 8 });
    }
    await eventually(() => evaluate(`JSON.parse(localStorage.getItem(${JSON.stringify(storageKey)}))?.[${JSON.stringify(name)}] === ${JSON.stringify(value)}`), `${name} saved`);
  };
  const reload = async (origin, mount) => {
    const previousLoads = intercepted;
    await send('Page.reload', { ignoreCache: true });
    // A fresh pinned-bundle request proves this is the new document, not the
    // old DOM still visible while Chrome begins its reload.
    await eventually(() => intercepted > previousLoads, 'fresh viewer after reload');
    await eventually(() => evaluate(`document.querySelector('input[id$="-origin"]')?.value === ${JSON.stringify(origin)} &&
      document.querySelector('input[id$="-portalBasePath"]')?.value === ${JSON.stringify(mount)}`), 'restored server variables');
  };
  await editVariable('origin', 'https://login.example.test:9443');
  await editVariable('portalBasePath', '/team/portal');
  assert.deepEqual(await evaluate(`JSON.parse(localStorage.getItem(${JSON.stringify(storageKey)}))`), {
    origin: 'https://login.example.test:9443', portalBasePath: '/team/portal',
  });
  for (const operation of oauthOperations) await checkOperationURL(operation, 'https://login.example.test:9443', '/team/portal');
  await reload('https://login.example.test:9443', '/team/portal');
  for (const operation of oauthOperations) await checkOperationURL(operation, 'https://login.example.test:9443', '/team/portal');
  await editVariable('portalBasePath', '');
  await reload('https://login.example.test:9443', '');
  for (const operation of oauthOperations) await checkOperationURL(operation, 'https://login.example.test:9443', '');
  await editVariable('portalBasePath', '/portal');
  // Commit the edit through a real blur, then verify the root template expands.
  await evaluate(`document.querySelector('input[id$="-origin"]').focus()`);
  for (const operation of oauthOperations) await checkOperationURL(operation, 'https://login.example.test:9443', '/portal');
  await evaluate(`localStorage.setItem(${JSON.stringify(storageKey)}, '{broken')`);
  await reload('https://auth.myfiosgateway.com:8443', '/auth');
  assert.equal(await evaluate(`!!document.querySelector('.scalar-load-error')`), false);
  assert.deepEqual(errors, [], 'browser raised runtime errors');
});
