// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../core/js/sandbox_mfa_u2f.js'), 'utf8');

test('WebAuthn recovery uses localized plain text for unsupported and rejected operations', async () => {
  for (const supported of [false, true]) {
    for (const registration of [false, true]) {
      const nodes = new Map();
      const node = () => ({ children: [], classList: { add() {}, remove() {} }, appendChild(child) { this.children.push(child); }, remove() {} });
      const form = node(), parent = node(); parent.insertBefore = child => parent.appendChild(child); form.parentNode = parent;
      nodes.set('form', form); nodes.set('form-rst', node()); nodes.set('button', node());
      const messages = { mfa_browser_unsupported: 'غير مدعوم', mfa_browser_failed: 'Échec <test> & vérification', mfa_browser_registration_failed: 'Échec de l’enregistrement' };
      const document = {
        currentScript: { dataset: { i18n: JSON.stringify(messages) } },
        getElementById: id => nodes.get(id), createElement: node, createTextNode: text => ({ text }),
      };
      const reject = async () => { throw new Error('Browser-specific English failure'); };
      const context = { document, navigator: supported ? { credentials: { create: reject, get: reject } } : {},
        console: { log() {}, error() {} }, atob: value => Buffer.from(value, 'base64').toString('binary'), TextEncoder };
      vm.runInNewContext(source, context);
      const params = { challenge: 'YWJj', user_id: 'fixture', allowed_credentials: [] };
      if (registration) context.register_u2f_token('form', 'button', params);
      else context.authenticate_u2f_token('form', params);
      await new Promise(resolve => setImmediate(resolve));
      const message = parent.children[0].children[0].children[0];
      const key = !supported ? 'mfa_browser_unsupported' : registration ? 'mfa_browser_registration_failed' : 'mfa_browser_failed';
      assert.equal(message.text, messages[key]);
      assert.equal(parent.children.length, 1);
    }
  }
});
