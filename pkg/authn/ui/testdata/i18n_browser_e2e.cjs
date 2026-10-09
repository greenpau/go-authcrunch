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
    // Wrapped inline links have empty space inside their aggregate bounding box.
    const box = element.getClientRects()[0];
    return { x: box.x + box.width / 2, y: box.y + box.height / 2 };
  }, selector);
  await command("Input.dispatchMouseEvent", { type: "mousePressed", button: "left", clickCount: 1, ...point }, tab);
  await command("Input.dispatchMouseEvent", { type: "mouseReleased", button: "left", clickCount: 1, ...point }, tab);
}
async function screenshot(tab, name) {
  await evaluate(tab, async () => {
    window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
    await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  });
  const { cssContentSize, cssLayoutViewport } = await command("Page.getLayoutMetrics", {}, tab);
  // Unneeded full-page clipping can shift RTL captures after viewport resizing.
  const beyondViewport = cssContentSize.height > cssLayoutViewport.clientHeight ||
    cssContentSize.width > cssLayoutViewport.clientWidth;
  const { data } = await command("Page.captureScreenshot", {
    format: "png", captureBeyondViewport: beyondViewport,
    ...(beyondViewport ? { clip: { ...cssContentSize, scale: 1 } } : {}),
  }, tab);
  fs.writeFileSync(path.join(config.screenshots, name + ".png"), Buffer.from(data, "base64"), { mode: 0o600 });
}
// Expected translations are independent of the server catalog.
const expectations = {
  fr: {
    badRequest: 'Requête incorrecte', unauthorized: 'Non autorisé', notFound: 'Page non trouvée',
    direction: 'ltr', proceed: 'Continuer', password: 'Veuillez saisir votre mot de passe',
    approve: 'Approuver', deny: 'Refuser', confirm: 'Approuver la connexion',
    cancelled: 'Connexion annulée', copied: 'Lien copié.', waiting: 'En attente d’approbation.',
    consent: 'Autoriser l’application', permission: 'Identifiant du compte',
    account: 'Connecté en tant que', allow: 'Autoriser l’accès',
    logout: 'Se déconnecter', qrAlt: 'Code QR', verify: 'Vérifier',
    error: 'Impossible de continuer', register: 'S’inscrire',
    invalidCode: 'Le code de vérification du formulaire d’inscription est invalide',
    invalidPassword: 'Nous n’avons pas pu vérifier vos identifiants.',
    policy: 'Longueur du nom d’utilisateur', session: 'Ce navigateur nécessite une nouvelle connexion pour continuer.',
    logo: 'Portail d’authentification', description: 'Authentifie les utilisateurs.',
    keyFailure: 'L’enregistrement de la clé de sécurité n’a pas abouti. Réessayez en suivant les instructions de votre navigateur.',
    passwordLabel: 'Mot de passe', passcode: "Code d'accès",
    unexpected: 'Malheureusement, les choses ne se sont pas passées comme prévu.',
    mismatch: 'L’identifiant d’inscription ne correspond pas', missing: 'Identifiant d’inscription introuvable',
    confirmed: "Merci d'avoir confirmé votre inscription et validé votre adresse e-mail !",
  },
  ar: {
    badRequest: 'طلب غير صالح', unauthorized: 'غير مصرح', notFound: 'الصفحة غير موجودة',
    direction: 'rtl', proceed: 'متابعة', password: 'يرجى إدخال كلمة المرور',
    approve: 'موافقة', deny: 'رفض', confirm: 'الموافقة على تسجيل الدخول',
    cancelled: 'تم إلغاء تسجيل الدخول', copied: 'تم نسخ الرابط.', waiting: 'في انتظار الموافقة.',
    consent: 'تفويض التطبيق', permission: 'معرّف الحساب', account: 'تم تسجيل الدخول باسم', allow: 'السماح بالوصول',
    logout: 'تسجيل الخروج', qrAlt: 'رمز QR', verify: 'تحقق', error: 'تعذرت المتابعة', register: 'إنشاء حساب',
    invalidCode: 'رمز التحقق في نموذج التسجيل غير صالح', invalidPassword: 'تعذر التحقق من بيانات اعتمادك.',
    policy: 'طول اسم المستخدم', session: 'يتطلب هذا المتصفح تسجيل الدخول مجدداً للمتابعة.',
    logo: 'بوابة المصادقة', description: 'يُجري مصادقة المستخدمين.',
    keyFailure: 'لم يكتمل تسجيل مفتاح الأمان. حاول مجدداً واتبع تعليمات المتصفح.',
    passwordLabel: 'كلمة المرور', passcode: 'رمز المرور',
    unexpected: 'للأسف، لم تسر الأمور كما كان متوقعًا.',
    mismatch: 'معرّف التسجيل غير متطابق', missing: 'لم يتم العثور على معرّف التسجيل',
    confirmed: 'شكرًا لك على تأكيد تسجيلك والتحقق من عنوان بريدك الإلكتروني!',
  },
  he: {
    badRequest: 'בקשה לא תקינה', unauthorized: 'לא מורשה', notFound: 'הדף לא נמצא',
    direction: 'rtl', proceed: 'המשך', password: 'יש להזין את הסיסמה שלך',
    approve: 'אישור', deny: 'דחייה', confirm: 'אישור כניסה',
    cancelled: 'הכניסה בוטלה', copied: 'הקישור הועתק.', waiting: 'ממתין לאישור.',
    consent: 'הרשאת יישום', permission: 'מזהה חשבון', account: 'החשבון המחובר', allow: 'אישור גישה',
    logout: 'התנתק', qrAlt: 'קוד QR', verify: 'בדיקה', error: 'לא ניתן להמשיך', register: 'הרשמה',
    invalidCode: 'קוד האימות בטופס הרישום אינו תקין', invalidPassword: 'לא ניתן לאמת את פרטי הכניסה.',
    policy: 'אורך שם המשתמש', session: 'בדפדפן זה יש להיכנס שוב כדי להמשיך.',
    logo: 'פורטל אימות', description: 'מבצע אימות משתמשים.',
    keyFailure: 'רישום מפתח האבטחה לא הושלם. יש לנסות שוב ולפעול לפי הוראות הדפדפן.',
    passwordLabel: 'סיסמה', passcode: 'קוד גישה',
    unexpected: 'לצערנו, הדברים לא התנהלו כמצופה.',
    mismatch: 'מזהה הרישום אינו תואם', missing: 'מזהה הרישום לא נמצא',
    confirmed: 'תודה שאישרת את ההרשמה ואימתת את כתובת האימייל שלך!',
  },
  ja: {
    badRequest: '不正なリクエスト', unauthorized: '認証が必要です', notFound: 'ページが見つかりません',
    direction: 'ltr', proceed: '続行', password: 'パスワードを入力してください',
    approve: '承認', deny: '拒否', confirm: 'サインインを承認',
    cancelled: 'サインインがキャンセルされました', copied: 'リンクをコピーしました。', waiting: '承認を待っています。',
    consent: 'アプリケーションを認可', permission: 'アカウント識別子', account: 'サインイン中のアカウント', allow: 'アクセスを許可',
    logout: 'サインアウト', qrAlt: 'QRコード', verify: '確認', error: '続行できません', register: '登録',
    invalidCode: '登録フォームの確認コードが無効です', invalidPassword: '認証情報を確認できませんでした。',
    policy: 'ユーザー名の長さ', session: 'このブラウザで続行するには、再度サインインしてください。',
    logo: '認証ポータル', description: 'ユーザー認証を行います。',
    keyFailure: 'セキュリティキーの登録が完了しませんでした。ブラウザの指示に従って再試行してください。',
    passwordLabel: 'パスワード', passcode: 'パスコード',
    unexpected: '申し訳ありませんが、予期しないエラーが発生しました。',
    mismatch: '登録識別子が一致しません', missing: '登録識別子が見つかりません',
    confirmed: '登録の確認とメールアドレスの認証が完了しました。ありがとうございます！',
  },
};
const expected = expectations[config.lang];
assert.ok(expected, 'unsupported browser test language: ' + config.lang);
async function text(tab, selector) {
  return evaluate(tab, selector => document.querySelector(selector)?.textContent.trim(), selector);
}
async function check(tab, name) {
  await waitFor(() => evaluate(tab, () => document.readyState === 'complete' && [...document.images]
    .filter(img => img.getClientRects().length).every(img => img.complete)));
  const brokenImages = await evaluate(tab, () => [...document.images]
    .filter(img => img.getClientRects().length && !img.naturalWidth)
    .map(img => img.id || img.className || img.alt));
  assert.deepEqual(brokenImages, [], name + ': visible images failed to load');
  await evaluate(tab, async () => { await document.fonts.ready; });
  for (const width of [320, 390, 1280]) {
    await command('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: width < 640 }, tab);
    const state = await evaluate(tab, () => ({
      lang: document.documentElement.lang, dir: document.documentElement.dir,
      direction: getComputedStyle(document.body).direction,
      overflow: document.documentElement.scrollWidth > innerWidth,
      controls: [...document.querySelectorAll('button, input:not([type="hidden"]), textarea')]
        .filter(el => el.getClientRects().length).every(el => {
          const r = el.getBoundingClientRect(); return (el.tagName !== "BUTTON" || r.height <= 112) && r.left >= 0 && r.right <= innerWidth && el.scrollWidth <= el.clientWidth + 1;
        }),
      listMarkers: [...document.querySelectorAll('ol.list-decimal')].every(list => {
        const box = list.getBoundingClientRect(), item = list.firstElementChild.getBoundingClientRect();
        return (getComputedStyle(list).direction === 'rtl' ? box.right - item.right : item.left - box.left) >= 16;
      }),
      code: document.getElementById('cross-device-code')?.dir,
    }));
    assert.equal(state.lang, config.lang, name + ' language');
    assert.equal(state.dir, expected.direction, name + ' direction');
    assert.equal(state.direction, expected.direction, name + ' computed direction');
    assert.equal(state.overflow, false, `${name}: page overflow at ${width}`);
    assert.ok(state.controls, `${name}: control overflow at ${width}`);
    assert.ok(state.listMarkers, `${name}: numbered instructions lack marker space at ${width}`);
    if (state.code) assert.equal(state.code, 'ltr', 'matching code order');
    if (width !== 320) await screenshot(tab, name + (width === 390 ? '-phone' : '-desktop'));
  }
  await command('Emulation.setDeviceMetricsOverride', { width: 390, height: 900, deviceScaleFactor: 1, mobile: true }, tab);
}
async function signIn(tab, username, incorrect = false) {
  await waitFor(() => evaluate(tab, () => !!document.querySelector('#username')));
  await evaluate(tab, username => { document.querySelector('#username').value = username; document.querySelector('#username').form.requestSubmit(); }, username);
  await waitFor(() => evaluate(tab, () => !!document.querySelector('#secret')));
  assert.equal(await text(tab, 'label[for="secret"]'), expected.password);
  await check(tab, 'password');
  if (incorrect) {
    await evaluate(tab, () => { const input = document.querySelector('#secret'); input.value = 'invalid-fixture-password'; input.form.requestSubmit(); });
    await waitFor(() => evaluate(tab, () => !!document.querySelector('.app-txt-section') && !document.querySelector('#secret')));
    assert.ok((await text(tab, '.app-container')).includes(expected.invalidPassword));
    await check(tab, 'password-error');
    await click(tab, 'a[href*="/sandbox/"]');
    await waitFor(() => evaluate(tab, () => !!document.querySelector('#secret')));
  }
  await evaluate(tab, password => { const input = document.querySelector('#secret'); input.value = password; input.form.requestSubmit(); }, password);
}

(async () => {
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', reject, { once: true });
  });
  let tab;
  try {
    const mainContext = (await command('Target.createBrowserContext')).browserContextId;
    const requestContext = (await command('Target.createBrowserContext')).browserContextId;
    tab = await page(mainContext);
    const requester = await page(requestContext);
    stage = 'login';
    await navigate(tab, config.issuer + '/login', '#username');
    assert.equal(await evaluate(tab, () => document.querySelector('.logo-img').alt), expected.logo);
    assert.equal(await evaluate(tab, () => document.querySelector('meta[name="description"]').content), expected.description);
    assert.ok((await evaluate(tab, () => document.title)).includes('AuthCrunch'), 'custom metadata is preserved');
    await check(tab, 'login');
    await command('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false }, tab);
    await click(tab, '#show-qrcode');
    assert.equal(await evaluate(tab, () => document.querySelector('#qrcode img').alt), expected.qrAlt);
    await click(tab, '#close-qrcode');

    stage = 'generic errors';
    for (const [route, status, title] of [
      ['/register', 400, expected.badRequest],
      ['/sandbox/missing', 401, expected.unauthorized],
      ['/missing-page', 404, expected.notFound],
    ]) {
      const url = config.issuer + route;
      const response = await evaluate(tab, async url => {
        const response = await fetch(url, { headers: { Accept: 'text/html' }, redirect: 'error' });
        return { status: response.status, type: response.headers.get('Content-Type') };
      }, url);
      assert.equal(response.status, status, 'localized errors retain their HTTP status');
      assert.equal(response.type, 'text/html; charset=utf-8');
      await navigate(tab, url, '#generic-title');
      assert.equal(await text(tab, '#generic-title'), title);
      assert.ok((await evaluate(tab, () => document.title)).endsWith(title));
      await check(tab, 'http-error-' + status);
    }

    stage = 'registration';
    await navigate(tab, config.issuer + '/register/local', '#registrant');
    assert.equal(await text(tab, 'h2'), expected.register);
    assert.equal(await text(tab, 'label[for="registrant_password"]'), expected.passwordLabel);
    assert.ok((await evaluate(tab, () => document.querySelector('#registrant').title)).startsWith(expected.policy));
    await check(tab, 'registration');
    await evaluate(tab, password => {
      document.querySelector('#registrant').value = 'newuser';
      document.querySelector('#registrant_password').value = password;
      document.querySelector('#registrant_email').value = 'newuser@example.test';
      document.querySelector('#registrant_code').value = 'invalid';
      document.querySelector('#accept_terms').checked = true;
      document.querySelector('#registrant').form.requestSubmit();
    }, password);
    await waitFor(() => evaluate(tab, () => !!document.querySelector('#alerts')));
    assert.ok((await text(tab, '#alerts')).includes(expected.invalidCode));
    await check(tab, 'registration-error');

    stage = 'registration confirmation';
    await evaluate(tab, password => {
      document.querySelector('#registrant').value = 'newuser';
      document.querySelector('#registrant_password').value = password;
      document.querySelector('#registrant_email').value = 'newuser@example.test';
      document.querySelector('#registrant_code').value = 'invitation';
      document.querySelector('#accept_terms').checked = true;
      document.querySelector('#registrant').form.requestSubmit();
    }, password);
    await waitFor(() => evaluate(tab, () => !!document.querySelector('#registered-section')));
    await check(tab, 'registration-sent');
    // Consume the delivered email, just as the registrant would. Do not read
    // portal caches or fabricate a confirmation capability.
    const mailFiles = () => fs.readdirSync(config.mail).filter(name => name.endsWith('.eml'));
    assert.equal(mailFiles().length, 1, 'one confirmation email must be delivered');
    const mail = fs.readFileSync(path.join(config.mail, mailFiles()[0]), 'utf8');
    assert.match(mail, /Content-Transfer-Encoding: quoted-printable/);
    const body = mail.split(/\r?\n\r?\n/).slice(1).join('\n\n')
      .replace(/=\r?\n/g, '').replace(/=([0-9A-F]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
    const linkMatch = body.match(/href="([^"]+\/register\/local\/ack\/[A-Za-z0-9]+)"/);
    const codeMatch = body.match(/<b><code>([A-Za-z0-9]+)<\/code><\/b>/);
    assert.ok(linkMatch && codeMatch, 'confirmation email must contain a link and code');
    const confirmationURL = new URL(linkMatch[1]);
    assert.equal(confirmationURL.origin, new URL(config.issuer).origin, 'confirmation stays on the portal origin');
    const confirmationCode = codeMatch[1];
    await navigate(tab, confirmationURL.href, '#registration_code');
    assert.equal(await text(tab, 'label[for="registration_code"]'), expected.passcode);
    assert.equal(await evaluate(tab, () => getComputedStyle(document.querySelector('#registration_code')).direction), 'ltr');
    await check(tab, 'registration-confirm');
    const submitCode = code => evaluate(tab, code => {
      const input = document.querySelector('#registration_code');
      input.value = code; input.form.requestSubmit();
    }, code);
    await submitCode((confirmationCode[0] === 'A' ? 'B' : 'A') + confirmationCode.slice(1));
    await waitFor(() => evaluate(tab, () => !document.querySelector('#registration_code')));
    assert.ok((await text(tab, '.app-container')).includes(expected.unexpected));
    assert.ok((await text(tab, '.app-container')).includes(expected.mismatch));
    assert.equal(mailFiles().length, 1, 'a wrong code cannot confirm registration');
    await check(tab, 'registration-confirm-error');
    await navigate(tab, confirmationURL.href, '#registration_code');
    await submitCode(confirmationCode);
    await waitFor(() => evaluate(tab, () => !document.querySelector('#registration_code')));
    assert.ok((await text(tab, '.app-container')).includes(expected.confirmed));
    assert.equal(mailFiles().length, 2, 'confirmation must notify the administrator');
    await check(tab, 'registration-confirmed');
    await navigate(tab, confirmationURL.href, '.app-container');
    assert.ok((await text(tab, '.app-container')).includes(expected.missing));
    assert.equal(mailFiles().length, 2, 'confirmation replay cannot emit another notification');

    stage = 'cross-device cancellation';
    await navigate(requester, config.issuer + '/cross-device', '#cross-device-copy');
    await waitFor(() => evaluate(requester, () => !document.querySelector('#cross-device-copy').disabled));
    assert.ok((await text(requester, '#cross-device-status')).startsWith(expected.waiting));
    await check(requester, 'cross-device-request');
    await command('Browser.grantPermissions', { origin: new URL(config.issuer).origin, browserContextId: requestContext, permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite'] });
    await command('Page.bringToFront', {}, requester);
    await click(requester, '#cross-device-copy');
    await waitFor(() => evaluate(requester, () => !!document.querySelector('#cross-device-copy-status').textContent));
    assert.ok((await text(requester, '#cross-device-copy-status')).startsWith(expected.copied));
    await click(requester, '#cross-device-cancel');
    assert.equal(await text(requester, 'h1'), expected.cancelled);
    await check(requester, 'cross-device-cancelled');

    stage = 'cross-device approval';
    await navigate(requester, config.issuer + '/cross-device', '#cross-device-copy');
    await waitFor(() => evaluate(requester, () => !document.querySelector('#cross-device-copy').disabled));
    const link = await evaluate(requester, () => document.querySelector('#cross-device-link').value);
    const code = await text(requester, '#cross-device-code');
    await navigate(tab, link, '.cross-device-actions button');
    assert.equal(await text(tab, '.cross-device-actions button'), expected.proceed);
    await check(tab, 'cross-device-continue');
    await click(tab, '.cross-device-actions button');
    await signIn(tab, 'alice', true);
    await waitFor(() => evaluate(tab, () => !!document.querySelector('button[value="approve"]')));
    assert.equal(await text(tab, 'h1'), expected.confirm);
    assert.ok(await text(tab, '#cross-device-code') === code, 'both devices must show the same matching code');
    assert.equal(await text(tab, 'button[value="approve"]'), expected.approve);
    assert.equal(await text(tab, 'button[value="deny"]'), expected.deny);
    await check(tab, 'cross-device-approve');
    await click(tab, 'button[value="approve"]');
    await waitFor(() => evaluate(requester, () => !!document.querySelector('.app-link-list')));
    await check(requester, 'portal');

    stage = 'OIDC consent';
    await navigate(tab, config.authorize, 'button[value="allow"]');
    assert.equal(await text(tab, 'h1'), expected.consent);
    assert.ok((await text(tab, '.oidc-permission-list')).includes(expected.permission));
    assert.equal(await text(tab, '.oidc-account-label'), expected.account);
    assert.equal(await text(tab, 'button[value="allow"]'), expected.allow);
    await check(tab, 'oidc-consent');
    await click(tab, 'button[value="deny"]');
    await waitFor(() => evaluate(tab, () => !!document.querySelector('#callback')));
    const postURL = new URL(config.authorize); postURL.searchParams.set('response_mode', 'form_post');
    const suppress = await command('Page.addScriptToEvaluateOnNewDocument', { source: 'HTMLFormElement.prototype.submit = function() {};' }, tab);
    await navigate(tab, postURL.href, 'button[value="allow"]');
    await click(tab, 'button[value="allow"]');
    await waitFor(() => evaluate(tab, () => !!document.querySelector('#response')));
    assert.equal(await text(tab, '#response button'), expected.proceed);
    await check(tab, 'oidc-continue');
    await click(tab, '#response button');
    await waitFor(() => evaluate(tab, () => !!document.querySelector('#callback')));
    await command('Page.removeScriptToEvaluateOnNewDocument', { identifier: suppress.identifier }, tab);
    await navigate(tab, config.issuer + '/oidc/authorize', '#oidc-title');
    assert.equal(await text(tab, 'h1'), expected.error);
    await check(tab, 'oidc-error');

    stage = 'session and identity';
    await navigate(tab, config.issuer + '/whoami', 'pre');
    assert.equal(await evaluate(tab, () => document.querySelector('pre').dir), 'ltr');
    await check(tab, 'identity');
    await navigate(tab, config.issuer + '/logout', '#session-logout');
    // Session status comes from an external script under the production CSP.
    assert.equal(await text(tab, '#session-logout'), expected.logout);
    await check(tab, 'logout');
    await click(tab, '#session-logout');
    await waitFor(() => evaluate(tab, () => !!document.querySelector('#username')));

    stage = 'MFA';
    await signIn(tab, 'mfauser');
    await waitFor(() => evaluate(tab, () => !!document.querySelector('#passcode')));
    assert.equal(await text(tab, 'label[for="passcode"]'), expected.passcode);
    assert.equal(await text(tab, 'button[type="submit"]'), expected.verify);
    assert.equal(await evaluate(tab, () => document.querySelector('#passcode').dir), 'ltr');
    await check(tab, 'mfa');
    const counter = Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
    const mac = require('node:crypto').createHmac('sha1', '0123456789abcdef0123456789abcdef').update(counter).digest();
    const codeTOTP = String((mac.readUInt32BE(mac[mac.length - 1] & 15) & 0x7fffffff) % 1000000).padStart(6, '0');
    await evaluate(tab, code => { const input = document.querySelector('#passcode'); input.value = code; input.form.requestSubmit(); }, codeTOTP);
    await waitFor(() => evaluate(tab, () => !!document.querySelector('.app-link-list')));
    const blocked = await command('Page.addScriptToEvaluateOnNewDocument', { source: 'Object.defineProperty(navigator, "locks", {value: undefined});' }, tab);
    await navigate(tab, config.issuer + '/logout', '#session-logout');
    await waitFor(() => evaluate(tab, () => document.querySelector('#session-message').textContent !== ''));
    assert.equal(await text(tab, '#session-message'), expected.session);
    await check(tab, 'session-recovery');
    await command('Page.removeScriptToEvaluateOnNewDocument', { identifier: blocked.identifier }, tab);

    stage = 'MFA enrollment';
    await navigate(tab, config.issuer + '/logout', '#session-logout');
    await click(tab, '#session-logout');
    await waitFor(() => evaluate(tab, () => !!document.querySelector('#username')));
    await signIn(tab, 'admin');
    await waitFor(() => evaluate(tab, () => !!document.querySelector('a[href$="/mfa-app-register"]')));
    await check(tab, 'mfa-choice');
    const keyURL = await evaluate(tab, () => document.querySelector('a[href$="/mfa-u2f-register"]').href);
    await click(tab, 'a[href$="/mfa-app-register"]');
    await waitFor(() => evaluate(tab, () => !!document.querySelector('#mfa-get-qr-code')));
    await check(tab, 'mfa-setup');
    // Change a valid parameter to force QR image regeneration, including its alt text.
    await evaluate(tab, () => { document.querySelector('#period').value = '60'; });
    await click(tab, '#mfa-get-qr-code a');
    await waitFor(() => evaluate(tab, () => !document.querySelector('#mfa-qr-code').classList.contains('hidden')));
    assert.equal(await evaluate(tab, () => document.querySelector('#mfa-qr-code-image img').alt), expected.qrAlt);
    const qr = await evaluate(tab, () => ({
      payload: new URL(document.querySelector('#mfa-qr-code-image img').src).pathname.split('/').pop().slice(0, -4),
      uri: document.querySelector('#mfa-no-camera-link a').href,
    }));
    assert.match(qr.payload, /^[A-Za-z0-9_-]+$/, 'QR path must remain canonical');
    assert.ok(Buffer.from(qr.payload, 'base64url').toString('utf8') === qr.uri, 'QR and manual enrollment URIs must match');
    assert.equal(new URL(qr.uri).searchParams.get('period'), '60');
    await check(tab, 'mfa-setup-qr');

    stage = 'security key browser rejection';
    const rejection = await command('Page.addScriptToEvaluateOnNewDocument', {
      source: 'navigator.credentials.create = () => Promise.reject(new DOMException("Synthetic browser failure", "NotAllowedError"));',
    }, tab);
    await navigate(tab, keyURL, '#mfa-add-u2f-button');
    await check(tab, 'security-key');
    await click(tab, '#mfa-add-u2f-button');
    await waitFor(() => evaluate(tab, () => !document.querySelector('#mfa-add-u2f-form-rst').classList.contains('hidden')));
    assert.ok((await text(tab, '.app-container')).includes(expected.keyFailure));
    assert.ok(!(await text(tab, '.app-container')).includes('Synthetic browser failure'));
    await check(tab, 'security-key-error');
    await command('Page.removeScriptToEvaluateOnNewDocument', { identifier: rejection.identifier }, tab);
    process.stdout.write(JSON.stringify({ passed: true }));
  } catch (error) {
    if (tab) { try { await screenshot(tab, 'failure'); } catch (_) {} }
    process.stderr.write(stage + ': ' + error.stack + '\n'); process.exitCode = 1;
  } finally { socket.close(); }
})();
