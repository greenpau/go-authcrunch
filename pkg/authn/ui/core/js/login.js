/**
 * Authentication Portal Scripts
 * Author: Paul Greenberg github.com/greenpau
 * Date: 05/22/2022
 */

function hideLoginForm() {
  document.getElementById('loginform').classList.add('hidden');
  document.getElementById('authenticators').classList.remove('hidden');
}

let qrCodeLoginPanels = null;

function showQRCode(path) {
  if (qrCodeLoginPanels !== null) return;
  // Preserve the active realm view and its fields while displaying the QR code.
  qrCodeLoginPanels = ['loginform', 'authenticators']
    .map((id) => document.getElementById(id))
    .filter((panel) => panel && !panel.classList.contains('hidden'));
  qrCodeLoginPanels.forEach((panel) => panel.classList.add('hidden'));
  document.getElementById('bookmarks').classList.remove('sm:block');
  document.getElementById('show-qrcode')?.setAttribute('aria-expanded', 'true');
  const img = document.createElement('img');
  img.src = path;
  img.alt = 'Sign-in QR code';
  document.getElementById('qrcode').replaceChildren(img);
  document.getElementById('qr').classList.remove('hidden');
  document.getElementById('close-qrcode')?.focus();
}

function hideQRCode() {
  if (qrCodeLoginPanels === null) return;
  const panels = qrCodeLoginPanels;
  qrCodeLoginPanels = null;
  document.getElementById('qr').classList.add('hidden');
  document.getElementById('qrcode').replaceChildren();
  panels.forEach((panel) => panel.classList.remove('hidden'));
  document.getElementById('bookmarks').classList.add('sm:block');
  const trigger = document.getElementById('show-qrcode');
  trigger?.setAttribute('aria-expanded', 'false');
  if (trigger?.getClientRects().length) {
    trigger.focus();
  } else {
    // The desktop bookmark may have disappeared after a viewport resize.
    panels[0]?.querySelector('input:not([type="hidden"]), a, button')?.focus();
  }
}

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && qrCodeLoginPanels !== null) hideQRCode();
});

function showLoginForm(storeName, registrationEnabled, usernameRecoveryEnabled, contactSupportEnabled, baseUrl) {
  if (baseUrl == '<no value>') {
    baseUrl = '/';
  }
  const userActions = document.getElementById('user_actions');
  if (registrationEnabled == 'yes' || usernameRecoveryEnabled == 'yes' || contactSupportEnabled == 'yes') {
    const userRegisterLink = document.getElementById('user_register_link');
    userRegisterLink.getElementsByTagName('a')[0].href = baseUrl + 'register/' + storeName;
    const forgotUsernameLink = document.getElementById('forgot_username_link');
    forgotUsernameLink.getElementsByTagName('a')[0].href = baseUrl + 'forgot/' + storeName;
    const contactSupportLink = document.getElementById('contact_support_link');
    contactSupportLink.getElementsByTagName('a')[0].href = baseUrl + 'help/' + storeName;
    registrationEnabled == 'yes' ? userRegisterLink.classList.remove('hidden') : userRegisterLink.classList.add('hidden');
    usernameRecoveryEnabled == 'yes' ? forgotUsernameLink.classList.remove('hidden') : forgotUsernameLink.classList.add('hidden');
    contactSupportEnabled == 'yes' ? contactSupportLink.classList.remove('hidden') : contactSupportLink.classList.add('hidden');
    userActions.classList.remove('hidden');
  } else {
    userActions.classList.add('hidden');
  }

  document.getElementById('authenticators').classList.add('hidden');
  document.getElementById('loginform').classList.remove('hidden');
  document.getElementById('realm').value = storeName;
  document.getElementById('username').value = '';
  document.getElementById('username').focus();
}
