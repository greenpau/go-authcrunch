/**
 * Authentication Portal Scripts
 * Author: Paul Greenberg github.com/greenpau
 * Date: 05/22/2022
 */

function hideLoginForm() {
  document.getElementById('loginform').classList.add('hidden');
  document.getElementById('authenticators').classList.remove('hidden');
}

function showQRCode(path) {
  console.log('show QR code: path');
  document.getElementById('bookmarks').classList.remove('sm:block');
  document.getElementById('qr').classList.remove('hidden');
  const qrCode = document.getElementById('qrcode');
  const img = document.createElement('img');
  // img.src = 'https://upload.wikimedia.org/wikipedia/commons/thumb/d/d0/QR_code_for_mobile_English_Wikipedia.svg/220px-QR_code_for_mobile_English_Wikipedia.svg.png';
  img.src = path;
  qrCode.appendChild(img);
}

function hideQRCode() {
  console.log('hide QR code');
  document.getElementById('bookmarks').classList.add('sm:block');
  document.getElementById('qr').classList.add('hidden');
  const qrCode = document.getElementById('qrcode');
  while (qrCode.firstChild) {
    qrCode.removeChild(qrCode.firstChild);
  }
}

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
