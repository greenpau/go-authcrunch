/**
 * Authentication Portal Scripts
 * Author: Paul Greenberg github.com/greenpau
 */

/* MFA Application Functions */
function toggleAdvancedSetupMode() {
  let items = ['all']
  for(let i = 0 ; i < items.length; i++) {
    toggleElementByID('advanced-setup-' + items[i]);
  }
}

function toggleElementByID(elem) {
  let item = document.getElementById(elem);
  item.classList.toggle("hidden");
}

function hideElementByID(elem) {
  let item = document.getElementById(elem);
  item.classList.add("hidden");
}

function showElementByID(elem) {
  let item = document.getElementById(elem);
  item.classList.remove("hidden");
}

function encodeBase64(s) {
  let b = encodeURIComponent(s).replace(/%([0-9A-F]{2})/g, function (m, p) {
    return String.fromCharCode('0x' + p);
  });
  return btoa(b);
}

function encodeBase32(s, padding) {
  let cs = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.split('');
  let output = '';
  let length = s.length;
  let count = parseInt(length / 5) * 5;
  let c = [];
  let i = 0
  for (i = 0, count = parseInt(length / 5) * 5; i < count;) {
    for(let j = 0 ; j < 5; j++) {
      c[j] = s.charCodeAt(i++);
    }
    output += cs[c[0] >>> 3] + cs[(c[0] << 2 | c[1] >>> 6) & 31] +
      cs[(c[1] >>> 1) & 31] + cs[(c[1] << 4 | c[2] >>> 4) & 31] +
      cs[(c[2] << 1 | c[3] >>> 7) & 31] + cs[(c[3] >>> 2) & 31] +
      cs[(c[3] << 3 | c[4] >>> 5) & 31] + cs[c[4] & 31];
  }
  switch (length - count) {
    case 1:
      c[0] = s.charCodeAt(i);
      output += cs[c[0] >>> 3] + cs[(c[0] << 2) & 31];
      if (padding) output += '======';
      break;
    case 2:
      c[0] = s.charCodeAt(i++);
      c[1] = s.charCodeAt(i);
      output += cs[c[0] >>> 3] + cs[(c[0] << 2 | c[1] >>> 6) & 31] +
        cs[(c[1] >>> 1) & 31] + cs[(c[1] << 4) & 31];
      if (padding) output += '====';
      break;
    case 3:
      c[0] = s.charCodeAt(i++);
      c[1] = s.charCodeAt(i++);
      c[2] = s.charCodeAt(i);
      output += cs[c[0] >>> 3] + cs[(c[0] << 2 | c[1] >>> 6) & 31] +
        cs[(c[1] >>> 1) & 31] + cs[(c[1] << 4 | c[2] >>> 4) & 31] +
        cs[(c[2] << 1) & 31];
      if (padding) output += '===';
      break;
    case 4:
      c[0] = s.charCodeAt(i++);
      c[1] = s.charCodeAt(i++);
      c[2] = s.charCodeAt(i++);
      c[3] = s.charCodeAt(i);
      output += cs[c[0] >>> 3] +
        cs[(c[0] << 2 | c[1] >>> 6) & 31] + cs[(c[1] >>> 1) & 31] +
        cs[(c[1] << 4 | c[2] >>> 4) & 31] + cs[(c[2] << 1 | c[3] >>> 7) & 31] +
        cs[(c[3] >>> 2) & 31] + cs[(c[3] << 3) & 31];
      if (padding) output += '=';
      break;
  }
  return output;
};

function updateQRCode() {
  let issuer = document.getElementById('label').value;
  if (!(issuer)) {
    issuer = "AUTHP";
  }
  let email = document.getElementById('email').value;
  let secret = document.getElementById('secret').value;
  let digits = document.getElementById('digits').value;
  let period = document.getElementById('period').value;
  let barcodeURI = document.getElementById('barcode_uri').value;
  let tokenLink = document.getElementById('mfa-no-camera-link').childNodes[1]
  let tokenURL = 'otpauth://totp/' + encodeURI(issuer + ':' + email) +
                 '?secret=' + encodeBase32(secret, false) + '&issuer=' + encodeURI(issuer) +
                 '&digits=' + digits + '&period=' + period;
  if (tokenURL.localeCompare(tokenLink.href) != 0) {
    tokenLink.href = tokenURL;
    let imageDiv = document.getElementById('mfa-qr-code-image');
    let curImageNode = imageDiv.childNodes[1];
    let barcodeURL = barcodeURI + '/' + encodeBase64(tokenURL) + '.png';
    let newImageNode = document.createElement("img");
    newImageNode.setAttribute("src", barcodeURL);
    newImageNode.setAttribute("alt", "QR Code");
    imageDiv.insertBefore(newImageNode, curImageNode);
    imageDiv.removeChild(curImageNode);
  }

  if (digits.localeCompare("6") != 0) {
    updatePasscode('passcode', digits);
  }
}

function getQRCode() {
  updateQRCode();
  hideElementByID("token-params");
  showElementByID("mfa-qr-code");
}

function updatePasscode(s, digits) {
  let passcode = document.getElementById(s)
  switch (digits) {
    case "4":
      passcode.setAttribute("placeholder", "____");
      passcode.setAttribute("pattern", "[0-9]{4}");
      passcode.setAttribute("maxlength", "4");
      break;
    case "8":
      passcode.setAttribute("pattern", "[0-9]{8}");
      passcode.setAttribute("maxlength", "8");
      passcode.setAttribute("placeholder", "________");
      break;
  }
}

document.addEventListener("DOMContentLoaded", function(){
  let testForm = document.getElementById('mfa-test-app-form');
  if (typeof(testForm) != 'undefined' && testForm != null) {
    let digits = document.getElementById('digits').value;
    if (digits.localeCompare("6") != 0) {
      updatePasscode('passcode', digits);
    }
  }
});
