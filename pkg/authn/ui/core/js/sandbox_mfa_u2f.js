/**
 * Authentication Portal Scripts
 * Author: Paul Greenberg github.com/greenpau
 */

/* add mfa u2f */
function str_to_uint8_array(s) {
  buf = [];
  for (let i = 0; i < s.length; i += 2) {
    let j = parseInt(s.substring(i, i + 2), 16);
    buf.push(j);
  }
  return Uint8Array.from(buf);
}

function uint8array_to_buffer(arr) {
  return arr.buffer.slice(arr.byteOffset, arr.byteLength + arr.byteOffset);
}

function buffer_to_hex(buffer) {
  return uint8array_to_hex(new Uint8Array(buffer));
}

function uint8array_to_hex(arr) {
  return Array.prototype.map
    .call(arr, function (x) {
      return ("00" + x.toString(16)).slice(-2);
    })
    .join("");
}

function buffer_to_base64(buffer) {
  return uint8array_to_base64(new Uint8Array(buffer));
}

function uint8array_to_base64(array) {
  return window.btoa(String.fromCharCode.apply(null, array));
}

function parseAttestationObjectAttestationStatement(attStmt) {
  let alg = "es256";
  let algNum = -7;
  if ("alg" in attStmt) {
    algNum = attStmt["alg"];
    switch(attStmt["alg"]) {
    case -257:
      alg = "rs256";
      break;
    case -8:
      alg = "eddsa";
    case -7:
      alg = "es256";
      break;
    default:
      throw `algo ${attStmt["alg"]} is unsupported in attestation statement`;
    }
  } else {
    console.log("alg not found in attestation statement, assuming es256", attStmt);
  }

  // See Packed Attestation Statement Format for details
  // https://www.w3.org/TR/webauthn-1/#packed-attestation
  response = {
    // Algorithms, see IANA COSE Algorithms registry
    // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
    // -7: ES256 (ECDSA w/ SHA-256)
    // -257: RS256 (RSASSA-PKCS1-v1_5 using SHA-256)
    alg: algNum,
  };

  if (!("sig" in attStmt)) {
    throw "sig not found in attestation statement";
  }
  // A byte string containing the attestation signature
  response["sig"] = uint8array_to_base64(attStmt.sig);

  if ("x5c" in attStmt) {
    // Handle non-ECDAA attestation type
    let certChain = [];
    // The elements of this array contain attestnCert and its
    // certificate chain, each encoded in X.509 format. The attestation
    // certificate attestnCert MUST be the first element in the array.
    response["x5c"] = [];
    attStmt.x5c.forEach((item) =>
      response.x5c.push(uint8array_to_base64(item))
    );
  } else {
    if ("ecdaaKeyId" in attStmt) {
      // Handle ECDAA attestation type
      console.log("found ecdaaKeyId in attestation statement", attStmt)
    }
  }

  return response;
}

function parseAttestationObjectAuthData(data, alg) {
  // See https://www.w3.org/TR/webauthn-1/#sctn-attestation
  let dv = new DataView(data, 0);
  let offset = 0;
  let rp_id_hash = dv.buffer.slice(offset, offset + 32);
  offset += 32;
  let flags = dv.getUint8(offset);
  offset += 1;
  let counter = dv.getUint32(offset, false);
  offset += 4;
  let response = {
    rpIdHash: buffer_to_hex(rp_id_hash),
    flags: {
      UP: !!(flags & 0x01), // User Present (UP)
      RFU1: !!(flags & 0x02),
      UV: !!(flags & 0x04), // User Verified (UV)
      RFU2a: !!(flags & 0x08),
      RFU2b: !!(flags & 0x10),
      RFU2c: !!(flags & 0x20),
      AT: !!(flags & 0x40), // Attested credential data included
      ED: !!(flags & 0x80), // Extension data included
    },
    signatureCounter: counter,
    credentialData: {},
    extensions: {},
  };

  if (response["flags"]["AT"]) {
    let aaguid = dv.buffer.slice(offset, offset + 16);
    offset += 16;
    response["credentialData"]["aaguid"] = buffer_to_base64(aaguid);
    let credentialIdLength = dv.getUint16(offset);
    offset += 2;
    let credentialId = dv.buffer.slice(offset, credentialIdLength);
    offset += credentialIdLength;
    response["credentialData"]["credentialId"] = buffer_to_base64(credentialId);
    let publicKeyBytes = dv.buffer.slice(offset);
    let publicKeyObject = CBOR.decode(publicKeyBytes);

    offset += publicKeyObject["length"];

    switch(alg) {
    case -7:
      response["credentialData"]["publicKey"] = {
        // See COSE Key Types: https://www.iana.org/assignments/cose/cose.xhtml#key-type
        // 2 = Elliptic Curve Keys w/ x- and y-coordinate pair
        key_type: publicKeyObject[1],
        // See COSE Algorithms: https://www.iana.org/assignments/cose/cose.xhtml#algorithms
        // -7 = ECDSA with SHA256
        algorithm: publicKeyObject[3],
        // See COSE Elliptic Curves: https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
        // 1 = P-256 (NIST P-256 also known as secp256r1)
        curve_type: publicKeyObject[-1],
        // Elliptic Curve x-coordinate as byte string 32 bytes in length
        curve_x: uint8array_to_base64(publicKeyObject[-2]),
        // Elliptic Curve y-coordinate as byte string 32 bytes in length
        curve_y: uint8array_to_base64(publicKeyObject[-3]),
      };
      break;
    case -257:
      response["credentialData"]["publicKey"] = {
        // See COSE Key Types: https://www.iana.org/assignments/cose/cose.xhtml#key-type
        // 3 = RSA Key
        key_type: publicKeyObject[1],
        // See COSE Algorithms: https://www.iana.org/assignments/cose/cose.xhtml#algorithms
        // -257 = RSASSA-PKCS1-v1_5 using SHA-256
        algorithm: publicKeyObject[3],
        modulus: uint8array_to_base64(publicKeyObject[-1]),
        exponent: uint8array_to_base64(publicKeyObject[-2]),
      };
      break;
    default:
      throw `algo ${attStmt["alg"]} is unsupported in attestation statement`;
    }
  }

  if (response["flags"]["ED"]) {
    // let extensionData = dv.buffer.slice(offset);
  }

  return response;
}

function decodeArrayBuffer(str) {
  var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  var rchars = new Uint8Array(256);
  for (var i = 0; i < chars.length; i++) {
    rchars[chars.charCodeAt(i)] = i;
  }
  var padlen = str.charAt(str.length - 2) === '=' ? 2 : str.charAt(str.length - 1) === '=' ? 1 : 0;
  var arrlen = (str.length * 3 / 4) - padlen
  var arr = new ArrayBuffer(arrlen);
  var tarr = new Uint8Array(arr);
  var j = 0;
  for (var i = 0; i < str.length; i += 4) {
    var c0 = rchars[str.charCodeAt(i)];
    var c1 = rchars[str.charCodeAt(i + 1)];
    var c2 = rchars[str.charCodeAt(i + 2)];
    var c3 = rchars[str.charCodeAt(i + 3)];
    tarr[j++] = (c0 << 2) | (c1 >> 4);
    tarr[j++] = ((c1 & 15) << 4) | (c2 >> 2);
    tarr[j++] = ((c2 & 3) << 6) | (c3 & 63);
  }
  return arr;
}

function encodeArrayBuffer(buf) {
  var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  var arr = new Uint8Array(buf);
  var b = "";
  for (var i = 0; i < arr.length; i += 3) {
    b += chars[arr[i] >> 2];
    b += chars[((arr[i] & 3) << 4) | (arr[i+1] >> 4)];
    b += chars[((arr[i+1] & 15) << 2) | (arr[i+2] >> 6)];
    b += chars[arr[i+2] & 63];
  }
  switch (arr.length % 3) {
   case 1:
     b = b.substring(0, b.length - 2);
     break;
   case 2:
     b = b.substring(0, b.length - 1);
     break;
   }
   return b;
}

function parseNavigatorCredentialsCreateResponse(result) {
  let decoder = new TextDecoder("utf-8");
  clientData = JSON.parse(decoder.decode(result.response.clientDataJSON));
  let attestationObject = CBOR.decode(result.response.attestationObject);
  let attestationObjectAuthData = uint8array_to_buffer(
    attestationObject.authData
  );
  let attStmt = parseAttestationObjectAttestationStatement(
    attestationObject.attStmt
  );
  let authData = parseAttestationObjectAuthData(attestationObjectAuthData, attStmt['alg']);
  let response = {
    id: result.id,
    type: result.type,
    transports: ["usb","nfc","ble","internal"],
    success: true,
    attestationObject: {
      attStmt: attStmt,
      authData: authData,
      fmt: attestationObject.fmt,
    },
    clientData: clientData,
    device: {
      name: "Unknown device",
      type: "unknown",
    }
  };
  return response;
}

function register_u2f_token(formID, btnID, params) {
  const req = {
    publicKey: {
      challenge: decodeArrayBuffer(params.challenge),
      rp: {
        name: params.rp_name
      },
      user: {
        id: str_to_uint8_array(params.user_id),
        name: params.user_name,
        displayName: params.user_display_name
      },
      authenticatorSelection: {
        userVerification: params.user_verification
      },
      attestation: params.attestation,
      pubKeyCredParams: [
        {
          type: "public-key",
          alg: -7,
        },
        {
          type: "public-key",
          alg: -8,
        },
        {
          type: "public-key",
          alg: -257,
        }
      ]
    }
  };
  let btn = document.getElementById(btnID);
  btn.classList.add("hidden");
  if ("credentials" in navigator) {
    navigator.credentials.create(req)
      .then((result) => {
        response = parseNavigatorCredentialsCreateResponse(result);
        jresponse = btoa(JSON.stringify(response));
        document.getElementById("webauthn_register").value = jresponse;
        document.getElementById(formID).submit();
      })
      .catch((err) => {
        console.log("navigator credentials error", err);
        if (typeof err === 'string' || err instanceof String) {
          render_u2f_status(formID, "Navigator Credentials Error", err);
        } else {
          render_u2f_status(formID, err.name, err.message);
        }
      });
    return
  } else {
    console.error("navigator credentials credentials not found");
  }
  render_u2f_status(formID, "Failed Token Registration", "navigator.credentials is not supported");
}

function render_u2f_status(formID, name, message) {
  const form = document.getElementById(formID);
  const msgDiv = document.createElement("div");
  msgDiv.className = 'space-y-6 pb-4 text-lg leading-7 text-primary-600';
  const msgBody = document.createElement("p");
  const msgBodyText = document.createTextNode(name + ": " + message);
  msgBody.appendChild(msgBodyText);
  msgDiv.appendChild(msgBody);
  form.parentNode.insertBefore(msgDiv, form.nextSibling);
  form.remove();
  const formResetBtn = document.getElementById(formID + "-rst");
  formResetBtn.classList.remove("hidden");
}
/* u2f test */
function parseNavigatorCredentialsGetResponse(result) {
  if (!('response' in result)) {
    throw new Error('Response is empty.');
  }
  if (!('type' in result)) {
    throw new Error('Credential type not found.');
  }
  if (!('id' in result)) {
    throw new Error('Transaction ID not found.');
  }
  let response = {
    id: result.id,
    type: result.type,
    auth_data_encoded: buffer_to_base64(result.response.authenticatorData),
    client_data_encoded: buffer_to_base64(result.response.clientDataJSON),
    signature_encoded: buffer_to_base64(result.response.signature),
  };
  return response;
}

function authenticate_u2f_token(formID, params) {
  const req = {
    publicKey: {
      challenge: decodeArrayBuffer(params.challenge),
      timeout: params.timeout,
      rp: params.rp_name,
      userVerification: params.user_verification,
      allowCredentials: [],
      extensions: {
        uvm: params.ext_uvm,
        loc: params.ext_loc,
        txAuthSimple: params.ext_tx_auth_simple,
      }
    }
  };
  for (const cred of params.allowed_credentials) {
    item = {
      id: decodeArrayBuffer(cred.id),
      type: cred.type,
    };
    if ('transports' in cred) {
      item.transports = cred.transports;
    }
    req.publicKey.allowCredentials.push(item);
  }
  if ("credentials" in navigator) {
    navigator.credentials.get(req)
      .then((result) => {
        response = parseNavigatorCredentialsGetResponse(result);
        jresponse = btoa(JSON.stringify(response));
        document.getElementById("webauthn_request").value = jresponse;
        document.getElementById(formID).submit();
      })
      .catch((err) => {
        render_u2f_status(formID, err.name, err.message);
      });
    return
  }
  render_u2f_status(formID, "Failed Token Test", "navigator.credentials is not supported");
}
