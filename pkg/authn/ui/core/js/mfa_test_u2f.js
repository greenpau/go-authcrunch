/**
 * Authentication Portal Scripts
 * Author: Paul Greenberg github.com/greenpau
 */

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

function authenticate_u2f_token(formID, btnID, params) {
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
  let btn = document.getElementById(btnID);
  let form = document.getElementById(formID);
  btn.classList.add("hide");
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
