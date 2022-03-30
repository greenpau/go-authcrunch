// Copyright 2022 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oauth

import (
	"fmt"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"testing"
)

func TestValidateJwksKey(t *testing.T) {
	var testcases = []struct {
		name      string
		input     *JwksKey
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name:      "empty key",
			input:     &JwksKey{},
			shouldErr: true,
			err:       errors.ErrJwksKeyIDEmpty,
		},
		{
			name: "unsupported algorithm with rsa keys",
			input: &JwksKey{
				KeyID:     "0",
				KeyType:   "RSA",
				Algorithm: "FOO",
			},
			shouldErr: true,
			err:       errors.ErrJwksKeyAlgoUnsupported.WithArgs("FOO", "0"),
		},
		{
			name: "unsupported algorithm with shared keys",
			input: &JwksKey{
				KeyID:        "0",
				KeyType:      "oct",
				Algorithm:    "FOO",
				SharedSecret: "FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ",
			},
			shouldErr: true,
			err:       errors.ErrJwksKeyAlgoUnsupported.WithArgs("FOO", "0"),
		},
		{
			name: "key type is empty",
			input: &JwksKey{
				KeyID:     "0",
				Algorithm: "RS256",
			},
			shouldErr: true,
			err:       errors.ErrJwksKeyTypeEmpty.WithArgs("0"),
		},
		{
			name: "key type is unsupported",
			input: &JwksKey{
				KeyID:     "0",
				Algorithm: "RS256",
				KeyType:   "FOO",
			},
			shouldErr: true,
			err:       errors.ErrJwksKeyTypeUnsupported.WithArgs("FOO", "0"),
		},
		{
			name: "key usage is unsupported",
			input: &JwksKey{
				KeyID:        "0",
				Algorithm:    "RS256",
				KeyType:      "RSA",
				PublicKeyUse: "FOO",
			},
			shouldErr: true,
			err:       errors.ErrJwksKeyUsageUnsupported.WithArgs("FOO", "0"),
		},
		{
			name: "key exponent is empty",
			input: &JwksKey{
				KeyID:        "0",
				Algorithm:    "RS256",
				KeyType:      "RSA",
				PublicKeyUse: "sig",
			},
			shouldErr: true,
			err:       errors.ErrJwksKeyExponentEmpty.WithArgs("0"),
		},
		{
			name: "key modulus is empty",
			input: &JwksKey{
				KeyID:        "0",
				Algorithm:    "RS256",
				KeyType:      "RSA",
				PublicKeyUse: "sig",
				Exponent:     "foo",
			},
			shouldErr: true,
			err:       errors.ErrJwksKeyModulusEmpty.WithArgs("0"),
		},
		{
			name: "key exponent decoding failure",
			input: &JwksKey{
				KeyID:        "0",
				Algorithm:    "RS256",
				KeyType:      "RSA",
				PublicKeyUse: "sig",
				Exponent:     "foo",
				Modulus:      "bar",
			},
			shouldErr: true,
			err:       errors.ErrJwksKeyDecodeExponent.WithArgs("0", "illegal base64 data at input byte 0"),
		},
		{
			name: "key exponent decoding failure",
			input: &JwksKey{
				KeyID:        "0",
				Algorithm:    "RS256",
				KeyType:      "RSA",
				PublicKeyUse: "sig",
				Exponent:     "foo",
				Modulus:      "/",
			},
			shouldErr: true,
			err:       errors.ErrJwksKeyDecodeModulus.WithArgs("0", "/===", "illegal base64 data at input byte 1"),
		},
		{
			name: "valid RSA256 key",
			input: &JwksKey{
				KeyID:        "wyMwK4A6CL9Qw11uofVeyQ119XyX-xykymkkXygZ5OM",
				Algorithm:    "RS256",
				KeyType:      "RSA",
				PublicKeyUse: "sig",
				Exponent:     "AQAB",
				Modulus: "ok6rvXu95337IxsDXrKzlIqw_I_zPDG8JyEw2CTOtNMoDi1QzpXQVMGj2snNEmvNYaCTmFf51" +
					"I-EDgeFLLexr40jzBXlg72quV4aw4yiNuxkigW0gMA92OmaT2jMRIdDZM8mVokoxyPfLub2YnXHFq0XuUUgkX_" +
					"TlutVhgGbyPN0M12teYZtMYo2AUzIRggONhHvnibHP0CPWDjCwSfp3On1Recn4DPxbn3DuGslF2myalmCtkujNcrhHLhwY" +
					"PP-yZFb8e0XSNTcQvXaQxAqmnWH6NXcOtaeWMQe43PNTAyNinhndgI8ozG3Hz-1NzHssDH_yk6UYFSszhDbWAzyqw",
			},
		},
		{
			name: "valid RSA256 key2",
			input: &JwksKey{
				KeyID:        "X5eXk4xyojNFum1kl2Ytv8dlNP4-c57dO6QGTVBwaNk",
				Algorithm:    "RS256",
				KeyType:      "RSA",
				PublicKeyUse: "sig",
				Exponent:     "AQAB",
				Modulus: "tVKUtcx_n9rt5afY_2WFNvU6PlFMggCatsZ3l4RjKxH0jgdLq6CScb0P3ZGX" +
					"YbPzXvmmLiWZizpb-h0qup5jznOvOr-Dhw9908584BSgC83YacjWNqEK3urxhyE2jWjwRm" +
					"2N95WGgb5mzE5XmZIvkvyXnn7X8dvgFPF5QwIngGsDG8LyHuJWlaDhr_EPLMW4wHvH0zZCu" +
					"RMARIJmmqiMy3VD4ftq4nS5s8vJL0pVSrkuNojtokp84AtkADCDU_BUhrc2sIgfnvZ03ko" +
					"CQRoZmWiHu86SuJZYkDFstVTVSR0hiXudFlfQ2rOhPlpObmku68lXw-7V-P7jwrQRFfQVXw",
			},
		},
		{
			name: "ec key curve is empty",
			input: &JwksKey{
				KeyID:   "0",
				KeyType: "EC",
			},
			shouldErr: true,
			err:       errors.ErrJwksKeyCurveEmpty.WithArgs("0"),
		},
		{
			name: "ec key curve is unsupported",
			input: &JwksKey{
				KeyID:   "0",
				KeyType: "EC",
				Curve:   "FOO",
			},
			shouldErr: true,
			err:       errors.ErrJwksKeyCurveUnsupported.WithArgs("FOO", "0"),
		},
		{
			name: "ec key curve has no coordinates",
			input: &JwksKey{
				KeyID:   "0",
				KeyType: "EC",
				Curve:   "P-256",
			},
			shouldErr: true,
			err:       errors.ErrJwksKeyCurveCoordNotFound.WithArgs("0"),
		},
		{
			name: "valid ES256 key",
			input: &JwksKey{
				KeyID:   "0",
				KeyType: "EC",
				Curve:   "P-256",
				CoordX:  "5lhEug5xK4xBDZ2nAbaxLtaLiv85bxJ7ePd1dkO23HQ",
				CoordY:  "4aiK72sBeUAGkv0TaLsmwokYUYyNxGsS5EMIKwsNIKk",
			},
		},
		{
			name: "valid ES384 key",
			input: &JwksKey{
				KeyID:   "0",
				KeyType: "EC",
				Curve:   "P-384",
				CoordX:  "Wyidjnd4VBA3nih1RZCJJ1EkKgHSApODejS_JCReqg6K0RhxaIzr9jh_NRslfjnd",
				CoordY:  "kcGQFUrRDHqcj1dTwL_SOyaf6cnkp8dL5NX70WiV3Ti97bFLrCE1dfRGpnCPW4R6",
			},
		},
		{
			name: "valid ES512 key",
			input: &JwksKey{
				KeyID:   "0",
				KeyType: "EC",
				Curve:   "P-521",
				CoordX:  "AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk",
				CoordY:  "ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2",
			},
		},
		{
			name: "shared secret key is empty",
			input: &JwksKey{
				KeyID:   "0",
				KeyType: "oct",
			},
			shouldErr: true,
			err:       errors.ErrJwksKeySharedSecretEmpty.WithArgs("0"),
		},
		{
			name: "valid HS256 key",
			input: &JwksKey{
				KeyID:        "fcd54a6f-9708-4805-ba9c-c05356066a56",
				Algorithm:    "HS256",
				KeyType:      "oct",
				SharedSecret: "FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ",
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("config: %v", tc.input))
			err := tc.input.Validate()
			if tests.EvalErrWithLog(t, err, nil, tc.shouldErr, tc.err, msgs) {
				return
			}
			// got := make(map[string]interface{})
			// got["config"] = config
			// tests.EvalObjectsWithLog(t, "config", tc.want, got, msgs)
		})
	}
}
