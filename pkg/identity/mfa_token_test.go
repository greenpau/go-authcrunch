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

package identity

import (
	"fmt"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"math"
	"testing"
	"time"
)

func generateTestPasscode(r *requests.Request, offset bool) error {
	var t time.Time
	if r.MfaToken.Passcode != "" || r.MfaToken.Period == 0 {
		return nil
	}
	if offset {
		t = time.Now().Add(-time.Second * time.Duration(r.MfaToken.Period)).UTC()
	} else {
		t = time.Now().UTC()
	}
	ts := uint64(math.Floor(float64(t.Unix()) / float64(r.MfaToken.Period)))
	code, err := generateMfaCode(r.MfaToken.Secret, r.MfaToken.Algorithm, r.MfaToken.Digits, ts)
	if err != nil {
		return err
	}
	r.MfaToken.Passcode = code
	return nil
}

func TestNewMfaToken(t *testing.T) {
	testcases := []struct {
		name      string
		req       *requests.Request
		shouldErr bool
		err       error
	}{
		{
			name: "valid totp app token with sha1",
			req: &requests.Request{
				MfaToken: requests.MfaToken{
					Comment:   "ms auth app",
					Type:      "totp",
					Secret:    "c71ca4c68bc14ec5b4ab8d3c3b63802c",
					Algorithm: "sha1",
					Period:    30,
					Digits:    6,
				},
			},
		},
		{
			name: "valid totp app token with sha256",
			req: &requests.Request{
				MfaToken: requests.MfaToken{
					Comment:   "ms auth app",
					Type:      "totp",
					Secret:    "c71ca4c68bc14ec5b4ab8d3c3b63802c",
					Algorithm: "sha256",
					Period:    30,
					Digits:    6,
				},
			},
		},
		{
			name: "valid totp app token with sha512",
			req: &requests.Request{
				MfaToken: requests.MfaToken{
					Comment:   "ms auth app",
					Type:      "totp",
					Secret:    "c71ca4c68bc14ec5b4ab8d3c3b63802c",
					Algorithm: "sha512",
					Period:    30,
					Digits:    6,
				},
			},
		},
		{
			name: "valid totp app token without algo",
			req: &requests.Request{
				MfaToken: requests.MfaToken{
					Comment: "ms auth app",
					Type:    "totp",
					Secret:  "c71ca4c68bc14ec5b4ab8d3c3b63802c",
					//Algorithm: "sha512",
					Period: 30,
					Digits: 6,
				},
			},
			shouldErr: true,
			err:       errors.ErrMfaTokenEmptyAlgorithm,
		},
		{
			name: "valid totp app token without invalid algo",
			req: &requests.Request{
				MfaToken: requests.MfaToken{
					Comment:   "ms auth app",
					Type:      "totp",
					Secret:    "c71ca4c68bc14ec5b4ab8d3c3b63802c",
					Algorithm: "sha2048",
					Period:    30,
					Digits:    6,
				},
			},
			shouldErr: true,
			err:       errors.ErrMfaTokenInvalidAlgorithm.WithArgs("sha2048"),
		},
		{
			name: "valid mfa token with long secret",
			req: &requests.Request{
				MfaToken: requests.MfaToken{
					Secret:    "TJhDkLuPEtRapebVbBmV81JgdxSmZhYwLisDhA2G57yju4gWH4IRJ8KCIviDaFP5lgjsBnTG7L7yeK5kb",
					Comment:   "ms auth app",
					Period:    30,
					Digits:    6,
					Type:      "totp",
					Algorithm: "sha1",
				},
			},
		},
		{
			name: "invalid mfa token with matching codes",
			req: &requests.Request{
				MfaToken: requests.MfaToken{
					Secret:   "c71ca4c68bc14ec5b4ab8d3c3b63802c",
					Comment:  "ms auth app",
					Period:   30,
					Type:     "totp",
					Passcode: "1234",
				},
			},
			shouldErr: true,
			err:       errors.ErrMfaTokenInvalidPasscode.WithArgs("digits length mismatch"),
		},
		{
			name: "invalid mfa token with codes being too long",
			req: &requests.Request{
				MfaToken: requests.MfaToken{
					Secret:   "c71ca4c68bc14ec5b4ab8d3c3b63802c",
					Comment:  "ms auth app",
					Period:   30,
					Type:     "totp",
					Passcode: "987654321",
				},
			},
			shouldErr: true,
			err:       errors.ErrMfaTokenInvalidPasscode.WithArgs("not 4-8 characters long"),
		},
		{
			name: "invalid mfa token with codes being too short",
			req: &requests.Request{
				MfaToken: requests.MfaToken{
					Secret:   "c71ca4c68bc14ec5b4ab8d3c3b63802c",
					Comment:  "ms auth app",
					Period:   30,
					Type:     "totp",
					Passcode: "123",
				},
			},
			shouldErr: true,
			err:       errors.ErrMfaTokenInvalidPasscode.WithArgs("not 4-8 characters long"),
		},
		{
			name: "valid u2f token",
			req: &requests.Request{
				MfaToken: requests.MfaToken{
					Comment: "u2f token",
					Type:    "u2f",
				},
				WebAuthn: requests.WebAuthn{
					Challenge: "gBRjbIXJu7YtwaHy5eM1MgpxeYIrbpxroOkGw0D7qFxW6HDA85Wxfnh3isb2utUPnVxW",
					Register: "eyJpZCI6ImZjZWNmN2FkLTk0MDMtNGYzZi05ZTE0LWJiYTZkN2FhNTc0YiIsInR5cGUiOiJwdWJs" +
						"aWMta2V5Iiwic3VjY2VzcyI6dHJ1ZSwiYXR0ZXN0YXRpb25PYmplY3QiOnsiYXR0U3RtdCI6eyJh" +
						"bGciOi03LCJzaWciOiJNRVFDSUJSUU1tMUdsUmdLKzdVUVhZY3VjMElXRXNNOW5XZWpTaTBjeWFR" +
						"UVV2RHlBaUJIdzlCZ1BkdDl0Qzd3NUl0cjI5eEZwb2RaZ204RHZYRkpuTE9veXM2R1p3PT0iLCJ4" +
						"NWMiOlsiTUlJQ3ZUQ0NBYVdnQXdJQkFnSUVOY1JURGpBTkJna3Foa2lHOXcwQkFRc0ZBREF1TVN3" +
						"d0tnWURWUVFERXlOWmRXSnBZMjhnVlRKR0lGSnZiM1FnUTBFZ1UyVnlhV0ZzSURRMU56SXdNRFl6" +
						"TVRBZ0Z3MHhOREE0TURFd01EQXdNREJhR0E4eU1EVXdNRGt3TkRBd01EQXdNRm93YmpFTE1Ba0dB" +
						"MVVFQmhNQ1UwVXhFakFRQmdOVkJBb01DVmwxWW1samJ5QkJRakVpTUNBR0ExVUVDd3daUVhWMGFH" +
						"VnVkR2xqWVhSdmNpQkJkSFJsYzNSaGRHbHZiakVuTUNVR0ExVUVBd3dlV1hWaWFXTnZJRlV5UmlC" +
						"RlJTQlRaWEpwWVd3Z09UQXlNRFU0TnpZMk1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNE" +
						"UWdBRVpxN05yaVVZamtvamx3QllRWVIvWmEzeDhJc0VJL3FGWTBxN3FZWXVGQzMzdWZRSjN5NU9Y" +
						"cDRHcjNvWE9lRlIxWGVRTUxXSzEzRzFYMngxWW40ckI2TnNNR293SWdZSkt3WUJCQUdDeEFvQ0JC" +
						"VXhMak11Tmk0eExqUXVNUzQwTVRRNE1pNHhMamN3RXdZTEt3WUJCQUdDNVJ3Q0FRRUVCQU1DQlNB" +
						"d0lRWUxLd1lCQkFHQzVSd0JBUVFFRWdRUTdvZ29lWEljU1JPWGRUMzh6cGNIS2pBTUJnTlZIUk1C" +
						"QWY4RUFqQUFNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUJBUUNxeUk4MmVCeERvOXRRbTNGaXJ0S1dL" +
						"OXN1dnBtcFVCUithcnBDaVZYRS9JdHdqc0w4cmtJaUczd0RRTnNHeENQc0VNNmhhVHM5WjhKaXlJ" +
						"TjVOOHFtb3JEKzNzRFBiMFNxejBmcGkzMUgybnJuV3diTUlnVmZKZEpJdC9sNkpTOHdrRFh1cU5E" +
						"NmJNeUlzMmxaMUpjb3dBY1lLSVBkNTRGUy9HWXhMVzB0bDlUWGFCK0RDZG9UQUZCYjdBNTBoVWFy" +
						"ZFQ4ZTF3WmhlNVZ4UVluSjZtZzlITjF2SjlVWUVOMC9ORWJtQlZnNnpFV0h5YkRNMlFySU4ySnpj" +
						"Y2JlcWRhVEI0UzBKdGdZVWhnb1IzdEN1QzRFeFk3cU4zcmJMUlUxbFNJa0NYQ2VLQ2d6TzZ2aDZz" +
						"OGZSR1BhaUdkRytOMFBjcHFHdU9LSkcrZXhEUS9IK1pBbiJdfSwiYXV0aERhdGEiOnsicnBJZEhh" +
						"c2giOiI0OTk2MGRlNTg4MGU4YzY4NzQzNDE3MGY2NDc2NjA1YjhmZTRhZWI5YTI4NjMyYzc5OTVj" +
						"ZjNiYTgzMWQ5NzYzIiwiZmxhZ3MiOnsiVVAiOnRydWUsIlJGVTEiOmZhbHNlLCJVViI6ZmFsc2Us" +
						"IlJGVTJhIjpmYWxzZSwiUkZVMmIiOmZhbHNlLCJSRlUyYyI6ZmFsc2UsIkFUIjp0cnVlLCJFRCI6" +
						"ZmFsc2V9LCJzaWduYXR1cmVDb3VudGVyIjozLCJjcmVkZW50aWFsRGF0YSI6eyJhYWd1aWQiOiI3" +
						"b2dvZVhJY1NST1hkVDM4enBjSEtnPT0iLCJjcmVkZW50aWFsSWQiOiJzU3RHTjA3NFNBVTAiLCJw" +
						"dWJsaWNLZXkiOnsia2V5X3R5cGUiOjIsImFsZ29yaXRobSI6LTcsImN1cnZlX3R5cGUiOjEsImN1" +
						"cnZlX3giOiJlYlU4cXZZTXZjSHhYTFQ1OEdkeDZLTjFMVldObFpvNjVmSjJxM1NzQnJBPSIsImN1" +
						"cnZlX3kiOiJZTDB3c1BhSTdRZUJsZXlFWFJOdFpqQU9PZUZiSlJ6MXg2aVZZUkx4RFlNPSJ9fSwi" +
						"ZXh0ZW5zaW9ucyI6e319LCJmbXQiOiJwYWNrZWQifSwiY2xpZW50RGF0YSI6eyJ0eXBlIjoid2Vi" +
						"YXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiQUFBTEFBQUFBQUJlQUFBQURnQUxBQUFBQU5jQUFB" +
						"YmFoUUFQQUFDeUFBQUFBQSIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJjcm9z" +
						"c09yaWdpbiI6ZmFsc2V9LCJkZXZpY2UiOnsibmFtZSI6IlVua25vd24gZGV2aWNlIiwidHlwZSI6" +
						"InVua25vd24ifX0K",
				},
			},
		},

		{
			name: "invalid mfa token type",
			req: &requests.Request{
				MfaToken: requests.MfaToken{
					Type: "foobar",
				},
			},
			shouldErr: true,
			err:       errors.ErrMfaTokenInvalidType.WithArgs("foobar"),
		},
		{
			name: "empty mfa token type",
			req: &requests.Request{
				MfaToken: requests.MfaToken{},
			},
			shouldErr: true,
			err:       errors.ErrMfaTokenTypeEmpty,
		},
		{
			name: "app token with invalid algorithm",
			req: &requests.Request{
				MfaToken: requests.MfaToken{
					Type:      "totp",
					Algorithm: "foobar",
				},
			},
			shouldErr: true,
			err:       errors.ErrMfaTokenInvalidAlgorithm.WithArgs("foobar"),
		},
		{
			name: "app token with invalid period",
			req: &requests.Request{
				MfaToken: requests.MfaToken{
					Type:      "totp",
					Algorithm: "sha1",
					Period:    10,
				},
			},
			shouldErr: true,
			err:       errors.ErrMfaTokenInvalidPeriod.WithArgs(10),
		},
		{
			name: "app token with invalid digits",
			req: &requests.Request{
				MfaToken: requests.MfaToken{
					Type:      "totp",
					Algorithm: "sha1",
					Period:    30,
					Digits:    2,
				},
			},
			shouldErr: true,
			err:       errors.ErrMfaTokenInvalidDigits.WithArgs(2),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			if tc.req.MfaToken.Type == "totp" && tc.req.MfaToken.Passcode == "" {
				if err := generateTestPasscode(tc.req, true); err != nil {
					if tests.EvalErrWithLog(t, err, "mfa token passcode", tc.shouldErr, tc.err, msgs) {
						return
					}
					t.Fatalf("unexpected failure during passcode generation: %v", err)
				}
			}

			token, err := NewMfaToken(tc.req)
			if tests.EvalErrWithLog(t, err, "new mfa token", tc.shouldErr, tc.err, msgs) {
				return
			}
			// t.Logf("token: %v", token)

			if tc.req.MfaToken.Type == "totp" {
				generateTestPasscode(tc.req, false)
				if err := token.ValidateCode(tc.req.MfaToken.Passcode); err != nil {
					t.Fatalf("unexpected failure during passcode validation: %v", err)
				}
				if err := token.ValidateCode("123456"); err == nil {
					t.Fatalf("unexpected success during passcode validation: %v", err)
				}
				if err := token.ValidateCode(""); err == nil {
					t.Fatalf("unexpected success during passcode validation: %v", err)
				}
				token.Algorithm = "sha2048"
				if err := token.ValidateCode(tc.req.MfaToken.Passcode); err == nil {
					t.Fatalf("unexpected success during passcode validation: %v", err)
				}
			}

			bundle := NewMfaTokenBundle()
			bundle.Add(token)
			bundle.Get()
			token.Disable()
		})
	}
}
