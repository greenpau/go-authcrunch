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

package qr

import (
	"fmt"
	"github.com/greenpau/aaasf/internal/tests"
	"testing"
)

func TestNewCode(t *testing.T) {
	testcases := []struct {
		name      string
		code      *Code
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name: "valid totp app token code with sha1",
			code: &Code{
				Secret:    "foobar",
				Type:      "totp",
				Label:     "app token",
				Period:    30,
				Algorithm: "sha1",
				Issuer:    "Self",
				Digits:    6,
			},
			want: map[string]interface{}{
				"code":    "otpauth://totp/app+token?secret=MZXW6YTBOI&issuer=Self&algorithm=sha1&digits=6&period=30",
				"encoded": "b3RwYXV0aDovL3RvdHAvYXBwK3Rva2VuP3NlY3JldD1NWlhXNllUQk9JJmlzc3Vlcj1TZWxmJmFsZ29yaXRobT1zaGExJmRpZ2l0cz02JnBlcmlvZD0zMA==",
			},
		},
		{
			name: "valid hotp app token code with sha1",
			code: &Code{
				Secret:    "foobar",
				Type:      "hotp",
				Label:     "app token",
				Algorithm: "sha1",
				Issuer:    "Self",
				Counter:   100,
			},
			want: map[string]interface{}{
				"code":    "otpauth://hotp/app+token?secret=MZXW6YTBOI&issuer=Self&algorithm=sha1&digits=6&counter=100&period=30",
				"encoded": "b3RwYXV0aDovL2hvdHAvYXBwK3Rva2VuP3NlY3JldD1NWlhXNllUQk9JJmlzc3Vlcj1TZWxmJmFsZ29yaXRobT1zaGExJmRpZ2l0cz02JmNvdW50ZXI9MTAwJnBlcmlvZD0zMA==",
			},
		},
		{
			name: "valid totp app token code with defaults",
			code: &Code{
				Secret: "foobar",
				Type:   "totp",
				Label:  "app token",
				Issuer: "Self",
			},
			want: map[string]interface{}{
				"code":    "otpauth://totp/app+token?secret=MZXW6YTBOI&issuer=Self&digits=6&period=30",
				"encoded": "b3RwYXV0aDovL3RvdHAvYXBwK3Rva2VuP3NlY3JldD1NWlhXNllUQk9JJmlzc3Vlcj1TZWxmJmRpZ2l0cz02JnBlcmlvZD0zMA==",
			},
		},
		{
			name: "invalid token code without type",
			code: &Code{
				Label:  "app token",
				Secret: "foobar",
			},
			shouldErr: true,
			err:       fmt.Errorf("token type must be either totp or hotp"),
		},
		{
			name: "invalid token code without label",
			code: &Code{
				Type: "totp",
			},
			shouldErr: true,
			err:       fmt.Errorf("token label must be set"),
		},
		{
			name: "invalid token code without secret",
			code: &Code{
				Type:  "totp",
				Label: "app token",
			},
			shouldErr: true,
			err:       fmt.Errorf("token secret must be set"),
		},
		{
			name: "invalid token code with secret too short",
			code: &Code{
				Type:   "totp",
				Label:  "app token",
				Secret: "12345",
			},
			shouldErr: true,
			err:       fmt.Errorf("token secret must be at least 6 characters long"),
		},
		{
			name: "invalid token code with invalid digits value",
			code: &Code{
				Type:   "totp",
				Label:  "app token",
				Secret: "foobar",
				Digits: 100,
			},
			shouldErr: true,
			err:       fmt.Errorf("digits must be between 4 and 8 numbers long"),
		},
		{
			name: "invalid token code with invalid period value",
			code: &Code{
				Type:   "totp",
				Label:  "app token",
				Secret: "foobar",
				Period: 360,
			},
			shouldErr: true,
			err:       fmt.Errorf("token period must be between 30 and 180 seconds"),
		},
		{
			name: "invalid hotp token code without counter",
			code: &Code{
				Type:   "hotp",
				Label:  "app token",
				Secret: "foobar",
			},
			shouldErr: true,
			err:       fmt.Errorf("hotp token counter must be set"),
		},
		{
			name: "invalid token code with invalid algorithm value",
			code: &Code{
				Type:      "totp",
				Label:     "app token",
				Secret:    "foobar",
				Algorithm: "foobar",
			},
			shouldErr: true,
			err:       fmt.Errorf("token algo must be SHA1, SHA256, or SHA512"),
		},
		{
			name:      "empty code",
			shouldErr: true,
			err:       fmt.Errorf("token label must be set"),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			if tc.code == nil {
				tc.code = NewCode()
			}
			err := tc.code.Build()
			if tests.EvalErrWithLog(t, err, "", tc.shouldErr, tc.err, msgs) {
				return
			}
			got := map[string]interface{}{
				"code":    tc.code.Get(),
				"encoded": tc.code.GetEncoded(),
			}
			tests.EvalObjectsWithLog(t, "qr code", tc.want, got, msgs)
		})
	}
}
