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

package waf

import (
	"testing"
)

func TestMalformedInput(t *testing.T) {
	testcases := []struct {
		name    string
		kind    string
		entries []string
		want    bool
	}{
		{
			name: "test valid X-Forwarded-Proto header value",
			kind: "X-Forwarded-Proto",
			entries: []string{
				``,
				`http`,
				`https`,
			},
			want: false,
		},
		{
			name: "test malformed X-Forwarded-Proto header value",
			kind: "X-Forwarded-Proto",
			entries: []string{
				`123`,
				`F`,
				`ldap`,
			},
			want: true,
		},
		{
			name: "test valid X-Forwarded-Host header value",
			kind: "X-Forwarded-Host",
			entries: []string{
				``,
				`authcrunch.com`,
				`host1.authcrunch.com`,
				`مشوه`,
				`中国.icom.museum`,
				`κυπρος.icom.museum`,
			},
			want: false,
		},
		{
			name: "test malformed X-Forwarded-Host header value",
			kind: "X-Forwarded-Host",
			entries: []string{
				`f`,
				`malformed!.com`,
				`المغرب.icom.🤣museum`,
			},
			want: true,
		},
		{
			name:    "test valid X-Forwarded-Port header value",
			kind:    "X-Forwarded-Port",
			entries: []string{``, `80`, `443`},
			want:    false,
		},
		{
			name:    "test malformed X-Forwarded-Port header value",
			kind:    "X-Forwarded-Port",
			entries: []string{`foo`, `1000000`, `99999`, `00000`},
			want:    true,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var got bool
			var failed bool

			for _, entry := range tc.entries {
				switch tc.kind {
				case "X-Forwarded-Proto":
					got = IsMalformedForwardedProto(entry, 2, 10)
				case "X-Forwarded-Host":
					got = IsMalformedForwardedHost(entry, 2, 255)
				case "X-Forwarded-Port":
					got = IsMalformedForwardedPort(entry, 2, 5)
				default:
					t.Fatalf("unsuppored check type: %s", tc.kind)
				}
				if tc.want != got {
					t.Logf("got %t when expected %t: %q", got, tc.want, entry)
					failed = true
				}
			}

			if failed {
				t.Fatalf("test failed")
			}

		})
	}
}
