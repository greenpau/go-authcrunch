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

package messaging

import (
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"

	"testing"
)

func TestNewProvider(t *testing.T) {
	testcases := []struct {
		name      string
		entry     []string
		want      map[string]any
		shouldErr bool
		err       error
	}{
		{
			name: "test valid email provider config",
			entry: []string{
				"name default",
				"kind email",
				"address localhost",
				"credentials default_email_creds",
				"protocol smtp",
				cfgutil.EncodeArgs([]string{"sender", "root@localhost", "My Auth Portal"}),
			},
			want: map[string]any{
				"address":      "localhost",
				"kind":         "email",
				"passwordless": false,
				"credentials":  "default_email_creds",
				"name":         "default",
				"protocol":     "smtp",
				"sender_email": "root@localhost",
				"sender_name":  "My Auth Portal",
			},
		},
		{
			name: "test malformed email provider config",
			entry: []string{
				"kind email",
			},
			shouldErr: true,
			err:       errors.ErrMessagingProviderKeyValueEmpty.WithArgs("name"),
		},
		{
			name: "test valid file provider config",
			entry: []string{
				"name default",
				"kind file",
				"root_dir /var/spool/auth-messaging/",
				cfgutil.EncodeArgs([]string{"sender", "root@localhost", "My Auth Portal"}),
			},
			want: map[string]any{
				"name":         "default",
				"root_dir":     "/var/spool/auth-messaging/",
				"sender_email": "root@localhost",
				"sender_name":  "My Auth Portal",
				"kind":         "file",
			},
		},
		{
			name: "test malformed file provider config",
			entry: []string{
				"kind file",
			},
			shouldErr: true,
			err:       errors.ErrMessagingProviderKeyValueEmpty.WithArgs("name"),
		},
		{
			name: "test unsupported provider config",
			entry: []string{
				"kind foo",
			},
			shouldErr: true,
			err:       errors.ErrMessagingUnsupportedKind.WithArgs("foo"),
		},
		{
			name: "bad messaging provider instruction encoding",
			entry: []string{
				"",
			},
			shouldErr: true,
			err:       errors.ErrMessagingMalformedInstructionThrown.WithArgs("EOF", ""),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := NewProvider(tc.entry)
			if err != nil {
				if !tc.shouldErr {
					t.Fatalf("expected success, got: %v", err)
				}
				if diff := cmp.Diff(err.Error(), tc.err.Error()); diff != "" {
					t.Fatalf("unexpected error: %v, want: %v", err, tc.err)
				}
				return
			}
			if tc.shouldErr {
				t.Fatalf("unexpected success, want: %v", tc.err)
			}

			got := provider.AsMap()
			want := tests.Unpack(t, tc.want)

			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("NewProvider() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
