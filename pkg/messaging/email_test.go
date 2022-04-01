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
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"testing"
)

func TestValidateEmailProvider(t *testing.T) {
	testcases := []struct {
		name      string
		entry     *EmailProvider
		want      string
		shouldErr bool
		err       error
	}{
		{
			name: "test valid email provider config",
			entry: &EmailProvider{
				Name:        "default",
				Address:     "localhost",
				Protocol:    "smtp",
				Credentials: "default_email_creds",
				SenderEmail: "root@localhost",
			},
		},
		{
			name: "test email provider config with credentials and passwordless",
			entry: &EmailProvider{
				Name:         "default",
				Address:      "localhost",
				Protocol:     "smtp",
				Credentials:  "default_email_creds",
				Passwordless: true,
				SenderEmail:  "root@localhost",
			},
			shouldErr: true,
			err:       errors.ErrMessagingProviderCredentialsWithPasswordless,
		},
		{
			name: "test email provider config without credentials and passwordless",
			entry: &EmailProvider{
				Name:        "default",
				Address:     "localhost",
				Protocol:    "smtp",
				SenderEmail: "root@localhost",
			},
			shouldErr: true,
			err:       errors.ErrMessagingProviderKeyValueEmpty.WithArgs("credentials"),
		},
		{
			name: "test email provider config without address",
			entry: &EmailProvider{
				Name: "default",
				// Address:     "localhost",
				Protocol:    "smtp",
				Credentials: "default_email_creds",
				SenderEmail: "root@localhost",
			},
			shouldErr: true,
			err:       errors.ErrMessagingProviderKeyValueEmpty.WithArgs("address"),
		},
		{
			name: "test email provider config without protocol",
			entry: &EmailProvider{
				Name:    "default",
				Address: "localhost",
				// Protocol:    "smtp",
				Credentials: "default_email_creds",
				SenderEmail: "root@localhost",
			},
			shouldErr: true,
			err:       errors.ErrMessagingProviderKeyValueEmpty.WithArgs("protocol"),
		},
		{
			name: "test email provider config with unsupported protocol",
			entry: &EmailProvider{
				Name:        "default",
				Address:     "localhost",
				Protocol:    "foobar",
				Credentials: "default_email_creds",
				SenderEmail: "root@localhost",
			},
			shouldErr: true,
			err:       errors.ErrMessagingProviderProtocolUnsupported.WithArgs("foobar"),
		},
		{
			name: "test email provider config without sender email",
			entry: &EmailProvider{
				Name:        "default",
				Address:     "localhost",
				Protocol:    "smtp",
				Credentials: "default_email_creds",
				// SenderEmail: "root@localhost",
			},
			shouldErr: true,
			err:       errors.ErrMessagingProviderKeyValueEmpty.WithArgs("sender_email"),
		},
		{
			name:      "test email provider config without name",
			entry:     &EmailProvider{},
			shouldErr: true,
			err:       errors.ErrMessagingProviderKeyValueEmpty.WithArgs("name"),
		},
		{
			name: "test email provider config with invalid template",
			entry: &EmailProvider{
				Name:        "default",
				Address:     "localhost",
				Protocol:    "smtp",
				Credentials: "default_email_creds",
				SenderEmail: "root@localhost",
				Templates: map[string]string{
					"foo": "bar",
				},
			},
			shouldErr: true,
			err:       errors.ErrMessagingProviderInvalidTemplate.WithArgs("foo"),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.entry.Validate()
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
		})
	}
}
