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

func TestNewEmailProvider(t *testing.T) {
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
				"template password_recovery tmpl/custom_password_recovery.template",
				"template registration_confirmation tmpl/registration_confirmation.template",
				"template registration_ready tmpl/registration_ready.template",
				"template registration_verdict tmpl/registration_verdict.template",
				"template mfa_otp tmpl/mfa_otp.template",
				"bcc foo@localhost bar@localhost",
				"bcc baz@localhost",
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
				"templates": map[string]string{
					"mfa_otp":                   "tmpl/mfa_otp.template",
					"password_recovery":         "tmpl/custom_password_recovery.template",
					"registration_confirmation": "tmpl/registration_confirmation.template",
					"registration_ready":        "tmpl/registration_ready.template",
					"registration_verdict":      "tmpl/registration_verdict.template",
				},
				"bcc": []string{"foo@localhost", "bar@localhost", "baz@localhost"},
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
			name: "test malformed name instruction",
			entry: []string{
				"name foo bar",
			},
			shouldErr: true,
			err:       errors.ErrMessagingMalformedInstructionBadSyntax.WithArgs("name foo bar"),
		},
		{
			name: "test malformed address instruction",
			entry: []string{
				"name default",
				"address localhost foo",
			},
			shouldErr: true,
			err:       errors.ErrMessagingMalformedInstructionBadSyntax.WithArgs("address localhost foo"),
		},
		{
			name: "test malformed bcc instruction",
			entry: []string{
				"name default",
				"bcc",
			},
			shouldErr: true,
			err:       errors.ErrMessagingMalformedInstructionBadSyntax.WithArgs("bcc"),
		},
		{
			name: "test malformed template instruction",
			entry: []string{
				"name default",
				"template foo",
			},
			shouldErr: true,
			err:       errors.ErrMessagingMalformedInstructionBadSyntax.WithArgs("template foo"),
		},
		{
			name: "test malformed protocol instruction",
			entry: []string{
				"name default",
				"kind email",
				"address localhost",
				"protocol smtp foo",
			},
			shouldErr: true,
			err:       errors.ErrMessagingMalformedInstructionBadSyntax.WithArgs("protocol smtp foo"),
		},
		{
			name: "test malformed credentials instruction",
			entry: []string{
				"name default",
				"kind email",
				"address localhost",
				"credentials default_email_creds foo",
			},
			shouldErr: true,
			err:       errors.ErrMessagingMalformedInstructionBadSyntax.WithArgs("credentials default_email_creds foo"),
		},
		{
			name: "test malformed sender instruction",
			entry: []string{
				"name default",
				"kind email",
				"address localhost",
				"credentials default_email_creds",
				"passwordless",
				"protocol smtp",
				"sender",
			},
			shouldErr: true,
			err:       errors.ErrMessagingMalformedInstructionBadSyntax.WithArgs("sender"),
		},
		{
			name: "test malformed kind instruction",
			entry: []string{
				"kind file bar",
			},
			shouldErr: true,
			err:       errors.ErrMessagingMalformedInstructionBadSyntax.WithArgs("kind file bar"),
		},
		{
			name: "test unsupported instruction",
			entry: []string{
				"foo bar",
			},
			shouldErr: true,
			err:       errors.ErrMessagingMalformedInstructionUnsupportedKey.WithArgs("foo bar"),
		},
		{
			name: "test unsupported provider kind",
			entry: []string{
				"kind foo",
			},
			shouldErr: true,
			err:       errors.ErrMessagingMalformedInstructionKindMismatch.WithArgs(EmailMessagingProviderKindLabel, "foo"),
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
			provider, err := NewEmailProvider(tc.entry)
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

			tests.EvalObjects(t, "NewEmailProvider", tc.want, got)
		})
	}
}

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
