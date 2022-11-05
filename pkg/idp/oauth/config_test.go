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
	"github.com/greenpau/go-authcrunch/pkg/authn/icons"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"testing"
)

func TestValidateConfig(t *testing.T) {
	testcases := []struct {
		name      string
		config    *Config
		want      *Config
		shouldErr bool
		err       error
	}{
		{
			name: "validate generic oauth config",
			config: &Config{
				Name:         "contoso",
				Realm:        "contoso",
				Driver:       "generic",
				ClientID:     "foo",
				ClientSecret: "bar",
				BaseAuthURL:  "https://localhost/oauth",
				MetadataURL:  "https://localhost/oauth/.well-known/openid-configuration",
			},
			want: &Config{
				Name:         "contoso",
				Realm:        "contoso",
				Driver:       "generic",
				ClientID:     "foo",
				ClientSecret: "bar",
				BaseAuthURL:  "https://localhost/oauth",
				// After the validation.
				ServerName:          "localhost",
				IdentityTokenName:   "id_token",
				Scopes:              []string{"openid", "email", "profile"},
				ResponseType:        []string{"code"},
				RequiredTokenFields: []string{"access_token", "id_token"},
				MetadataURL:         "https://localhost/oauth/.well-known/openid-configuration",
				LoginIcon: &icons.LoginIcon{
					ClassName:       "lab la-codepen la-2x",
					Color:           "white",
					BackgroundColor: "#324960",
					TextColor:       "#37474f",
				},
			},
		},
		{
			name: "validate facebook oauth config",
			config: &Config{
				Name:         "facebook",
				Realm:        "facebook",
				Driver:       "facebook",
				ClientID:     "foo",
				ClientSecret: "bar",
			},
			want: &Config{
				Name:         "facebook",
				Realm:        "facebook",
				Driver:       "facebook",
				ClientID:     "foo",
				ClientSecret: "bar",
				// After the validation.
				ServerName:          "www.facebook.com",
				IdentityTokenName:   "id_token",
				Scopes:              []string{"email"},
				BaseAuthURL:         "https://www.facebook.com/v12.0/dialog/",
				ResponseType:        []string{"code"},
				RequiredTokenFields: []string{"access_token"},
				AuthorizationURL:    "https://www.facebook.com/v12.0/dialog/oauth",
				TokenURL:            "https://graph.facebook.com/v12.0/oauth/access_token",
				LoginIcon: &icons.LoginIcon{
					ClassName:       "lab la-facebook la-2x",
					Color:           "white",
					BackgroundColor: "#0d47a1",
					Text:            "Facebook",
					TextColor:       "#37474f",
				},
			},
		},
		{
			name: "validate discord oauth config",
			config: &Config{
				Name:         "discord",
				Realm:        "discord",
				Driver:       "discord",
				ClientID:     "foo",
				ClientSecret: "bar",
			},
			want: &Config{
				Name:         "discord",
				Realm:        "discord",
				Driver:       "discord",
				ClientID:     "foo",
				ClientSecret: "bar",
				// After the validation.
				ServerName:          "discord.com",
				IdentityTokenName:   "id_token", // maybe change this to access_token
				Scopes:              []string{"identify"},
				BaseAuthURL:         "https://discord.com/oauth2",
				ResponseType:        []string{"code"},
				RequiredTokenFields: []string{"access_token"},
				AuthorizationURL:    "https://discord.com/oauth2/authorize",
				TokenURL:            "https://discord.com/api/oauth2/token",
				LoginIcon: &icons.LoginIcon{
					ClassName:       "lab la-discord la-2x",
					Color:           "white",
					Text: 					 "Discord",
					BackgroundColor: "#5865f2",
					TextColor:       "#37474f",
				},
			},
		},
		{
			name: "validate nextcloud oauth config",
			config: &Config{
				Name:         "nextcloud",
				Realm:        "nextcloud",
				Driver:       "nextcloud",
				ClientID:     "foo",
				ClientSecret: "bar",
				BaseAuthURL:  "https://localhost/oauth",
			},
			want: &Config{
				Name:         "nextcloud",
				Realm:        "nextcloud",
				Driver:       "nextcloud",
				ClientID:     "foo",
				ClientSecret: "bar",
				BaseAuthURL:  "https://localhost/oauth",
				// After the validation.
				ServerName:          "localhost",
				IdentityTokenName:   "id_token",
				Scopes:              []string{"email"},
				ResponseType:        []string{"code"},
				RequiredTokenFields: []string{"access_token", "id_token"},
				AuthorizationURL:    "https://localhost/oauth/apps/oauth2/authorize",
				TokenURL:            "https://localhost/oauth/apps/oauth2/api/v1/token",
				LoginIcon: &icons.LoginIcon{
					ClassName:       "lab la-codepen la-2x",
					Color:           "white",
					BackgroundColor: "#324960",
					TextColor:       "#37474f",
				},
			},
		},
		{
			name: "validate okta oauth config",
			config: &Config{
				Name:         "okta",
				Realm:        "okta",
				Driver:       "okta",
				ClientID:     "foo",
				ClientSecret: "bar",
				DomainName:   "foo.okta.dev",
				ServerID:     "default",
				Scopes: []string{
					"openid", "email", "profile", "groups",
				},
			},
			want: &Config{
				Name:         "okta",
				Realm:        "okta",
				Driver:       "okta",
				ClientID:     "foo",
				ClientSecret: "bar",
				DomainName:   "foo.okta.dev",
				ServerID:     "default",
				Scopes: []string{
					"openid", "email", "profile", "groups",
				},
				// After the validation.
				ServerName:          "foo.okta.dev",
				IdentityTokenName:   "id_token",
				BaseAuthURL:         "https://foo.okta.dev/oauth2/default/",
				MetadataURL:         "https://foo.okta.dev/oauth2/default/.well-known/openid-configuration?client_id=foo",
				ResponseType:        []string{"code"},
				RequiredTokenFields: []string{"access_token", "id_token"},
				LoginIcon: &icons.LoginIcon{
					ClassName:       "lab la-codepen la-2x",
					Color:           "white",
					BackgroundColor: "#324960",
					TextColor:       "#37474f",
				},
			},
		},
		{
			name: "validate google oauth config",
			config: &Config{
				Name:         "google",
				Realm:        "google",
				Driver:       "google",
				ClientID:     "foo",
				ClientSecret: "bar",
			},
			want: &Config{
				Name:   "google",
				Realm:  "google",
				Driver: "google",
				// ClientID:     "foo",
				ClientSecret: "bar",
				// After the validation.
				ClientID:            "foo.apps.googleusercontent.com",
				ServerName:          "accounts.google.com",
				IdentityTokenName:   "id_token",
				Scopes:              []string{"openid", "email", "profile"},
				BaseAuthURL:         "https://accounts.google.com/o/oauth2/v2/",
				MetadataURL:         "https://accounts.google.com/.well-known/openid-configuration",
				ResponseType:        []string{"code"},
				RequiredTokenFields: []string{"access_token", "id_token"},
				LoginIcon: &icons.LoginIcon{
					ClassName:       "lab la-google la-2x",
					Color:           "white",
					BackgroundColor: "#e53935",
					Text:            "Google",
					TextColor:       "#37474f",
				},
			},
		},
		{
			name: "validate github oauth config",
			config: &Config{
				Name:         "github",
				Realm:        "github",
				Driver:       "github",
				ClientID:     "foo",
				ClientSecret: "bar",
			},
			want: &Config{
				Name:         "github",
				Realm:        "github",
				Driver:       "github",
				ClientID:     "foo",
				ClientSecret: "bar",
				// After the validation.
				ServerName:        "github.com",
				IdentityTokenName: "id_token",
				// Scopes:              []string{"openid", "email", "profile"},
				Scopes:              []string{"read:user"},
				BaseAuthURL:         "https://github.com/login/oauth/",
				ResponseType:        []string{"code"},
				RequiredTokenFields: []string{"access_token"},
				AuthorizationURL:    "https://github.com/login/oauth/authorize",
				TokenURL:            "https://github.com/login/oauth/access_token",
				LoginIcon: &icons.LoginIcon{
					ClassName:       "lab la-github la-2x",
					Color:           "#f6f8fa",
					BackgroundColor: "#24292f",
					Text:            "Github",
					TextColor:       "#37474f",
				},
			},
		},
		{
			name: "validate gitlab oauth config",
			config: &Config{
				Name:         "gitlab",
				Realm:        "gitlab",
				Driver:       "gitlab",
				ClientID:     "foo",
				ClientSecret: "bar",
				Scopes: []string{
					"openid", "email", "profile",
				},
				UserGroupFilters: []string{
					"barfoo", "^a",
				},
			},
			want: &Config{
				Name:         "gitlab",
				Realm:        "gitlab",
				Driver:       "gitlab",
				ClientID:     "foo",
				ClientSecret: "bar",
				Scopes: []string{
					"openid", "email", "profile",
				},
				UserGroupFilters: []string{
					"barfoo", "^a",
				},
				// After the validation.
				DomainName:          "gitlab.com",
				ServerName:          "gitlab.com",
				IdentityTokenName:   "id_token",
				BaseAuthURL:         "https://gitlab.com/",
				MetadataURL:         "https://gitlab.com/.well-known/openid-configuration",
				ResponseType:        []string{"code"},
				RequiredTokenFields: []string{"access_token", "id_token"},
				LoginIcon: &icons.LoginIcon{
					ClassName:       "lab la-gitlab la-2x",
					Color:           "white",
					BackgroundColor: "#fc6d26",
					TextColor:       "#37474f",
				},
			},
		},
		{
			name: "validate azure oauth config",
			config: &Config{
				Name:         "azure",
				Realm:        "azure",
				Driver:       "azure",
				ClientID:     "foo",
				ClientSecret: "bar",
			},
			want: &Config{
				Name:         "azure",
				Realm:        "azure",
				Driver:       "azure",
				ClientID:     "foo",
				ClientSecret: "bar",
				// After the validation.
				ServerName:          "login.microsoftonline.com",
				TenantID:            "common",
				IdentityTokenName:   "id_token",
				Scopes:              []string{"openid", "email", "profile"},
				BaseAuthURL:         "https://login.microsoftonline.com/common/oauth2/v2.0/",
				MetadataURL:         "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
				ResponseType:        []string{"code"},
				RequiredTokenFields: []string{"access_token", "id_token"},
				LoginIcon: &icons.LoginIcon{
					ClassName:       "lab la-windows la-2x",
					Color:           "white",
					BackgroundColor: "#03a9f4",
					Text:            "Azure",
					TextColor:       "#37474f",
				},
			},
		},
		{
			name: "validate gitlab oauth config with custom domain name",
			config: &Config{
				Name:         "gitlab",
				Realm:        "gitlab",
				Driver:       "gitlab",
				ClientID:     "foo",
				ClientSecret: "bar",
				DomainName:   "gitlab.contoso.com",
				Scopes: []string{
					"openid", "email", "profile",
				},
				UserGroupFilters: []string{
					"barfoo", "^a",
				},
			},
			want: &Config{
				Name:         "gitlab",
				Realm:        "gitlab",
				Driver:       "gitlab",
				ClientID:     "foo",
				ClientSecret: "bar",
				DomainName:   "gitlab.contoso.com",
				Scopes: []string{
					"openid", "email", "profile",
				},
				UserGroupFilters: []string{
					"barfoo", "^a",
				},
				// After the validation.
				ServerName:          "gitlab.contoso.com",
				IdentityTokenName:   "id_token",
				BaseAuthURL:         "https://gitlab.contoso.com/",
				MetadataURL:         "https://gitlab.contoso.com/.well-known/openid-configuration",
				ResponseType:        []string{"code"},
				RequiredTokenFields: []string{"access_token", "id_token"},
				LoginIcon: &icons.LoginIcon{
					ClassName:       "lab la-gitlab la-2x",
					Color:           "white",
					BackgroundColor: "#fc6d26",
					TextColor:       "#37474f",
				},
			},
		},
		{
			name: "test okta oauth config without server id",
			config: &Config{
				Name:         "okta",
				Realm:        "okta",
				Driver:       "okta",
				ClientID:     "foo",
				ClientSecret: "bar",
			},
			shouldErr: true,
			err:       errors.ErrIdentityProviderConfig.WithArgs("server id not found"),
		},
		{
			name: "test okta oauth config without domain name",
			config: &Config{
				Name:         "okta",
				Realm:        "okta",
				Driver:       "okta",
				ClientID:     "foo",
				ClientSecret: "bar",
				ServerID:     "default",
			},
			shouldErr: true,
			err:       errors.ErrIdentityProviderConfig.WithArgs("domain name not found"),
		},
		{
			name: "test empty config name",
			config: &Config{
				Realm: "contoso",
			},
			shouldErr: true,
			err:       errors.ErrIdentityProviderConfigureNameEmpty,
		},
		{
			name: "test empty config realm",
			config: &Config{
				Name: "contoso",
			},
			shouldErr: true,
			err:       errors.ErrIdentityProviderConfigureRealmEmpty,
		},
		{
			name: "test empty client id",
			config: &Config{
				Name:   "contoso",
				Realm:  "contoso",
				Driver: "generic",
				// ClientID: "foo",
				// ClientSecret: "bar",
				// BaseAuthURL:  "https://localhost/oauth/",
			},
			shouldErr: true,
			err:       errors.ErrIdentityProviderConfig.WithArgs("client id not found"),
		},
		{
			name: "test empty client secret",
			config: &Config{
				Name:     "contoso",
				Realm:    "contoso",
				Driver:   "generic",
				ClientID: "foo",
				// ClientSecret: "bar",
				// BaseAuthURL:  "https://localhost/oauth/",
			},
			shouldErr: true,
			err:       errors.ErrIdentityProviderConfig.WithArgs("client secret not found"),
		},
		{
			name: "test unsupported identity token name",
			config: &Config{
				Name:         "contoso",
				Realm:        "contoso",
				Driver:       "generic",
				ClientID:     "foo",
				ClientSecret: "bar",
				// BaseAuthURL:  "https://localhost/oauth/",
				IdentityTokenName: "foobar",
			},
			shouldErr: true,
			err: errors.ErrIdentityProviderConfig.WithArgs(
				fmt.Errorf("identity token name %q is unsupported", "foobar"),
			),
		},
		{
			name: "test empty base auth url",
			config: &Config{
				Name:         "contoso",
				Realm:        "contoso",
				Driver:       "generic",
				ClientID:     "foo",
				ClientSecret: "bar",
				// BaseAuthURL:  "https://localhost/oauth/",
			},
			shouldErr: true,
			err:       errors.ErrIdentityProviderConfig.WithArgs("base authentication url not found"),
		},
		{
			name: "test invalid base auth url",
			config: &Config{
				Name:         "contoso",
				Realm:        "contoso",
				Driver:       "generic",
				ClientID:     "foo",
				ClientSecret: "bar",
				BaseAuthURL:  "http://^localhost",
				MetadataURL:  "https://localhost/oauth/.well-known/openid-configuration",
			},
			shouldErr: true,
			err: errors.ErrIdentityProviderConfig.WithArgs(
				fmt.Errorf(
					"failed to parse base auth url %q: %v",
					"http://^localhost",
					`parse "http://^localhost": invalid character "^" in host name`,
				),
			),
		},
		{
			name: "test invalid user group regex",
			config: &Config{
				Name:         "contoso",
				Realm:        "contoso",
				Driver:       "generic",
				ClientID:     "foo",
				ClientSecret: "bar",
				BaseAuthURL:  "https://localhost/oauth",
				MetadataURL:  "https://localhost/oauth/.well-known/openid-configuration",
				UserGroupFilters: []string{
					"foo(",
				},
			},
			shouldErr: true,
			err: errors.ErrIdentityProviderConfig.WithArgs(
				fmt.Errorf(
					"invalid user group pattern %q: %v",
					"foo(",
					"error parsing regexp: missing closing ): `foo(`",
				),
			),
		},
		{
			name: "test invalid user org regex",
			config: &Config{
				Name:         "contoso",
				Realm:        "contoso",
				Driver:       "generic",
				ClientID:     "foo",
				ClientSecret: "bar",
				BaseAuthURL:  "https://localhost/oauth",
				MetadataURL:  "https://localhost/oauth/.well-known/openid-configuration",
				UserOrgFilters: []string{
					"foo(",
				},
			},
			shouldErr: true,
			err: errors.ErrIdentityProviderConfig.WithArgs(
				fmt.Errorf(
					"invalid user org pattern %q: %v",
					"foo(",
					"error parsing regexp: missing closing ): `foo(`",
				),
			),
		},
		{
			name: "test unsupported driver name",
			config: &Config{
				Name:         "contoso",
				Realm:        "contoso",
				Driver:       "foobar",
				ClientID:     "foo",
				ClientSecret: "bar",
				BaseAuthURL:  "https://localhost/oauth",
				MetadataURL:  "https://localhost/oauth/.well-known/openid-configuration",
			},
			shouldErr: true,
			err: errors.ErrIdentityProviderConfig.WithArgs(
				fmt.Errorf("driver %q is unsupported", "foobar"),
			),
		},
		{
			name: "test empty driver name",
			config: &Config{
				Name:  "contoso",
				Realm: "contoso",
				// Driver:       "foobar",
				ClientID:     "foo",
				ClientSecret: "bar",
				BaseAuthURL:  "https://localhost/oauth/",
			},
			shouldErr: true,
			err:       errors.ErrIdentityProviderConfig.WithArgs("driver name not found"),
		},
		{
			name: "test delayed start",
			config: &Config{
				Name:         "contoso",
				Realm:        "contoso",
				Driver:       "generic",
				ClientID:     "foo",
				ClientSecret: "bar",
				BaseAuthURL:  "https://localhost/oauth",
				MetadataURL:  "https://localhost/oauth/.well-known/openid-configuration",
				DelayStart:   10,
			},
			want: &Config{
				Name:         "contoso",
				Realm:        "contoso",
				Driver:       "generic",
				ClientID:     "foo",
				ClientSecret: "bar",
				BaseAuthURL:  "https://localhost/oauth",
				MetadataURL:  "https://localhost/oauth/.well-known/openid-configuration",
				DelayStart:   10,
				// After the validation.
				ServerName:          "localhost",
				IdentityTokenName:   "id_token",
				Scopes:              []string{"openid", "email", "profile"},
				RetryAttempts:       2,
				RetryInterval:       10,
				ResponseType:        []string{"code"},
				RequiredTokenFields: []string{"access_token", "id_token"},
				LoginIcon: &icons.LoginIcon{
					ClassName:       "lab la-codepen la-2x",
					Color:           "white",
					BackgroundColor: "#324960",
					TextColor:       "#37474f",
				},
			},
		},
		{
			name: "test custom retry attempts",
			config: &Config{
				Name:          "contoso",
				Realm:         "contoso",
				Driver:        "generic",
				ClientID:      "foo",
				ClientSecret:  "bar",
				BaseAuthURL:   "https://localhost/oauth",
				MetadataURL:   "https://localhost/oauth/.well-known/openid-configuration",
				RetryAttempts: 10,
			},
			want: &Config{
				Name:          "contoso",
				Realm:         "contoso",
				Driver:        "generic",
				ClientID:      "foo",
				ClientSecret:  "bar",
				BaseAuthURL:   "https://localhost/oauth",
				MetadataURL:   "https://localhost/oauth/.well-known/openid-configuration",
				RetryAttempts: 10,
				// After the validation.
				ServerName:          "localhost",
				IdentityTokenName:   "id_token",
				Scopes:              []string{"openid", "email", "profile"},
				RetryInterval:       5,
				ResponseType:        []string{"code"},
				RequiredTokenFields: []string{"access_token", "id_token"},
				LoginIcon: &icons.LoginIcon{
					ClassName:       "lab la-codepen la-2x",
					Color:           "white",
					BackgroundColor: "#324960",
					TextColor:       "#37474f",
				},
			},
		},
		{
			name: "test config with predefined keys",
			config: &Config{
				Name:                "contoso",
				Realm:               "contoso",
				Driver:              "generic",
				ClientID:            "foo",
				ClientSecret:        "bar",
				BaseAuthURL:         "https://localhost/oauth",
				ResponseType:        []string{"code"},
				RequiredTokenFields: []string{"access_token"},
				AuthorizationURL:    "https://localhost/oauth/authorize",
				TokenURL:            "https://localhost/oauth/access_token",
				JwksKeys: map[string]string{
					"87329db33bf": "../../../testdata/oauth/87329db33bf_pub.pem",
				},
			},
			want: &Config{
				Name:                "contoso",
				Realm:               "contoso",
				Driver:              "generic",
				ClientID:            "foo",
				ClientSecret:        "bar",
				BaseAuthURL:         "https://localhost/oauth",
				ResponseType:        []string{"code"},
				RequiredTokenFields: []string{"access_token"},
				AuthorizationURL:    "https://localhost/oauth/authorize",
				TokenURL:            "https://localhost/oauth/access_token",
				JwksKeys: map[string]string{
					"87329db33bf": "../../../testdata/oauth/87329db33bf_pub.pem",
				},

				// After the validation.
				ServerName:        "localhost",
				IdentityTokenName: "id_token",
				Scopes:            []string{"openid", "email", "profile"},
				LoginIcon: &icons.LoginIcon{
					ClassName:       "lab la-codepen la-2x",
					Color:           "white",
					BackgroundColor: "#324960",
					TextColor:       "#37474f",
				},
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}

			err := tc.config.Validate()

			if tests.EvalErrWithLog(t, err, "Config.Validate", tc.shouldErr, tc.err, msgs) {
				return
			}

			tests.EvalObjectsWithLog(t, "Config.Content", tc.want, tc.config, msgs)
		})
	}
}
