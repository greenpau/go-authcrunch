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

package ldap

import (
	"fmt"
	"github.com/greenpau/go-authcrunch/internal/tests"
	// "github.com/greenpau/go-authcrunch/internal/testutils"
	// "github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	// "github.com/greenpau/go-authcrunch/pkg/requests"
	logutil "github.com/greenpau/go-authcrunch/pkg/util/log"
	"go.uber.org/zap"
	"testing"
)

var (
	testConfig1 = &Config{
		Name:         "contoso.com",
		Realm:        "contoso.com",
		SearchBaseDN: "DC=CONTOSO,DC=COM",
		Servers: []AuthServer{
			{
				Address:          "ldaps://localhost:636",
				IgnoreCertErrors: true,
			},
		},
		BindUsername: "CN=authzsvc,OU=Service Accounts,OU=Administrative Accounts,DC=CONTOSO,DC=COM",
		BindPassword: "P@ssW0rd123",
		Groups: []UserGroup{
			{
				GroupDN: "CN=Admins,OU=Security,OU=Groups,DC=CONTOSO,DC=COM",
				Roles:   []string{"admin"},
			},
			{
				GroupDN: "CN=Editors,OU=Security,OU=Groups,DC=CONTOSO,DC=COM",
				Roles:   []string{"editor"},
			},
			{
				GroupDN: "CN=Viewers,OU=Security,OU=Groups,DC=CONTOSO,DC=COM",
				Roles:   []string{"viewer"},
			},
		},
	}
)

func TestNewIdentityStore(t *testing.T) {
	testcases := []struct {
		name              string
		config            *Config
		logger            *zap.Logger
		testRequests      bool
		publicKeysEnabled bool
		want              map[string]interface{}

		errPhase  string
		shouldErr bool
		err       error
	}{
		{
			name:   "test ldap store",
			config: testConfig1,
			logger: logutil.NewLogger(),
			want: map[string]interface{}{
				"name":  "contoso.com",
				"kind":  "ldap",
				"realm": "contoso.com",
				"config": map[string]interface{}{
					"name":                "contoso.com",
					"realm":               "contoso.com",
					"bind_password":       "**masked**",
					"bind_username":       "CN=authzsvc,OU=Service Accounts,OU=Administrative Accounts,DC=CONTOSO,DC=COM",
					"search_base_dn":      "DC=CONTOSO,DC=COM",
					"search_group_filter": "(&(uniqueMember=%s)(objectClass=groupOfUniqueNames))",
					"search_user_filter":  "(&(|(sAMAccountName=%s)(mail=%s))(objectclass=user))",
					"attributes": map[string]interface{}{
						"email":     "mail",
						"member_of": "memberOf",
						"name":      "givenName",
						"surname":   "sn",
						"username":  "sAMAccountName",
					},
					"servers": []interface{}{
						map[string]interface{}{
							"address":            "ldaps://localhost:636",
							"ignore_cert_errors": true,
						},
					},
					"groups": []interface{}{
						map[string]interface{}{
							"dn":    "CN=Admins,OU=Security,OU=Groups,DC=CONTOSO,DC=COM",
							"roles": []interface{}{"admin"},
						},
						map[string]interface{}{
							"dn":    "CN=Editors,OU=Security,OU=Groups,DC=CONTOSO,DC=COM",
							"roles": []interface{}{"editor"},
						},
						map[string]interface{}{
							"dn":    "CN=Viewers,OU=Security,OU=Groups,DC=CONTOSO,DC=COM",
							"roles": []interface{}{"viewer"},
						},
					},
				},
				"configured": true,
			},
		},
		{
			name: "test empty config name",
			config: &Config{
				Realm: "contoso.com",
			},
			logger:    logutil.NewLogger(),
			shouldErr: true,
			errPhase:  "initialize",
			err:       errors.ErrIdentityStoreConfigureNameEmpty,
		},
		{
			name: "test empty config realm",
			config: &Config{
				Name: "ldap_store",
			},
			logger:    logutil.NewLogger(),
			shouldErr: true,
			errPhase:  "initialize",
			err:       errors.ErrIdentityStoreConfigureRealmEmpty,
		},
		{
			name: "test empty logger",
			config: &Config{
				Name:  "ldap_store",
				Realm: "contoso.com",
			},
			shouldErr: true,
			errPhase:  "initialize",
			err:       errors.ErrIdentityStoreConfigureLoggerNotFound,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got := make(map[string]interface{})
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			// msgs = append(msgs, fmt.Sprintf("db path: %v", tc.config.Path))
			msgs = append(msgs, fmt.Sprintf("config:\n%v", tc.config))

			st, err := NewIdentityStore(tc.config, tc.logger)
			if tc.errPhase == "initialize" {
				if tests.EvalErrWithLog(t, err, "NewIdentityStore", tc.shouldErr, tc.err, msgs) {
					return
				}
			} else {
				if tests.EvalErrWithLog(t, err, "NewIdentityStore", false, nil, msgs) {
					return
				}
			}

			err = st.Configure()
			if tc.errPhase == "configure" {
				if tests.EvalErrWithLog(t, err, "IdentityStore.Configure", tc.shouldErr, tc.err, msgs) {
					return
				}
			} else {
				if tests.EvalErrWithLog(t, err, "IdentityStore.Configure", false, nil, msgs) {
					return
				}
			}

			got["name"] = st.GetName()
			got["realm"] = st.GetRealm()
			got["kind"] = st.GetKind()
			got["config"] = st.GetConfig()
			got["configured"] = st.Configured()

			tests.EvalObjectsWithLog(t, "config", tc.want, got, msgs)
		})
	}
}
