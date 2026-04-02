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

package kms

import (
	"fmt"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	logutil "github.com/greenpau/go-authcrunch/pkg/util/log"
)

type TestUserClaims struct {
	Roles         []string               `json:"roles,omitempty" xml:"roles" yaml:"roles,omitempty"`
	Role          string                 `json:"role,omitempty" xml:"role" yaml:"role,omitempty"`
	Groups        []string               `json:"groups,omitempty" xml:"groups" yaml:"groups,omitempty"`
	Group         string                 `json:"group,omitempty" xml:"group" yaml:"group,omitempty"`
	Organizations []string               `json:"org,omitempty" xml:"org" yaml:"org,omitempty"`
	Address       string                 `json:"addr,omitempty" xml:"addr" yaml:"addr,omitempty"`
	AppMetadata   map[string]interface{} `json:"app_metadata,omitempty" xml:"app_metadata" yaml:"app_metadata,omitempty"`
	jwtlib.RegisteredClaims
}

func TestKeystoreOperators(t *testing.T) {
	testcases := []struct {
		name            string
		config          []string
		signTokenName   string
		signAlgorithm   string
		verifyTokenName string
		sign            bool
		user            *user.User
		claims          *TestUserClaims
		roles           []string
		addr            string
		operatorErr     bool
		operatorSignErr bool
		err             error
		shouldErr       bool
	}{
		{
			name: "user with roles claims and ip address",
			config: []string{
				"crypto key sign-verify foobar",
			},
			claims: &TestUserClaims{
				Roles: []string{"admin", "editor", "viewer"},
				RegisteredClaims: jwtlib.RegisteredClaims{
					ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(10 * time.Minute)),
					IssuedAt:  jwtlib.NewNumericDate(time.Now().Add(10 * time.Minute * -1)),
					NotBefore: jwtlib.NewNumericDate(time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC)),
					Subject:   "smithj@outlook.com",
				},
			},
			roles: []string{"admin", "editor", "viewer"},
			addr:  "127.0.0.1",
		},
		{
			name: "user with groups claims and ip address",
			config: []string{
				"crypto key sign-verify foobar",
			},
			claims: &TestUserClaims{
				Groups: []string{"admin", "editor", "viewer"},
				RegisteredClaims: jwtlib.RegisteredClaims{
					ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(10 * time.Minute)),
					IssuedAt:  jwtlib.NewNumericDate(time.Now().Add(10 * time.Minute * -1)),
					NotBefore: jwtlib.NewNumericDate(time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC)),
					Subject:   "smithj@outlook.com",
				},
			},
			roles: []string{"admin", "editor", "viewer"},
			addr:  "127.0.0.1",
		},
		{
			name: "user with role claim and ip address",
			config: []string{
				"crypto key sign-verify foobar",
			},
			claims: &TestUserClaims{
				Role:    "admin",
				Address: "192.168.1.1",
				RegisteredClaims: jwtlib.RegisteredClaims{
					ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(10 * time.Minute)),
					IssuedAt:  jwtlib.NewNumericDate(time.Now().Add(10 * time.Minute * -1)),
					NotBefore: jwtlib.NewNumericDate(time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC)),
					Subject:   "smithj@outlook.com",
				},
			},
			roles: []string{"admin"},
			addr:  "192.168.1.1",
		},
		{
			name: "user with group claim and ip address",
			config: []string{
				"crypto key sign-verify foobar",
			},
			claims: &TestUserClaims{
				Group:   "admin",
				Address: "192.168.1.1",
				RegisteredClaims: jwtlib.RegisteredClaims{
					ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(10 * time.Minute)),
					IssuedAt:  jwtlib.NewNumericDate(time.Now().Add(10 * time.Minute * -1)),
					NotBefore: jwtlib.NewNumericDate(time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC)),
					Subject:   "smithj@outlook.com",
				},
			},
			roles: []string{"admin"},
			addr:  "192.168.1.1",
		},
		{
			name: "user with expired token",
			config: []string{
				"crypto key sign-verify foobar",
			},
			claims: &TestUserClaims{
				Roles: []string{"admin", "editor", "viewer"},
				RegisteredClaims: jwtlib.RegisteredClaims{
					ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(5 * time.Minute * -1)),
					IssuedAt:  jwtlib.NewNumericDate(time.Now().Add(10 * time.Minute * -1)),
					NotBefore: jwtlib.NewNumericDate(time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC)),
					Subject:   "smithj@outlook.com",
				},
			},
			roles:     []string{"admin", "editor", "viewer"},
			addr:      "127.0.0.1",
			shouldErr: true,
			err:       errors.ErrCryptoKeyStoreParseTokenExpired,
		},
		{
			name: "user with not yet ready token",
			config: []string{
				"crypto key sign-verify foobar",
			},
			claims: &TestUserClaims{
				Roles: []string{"admin", "editor", "viewer"},
				AppMetadata: map[string]interface{}{
					"authorization": map[string]interface{}{
						"roles": []interface{}{
							1, 2, 3,
						},
					},
				},
				RegisteredClaims: jwtlib.RegisteredClaims{
					ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(20 * time.Minute)),
					IssuedAt:  jwtlib.NewNumericDate(time.Now().Add(10 * time.Minute * -1)),
					NotBefore: jwtlib.NewNumericDate(time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC)),
					Subject:   "smithj@outlook.com",
				},
			},
			roles:     []string{"admin", "editor", "viewer"},
			addr:      "127.0.0.1",
			shouldErr: true,
			err:       errors.ErrCryptoKeyStoreTokenData,
		},
		{
			name: "token name mismatch",
			config: []string{
				"crypto key sign-verify foobar",
			},
			verifyTokenName: `foobar`,
			claims: &TestUserClaims{
				Group:   "admin",
				Address: "192.168.1.1",
				RegisteredClaims: jwtlib.RegisteredClaims{
					ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(10 * time.Minute)),
					IssuedAt:  jwtlib.NewNumericDate(time.Now().Add(10 * time.Minute * -1)),
					NotBefore: jwtlib.NewNumericDate(time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC)),
					Subject:   "smithj@outlook.com",
				},
			},
			roles:     []string{"admin"},
			addr:      "192.168.1.1",
			shouldErr: true,
			err:       errors.ErrCryptoKeyStoreParseTokenFailed,
		},
		{
			name: "failed verification",
			config: []string{
				"crypto key sign-verify foobar",
			},
			sign:            true,
			signAlgorithm:   "HS512",
			verifyTokenName: `foobar`,
			user:            newTestUser(),
			operatorErr:     true,
			shouldErr:       true,
			err:             errors.ErrCryptoKeyStoreParseTokenFailed,
		},
		{
			name: "failed signing due to algo mismatch",
			config: []string{
				"crypto key sign-verify foobar",
			},
			sign:            true,
			signAlgorithm:   "RS512",
			verifyTokenName: `foobar`,
			user:            newTestUser(),
			operatorErr:     true,
			operatorSignErr: true,
			shouldErr:       true,
			err:             errors.ErrUnsupportedSigningMethod.WithArgs("RS512"),
		},
		{
			name: "failed signing due to token name mismatch",
			config: []string{
				"crypto key sign-verify foobar",
			},
			sign:            true,
			signAlgorithm:   "RS512",
			signTokenName:   `foobar`,
			user:            newTestUser(),
			operatorErr:     true,
			operatorSignErr: true,
			shouldErr:       true,
			err:             errors.ErrCryptoKeyStoreSignTokenFailed,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var signedToken string
			var msgs []string
			msgs = append(msgs, fmt.Sprintf("test name: %s", tc.name))

			ksCfg, err := NewCryptoKeyStoreConfig(tc.config)
			if err != nil {
				t.Fatalf("failed NewCryptoKeyStoreConfig: %v", err)
			}

			ks, err := NewCryptoKeyStore(ksCfg, logutil.NewLogger())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			privKey := ks.GetKeys()[0]
			if tc.signTokenName == "" {
				tc.signTokenName = privKey.Sign.Token.Name
			}

			tokenName := "authp_access_token"

			for _, k := range ks.GetKeys() {
				if k.Sign.Token.Capable {
					k.Sign.Token.CookieNames[tokenName] = true
					k.Sign.Token.HeaderNames[tokenName] = true
					k.Sign.Token.QueryParamNames[tokenName] = true
				}
				if k.Verify.Token.Capable {
					k.Verify.Token.CookieNames[tokenName] = true
					k.Verify.Token.HeaderNames[tokenName] = true
					k.Verify.Token.QueryParamNames[tokenName] = true
				}
			}

			if tc.sign {
				err := ks.SignToken(tc.signTokenName, tc.signAlgorithm, tc.user)
				if tc.operatorSignErr {
					if tests.EvalErrWithLog(t, err, "sign token", tc.shouldErr, tc.err, msgs) {
						return
					}
				}
			} else {
				token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS512, tc.claims)
				var err error
				signedToken, err = token.SignedString(privKey.Sign.Secret)
				if err != nil {
					t.Fatalf("failed signing claims: %s", err)
				}
			}

			msgs = append(msgs, fmt.Sprintf("signed token: %s", signedToken))

			ar := requests.NewAuthorizationRequest()
			ar.ID = "TEST_REQUEST_ID"
			ar.SessionID = "TEST_SESSION_ID"
			if tc.verifyTokenName != "" {
				ar.Token.Name = tc.verifyTokenName
			} else {
				ar.Token.Name = tokenName
			}
			ar.Token.Payload = signedToken
			ar.Token.Source = tokenSourceHeader
			usr, err := ks.ParseToken(ar)
			if tests.EvalErrWithLog(t, err, "ParseToken", tc.shouldErr, tc.err, msgs) {
				return
			}

			msgs = append(msgs, fmt.Sprintf("parsed claims: %v", usr.Claims))
			msgs = append(msgs, fmt.Sprintf("roles: %v", usr.Claims.Roles))
			if len(tc.roles) > 0 {
				tests.EvalObjectsWithLog(t, "roles", tc.roles, usr.Claims.Roles, msgs)
			}
		})
	}
}

func TestDefaultTokenLifetimePropagation(t *testing.T) {
	var testcases = []struct {
		name         string
		config       []string
		wantLifetime int
	}{
		{
			name: "explicit key inherits default lifetime",
			config: []string{
				"crypto default token lifetime 2592000",
				"crypto key sign-verify foobar",
			},
			wantLifetime: 2592000,
		},
		{
			name: "explicit key uses own lifetime over default",
			config: []string{
				"crypto default token lifetime 2592000",
				"crypto key token lifetime 3600",
				"crypto key sign-verify foobar",
			},
			wantLifetime: 3600,
		},
		{
			name: "explicit key lifetime of 900 preserved over default",
			config: []string{
				"crypto default token lifetime 2592000",
				"crypto key token lifetime 900",
				"crypto key sign-verify foobar",
			},
			wantLifetime: 900,
		},
		{
			name: "no default falls back to 900",
			config: []string{
				"crypto key sign-verify foobar",
			},
			wantLifetime: 900,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			ksCfg, err := NewCryptoKeyStoreConfig(tc.config)
			if err != nil {
				t.Fatalf("unexpected NewCryptoKeyStoreConfig error: %v", err)
			}
			ks, err := NewCryptoKeyStore(ksCfg, logutil.NewLogger())
			if err != nil {
				t.Fatalf("unexpected NewCryptoKeyStore error: %v", err)
			}
			got := ks.GetTokenLifetime(nil, nil)
			tests.EvalObjectsWithLog(t, "token_lifetime", tc.wantLifetime, got, msgs)
		})
	}
}

func TestCryptoKeyStoreAutoGenerate(t *testing.T) {
	var testcases = []struct {
		name      string
		tag       string
		algorithm string
		shouldErr bool
		err       error
	}{
		{
			name:      "generate es512 key pair",
			tag:       "default",
			algorithm: "ES512",
			// shouldErr: true,
			//err:       fmt.Errorf(`kms: file "foo" is not supported due to extension type`),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("algorithm: %s", tc.algorithm))
			ksCfg, err := NewCryptoKeyStoreConfig([]string{
				fmt.Sprintf("crypto default autogenerate tag %s", tc.tag),
				fmt.Sprintf("crypto default autogenerate algorithm %s", tc.algorithm),
			})
			if err != nil {
				t.Fatalf("unexpected NewCryptoKeyStoreConfig error: %v", err)
			}
			_, err = NewCryptoKeyStore(ksCfg, logutil.NewLogger())
			if tests.EvalErrWithLog(t, err, nil, tc.shouldErr, tc.err, msgs) {
				return
			}
		})
	}
}
