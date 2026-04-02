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

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/errors"
)

func TestNewCryptoKeyStoreConfig(t *testing.T) {
	var testcases = []struct {
		name      string
		config    []string
		want      *CryptoKeyStoreConfig
		shouldErr bool
		err       error
	}{
		{
			name: "test crypto key store config",
			config: []string{
				"crypto default token lifetime 3600",
				"crypto default token name AUTHP_ACCESS_TOKEN",
				"crypto key sign-verify foobar",
			},
			want: &CryptoKeyStoreConfig{
				TokenName:     "AUTHP_ACCESS_TOKEN",
				TokenLifetime: 3600,
				RawKeyConfigs: []string{
					"crypto default token lifetime 3600",
					"crypto default token name AUTHP_ACCESS_TOKEN",
					"crypto key sign-verify foobar",
				},
				AutoGenerateTag:  "default",
				AutoGenerateAlgo: "ES512",
			},
		},
		{
			name: "test no crypto prefix",
			config: []string{
				"foo",
			},
			shouldErr: true,
			err:       errors.ErrCryptoKeyStoreConfigEntryInvalid.WithArgs("foo", "must be prefixed with 'crypto' keyword"),
		},
		{
			name: "test too few arguments for crypto default",
			config: []string{
				"crypto default foo",
			},
			shouldErr: true,
			err:       errors.ErrCryptoKeyStoreConfigEntryInvalid.WithArgs("crypto default foo", "too few arguments"),
		},
		{
			name: "test too few arguments for crypto key",
			config: []string{
				"crypto key foo",
			},
			shouldErr: true,
			err:       errors.ErrCryptoKeyStoreConfigEntryInvalid.WithArgs("crypto key foo", "too few arguments"),
		},
		{
			name: "test malformed crypto default prefix",
			config: []string{
				"crypto foo",
			},
			shouldErr: true,
			err:       errors.ErrCryptoKeyStoreConfigEntryInvalid.WithArgs("crypto foo", "unsupported arguments"),
		},
		{
			name: "test malformed crypto default parameter",
			config: []string{
				"crypto default foo bar baz",
			},
			shouldErr: true,
			err: errors.ErrCryptoKeyStoreConfigEntryInvalid.WithArgs("crypto default foo bar baz",
				fmt.Sprintf("contains unsupported 'crypto default' keyword: %s", "foo"),
			),
		},

		{
			name: "test malformed crypto default token parameter",
			config: []string{
				"crypto default token foo bar",
			},
			shouldErr: true,
			err: errors.ErrCryptoKeyStoreConfigEntryInvalid.WithArgs("crypto default token foo bar",
				fmt.Sprintf("contains unsupported 'crypto default token' parameter: %s", "foo"),
			),
		},
		{
			name: "test malformed crypto default token lifetime value",
			config: []string{
				"crypto default token lifetime foo",
			},
			shouldErr: true,
			err: errors.ErrCryptoKeyStoreConfigEntryInvalid.WithArgs("crypto default token lifetime foo",
				fmt.Errorf("strconv.Atoi: parsing %q: invalid syntax", "foo"),
			),
		},
		{
			name: "test malformed crypto default autogenerate value",
			config: []string{
				"crypto default autogenerate foo bar",
			},
			shouldErr: true,
			err: errors.ErrCryptoKeyStoreConfigEntryInvalid.WithArgs("crypto default autogenerate foo bar",
				fmt.Sprintf("contains unsupported 'crypto default autogenerate' parameter: %s", "foo"),
			),
		},
		{
			name: "test failed statement decoding",
			config: []string{
				"\"crypto",
			},
			shouldErr: true,
			err:       fmt.Errorf(`parse error on line 1, column 8: extraneous or missing " in quoted-field`),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("config: %v", tc.config))
			got, err := NewCryptoKeyStoreConfig(tc.config)
			if tests.EvalErrWithLog(t, err, nil, tc.shouldErr, tc.err, msgs) {
				return
			}
			tests.EvalObjects(t, "NewCryptoKeyStoreConfig", tc.want, got)
		})
	}
}
