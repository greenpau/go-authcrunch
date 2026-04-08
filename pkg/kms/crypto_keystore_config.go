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
	"strconv"

	"github.com/greenpau/go-authcrunch/pkg/errors"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// CryptoKeyStoreConfig holds crypto key store configuration settings.
type CryptoKeyStoreConfig struct {
	// TokenName is the token name associated with the key store.
	TokenName string `json:"token_name,omitempty" xml:"token_name,omitempty" yaml:"token_name,omitempty"`
	// TokenLifetime is the expected token grant lifetime in seconds.
	TokenLifetime int `json:"token_lifetime,omitempty" xml:"token_lifetime,omitempty" yaml:"token_lifetime,omitempty"`

	RawKeyConfigs    []string `json:"raw_key_configs,omitempty" xml:"raw_key_configs,omitempty" yaml:"raw_key_configs,omitempty"`
	AutoGenerateTag  string   `json:"auto_generate_tag,omitempty" xml:"auto_generate_tag,omitempty" yaml:"auto_generate_tag,omitempty"`
	AutoGenerateAlgo string   `json:"auto_generate_algo,omitempty" xml:"auto_generate_algo,omitempty" yaml:"auto_generate_algo,omitempty"`
}

// NewCryptoKeyStoreConfig returns instance of CryptoKeyStoreConfig
func NewCryptoKeyStoreConfig(statements []string) (*CryptoKeyStoreConfig, error) {
	cfg := &CryptoKeyStoreConfig{
		AutoGenerateTag:  "default",
		AutoGenerateAlgo: "ES512",
	}

	cryptoKeyConfigs := []string{}

	for _, statement := range statements {
		args, err := cfgutil.DecodeArgs(statement)
		if err != nil {
			return nil, err
		}
		if args[0] != "crypto" {
			return nil, errors.ErrCryptoKeyStoreConfigEntryInvalid.WithArgs(statement, "must be prefixed with 'crypto' keyword")
		}
		switch args[1] {
		case "default":
			if len(args) < 5 {
				return nil, errors.ErrCryptoKeyStoreConfigEntryInvalid.WithArgs(statement, "too few arguments")
			}
			switch args[2] {
			case "token":
				switch args[3] {
				case "name":
					cfg.TokenName = args[4]
				case "lifetime":
					lifetime, err := strconv.Atoi(args[4])
					if err != nil {
						return nil, errors.ErrCryptoKeyStoreConfigEntryInvalid.WithArgs(statement, err)
					}
					cfg.TokenLifetime = lifetime
				default:
					return nil, errors.ErrCryptoKeyStoreConfigEntryInvalid.WithArgs(statement, fmt.Sprintf("contains unsupported 'crypto default token' parameter: %s", args[3]))
				}
			case "autogenerate":
				switch args[3] {
				case "tag":
					cfg.AutoGenerateTag = args[4]
				case "algorithm":
					cfg.AutoGenerateAlgo = args[4]
				default:
					return nil, errors.ErrCryptoKeyStoreConfigEntryInvalid.WithArgs(statement, fmt.Sprintf("contains unsupported 'crypto default autogenerate' parameter: %s", args[3]))
				}
			default:
				return nil, errors.ErrCryptoKeyStoreConfigEntryInvalid.WithArgs(statement, fmt.Sprintf("contains unsupported 'crypto default' keyword: %s", args[2]))
			}
		case "key":
			if len(args) < 4 {
				return nil, errors.ErrCryptoKeyStoreConfigEntryInvalid.WithArgs(statement, "too few arguments")
			}
			cryptoKeyConfigs = append(cryptoKeyConfigs, statement)
		default:
			return nil, errors.ErrCryptoKeyStoreConfigEntryInvalid.WithArgs(statement, "unsupported arguments")
		}
	}

	cfg.RawKeyConfigs = cryptoKeyConfigs

	return cfg, nil
}
