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
	"strings"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"go.uber.org/zap"
)

var (
	tokenSourceHeader = "header"
	tokenSourceCookie = "cookie"
	tokenSourceQuery  = "query"
)

// CryptoKeyStore constains keys assembled for a specific purpose, i.e. signing or
// validation.
type CryptoKeyStore struct {
	config     *CryptoKeyStoreConfig
	keys       []*CryptoKey
	signKeys   []*CryptoKey
	verifyKeys []*CryptoKey
	logger     *zap.Logger
}

// NewCryptoKeyStore returns a new instance of CryptoKeyStore
func NewCryptoKeyStore(cfg *CryptoKeyStoreConfig, logger *zap.Logger) (*CryptoKeyStore, error) {
	ks := &CryptoKeyStore{
		config: cfg,
		logger: logger,
	}
	if len(cfg.RawKeyConfigs) > 0 {
		cryptoKeyConfigs, err := ParseCryptoKeyConfigs(cfg.RawKeyConfigs)
		if err != nil {
			return nil, errors.ErrConfigDirectiveFail.WithArgs("crypto.key", cfg.RawKeyConfigs, err)
		}
		if err := ks.AddKeysWithConfigs(cryptoKeyConfigs); err != nil {
			return nil, err
		}
	} else {
		if err := ks.AutoGenerate(); err != nil {
			return nil, err
		}
	}
	return ks, nil
}

// GetConfig returns keystore config.
func (ks *CryptoKeyStore) GetConfig() *CryptoKeyStoreConfig {
	return ks.config
}

// AutoGenerate auto-generates public-private key pair capable of both
// signing and verifying tokens.
func (ks *CryptoKeyStore) AutoGenerate() error {
	keyCfg := &CryptoKeyConfig{
		ID:            "0",
		Usage:         "sign-verify",
		TokenName:     "access_token",
		Source:        "config",
		TokenLifetime: 900,
		parsed:        true,
	}

	if ks.config.TokenName != "" {
		keyCfg.TokenName = ks.config.TokenName
	}
	if ks.config.TokenLifetime > 0 {
		keyCfg.TokenLifetime = ks.config.TokenLifetime
	}

	if len(ks.keys) > 0 {
		return errors.ErrCryptoKeyStoreAutoGenerateNotAvailable
	}

	key, err := generateKey(keyCfg, ks.config.AutoGenerateTag, ks.config.AutoGenerateAlgo)
	if err != nil {
		return err
	}

	key.enableUsage()
	ks.keys = append(ks.keys, key)
	ks.signKeys = append(ks.signKeys, key)
	ks.verifyKeys = append(ks.verifyKeys, key)
	return nil
}

// GetKeys returns CryptoKey instances from CryptoKeyStore.
func (ks *CryptoKeyStore) GetKeys() []*CryptoKey {
	return ks.keys
}

// GetSignKeys returns CryptoKey instances with key signing capabilities
// from CryptoKeyStore.
func (ks *CryptoKeyStore) GetSignKeys() []*CryptoKey {
	return ks.signKeys
}

// GetVerifyKeys returns CryptoKey instances with key verification capabilities
// from CryptoKeyStore.
func (ks *CryptoKeyStore) GetVerifyKeys() []*CryptoKey {
	return ks.verifyKeys
}

// AddKeysWithConfigs adds CryptoKey instances by providing their
// configurations to CryptoKeyStore.
func (ks *CryptoKeyStore) AddKeysWithConfigs(cfgs []*CryptoKeyConfig) error {
	keys, err := GetKeysFromConfigs(cfgs)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if err := ks.AddKey(k); err != nil {
			return err
		}
	}
	return nil
}

// HasVerifyKeys returns true if CryptoKeyStore has key verification
// capabilities.
func (ks *CryptoKeyStore) HasVerifyKeys() error {
	if len(ks.verifyKeys) > 0 {
		return nil
	}
	return errors.ErrCryptoKeyStoreNoVerifyKeysFound
}

// HasSignKeys returns true if CryptoKeyStore has key signing
// capabilities.
func (ks *CryptoKeyStore) HasSignKeys() error {
	if len(ks.signKeys) > 0 {
		return nil
	}
	return errors.ErrCryptoKeyStoreNoSignKeysFound
}

// AddKeys adds CryptoKey instances to CryptoKeyStore.
func (ks *CryptoKeyStore) AddKeys(keys []*CryptoKey) error {
	for _, k := range keys {
		if err := ks.AddKey(k); err != nil {
			return err
		}
	}
	return nil
}

// AddKey adds CryptoKey instance to CryptoKeyStore.
func (ks *CryptoKeyStore) AddKey(k *CryptoKey) error {
	if k == nil {
		return errors.ErrCryptoKeyStoreAddKeyNil
	}
	if k.Sign != nil {
		if k.Sign.Capable {
			ks.signKeys = append(ks.signKeys, k)
		}
	}
	if k.Verify != nil {
		if k.Verify.Capable {
			ks.verifyKeys = append(ks.verifyKeys, k)
		}
	}
	if k.Verify == nil && k.Sign == nil {
		return errors.ErrCryptoKeyStoreAddKeyNil
	}
	ks.keys = append(ks.keys, k)
	return nil
}

// ParseToken parses JWT token and returns User instance.
func (ks *CryptoKeyStore) ParseToken(ar *requests.AuthorizationRequest) (*user.User, error) {
	for _, k := range ks.verifyKeys {
		if !k.Verify.Capable {
			continue
		}
		switch ar.Token.Source {
		case tokenSourceCookie:
			if _, allowed := k.Verify.Token.CookieNames[ar.Token.Name]; !allowed {
				continue
			}
		case tokenSourceHeader:
			if _, allowed := k.Verify.Token.HeaderNames[ar.Token.Name]; !allowed {
				continue
			}
		case tokenSourceQuery:
			if _, allowed := k.Verify.Token.QueryParamNames[ar.Token.Name]; !allowed {
				continue
			}
		default:
			continue
		}

		parsedToken, err := jwtlib.Parse(ar.Token.Payload, k.ProvideKey)
		if err != nil && !strings.Contains(err.Error(), "is expired") {
			continue
		}

		userData := make(map[string]interface{})
		errData := make(map[string]interface{})
		for k, v := range parsedToken.Claims.(jwtlib.MapClaims) {
			switch k {
			case "iss":
				if strings.HasPrefix(v.(string), "http") {
					ar.Redirect.AuthURL = strings.TrimSuffix(v.(string), "authorization-code-callback")
				}
			case "mail", "email":
				errData["email"] = v.(string)
				ar.Redirect.LoginHint = v.(string)
			case "sub", "name", "jti":
				errData[k] = v.(string)
			}
			userData[k] = v
		}

		if err != nil {
			ar.Response.User = errData
			return nil, errors.ErrCryptoKeyStoreParseTokenExpired
		}

		usr, err := user.NewUser(userData)
		if err != nil {
			return usr, errors.ErrCryptoKeyStoreTokenData
		}
		return usr, nil
	}
	return nil, errors.ErrCryptoKeyStoreParseTokenFailed
}

// SignToken signs user claims and add signed token to user identity.
func (ks *CryptoKeyStore) SignToken(tokenName, signMethod interface{}, usr *user.User) error {
	for _, k := range ks.signKeys {
		if tokenName != nil {
			if tokenName.(string) != k.Sign.Token.Name {
				continue
			}
		}
		response, err := k.sign(signMethod, usr.AsMap())
		if err != nil {
			return err
		}
		usr.Token = response.(string)
		usr.TokenName = k.Sign.Token.Name
		return nil
	}
	return errors.ErrCryptoKeyStoreSignTokenFailed
}

// GetTokenLifetime returns lifetime for a signed token.
func (ks *CryptoKeyStore) GetTokenLifetime(tokenName, signMethod interface{}) int {
	for _, k := range ks.signKeys {
		if tokenName != nil {
			if tokenName.(string) != k.Sign.Token.Name {
				continue
			}
		}
		return k.Sign.Token.MaxLifetime
	}
	return 900
}
