// Copyright 2026 Paul Greenberg greenpau@outlook.com
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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"

	"github.com/greenpau/go-authcrunch/internal/jwtutil"
	"github.com/greenpau/go-authcrunch/pkg/errors"
)

func validateEd25519PrivateKey(key ed25519.PrivateKey) error {
	return jwtutil.ValidateEd25519PrivateKey(key)
}

func (k *CryptoKey) signEd25519(method, data string) (interface{}, error) {
	if method != "EdDSA" && method != "Ed25519" {
		return nil, errors.ErrDataSigningFailed.WithArgs("Ed25519", "unsupported method")
	}
	signature, err := jwtutil.Ed25519().Sign(data, k.Sign.Secret)
	if err != nil {
		return nil, errors.ErrDataSigningFailed.WithArgs(method, err)
	}
	return data + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func generateEd25519Key() ([]byte, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
