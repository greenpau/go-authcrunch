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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// publicJSONWebKey deliberately contains only public parameters. Never marshal
// CryptoKey or its operators here: they also contain private keys and secrets.
type publicJSONWebKey struct {
	KeyType   string `json:"kty" xml:"kty" yaml:"kty"`
	Use       string `json:"use" xml:"use" yaml:"use"`
	Algorithm string `json:"alg" xml:"alg" yaml:"alg"`
	KeyID     string `json:"kid,omitempty" xml:"kid,omitempty" yaml:"kid,omitempty"`
	N         string `json:"n,omitempty" xml:"n,omitempty" yaml:"n,omitempty"`
	E         string `json:"e,omitempty" xml:"e,omitempty" yaml:"e,omitempty"`
	Curve     string `json:"crv,omitempty" xml:"crv,omitempty" yaml:"crv,omitempty"`
	X         string `json:"x,omitempty" xml:"x,omitempty" yaml:"x,omitempty"`
	Y         string `json:"y,omitempty" xml:"y,omitempty" yaml:"y,omitempty"`
}

type jwksSigningKey struct {
	publicKey publicJSONWebKey
	signer    *CryptoKey
}

// GetJWKS returns an RFC 7517 JWK Set of public RSA and ECDSA signing keys.
// A successful result always contains a keys array, including for one key.
// It returns nil without an error when the signer selected by
// SignToken(nil, nil, user) is symmetric or absent. Verification-only keys and
// system keys are excluded. Each key advertises its default signing algorithm
// and includes kid only when the corresponding JWT header includes it.
// Like SignToken, this method requires key configuration to remain immutable
// while requests are being served.
func (ks *CryptoKeyStore) GetJWKS() ([]byte, error) {
	signers, err := ks.getJWKSSigningKeys()
	if err != nil || len(signers) == 0 {
		return nil, err
	}
	keys := make([]publicJSONWebKey, 0, len(signers))
	for _, signer := range signers {
		keys = append(keys, signer.publicKey)
	}
	return json.Marshal(struct {
		Keys []publicJSONWebKey `json:"keys"`
	}{Keys: keys})
}

func (ks *CryptoKeyStore) getJWKSSigningKeys() ([]jwksSigningKey, error) {
	if ks == nil {
		return nil, nil
	}
	var keys []jwksSigningKey
	seen := make(map[publicJSONWebKey]bool)
	selected := false
	for _, k := range ks.signKeys {
		if k.Config.Usage == "system" {
			continue
		}
		algorithm := signingMethods[k.Sign.Token.DefaultMethod]
		asymmetric := algorithm == "rsa" || algorithm == "ecdsa"
		if !selected {
			// Portal issuance uses the first non-system signer. A later RSA or
			// EC key must not enable discovery for an HMAC issuer.
			if !asymmetric {
				return nil, nil
			}
			selected = true
		}
		if !asymmetric {
			continue
		}
		key, err := k.publicJWK()
		if err != nil {
			return nil, err
		}
		if !seen[key] {
			keys = append(keys, jwksSigningKey{publicKey: key, signer: k})
			seen[key] = true
		}
	}
	return keys, nil
}

func (k *CryptoKey) publicJWK() (publicJSONWebKey, error) {
	key := publicJSONWebKey{Use: "sig", Algorithm: k.Sign.Token.DefaultMethod}
	if k.Sign.Token.injectKeyID {
		key.KeyID = k.Sign.Token.ID
	}
	// Derive the public key from the actual signer, including sign-only keys.
	// A separately configured verification key may belong to another issuer.
	switch secret := k.Sign.Secret.(type) {
	case *rsa.PrivateKey:
		if secret == nil || secret.N == nil || secret.N.Sign() <= 0 || secret.E <= 0 || signingMethods[key.Algorithm] != "rsa" {
			return publicJSONWebKey{}, fmt.Errorf("kms: invalid RSA signing key for JWKS")
		}
		key.KeyType = "RSA"
		key.N = base64.RawURLEncoding.EncodeToString(secret.N.Bytes())
		key.E = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(secret.E)).Bytes())
	case *ecdsa.PrivateKey:
		if secret == nil || secret.Curve == nil || secret.X == nil || secret.Y == nil {
			return publicJSONWebKey{}, fmt.Errorf("kms: invalid ECDSA signing key for JWKS")
		}
		var method string
		switch secret.Curve {
		case elliptic.P256():
			key.Curve, method = "P-256", "ES256"
		case elliptic.P384():
			key.Curve, method = "P-384", "ES384"
		case elliptic.P521():
			key.Curve, method = "P-521", "ES512"
		default:
			return publicJSONWebKey{}, fmt.Errorf("kms: unsupported ECDSA curve for JWKS")
		}
		if key.Algorithm != method || !secret.Curve.IsOnCurve(secret.X, secret.Y) {
			return publicJSONWebKey{}, fmt.Errorf("kms: invalid ECDSA signing key for JWKS")
		}
		key.KeyType = "EC"
		// RFC 7518 requires fixed-width coordinates, including leading zeroes.
		size := (secret.Curve.Params().BitSize + 7) / 8
		key.X = base64.RawURLEncoding.EncodeToString(secret.X.FillBytes(make([]byte, size)))
		key.Y = base64.RawURLEncoding.EncodeToString(secret.Y.FillBytes(make([]byte, size)))
	default:
		return publicJSONWebKey{}, fmt.Errorf("kms: unsupported signing key for JWKS")
	}
	return key, nil
}
