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
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/greenpau/go-authcrunch/pkg/errors"
)

const (
	privateKeyFormatPKCS8  = "pkcs8"
	privateKeyFormatPKCS1  = "pkcs1"
	privateKeyFormatSEC1   = "sec1"
	privateKeyFormatJWK    = "jwk"
	privateKeyEncodingPEM  = "pem"
	privateKeyEncodingDER  = "der"
	privateKeyEncodingJSON = "json"
)

type jwksPrivateKey struct {
	PublicKey  publicJSONWebKey `json:"public_key" xml:"public_key" yaml:"public_key"`
	PrivateKey json.RawMessage  `json:"private_key" xml:"private_key" yaml:"private_key"`
}

// GetJWKSPrivateKeys returns JSON pairing each public JWK from GetJWKS with its
// private key. Format accepts pkcs8 (default), pkcs1 (RSA only), sec1 (EC only),
// or jwk. The json format alias preserves PKCS#8 output for JSON API clients.
// Every format returns a keys array, including when only one key is exported.
// Encoding accepts pem (default) or der (standard base64 in JSON); jwk requires
// json encoding, which is its default. Empty arguments select defaults.
// Incompatible formats fail the entire export instead of omitting keys.
// The result contains signing credentials: callers must require explicit export
// configuration and administrator authorization, and must not log or cache it.
// Key selection and nil-result semantics match GetJWKS.
func (ks *CryptoKeyStore) GetJWKSPrivateKeys(format, encoding string) ([]byte, error) {
	switch format {
	case "", "json":
		format = privateKeyFormatPKCS8
	case privateKeyFormatPKCS8, privateKeyFormatPKCS1, privateKeyFormatSEC1, privateKeyFormatJWK:
	default:
		return nil, errors.ErrPrivateKeyExportFormat
	}
	if format == privateKeyFormatJWK {
		if encoding == "" {
			encoding = privateKeyEncodingJSON
		}
		if encoding != privateKeyEncodingJSON {
			return nil, errors.ErrPrivateKeyExportEncoding
		}
	} else {
		if encoding == "" {
			encoding = privateKeyEncodingPEM
		}
		if encoding != privateKeyEncodingPEM && encoding != privateKeyEncodingDER {
			return nil, errors.ErrPrivateKeyExportEncoding
		}
	}
	signers, err := ks.getJWKSSigningKeys()
	if err != nil || len(signers) == 0 {
		return nil, err
	}
	for _, signer := range signers {
		if (format == privateKeyFormatPKCS1 && signer.publicKey.KeyType != "RSA") ||
			(format == privateKeyFormatSEC1 && signer.publicKey.KeyType != "EC") {
			return nil, errors.ErrPrivateKeyExportKeyType
		}
	}
	keys := make([]jwksPrivateKey, 0, len(signers))
	for _, signer := range signers {
		secret, err := signer.privateSigningKey()
		if err != nil {
			return nil, err
		}
		encoded, err := marshalPrivateSigningKey(signer.publicKey, secret, format, encoding)
		if err != nil {
			return nil, err
		}
		keys = append(keys, jwksPrivateKey{PublicKey: signer.publicKey, PrivateKey: encoded})
	}
	return json.Marshal(struct {
		Keys []jwksPrivateKey `json:"keys"`
	}{Keys: keys})
}

func (key jwksSigningKey) privateSigningKey() (any, error) {
	switch secret := key.signer.Sign.Secret.(type) {
	case *rsa.PrivateKey:
		// x509 marshaling can mutate RSA precomputation. Keep it on a copy.
		copy := *secret
		copy.Precomputed = rsa.PrecomputedValues{}
		copy.Precompute()
		if err := copy.Validate(); err != nil {
			return nil, fmt.Errorf("kms: invalid private signing key")
		}
		return &copy, nil
	case *ecdsa.PrivateKey:
		// x509 assumes a non-nil scalar. Check bounds and public-key pairing.
		if secret.D == nil || secret.D.Sign() <= 0 || secret.D.Cmp(secret.Curve.Params().N) >= 0 {
			return nil, fmt.Errorf("kms: invalid private signing key")
		}
		x, y := secret.Curve.ScalarBaseMult(secret.D.Bytes())
		if x.Cmp(secret.X) != 0 || y.Cmp(secret.Y) != 0 {
			return nil, fmt.Errorf("kms: private signing key does not match its public key")
		}
		return secret, nil
	}
	return nil, fmt.Errorf("kms: unsupported private signing key")
}

func marshalPrivateSigningKey(public publicJSONWebKey, secret any, format, encoding string) (json.RawMessage, error) {
	if format == privateKeyFormatJWK {
		return marshalPrivateJWK(public, secret)
	}
	var der []byte
	var err error
	var blockType string
	switch format {
	case privateKeyFormatPKCS8:
		der, err = x509.MarshalPKCS8PrivateKey(secret)
		blockType = "PRIVATE KEY"
	case privateKeyFormatPKCS1:
		der = x509.MarshalPKCS1PrivateKey(secret.(*rsa.PrivateKey))
		blockType = "RSA PRIVATE KEY"
	case privateKeyFormatSEC1:
		der, err = x509.MarshalECPrivateKey(secret.(*ecdsa.PrivateKey))
		blockType = "EC PRIVATE KEY"
	}
	if err != nil {
		return nil, fmt.Errorf("kms: failed to encode private signing key")
	}
	if encoding == privateKeyEncodingDER {
		return json.Marshal(base64.StdEncoding.EncodeToString(der))
	}
	return json.Marshal(string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})))
}

// This private wire model is separate from the public JWKS model.
type privateJSONWebKey struct {
	publicJSONWebKey
	D           string            `json:"d" xml:"d" yaml:"d"`
	P           string            `json:"p,omitempty" xml:"p,omitempty" yaml:"p,omitempty"`
	Q           string            `json:"q,omitempty" xml:"q,omitempty" yaml:"q,omitempty"`
	DP          string            `json:"dp,omitempty" xml:"dp,omitempty" yaml:"dp,omitempty"`
	DQ          string            `json:"dq,omitempty" xml:"dq,omitempty" yaml:"dq,omitempty"`
	QI          string            `json:"qi,omitempty" xml:"qi,omitempty" yaml:"qi,omitempty"`
	OtherPrimes []privateJWKPrime `json:"oth,omitempty" xml:"oth,omitempty" yaml:"oth,omitempty"`
}

type privateJWKPrime struct {
	R string `json:"r" xml:"r" yaml:"r"`
	D string `json:"d" xml:"d" yaml:"d"`
	T string `json:"t" xml:"t" yaml:"t"`
}

func marshalPrivateJWK(public publicJSONWebKey, secret any) ([]byte, error) {
	key := privateJSONWebKey{publicJSONWebKey: public}
	encode := base64.RawURLEncoding.EncodeToString
	switch private := secret.(type) {
	case *rsa.PrivateKey:
		key.D = encode(private.D.Bytes())
		key.P = encode(private.Primes[0].Bytes())
		key.Q = encode(private.Primes[1].Bytes())
		key.DP = encode(private.Precomputed.Dp.Bytes())
		key.DQ = encode(private.Precomputed.Dq.Bytes())
		key.QI = encode(private.Precomputed.Qinv.Bytes())
		for i, prime := range private.Precomputed.CRTValues {
			key.OtherPrimes = append(key.OtherPrimes, privateJWKPrime{
				R: encode(private.Primes[i+2].Bytes()), D: encode(prime.Exp.Bytes()), T: encode(prime.Coeff.Bytes()),
			})
		}
	case *ecdsa.PrivateKey:
		size := (private.Curve.Params().N.BitLen() + 7) / 8
		key.D = encode(private.D.FillBytes(make([]byte, size)))
	}
	return json.Marshal(key)
}
