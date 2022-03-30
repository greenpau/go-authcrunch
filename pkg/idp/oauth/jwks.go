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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/util"
	"io/ioutil"
	"math/big"
	"strings"
)

// JwksKey is a JSON object that represents a cryptographic key.
// See https://tools.ietf.org/html/rfc7517#section-4,
// https://tools.ietf.org/html/rfc7518#section-6.3
type JwksKey struct {
	Algorithm    string `json:"alg,omitempty" xml:"alg,omitempty" yaml:"alg,omitempty"`
	Exponent     string `json:"e,omitempty" xml:"e,omitempty" yaml:"e,omitempty"`
	KeyID        string `json:"kid,omitempty" xml:"kid,omitempty" yaml:"kid,omitempty"`
	KeyType      string `json:"kty,omitempty" xml:"kty,omitempty" yaml:"kty,omitempty"`
	Modulus      string `json:"n,omitempty" xml:"n,omitempty" yaml:"n,omitempty"`
	PublicKeyUse string `json:"use,omitempty" xml:"use,omitempty" yaml:"use,omitempty"`
	NotBefore    string `json:"nbf,omitempty" xml:"nbf,omitempty" yaml:"nbf,omitempty"`

	Curve  string `json:"crv,omitempty" xml:"crv,omitempty" yaml:"crv,omitempty"`
	CoordX string `json:"x,omitempty" xml:"x,omitempty" yaml:"x,omitempty"`
	CoordY string `json:"y,omitempty" xml:"y,omitempty" yaml:"y,omitempty"`

	SharedSecret string `json:"k,omitempty" xml:"k,omitempty" yaml:"k,omitempty"`

	publicKey interface{}
}

// Validate returns error if JwksKey does not contain relevant information.
func (k *JwksKey) Validate() error {
	if k.KeyID == "" {
		return errors.ErrJwksKeyIDEmpty
	}

	switch k.KeyType {
	case "RSA":
		switch k.Algorithm {
		case "RS256", "RS384", "RS512", "":
		default:
			return errors.ErrJwksKeyAlgoUnsupported.WithArgs(k.Algorithm, k.KeyID)
		}
	case "EC":
		switch k.Curve {
		case "P-256", "P-384", "P-521":
		case "":
			return errors.ErrJwksKeyCurveEmpty.WithArgs(k.KeyID)
		default:
			return errors.ErrJwksKeyCurveUnsupported.WithArgs(k.Curve, k.KeyID)
		}
		if k.CoordX == "" || k.CoordY == "" {
			return errors.ErrJwksKeyCurveCoordNotFound.WithArgs(k.KeyID)
		}
	case "oct":
		if k.SharedSecret == "" {
			return errors.ErrJwksKeySharedSecretEmpty.WithArgs(k.KeyID)
		}
		switch k.Algorithm {
		case "HS256", "HS384", "HS512", "":
		default:
			return errors.ErrJwksKeyAlgoUnsupported.WithArgs(k.Algorithm, k.KeyID)
		}
	case "":
		return errors.ErrJwksKeyTypeEmpty.WithArgs(k.KeyID)
	default:
		return errors.ErrJwksKeyTypeUnsupported.WithArgs(k.KeyType, k.KeyID)
	}

	switch k.PublicKeyUse {
	case "sig", "enc", "":
	default:
		return errors.ErrJwksKeyUsageUnsupported.WithArgs(k.PublicKeyUse, k.KeyID)
	}

	switch k.KeyType {
	case "RSA":
		if k.Exponent == "" {
			return errors.ErrJwksKeyExponentEmpty.WithArgs(k.KeyID)
		}

		if k.Modulus == "" {
			return errors.ErrJwksKeyModulusEmpty.WithArgs(k.KeyID)
		}

		// Add padding
		if i := len(k.Modulus) % 4; i != 0 {
			k.Modulus += strings.Repeat("=", 4-i)
		}

		var mod []byte
		var err error
		if strings.ContainsAny(k.Modulus, "/+") {
			// This decoding works with + and / signs. (legacy)
			mod, err = base64.StdEncoding.DecodeString(k.Modulus)
		} else {
			// This decoding works with - and _ signs.
			mod, err = base64.URLEncoding.DecodeString(k.Modulus)
		}

		if err != nil {
			return errors.ErrJwksKeyDecodeModulus.WithArgs(k.KeyID, k.Modulus, err)
		}
		n := big.NewInt(0)
		n.SetBytes(mod)

		exp, err := base64.StdEncoding.DecodeString(k.Exponent)
		if err != nil {
			return errors.ErrJwksKeyDecodeExponent.WithArgs(k.KeyID, err)
		}
		// The "e" (exponent) parameter contains the exponent value for the RSA
		// public key.  It is represented as a Base64urlUInt-encoded value.
		//
		// For instance, when representing the value 65537, the octet sequence
		// to be base64url-encoded MUST consist of the three octets [1, 0, 1];
		// the resulting representation for this value is "AQAB".
		var eb []byte
		if len(exp) < 8 {
			eb = make([]byte, 8-len(exp), 8)
			eb = append(eb, exp...)
		} else {
			eb = exp
		}
		er := bytes.NewReader(eb)
		var e uint64
		if err := binary.Read(er, binary.BigEndian, &e); err != nil {
			return errors.ErrJwksKeyConvExponent.WithArgs(k.KeyID, err)
		}
		k.publicKey = &rsa.PublicKey{N: n, E: int(e)}
	case "EC":
		var expByteCount int
		pk := &ecdsa.PublicKey{}
		switch k.Curve {
		case "P-256":
			pk.Curve = elliptic.P256()
			expByteCount = 32
		case "P-384":
			pk.Curve = elliptic.P384()
			expByteCount = 48
		case "P-521":
			pk.Curve = elliptic.P521()
			expByteCount = 66
		}

		for i, c := range []string{k.CoordX, k.CoordY} {
			ltr := "X"
			if i > 0 {
				ltr = "Y"
			}
			b, err := base64.RawURLEncoding.DecodeString(c)
			if err != nil {
				return errors.ErrJwksKeyDecodeCoord.WithArgs(k.KeyID, ltr, err)
			}
			if len(b) != expByteCount {
				return errors.ErrJwksKeyCoordLength.WithArgs(k.KeyID, ltr, len(b), expByteCount)
			}
			bi := big.NewInt(0)
			bi.SetBytes(b)
			if i == 0 {
				pk.X = bi
				continue
			}
			pk.Y = bi
		}
		k.publicKey = pk
	case "oct":
		key, err := base64.RawURLEncoding.DecodeString(k.SharedSecret)
		if err != nil {
			return errors.ErrJwksKeyDecodeSharedSecret.WithArgs(k.KeyID, err)
		}
		k.publicKey = key
	default:
		return errors.ErrJwksKeyTypeNotImplemented.WithArgs(k.KeyID, k.KeyType, k)
	}

	return nil
}

// GetPublic returns pointer to public key.
func (k *JwksKey) GetPublic() interface{} {
	return k.publicKey
}

func createJwksKeyFromPubKey(pk *rsa.PublicKey) *JwksKey {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(pk.E))
	i := 0
	for ; i < len(b); i++ {
		if b[i] != 0x0 {
			break
		}
	}

	return &JwksKey{
		KeyType:      "RSA",
		PublicKeyUse: "sig",
		Exponent:     base64.RawURLEncoding.EncodeToString(b[i:]),
		Modulus:      base64.RawURLEncoding.EncodeToString(pk.N.Bytes()),
	}
}

// NewJwksKeyFromRSAPrivateKey returns an instance of Jwks from RSA private key.
func NewJwksKeyFromRSAPrivateKey(privKey *rsa.PrivateKey) (*JwksKey, error) {
	if len(privKey.Primes) != 2 {
		return nil, fmt.Errorf("unexpected prime number count: %d", len(privKey.Primes))
	}

	jk := createJwksKeyFromPubKey(&privKey.PublicKey)
	jk.KeyID = util.GetRandomStringFromRange(26, 32)
	if err := jk.Validate(); err != nil {
		return nil, fmt.Errorf("failed creating jwks key: %v", err)
	}

	return jk, nil
}

// NewJwksKeyFromRSAPublicKeyPEM returns an instance of Jwks from RSA public key in PEM format.
func NewJwksKeyFromRSAPublicKeyPEM(kid, fp string) (*JwksKey, error) {
	kb, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, err
	}

	var block *pem.Block
	if block, _ = pem.Decode(kb); block == nil {
		return nil, errors.ErrNotPEMEncodedKey
	}

	var pubKey *rsa.PublicKey

	switch {
	case bytes.Contains(kb, []byte("RSA PUBLIC KEY")):
		pubKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	case bytes.Contains(kb, []byte("PUBLIC KEY")):
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		switch pub := pub.(type) {
		case *rsa.PublicKey:
			pubKey = pub
		default:
			return nil, fmt.Errorf("key payload is not supported public key")
		}
	default:
		return nil, fmt.Errorf("key payload is not RSA public key")
	}

	jk := createJwksKeyFromPubKey(pubKey)
	jk.KeyID = kid
	if err := jk.Validate(); err != nil {
		return nil, fmt.Errorf("failed creating jwks key: %v", err)
	}

	return jk, nil
}
