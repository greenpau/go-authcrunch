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
	"crypto"
	"crypto/rsa"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

// preparePS256Verification pins RFC 7518's salt size without changing jwt's
// process-global method (whose default verifier accepts arbitrary salt lengths).
// RSA-PSS signing remains owned by the plugin; existing RSA defaults stay intact.
func preparePS256Verification(token *jwtlib.Token, secret any) error {
	method, ok := token.Method.(*jwtlib.SigningMethodRSAPSS)
	if !ok || method == nil || method.SigningMethodRSA == nil || method.Alg() != "PS256" || method.Hash != crypto.SHA256 || token.Header["alg"] != "PS256" {
		return jwtlib.ErrSignatureInvalid
	}
	public, ok := secret.(*rsa.PublicKey)
	if !ok || public == nil || public.N == nil || public.N.BitLen() < 2048 || public.N.BitLen() > 8192 {
		return jwtlib.ErrInvalidKey
	}
	token.Method = &jwtlib.SigningMethodRSAPSS{
		SigningMethodRSA: &jwtlib.SigningMethodRSA{Name: "PS256", Hash: crypto.SHA256},
		Options:          &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256},
		VerifyOptions:    &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256},
	}
	return nil
}
