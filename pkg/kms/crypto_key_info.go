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

// CryptoKeyInfo holds information about CryptoKey.
type CryptoKeyInfo struct {
	// Seq is the order in which a key would be processed.
	Seq int `json:"seq,omitempty" xml:"seq,omitempty" yaml:"seq,omitempty"`
	// ID is the key ID, aka kid.
	ID string `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	// Usage is the intended key usage. The values are: sign, verify, both,
	// or auto.
	Usage string `json:"usage,omitempty" xml:"usage,omitempty" yaml:"usage,omitempty"`
	// TokenName is the token name associated with the key.
	TokenName string `json:"token_name,omitempty" xml:"token_name,omitempty" yaml:"token_name,omitempty"`
	// CookieNames is the cookie names associated with the key.
	CookieNames []string `json:"cookie_names,omitempty" xml:"cookie_names,omitempty" yaml:"cookie_names,omitempty"`
	// Source is either config or env.
	Source string `json:"source,omitempty" xml:"source,omitempty" yaml:"source,omitempty"`
	// Algorithm is either hmac, rsa, or ecdsa.
	Algorithm string `json:"algorithm,omitempty" xml:"algorithm,omitempty" yaml:"algorithm,omitempty"`
	// TokenLifetime is the expected token grant lifetime in seconds.
	TokenLifetime int `json:"token_lifetime,omitempty" xml:"token_lifetime,omitempty" yaml:"token_lifetime,omitempty"`
	// PreferredSignMethod is the preferred method to sign tokens, e.g.
	// all HMAC keys could use HS256, HS384, and HS512 methods. By default,
	// the preferred method is HS512. However, one may prefer using HS256.
	PreferredSignMethod string `json:"token_sign_method,omitempty" xml:"token_sign_method,omitempty" yaml:"token_sign_method,omitempty"`
	// EvalExpr is a list of expressions evaluated whether a specific key
	// should be used for signing and verification.
	EvalExpr []string `json:"token_eval_expr,omitempty" xml:"token_eval_expr,omitempty" yaml:"token_eval_expr,omitempty"`
	// Parsed indicated whether the key was parsed via config.
	Parsed bool `json:"parsed" xml:"parsed" yaml:"parsed"`
	// Validated indicated whether the key config was validated.
	Validated     bool `json:"validated" xml:"validated" yaml:"validated"`
	SignCapable   bool `json:"sign_capable" xml:"sign_capable" yaml:"sign_capable"`
	VerifyCapable bool `json:"verify_capable" xml:"verify_capable" yaml:"verify_capable"`
}
