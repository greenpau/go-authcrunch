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

package authchal

import "github.com/greenpau/go-authcrunch/pkg/authchal/config"

const (
	// PasswordKeyword identifies a password challenge.
	PasswordKeyword = config.PasswordKeyword
	// TotpKeyword identifies a time-based one-time password challenge.
	TotpKeyword = config.TotpKeyword
	// U2fKeyword identifies a WebAuthn challenge.
	U2fKeyword = config.U2fKeyword
	// MfaKeyword identifies a generic MFA challenge.
	MfaKeyword = config.MfaKeyword
	// EmailKeyword identifies an email challenge.
	EmailKeyword = config.EmailKeyword
)

// Rule describes a typed authentication challenge selection rule.
type Rule = config.Rule
