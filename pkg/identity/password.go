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

package identity

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/greenpau/go-authcrunch/pkg/errors"
)

// Password is a memorized secret, typically a string of characters,
// used to confirm the identity of a user.
type Password struct {
	Purpose    string    `json:"purpose,omitempty" xml:"purpose,omitempty" yaml:"purpose,omitempty"`
	Algorithm  string    `json:"algorithm,omitempty" xml:"algorithm,omitempty" yaml:"algorithm,omitempty"`
	Hash       string    `json:"hash,omitempty" xml:"hash,omitempty" yaml:"hash,omitempty"`
	Cost       int       `json:"cost,omitempty" xml:"cost,omitempty" yaml:"cost,omitempty"`
	Expired    bool      `json:"expired,omitempty" xml:"expired,omitempty" yaml:"expired,omitempty"`
	ExpiredAt  time.Time `json:"expired_at,omitempty" xml:"expired_at,omitempty" yaml:"expired_at,omitempty"`
	CreatedAt  time.Time `json:"created_at,omitempty" xml:"created_at,omitempty" yaml:"created_at,omitempty"`
	Disabled   bool      `json:"disabled,omitempty" xml:"disabled,omitempty" yaml:"disabled,omitempty"`
	DisabledAt time.Time `json:"disabled_at,omitempty" xml:"disabled_at,omitempty" yaml:"disabled_at,omitempty"`
}

// ParseHashedPassword imports bcrypt:<cost>:<hash> or argon2:<PHC>.
// Argon2 imports must contain a bounded Argon2id v19 PHC string.
func ParseHashedPassword(s string) (*Password, error) {
	if hash, ok := strings.CutPrefix(s, "argon2:"); ok {
		if _, err := parseArgon2(hash); err != nil {
			return nil, errors.ErrPasswordHashed.WithArgs(err)
		}
		return &Password{Purpose: "generic", Algorithm: PasswordAlgorithmArgon2, Hash: hash, CreatedAt: time.Now().UTC()}, nil
	}
	if !strings.HasPrefix(s, "bcrypt:") {
		return nil, errors.ErrPasswordHashed.WithArgs("unsupported format")
	}

	arr := strings.SplitN(s, ":", 3)
	if len(arr) != 3 {
		return nil, errors.ErrPasswordHashed.WithArgs("invalid format")
	}

	cost, err := strconv.Atoi(arr[1])
	if err != nil || strconv.Itoa(cost) != arr[1] {
		return nil, errors.ErrPasswordHashed.WithArgs("cost conversion failed")
	}

	if cost < 8 {
		return nil, errors.ErrPasswordHashed.WithArgs("cost value is too low")
	}
	encodedCost, err := bcrypt.Cost([]byte(arr[2]))
	if err != nil || encodedCost != cost || !validBcryptHash(arr[2]) {
		return nil, errors.ErrPasswordHashed.WithArgs("invalid bcrypt hash or inconsistent cost")
	}

	return &Password{
		Purpose:   "generic",
		Algorithm: "bcrypt",
		Cost:      cost,
		Hash:      arr[2],
		CreatedAt: time.Now().UTC(),
	}, nil
}

// NewPassword imports a prefixed hash or generates bcrypt cost 10 from plaintext.
func NewPassword(s string) (*Password, error) {
	return NewPasswordWithOptions(s, "generic", "bcrypt", nil)
}

// NewPasswordWithOptions imports a prefixed hash or generates a password with
// the requested algorithm. Parameters are int values: cost for bcrypt, or
// memory (KiB), iterations and parallelism for argon2. Typed callers should use
// NewPasswordWithConfig. Imported parameters override generation options.
func NewPasswordWithOptions(s, purpose, algo string, params map[string]any) (*Password, error) {
	if strings.TrimSpace(s) == "" {
		return nil, errors.ErrPasswordEmpty
	}
	if IsPasswordHashImport(s) {
		p, err := ParseHashedPassword(strings.TrimSpace(s))
		if err == nil {
			p.Purpose = purpose
		}
		return p, err
	}
	if algo == "" {
		return nil, errors.ErrPasswordEmptyAlgorithm
	}
	if algo != PasswordAlgorithmBcrypt && algo != PasswordAlgorithmArgon2 {
		return nil, errors.ErrPasswordUnsupportedAlgorithm.WithArgs(algo)
	}
	c := &PasswordHashConfig{Algorithm: algo}
	for name, value := range params {
		n, ok := value.(int)
		if !ok {
			return nil, errors.ErrPasswordGenerate.WithArgs("password hash parameters must be integers")
		}
		switch name {
		case "cost":
			if algo != PasswordAlgorithmBcrypt {
				return nil, errors.ErrPasswordGenerate.WithArgs("bcrypt cost cannot be used with argon2")
			}
			c.Cost = n
		case "memory":
			c.Memory = n
		case "iterations":
			c.Iterations = n
		case "parallelism":
			c.Parallelism = n
		default:
			return nil, errors.ErrPasswordGenerate.WithArgs("unsupported password hash parameter")
		}
		if name != "cost" && n <= 0 {
			return nil, errors.ErrPasswordGenerate.WithArgs("argon2 parameters must be positive")
		}
	}
	// Preserve the legacy constructor's bcrypt cost default and error contract.
	if algo == PasswordAlgorithmBcrypt {
		if c.Cost < 8 {
			c.Cost = bcrypt.DefaultCost
		}
		if c.Cost > bcrypt.MaxCost {
			return nil, errors.ErrPasswordGenerate.WithArgs(bcrypt.InvalidCostError(c.Cost))
		}
	}
	return NewPasswordWithConfig(s, purpose, c)
}

// NewPasswordWithConfig creates a password using a snapshot of c. Recognized
// import prefixes retain their encoded algorithm and parameters. Plaintext is
// trimmed at creation, but never during Match or database authentication.
func NewPasswordWithConfig(s, purpose string, c *PasswordHashConfig) (*Password, error) {
	if c == nil {
		return nil, fmt.Errorf("password hash configuration is required")
	}
	config := *c
	if err := config.Validate(); err != nil {
		return nil, errors.ErrPasswordGenerate.WithArgs(err)
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.ErrPasswordEmpty
	}
	if IsPasswordHashImport(s) {
		p, err := ParseHashedPassword(s)
		if err == nil {
			p.Purpose = purpose
		}
		return p, err
	}
	p := &Password{Purpose: purpose, Algorithm: config.Algorithm, Cost: config.Cost, CreatedAt: time.Now().UTC()}
	if config.Algorithm == PasswordAlgorithmArgon2 {
		p.Hash = generateArgon2(s, &config)
		return p, nil
	}
	ph, err := bcrypt.GenerateFromPassword([]byte(s), config.Cost)
	if err != nil {
		return nil, errors.ErrPasswordGenerate.WithArgs(err)
	}
	p.Hash = string(ph)
	return p, nil
}

// Disable disables Password instance.
func (p *Password) Disable() {
	p.Expired = true
	p.ExpiredAt = time.Now().UTC()
	p.Disabled = true
	p.DisabledAt = time.Now().UTC()
}

// EncodedHash returns the configuration import representation of a password
// created by the constructors. It does not reveal the plaintext credential.
func (p *Password) EncodedHash() string {
	if p == nil {
		return ""
	}
	switch p.Algorithm {
	case "", PasswordAlgorithmBcrypt:
		return fmt.Sprintf("bcrypt:%d:%s", p.Cost, p.Hash)
	case PasswordAlgorithmArgon2:
		return "argon2:" + p.Hash
	}
	return ""
}

const bcryptHashAlphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

var bcryptHashEncoding = base64.NewEncoding(bcryptHashAlphabet).WithPadding(base64.NoPadding).Strict()

func validBcryptHash(hash string) bool {
	// bcrypt.Cost accepts unknown historical version bytes and does not validate
	// every separator. Enforce the complete import grammar before retaining a
	// credential, including canonical bcrypt Base64 for its salt and checksum.
	var costStart int
	switch {
	case strings.HasPrefix(hash, "$2$"):
		costStart = 3
	case len(hash) >= 4 && hash[0] == '$' && hash[1] == '2' && hash[3] == '$' &&
		strings.ContainsRune("abxy", rune(hash[2])):
		costStart = 4
	default:
		return false
	}
	separator := costStart + 2
	payloadStart := separator + 1
	if len(hash) != payloadStart+53 || hash[separator] != '$' ||
		hash[costStart] < '0' || hash[costStart] > '9' ||
		hash[costStart+1] < '0' || hash[costStart+1] > '9' {
		return false
	}
	payload := hash[payloadStart:]
	salt, err := bcryptHashEncoding.DecodeString(payload[:22])
	if err != nil || len(salt) != 16 {
		return false
	}
	checksum, err := bcryptHashEncoding.DecodeString(payload[22:])
	return err == nil && len(checksum) == 23
}

// Match returns true when the provided password matches the user.
func (p *Password) Match(s string) bool {
	if p == nil {
		return false
	}
	switch p.Algorithm {
	case "", PasswordAlgorithmBcrypt:
		return bcrypt.CompareHashAndPassword([]byte(p.Hash), []byte(s)) == nil
	case PasswordAlgorithmArgon2:
		hash, err := parseArgon2(p.Hash)
		return err == nil && hash.match(s)
	}
	return false
}
