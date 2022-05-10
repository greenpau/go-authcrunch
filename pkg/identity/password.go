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
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"golang.org/x/crypto/bcrypt"
	"strconv"
	"strings"
	"time"
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

// NewPassword returns an instance of Password.
func NewPassword(s string) (*Password, error) {
	return NewPasswordWithOptions(s, "generic", "bcrypt", nil)
}

// NewPasswordWithOptions returns an instance of Password based on the
// provided parameters.
func NewPasswordWithOptions(s, purpose, algo string, params map[string]interface{}) (*Password, error) {
	p := &Password{
		Purpose:   purpose,
		Algorithm: algo,
		CreatedAt: time.Now().UTC(),
	}

	if params != nil {
		if v, exists := params["cost"]; exists {
			p.Cost = v.(int)
		}
	}

	if err := p.hash(s); err != nil {
		return nil, err
	}
	return p, nil
}

// Disable disables Password instance.
func (p *Password) Disable() {
	p.Expired = true
	p.ExpiredAt = time.Now().UTC()
	p.Disabled = true
	p.DisabledAt = time.Now().UTC()
}

func (p *Password) hash(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return errors.ErrPasswordEmpty
	}

	// Handle bcrypt hashed password.
	if strings.HasPrefix(s, "bcrypt:") {
		arr := strings.SplitN(s, ":", 3)
		if len(arr) != 3 {
			return errors.ErrPasswordHashed.WithArgs("unsupported format")
		}
		cost, err := strconv.Atoi(arr[1])
		if err != nil {
			return errors.ErrPasswordHashed.WithArgs("cost converstion failed")
		}
		if cost < 8 {
			return errors.ErrPasswordHashed.WithArgs("cost value is too low")
		}
		p.Cost = cost
		p.Hash = arr[2]
		return nil
	}

	switch p.Algorithm {
	case "bcrypt":
		if p.Cost < 8 {
			p.Cost = 10
		}
		ph, err := bcrypt.GenerateFromPassword([]byte(s), p.Cost)
		if err != nil {
			return errors.ErrPasswordGenerate.WithArgs(err)
		}
		p.Hash = string(ph)
		return nil
	case "":
		return errors.ErrPasswordEmptyAlgorithm
	}
	return errors.ErrPasswordUnsupportedAlgorithm.WithArgs(p.Algorithm)
}

// Match returns true when the provided password matches the user.
func (p *Password) Match(s string) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(p.Hash), []byte(s)); err == nil {
		return true
	}
	return false
}
