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
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"golang.org/x/crypto/bcrypt"
	"time"
)

// APIKeyBundle is a collection of API keys.
type APIKeyBundle struct {
	keys []*APIKey
	size int
}

// APIKey is an API key.
type APIKey struct {
	ID         string    `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	Prefix     string    `json:"prefix,omitempty" xml:"prefix,omitempty" yaml:"prefix,omitempty"`
	Usage      string    `json:"usage,omitempty" xml:"usage,omitempty" yaml:"usage,omitempty"`
	Comment    string    `json:"comment,omitempty" xml:"comment,omitempty" yaml:"comment,omitempty"`
	Payload    string    `json:"payload,omitempty" xml:"payload,omitempty" yaml:"payload,omitempty"`
	Expired    bool      `json:"expired,omitempty" xml:"expired,omitempty" yaml:"expired,omitempty"`
	ExpiredAt  time.Time `json:"expired_at,omitempty" xml:"expired_at,omitempty" yaml:"expired_at,omitempty"`
	CreatedAt  time.Time `json:"created_at,omitempty" xml:"created_at,omitempty" yaml:"created_at,omitempty"`
	Disabled   bool      `json:"disabled,omitempty" xml:"disabled,omitempty" yaml:"disabled,omitempty"`
	DisabledAt time.Time `json:"disabled_at,omitempty" xml:"disabled_at,omitempty" yaml:"disabled_at,omitempty"`
}

// NewAPIKeyBundle returns an instance of APIKeyBundle.
func NewAPIKeyBundle() *APIKeyBundle {
	return &APIKeyBundle{
		keys: []*APIKey{},
	}
}

// Add adds APIKey to APIKeyBundle.
func (b *APIKeyBundle) Add(k *APIKey) {
	b.keys = append(b.keys, k)
	b.size++
}

// Get returns APIKey instances of the APIKeyBundle.
func (b *APIKeyBundle) Get() []*APIKey {
	return b.keys
}

// Size returns the number of APIKey instances in APIKeyBundle.
func (b *APIKeyBundle) Size() int {
	return b.size
}

// NewAPIKey returns an instance of APIKey.
func NewAPIKey(r *requests.Request) (*APIKey, error) {
	if r.Key.Payload == "" {
		return nil, errors.ErrAPIKeyPayloadEmpty
	}
	if r.Key.Usage == "" {
		return nil, errors.ErrAPIKeyUsageEmpty
	}
	if r.Key.Usage != "api" {
		return nil, errors.ErrAPIKeyUsageUnsupported.WithArgs(r.Key.Usage)
	}
	if r.Key.Comment == "" {
		return nil, errors.ErrAPIKeyCommentEmpty
	}
	p := &APIKey{
		Comment:   r.Key.Comment,
		ID:        GetRandomString(40),
		Prefix:    r.Key.Prefix,
		Payload:   r.Key.Payload,
		Usage:     r.Key.Usage,
		CreatedAt: time.Now().UTC(),
	}
	if r.Key.Disabled {
		p.Disabled = true
		p.DisabledAt = time.Now().UTC()
	}
	return p, nil
}

// Disable disables APIKey instance.
func (p *APIKey) Disable() {
	p.Expired = true
	p.ExpiredAt = time.Now().UTC()
	p.Disabled = true
	p.DisabledAt = time.Now().UTC()
}

// Match returns true when the provided API matches.
func (p *APIKey) Match(s string) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(p.Payload), []byte(s)); err == nil {
		return true
	}
	return false
}
