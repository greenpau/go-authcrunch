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

// Package sqlite provides durable email-confirmed account registration.
package sqlite

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/greenpau/go-authcrunch/internal/sqlitedb"
)

// Config fixes the enrollment destination and public confirmation-link origin.
type Config struct {
	Name          string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Path          string `json:"path,omitempty" xml:"path,omitempty" yaml:"path,omitempty"`
	Timeout       string `json:"timeout,omitempty" xml:"timeout,omitempty" yaml:"timeout,omitempty"`
	IdentityStore string `json:"identity_store,omitempty" xml:"identity_store,omitempty" yaml:"identity_store,omitempty"`
	Realm         string `json:"realm,omitempty" xml:"realm,omitempty" yaml:"realm,omitempty"`
	EmailProvider string `json:"email_provider,omitempty" xml:"email_provider,omitempty" yaml:"email_provider,omitempty"`
	PublicOrigin  string `json:"public_origin,omitempty" xml:"public_origin,omitempty" yaml:"public_origin,omitempty"`
	BasePath      string `json:"base_path,omitempty" xml:"base_path,omitempty" yaml:"base_path,omitempty"`
}

// Validate normalizes defaults without opening files or resolving providers.
func (c *Config) Validate() error {
	if c == nil || !sqlitedb.ValidText(c.Name, 128) || !sqlitedb.ValidText(c.IdentityStore, 128) || !sqlitedb.ValidText(c.EmailProvider, 128) || !matches(`^[A-Za-z0-9_-]{1,64}$`, c.Realm) {
		return ErrInvalid
	}
	u, err := url.Parse(c.PublicOrigin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || c.PublicOrigin != "https://"+u.Host || strings.ToLower(u.Host) != u.Host || len(c.PublicOrigin) > 2048 {
		return ErrInvalid
	}
	if c.BasePath == "" {
		c.BasePath = "/auth"
	}
	if c.BasePath != "/" && !matches(`^(/[A-Za-z0-9_-]+)+$`, c.BasePath) {
		return ErrInvalid
	}
	return sqlitedb.Normalize(&c.Path, &c.Timeout)
}
func matches(pattern, value string) bool {
	matched, _ := regexp.MatchString(pattern, value)
	return matched
}
