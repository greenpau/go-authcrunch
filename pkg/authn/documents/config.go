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

// Package documents stores encrypted documents and recipient key envelopes.
// It never receives plaintext, recovery secrets, or unwrapped document keys.
package documents

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"

	"github.com/greenpau/go-authcrunch/internal/sqlitedb"
	"github.com/greenpau/go-authcrunch/pkg/portalpath"
)

// ChunkSize is the protocol's plaintext chunk size, in bytes. Even an empty
// document has one chunk containing a 16-byte AES-GCM authentication tag.
const ChunkSize = 1 << 20

// Config configures a durable, portal-bound encrypted document store. Portal
// API enablement is separate from these storage settings. The parent directory
// of Database must already exist with owner-only permissions; the file is 0600.
type Config struct {
	Database         string   `json:"database,omitempty" xml:"database,omitempty" yaml:"database,omitempty"`
	PublicOrigin     string   `json:"public_origin,omitempty" xml:"public_origin,omitempty" yaml:"public_origin,omitempty"`
	BasePath         string   `json:"base_path,omitempty" xml:"base_path,omitempty" yaml:"base_path,omitempty"`
	Realms           []string `json:"realms,omitempty" xml:"realms,omitempty" yaml:"realms,omitempty"`
	MaxFileBytes     int64    `json:"max_file_bytes,omitempty" xml:"max_file_bytes,omitempty" yaml:"max_file_bytes,omitempty"`
	MaxUserBytes     int64    `json:"max_user_bytes,omitempty" xml:"max_user_bytes,omitempty" yaml:"max_user_bytes,omitempty"`
	MaxTotalBytes    int64    `json:"max_total_bytes,omitempty" xml:"max_total_bytes,omitempty" yaml:"max_total_bytes,omitempty"`
	MaxUserFiles     int      `json:"max_user_files,omitempty" xml:"max_user_files,omitempty" yaml:"max_user_files,omitempty"`
	MaxTotalFiles    int      `json:"max_total_files,omitempty" xml:"max_total_files,omitempty" yaml:"max_total_files,omitempty"`
	MaxKeys          int      `json:"max_keys,omitempty" xml:"max_keys,omitempty" yaml:"max_keys,omitempty"`
	MaxRecipients    int      `json:"max_recipients,omitempty" xml:"max_recipients,omitempty" yaml:"max_recipients,omitempty"`
	UploadTTLSeconds int64    `json:"upload_ttl_seconds,omitempty" xml:"upload_ttl_seconds,omitempty" yaml:"upload_ttl_seconds,omitempty"`
}

// ErrConfig indicates invalid settings without disclosing configuration values.
var ErrConfig = errors.New("invalid documents configuration")

// Validate installs defaults and validates storage settings without IO. Byte
// quotas count ciphertext, including authentication tags and unfinished uploads.
func (c *Config) Validate() error {
	if c == nil {
		return ErrConfig
	}
	timeout := "5s"
	if sqlitedb.Normalize(&c.Database, &timeout) != nil {
		return ErrConfig
	}
	if !validPublicOrigin(c.PublicOrigin) {
		return ErrConfig
	}
	if c.BasePath == "" {
		c.BasePath = "/"
	}
	if !sqlitedb.ValidText(c.BasePath, 2048) || portalpath.Validate(c.BasePath) != nil {
		return ErrConfig
	}
	if len(c.Realms) == 0 || len(c.Realms) > 64 {
		return ErrConfig
	}
	seen := make(map[string]bool)
	for _, realm := range c.Realms {
		if !sqlitedb.ValidText(realm, 128) || seen[realm] {
			return ErrConfig
		}
		seen[realm] = true
	}
	if c.MaxFileBytes == 0 {
		c.MaxFileBytes = 256 << 20
	}
	if c.MaxUserBytes == 0 {
		c.MaxUserBytes = 1 << 30
	}
	if c.MaxTotalBytes == 0 {
		c.MaxTotalBytes = 10 << 30
	}
	if c.MaxUserFiles == 0 {
		c.MaxUserFiles = 1000
	}
	if c.MaxTotalFiles == 0 {
		c.MaxTotalFiles = 10000
	}
	if c.MaxKeys == 0 {
		c.MaxKeys = 10000
	}
	if c.MaxRecipients == 0 {
		c.MaxRecipients = 100
	}
	if c.UploadTTLSeconds == 0 {
		c.UploadTTLSeconds = 86400
	}
	if c.MaxFileBytes < 16 || c.MaxFileBytes > 4<<30 || c.MaxUserBytes < c.MaxFileBytes || c.MaxUserBytes > 1<<40 || c.MaxTotalBytes < c.MaxUserBytes || c.MaxTotalBytes > 1<<50 || c.MaxUserFiles < 1 || c.MaxUserFiles > 100000 || c.MaxTotalFiles < c.MaxUserFiles || c.MaxTotalFiles > 1000000 || c.MaxKeys < 1 || c.MaxKeys > 1000000 || c.MaxRecipients < 1 || c.MaxRecipients > 1000 || c.UploadTTLSeconds < 60 || c.UploadTTLSeconds > 604800 {
		return ErrConfig
	}
	return nil
}

// Require an already serialized HTTPS origin. Browser URL parsing rewrites
// Unicode domains, numeric IP aliases, IPv6 spellings and ports; persisting one
// of those aliases would bind the database to an origin no browser can send.
// Reject instead of rewriting because this value is a permanent store binding.
func validPublicOrigin(value string) bool {
	if !sqlitedb.ValidText(value, 2048) || strings.ContainsAny(value, "\\%?#\r\n\t ") {
		return false
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawPath != "" || u.Host == "" {
		return false
	}
	host := u.Hostname()
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return false
		}
		canonical := addr.String()
		if addr.Is4In6() {
			// Browsers serialize mapped IPv6 addresses as hexadecimal groups.
			ip := addr.As16()
			canonical = "::ffff:" + strconv.FormatUint(uint64(ip[12])<<8|uint64(ip[13]), 16) + ":" + strconv.FormatUint(uint64(ip[14])<<8|uint64(ip[15]), 16)
		}
		if canonical != host {
			return false
		}
		if addr.Is6() {
			host = "[" + host + "]"
		}
	} else {
		ascii, err := idna.Lookup.ToASCII(host)
		if err != nil || ascii != host || host == "" || len(strings.TrimSuffix(host, ".")) > 253 {
			return false
		}
		labels := strings.Split(strings.TrimSuffix(host, "."), ".")
		for _, label := range labels {
			if label == "" || len(label) > 63 {
				return false
			}
		}
		// A numeric final label invokes the browser's legacy IPv4 parser.
		// Canonical IPv4 was accepted above; all remaining forms are aliases
		// or invalid browser hosts, rather than DNS names.
		last := labels[len(labels)-1]
		if strings.Trim(last, "0123456789") == "" || (strings.HasPrefix(last, "0x") && strings.Trim(last[2:], "0123456789abcdef") == "") {
			return false
		}
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 0 || n > 65535 || n == 443 || strconv.Itoa(n) != port {
			return false
		}
		host += ":" + port
	}
	return value == "https://"+host
}
