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

package qr

import (
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// Code holds the data associated with a QR code.
type Code struct {
	Type      string `json:"type,omitempty" xml:"type,omitempty" yaml:"type,omitempty"`
	Secret    string `json:"secret,omitempty" xml:"secret,omitempty" yaml:"secret,omitempty"`
	Algorithm string `json:"algorithm,omitempty" xml:"algorithm,omitempty" yaml:"algorithm,omitempty"`
	Label     string `json:"label,omitempty" xml:"label,omitempty" yaml:"label,omitempty"`
	Issuer    string `json:"issuer,omitempty" xml:"issuer,omitempty" yaml:"issuer,omitempty"`
	Period    int    `json:"period,omitempty" xml:"period,omitempty" yaml:"period,omitempty"`
	Digits    int    `json:"digits,omitempty" xml:"digits,omitempty" yaml:"digits,omitempty"`
	Counter   int    `json:"counter,omitempty" xml:"counter,omitempty" yaml:"counter,omitempty"`
	text      string
	encoded   string
}

// NewCode returns an instance of Code.
func NewCode() *Code {
	return &Code{}
}

func (c *Code) validate() error {
	if c.Label == "" {
		return fmt.Errorf("token label must be set")
	}
	if c.Secret == "" {
		return fmt.Errorf("token secret must be set")
	}
	if len(c.Secret) < 6 {
		return fmt.Errorf("token secret must be at least 6 characters long")
	}
	if c.Digits == 0 {
		c.Digits = 6
	} else {
		if c.Digits < 4 || c.Digits > 8 {
			return fmt.Errorf("digits must be between 4 and 8 numbers long")
		}
	}
	if c.Period == 0 {
		c.Period = 30
	} else {
		if c.Period < 30 || c.Period > 180 {
			return fmt.Errorf("token period must be between 30 and 180 seconds")
		}
	}
	switch c.Type {
	case "totp":
	case "hotp":
		if c.Counter < 1 {
			return fmt.Errorf("hotp token counter must be set")
		}
	default:
		return fmt.Errorf("token type must be either totp or hotp")
	}

	c.Algorithm = strings.ToLower(c.Algorithm)
	switch c.Algorithm {
	case "sha1", "sha256", "sha512":
	case "":
	default:
		return fmt.Errorf("token algo must be SHA1, SHA256, or SHA512")
	}

	return nil
}

// Build validates and build QR code.
func (c *Code) Build() error {
	if err := c.validate(); err != nil {
		return err
	}
	var sb strings.Builder
	sb.WriteString("otpauth://")
	sb.WriteString(c.Type + "/" + url.QueryEscape(c.Label))
	secretEncoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	sb.WriteString("?secret=" + secretEncoder.EncodeToString([]byte(c.Secret)))
	if c.Issuer != "" {
		sb.WriteString("&issuer=" + url.QueryEscape(c.Issuer))
	}
	if c.Algorithm != "" {
		sb.WriteString("&algorithm=" + c.Algorithm)
	}
	if c.Digits > 0 {
		sb.WriteString(fmt.Sprintf("&digits=%d", c.Digits))
	}
	if c.Counter > 0 {
		sb.WriteString(fmt.Sprintf("&counter=%d", c.Counter))
	}
	if c.Period > 0 {
		sb.WriteString(fmt.Sprintf("&period=%d", c.Period))
	}

	c.text = sb.String()
	c.encoded = base64.StdEncoding.EncodeToString([]byte(c.text))
	return nil
}

// Get return QR code.
func (c *Code) Get() string {
	return c.text
}

// GetEncoded returns base64-encoded QR code.
func (c *Code) GetEncoded() string {
	return c.encoded
}
