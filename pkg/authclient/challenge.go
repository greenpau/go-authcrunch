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

package authclient

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// PromptKind identifies the input needed to continue authentication.
type PromptKind string

const (
	// PromptPassword requests the user's password.
	PromptPassword PromptKind = "password"
	// PromptTOTP requests a current authenticator application code.
	PromptTOTP PromptKind = "totp"
	// PromptMFA requests a choice: "totp" or "webauthn". WebAuthn selection
	// preserves portal negotiation, but assertion handling is unsupported.
	PromptMFA PromptKind = "mfa"
)

var (
	// ErrInputRequired means no prompt was supplied for missing input.
	ErrInputRequired = errors.New("authentication input required")
	// ErrUnsupportedChallenge means this client cannot complete the challenge.
	ErrUnsupportedChallenge = errors.New("unsupported authentication challenge")
)

// PromptFunc obtains missing input without coupling authentication to a terminal.
// It should honor ctx and must not log entered values or return them in errors.
type PromptFunc func(ctx context.Context, kind PromptKind) (string, error)

func (c *Client) answer(ctx context.Context, kind string) (string, error) {
	switch kind {
	case string(PromptPassword):
		if c.config.Password != "" {
			return c.config.Password, nil
		}
		return c.input(ctx, PromptPassword)
	case string(PromptTOTP):
		return c.totp(ctx)
	case string(PromptMFA):
		// Noninteractive clients with a shared secret can choose TOTP directly.
		if c.prompt == nil && c.config.TOTPSecret != "" {
			return c.totp(ctx)
		}
		choice, err := c.input(ctx, PromptMFA)
		if err != nil {
			return "", err
		}
		switch strings.TrimSpace(choice) {
		case "totp":
			return c.totp(ctx)
		case "webauthn":
			return "webauthn", nil
		default:
			return "", fmt.Errorf("unsupported MFA selection")
		}
	default:
		// Do not include the server's challenge, which may contain secret data.
		return "", ErrUnsupportedChallenge
	}
}

func (c *Client) totp(ctx context.Context) (string, error) {
	if c.config.TOTPSecret != "" {
		return generateTOTP(c.config.TOTPSecret, c.config.TOTPCodeLength, c.config.TOTPCodeLifetime, time.Now()), nil
	}
	return c.input(ctx, PromptTOTP)
}

func (c *Client) input(ctx context.Context, kind PromptKind) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if c.prompt == nil {
		return "", fmt.Errorf("%w: %s", ErrInputRequired, kind)
	}
	value, err := c.prompt(ctx, kind)
	if err != nil {
		return "", fmt.Errorf("authentication prompt: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("empty authentication input")
	}
	return value, nil
}
