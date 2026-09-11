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

package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authclient"
)

func (wr *wrapper) authenticate(ctx context.Context) error {
	credentials, err := wr.authenticator.Authenticate(ctx)
	if err != nil {
		return err
	}
	if err := wr.tokenStore.Save(credentials); err != nil {
		return err
	}
	wr.credentials = *credentials
	log.Printf("auth token acquired: %s", wr.config.TokenPath)
	return nil
}

func (wr *wrapper) promptAuthentication(ctx context.Context, kind authclient.PromptKind) (string, error) {
	var prompt string
	switch kind {
	case authclient.PromptPassword:
		prompt = "Please enter password: "
	case authclient.PromptTOTP:
		prompt = "Please enter authenticator app code: "
	case authclient.PromptMFA:
		prompt = "Enter 1 for MFA Application token OR enter 2 for U2F/WebAuthn: "
	default:
		return "", authclient.ErrUnsupportedChallenge
	}
	input, err := wr.readUserInputWithTimeout(ctx, prompt, 30*time.Second)
	if err != nil {
		return "", err
	}
	if kind == authclient.PromptMFA {
		switch strings.TrimSpace(input) {
		case "1":
			return "totp", nil
		case "2":
			return "webauthn", nil
		default:
			return "", fmt.Errorf("unsupported MFA selection")
		}
	}
	return input, nil
}
