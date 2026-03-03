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

package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"go.uber.org/zap"
)

const (
	// EmailClaimKey is the email claim field
	EmailClaimKey = "email"
	// EmailVerifiedClaimKey is the claim key used to store the email verification status.
	EmailVerifiedClaimKey = "email_verified"
)

// ghEmailEntry represents the structure returned by the GitHub user emails API.
type ghEmailEntry struct {
	Email      string `json:"email"`
	Primary    bool   `json:"primary"`
	Verified   bool   `json:"verified"`
	Visibility string `json:"visibility,omitempty"`
}

func (b *IdentityProvider) fetchGithubEmail(data map[string]interface{}, metadata map[string]interface{}, endpointURL, tokenString string) error {
	if data == nil {
		return fmt.Errorf("local data not found")
	}

	if metadata == nil {
		return fmt.Errorf("local metadata not found")
	}

	if v, exists := data[EmailClaimKey]; exists {
		email, ok := v.(string)
		if !ok {
			return errors.New("found email claim but it is not a string")
		}
		if email == "" {
			return errors.New("found email claim but it is emtpy")
		}
		metadata[EmailClaimKey] = email
		return nil
	}

	var req *http.Request
	reqMethod := "GET"

	cli, err := b.newBrowser()
	if err != nil {
		return err
	}
	req, err = http.NewRequest(reqMethod, endpointURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Add("Authorization", "token "+tokenString)

	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	b.logger.Debug("User data received", zap.String("url", endpointURL), zap.Any("body", respBody))

	var emails []ghEmailEntry
	if err := json.Unmarshal(respBody, &emails); err != nil {
		return fmt.Errorf("failed to decode email data: %w", err)
	}

	var bestEmail string
	var bestVerified bool

	for i, e := range emails {
		if i == 0 {
			// Lowest Priority: The very first entry (if nothing else is set yet)
			bestEmail = e.Email
			bestVerified = e.Verified
		}

		if e.Primary && e.Verified {
			// Highest Priority: Primary AND Verified
			bestEmail = e.Email
			bestVerified = true
			break
		}

		// Second Priority: First Verified email found
		if e.Verified && !bestVerified {
			bestEmail = e.Email
			bestVerified = true
		}
	}

	if bestEmail != "" {
		metadata[EmailClaimKey] = bestEmail
		if bestVerified {
			metadata[EmailVerifiedClaimKey] = true
		}
	}

	b.logger.Debug(
		"Fetched user GitHub email",
		zap.String("url", endpointURL),
		zap.String(EmailClaimKey, bestEmail),
		zap.Bool(EmailVerifiedClaimKey, bestVerified),
	)

	return nil
}
