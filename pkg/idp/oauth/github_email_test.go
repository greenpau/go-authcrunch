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
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

func TestFetchGithubEmail(t *testing.T) {
	tests := []struct {
		name           string
		initialData    map[string]interface{}
		mockResponse   []ghEmailEntry
		expectedEmail  string
		expectedVerify bool
		expectError    bool
	}{
		{
			name:          "email already in data",
			initialData:   map[string]interface{}{EmailClaimKey: "existing@example.com"},
			expectedEmail: "existing@example.com",
		},
		{
			name: "primary and verified email exists",
			mockResponse: []ghEmailEntry{
				{Email: "verified@example.com", Verified: true, Primary: false},
				{Email: "primary.verified@example.com", Verified: true, Primary: true},
			},
			expectedEmail:  "primary.verified@example.com",
			expectedVerify: true,
		},
		{
			name: "first verified email picked",
			mockResponse: []ghEmailEntry{
				{Email: "unverified@example.com", Verified: false},
				{Email: "first.verified@example.com", Verified: true},
				{Email: "second.verified@example.com", Verified: true},
			},
			expectedEmail:  "first.verified@example.com",
			expectedVerify: true,
		},
		{
			name: "fallback",
			mockResponse: []ghEmailEntry{
				{Email: "unverified@example.com", Verified: false, Primary: false},
			},
			expectedEmail:  "unverified@example.com",
			expectedVerify: false,
		},
		{
			name:        "malformed email",
			initialData: map[string]interface{}{EmailClaimKey: 1234567890},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				// json.NewEncoder(w).Encode(tc.mockResponse)
				if err := json.NewEncoder(w).Encode(tc.mockResponse); err != nil {
					t.Errorf("Failed to encode mock response: %v", err)
				}
			}))
			defer server.Close()

			provider := &IdentityProvider{
				logger: zap.NewNop(),
			}

			metadata := make(map[string]interface{})
			if tc.initialData == nil {
				tc.initialData = make(map[string]interface{})
			}

			err := provider.fetchGithubEmail(tc.initialData, metadata, server.URL, "foo")

			if (err != nil) != tc.expectError {
				t.Fatalf("expected error: %v, got: %v", tc.expectError, err)
			}

			if !tc.expectError {
				if metadata[EmailClaimKey] != tc.expectedEmail {
					t.Errorf("expected email %s, got %s", tc.expectedEmail, metadata[EmailClaimKey])
				}
				if tc.expectedVerify && metadata[EmailVerifiedClaimKey] != true {
					t.Errorf("expected email_verified to be true")
				}
			}
		})
	}
}
