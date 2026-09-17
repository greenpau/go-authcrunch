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

package authcrunch_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestOIDCConformanceBrowserEvidenceRouting(t *testing.T) {
	const issuer, suiteURL = "https://portal.test/auth", "https://suite.test"
	browser, overrides := foundationBrowserConfiguration(issuer, suiteURL, "fixture-user", "fixture-password")
	for _, tc := range []struct {
		module, capturePath, capturePattern string
		interactive                         bool
	}{
		{module: "default", interactive: true},
		{module: "oidcc-ensure-request-object-with-redirect-uri", interactive: true},
		{module: "oidcc-prompt-login", capturePath: "/login*", capturePattern: "(?i)username", interactive: true},
		{module: "oidcc-max-age-1", capturePath: "/login*", capturePattern: "(?i)username", interactive: true},
		{module: "oidcc-ensure-registered-redirect-uri", capturePath: "/oidc/authorize*", capturePattern: "invalid_request"},
		{module: "oidcc-ensure-redirect-uri-in-authorization-request", capturePath: "/oidc/authorize*", capturePattern: "invalid_request"},
		{module: "oidcc-redirect-uri-query-added", capturePath: "/oidc/authorize*", capturePattern: "invalid_request"},
		{module: "oidcc-redirect-uri-query-mismatch", capturePath: "/oidc/authorize*", capturePattern: "invalid_request"},
	} {
		t.Run(tc.module, func(t *testing.T) {
			selected := browser
			if override, ok := overrides[tc.module]; ok {
				selected = override.(map[string]any)["browser"].([]any)
			}
			// Inspect the configuration the official runner will deserialize.
			data, err := json.Marshal(selected)
			if err != nil {
				t.Fatal(err)
			}
			var scripts []struct {
				Tasks []struct {
					Match    string
					Commands [][]any
				}
			}
			if err := json.Unmarshal(data, &scripts); err != nil {
				t.Fatal(err)
			}
			var captures int
			commands := map[string][][]any{}
			for _, script := range scripts {
				for _, task := range script.Tasks {
					for _, command := range task.Commands {
						if action, ok := command[len(command)-1].(string); ok && strings.HasPrefix(action, "update-image-placeholder") {
							captures++
							if tc.capturePath == "" || task.Match != issuer+tc.capturePath || len(command) != 6 || command[4] != tc.capturePattern {
								t.Fatal("capture can attach evidence to the wrong review placeholder")
							}
							continue
						}
						commands[task.Match] = append(commands[task.Match], command)
					}
				}
			}
			wantCaptures := 0
			if tc.capturePath != "" {
				wantCaptures = 1
			}
			if captures != wantCaptures {
				t.Fatalf("got %d capture commands, want %d", captures, wantCaptures)
			}
			if tc.interactive {
				for path, want := range map[string][][]any{
					issuer + "/login*":             {{"text", "name", "username", "fixture-user"}, {"click", "class", "app-btn-pri"}},
					issuer + "/sandbox/*":          {{"text", "name", "secret", "fixture-password"}, {"click", "name", "submit"}},
					issuer + "/oidc/*":             {{"click", "name", "decision"}},
					suiteURL + "/test/*/callback*": {{"wait", "id", "submission_complete", float64(10)}},
				} {
					if !reflect.DeepEqual(commands[path], want) {
						t.Fatal("browser capture changed the real login, consent, or callback interaction")
					}
				}
			}
		})
	}
}
