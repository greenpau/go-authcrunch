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

package messaging

import (
	"reflect"
	"testing"
)

func TestNewEmailTemplatesLibrary(t *testing.T) {
	t.Log("Creating Email Messaging Templates Library factory")

	sal, err := NewEmailTemplatesLibrary()
	if err != nil {
		t.Fatalf("Expected success, but got error: %v", err)
	}

	if sal == nil {
		t.Fatal("Expected StaticAssetLibrary instance, got nil")
	}

	wantCount := 6
	gotCount := sal.GetAssetCount()
	if gotCount != wantCount {
		t.Errorf("Expected asset count %d, got %d", wantCount, gotCount)
	}

	wantPaths := []string{
		"en/registration_confirmation_body",
		"en/registration_confirmation_subject",
		"en/registration_ready_body",
		"en/registration_ready_subject",
		"en/registration_verdict_body",
		"en/registration_verdict_subject",
	}

	gotPaths := sal.GetAssetPaths()

	if !reflect.DeepEqual(gotPaths, wantPaths) {
		t.Error("GetAssetPaths() mismatch detected:")

		// Create sets for comparison
		gotMap := make(map[string]bool)
		for _, p := range gotPaths {
			gotMap[p] = true
		}

		wantMap := make(map[string]bool)
		for _, p := range wantPaths {
			wantMap[p] = true
		}

		// Find missing (in want, but not in got)
		for _, p := range wantPaths {
			if !gotMap[p] {
				t.Errorf("  [-] expected file not found: %s", p)
			}
		}

		// Find extras (in got, but not in want)
		for _, p := range gotPaths {
			if !wantMap[p] {
				t.Errorf("  [+] found unexpected file:   %s", p)
			}
		}

		// Also check if order is the only problem
		if len(gotPaths) == len(wantPaths) {
			t.Log("Note: Slice lengths match; check for alphanumeric sorting errors.")
		}
	}

	t.Log("Email Messaging Templates Library initialized successfully")
}
