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

package ui

import (
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestNewPageTemplatesLibrary(t *testing.T) {
	t.Log("Creating Page Templates Library factory")

	sal, err := NewPageTemplatesLibrary()
	if err != nil {
		t.Fatalf("Expected success, but got error: %v", err)
	}

	if sal == nil {
		t.Fatal("Expected StaticAssetLibrary instance, got nil")
	}

	wantCount := 8
	gotCount := sal.GetAssetCount()
	if gotCount != wantCount {
		t.Errorf("Expected asset count %d, got %d", wantCount, gotCount)
	}

	wantPaths := []string{
		"basic/apps_mobile_access",
		"basic/apps_sso",
		"basic/generic",
		"basic/login",
		"basic/portal",
		"basic/register",
		"basic/sandbox",
		"basic/whoami",
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

	t.Log("Static Asset Library initialized successfully")
}

func TestExtractTemplatePhrases(t *testing.T) {
	sal, err := NewPageTemplatesLibrary()
	if err != nil {
		t.Fatalf("Expected success, but got error: %v", err)
	}

	tagRegex := regexp.MustCompile(`>([^<{}\n\t][^<{}]+[^<{}\n\t])<`)
	attrRegex := regexp.MustCompile(`\b(alt|title|label|placeholder)="([^"{}]*)"`)

	for _, assetPath := range sal.GetAssetPaths() {
		asset, err := sal.GetAsset(assetPath)
		if err != nil {
			t.Fatalf("Expected success with %s, but got error: %v", assetPath, err)
		}

		phrases := make(map[string]bool)

		tagMatches := tagRegex.FindAllStringSubmatch(asset.Content, -1)
		for _, m := range tagMatches {
			phrase := strings.TrimSpace(m[1])
			if len(phrase) > 1 {
				phrases[phrase] = true
			}
		}

		attrMatches := attrRegex.FindAllStringSubmatch(asset.Content, -1)
		for _, m := range attrMatches {
			phrase := strings.TrimSpace(m[2])
			if len(phrase) > 1 {
				phrases[phrase] = true
			}
		}

		var result []string
		for p := range phrases {
			result = append(result, p)
		}
		sort.Strings(result)

		if len(result) > 0 {
			t.Logf("Found translatable phrases in: %s", asset.FsPath)
			for _, p := range result {
				fmt.Println(p)
			}
		}
	}
}
