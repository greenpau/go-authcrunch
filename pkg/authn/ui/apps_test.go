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
	"encoding/json"
	"strings"
	"testing"
)

func TestEmbeddedApplications(t *testing.T) {
	library, err := NewAppAssetLibrary()
	if err != nil {
		t.Fatal(err)
	}
	for _, app := range []string{"profile", "operator", "documents"} {
		entry, err := library.GetAsset(app + "/")
		if err != nil || entry.ContentType != "text/html" || strings.Count(entry.Content, ApplicationBaseMarker) != 1 {
			t.Fatalf("invalid app entry: %s", app)
		}
		for _, asset := range []string{"index.html", "logo.svg", "favicon.svg", "manifest.json", "i18n/en.json", "i18n/ar.json"} {
			if !library.HasAsset(app + "/" + asset) {
				t.Fatalf("missing %s/%s", app, asset)
			}
		}
		manifest, _ := library.GetAsset(app + "/manifest.json")
		var data struct {
			StartURL string `json:"start_url"`
			Icons    []struct {
				Src string `json:"src"`
			} `json:"icons"`
		}
		if json.Unmarshal([]byte(manifest.Content), &data) != nil || (data.StartURL != "." && data.StartURL != "./") {
			t.Fatal("app manifest must be mount relative")
		}
		for _, icon := range data.Icons {
			if !library.HasAsset(app + "/" + strings.TrimPrefix(icon.Src, "./")) {
				t.Fatal("unresolved manifest icon")
			}
		}
	}
	for _, pathname := range library.GetAssetPaths() {
		asset, err := library.GetAsset(pathname)
		if err != nil || asset.ContentType == "" || asset.Checksum == "" {
			t.Fatalf("invalid embedded asset %s", pathname)
		}
	}
}
