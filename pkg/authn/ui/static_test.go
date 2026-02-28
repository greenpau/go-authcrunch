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
	"reflect"
	"testing"
)

func TestNewStaticAssetLibrary(t *testing.T) {
	t.Log("Creating Static Asset Library factory")

	sal, err := NewStaticAssetLibrary()
	if err != nil {
		t.Fatalf("Expected success, but got error: %v", err)
	}

	if sal == nil {
		t.Fatal("Expected StaticAssetLibrary instance, got nil")
	}

	wantCount := 87
	gotCount := sal.GetAssetCount()
	if gotCount != wantCount {
		t.Errorf("Expected asset count %d, got %d", wantCount, gotCount)
	}

	wantPaths := []string{
		"assets/cbor/cbor.js",
		"assets/css/apps_mobile_access.css",
		"assets/css/apps_sso.css",
		"assets/css/generic.css",
		"assets/css/login.css",
		"assets/css/mfa_app.css",
		"assets/css/password.css",
		"assets/css/portal.css",
		"assets/css/register.css",
		"assets/css/sandbox.css",
		"assets/css/settings.css",
		"assets/css/styles.css",
		"assets/css/whoami.css",
		"assets/google-webfonts/fonts/montserrat-v15-latin-500.eot",
		"assets/google-webfonts/fonts/montserrat-v15-latin-500.svg",
		"assets/google-webfonts/fonts/montserrat-v15-latin-500.ttf",
		"assets/google-webfonts/fonts/montserrat-v15-latin-500.woff",
		"assets/google-webfonts/fonts/montserrat-v15-latin-500.woff2",
		"assets/google-webfonts/fonts/montserrat-v15-latin-600.eot",
		"assets/google-webfonts/fonts/montserrat-v15-latin-600.svg",
		"assets/google-webfonts/fonts/montserrat-v15-latin-600.ttf",
		"assets/google-webfonts/fonts/montserrat-v15-latin-600.woff",
		"assets/google-webfonts/fonts/montserrat-v15-latin-600.woff2",
		"assets/google-webfonts/fonts/montserrat-v15-latin-regular.eot",
		"assets/google-webfonts/fonts/montserrat-v15-latin-regular.svg",
		"assets/google-webfonts/fonts/montserrat-v15-latin-regular.ttf",
		"assets/google-webfonts/fonts/montserrat-v15-latin-regular.woff",
		"assets/google-webfonts/fonts/montserrat-v15-latin-regular.woff2",
		"assets/google-webfonts/fonts/roboto-v20-latin-500.eot",
		"assets/google-webfonts/fonts/roboto-v20-latin-500.svg",
		"assets/google-webfonts/fonts/roboto-v20-latin-500.ttf",
		"assets/google-webfonts/fonts/roboto-v20-latin-500.woff",
		"assets/google-webfonts/fonts/roboto-v20-latin-500.woff2",
		"assets/google-webfonts/fonts/roboto-v20-latin-regular.eot",
		"assets/google-webfonts/fonts/roboto-v20-latin-regular.svg",
		"assets/google-webfonts/fonts/roboto-v20-latin-regular.ttf",
		"assets/google-webfonts/fonts/roboto-v20-latin-regular.woff",
		"assets/google-webfonts/fonts/roboto-v20-latin-regular.woff2",
		"assets/google-webfonts/montserrat.css",
		"assets/google-webfonts/roboto.css",
		"assets/highlight.js/css/atom-one-dark.min.css",
		"assets/highlight.js/js/highlight.js",
		"assets/highlight.js/js/languages/json.min.js",
		"assets/highlight.js/js/languages/plaintext.min.js",
		"assets/images/favicon.ico",
		"assets/images/favicon.png",
		"assets/images/logo.svg",
		"assets/js/apps_mobile_access.js",
		"assets/js/apps_sso.js",
		"assets/js/generic.js",
		"assets/js/login.js",
		"assets/js/mfa_add_app.js",
		"assets/js/mfa_add_u2f.js",
		"assets/js/mfa_test_u2f.js",
		"assets/js/portal.js",
		"assets/js/register.js",
		"assets/js/sandbox.js",
		"assets/js/sandbox_mfa_add_app.js",
		"assets/js/sandbox_mfa_u2f.js",
		"assets/js/settings.js",
		"assets/js/whoami.js",
		"assets/line-awesome/fonts/la-brands-400.eot",
		"assets/line-awesome/fonts/la-brands-400.svg",
		"assets/line-awesome/fonts/la-brands-400.ttf",
		"assets/line-awesome/fonts/la-brands-400.woff",
		"assets/line-awesome/fonts/la-brands-400.woff2",
		"assets/line-awesome/fonts/la-regular-400.eot",
		"assets/line-awesome/fonts/la-regular-400.svg",
		"assets/line-awesome/fonts/la-regular-400.ttf",
		"assets/line-awesome/fonts/la-regular-400.woff",
		"assets/line-awesome/fonts/la-regular-400.woff2",
		"assets/line-awesome/fonts/la-solid-900.eot",
		"assets/line-awesome/fonts/la-solid-900.svg",
		"assets/line-awesome/fonts/la-solid-900.ttf",
		"assets/line-awesome/fonts/la-solid-900.woff",
		"assets/line-awesome/fonts/la-solid-900.woff2",
		"assets/line-awesome/line-awesome.css",
		"assets/material-icons/MaterialIcons-Regular.eot",
		"assets/material-icons/MaterialIcons-Regular.svg",
		"assets/material-icons/MaterialIcons-Regular.ttf",
		"assets/material-icons/MaterialIcons-Regular.woff",
		"assets/material-icons/MaterialIcons-Regular.woff2",
		"assets/material-icons/material-icons.css",
		"assets/materialize-css/css/materialize.css",
		"assets/materialize-css/css/materialize.min.css",
		"assets/materialize-css/js/materialize.js",
		"assets/materialize-css/js/materialize.min.js",
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

	wantContentTypes := map[string]string{
		"assets/cbor/cbor.js":                                             "application/javascript",
		"assets/css/apps_mobile_access.css":                               "text/css",
		"assets/css/apps_sso.css":                                         "text/css",
		"assets/css/generic.css":                                          "text/css",
		"assets/css/login.css":                                            "text/css",
		"assets/css/mfa_app.css":                                          "text/css",
		"assets/css/password.css":                                         "text/css",
		"assets/css/portal.css":                                           "text/css",
		"assets/css/register.css":                                         "text/css",
		"assets/css/sandbox.css":                                          "text/css",
		"assets/css/settings.css":                                         "text/css",
		"assets/css/styles.css":                                           "text/css",
		"assets/css/whoami.css":                                           "text/css",
		"assets/google-webfonts/fonts/montserrat-v15-latin-500.eot":       "application/vnd.ms-fontobject",
		"assets/google-webfonts/fonts/montserrat-v15-latin-500.svg":       "image/svg+xml",
		"assets/google-webfonts/fonts/montserrat-v15-latin-500.ttf":       "font/ttf",
		"assets/google-webfonts/fonts/montserrat-v15-latin-500.woff":      "font/woff",
		"assets/google-webfonts/fonts/montserrat-v15-latin-500.woff2":     "font/woff2",
		"assets/google-webfonts/fonts/montserrat-v15-latin-600.eot":       "application/vnd.ms-fontobject",
		"assets/google-webfonts/fonts/montserrat-v15-latin-600.svg":       "image/svg+xml",
		"assets/google-webfonts/fonts/montserrat-v15-latin-600.ttf":       "font/ttf",
		"assets/google-webfonts/fonts/montserrat-v15-latin-600.woff":      "font/woff",
		"assets/google-webfonts/fonts/montserrat-v15-latin-600.woff2":     "font/woff2",
		"assets/google-webfonts/fonts/montserrat-v15-latin-regular.eot":   "application/vnd.ms-fontobject",
		"assets/google-webfonts/fonts/montserrat-v15-latin-regular.svg":   "image/svg+xml",
		"assets/google-webfonts/fonts/montserrat-v15-latin-regular.ttf":   "font/ttf",
		"assets/google-webfonts/fonts/montserrat-v15-latin-regular.woff":  "font/woff",
		"assets/google-webfonts/fonts/montserrat-v15-latin-regular.woff2": "font/woff2",
		"assets/google-webfonts/fonts/roboto-v20-latin-500.eot":           "application/vnd.ms-fontobject",
		"assets/google-webfonts/fonts/roboto-v20-latin-500.svg":           "image/svg+xml",
		"assets/google-webfonts/fonts/roboto-v20-latin-500.ttf":           "font/ttf",
		"assets/google-webfonts/fonts/roboto-v20-latin-500.woff":          "font/woff",
		"assets/google-webfonts/fonts/roboto-v20-latin-500.woff2":         "font/woff2",
		"assets/google-webfonts/fonts/roboto-v20-latin-regular.eot":       "application/vnd.ms-fontobject",
		"assets/google-webfonts/fonts/roboto-v20-latin-regular.svg":       "image/svg+xml",
		"assets/google-webfonts/fonts/roboto-v20-latin-regular.ttf":       "font/ttf",
		"assets/google-webfonts/fonts/roboto-v20-latin-regular.woff":      "font/woff",
		"assets/google-webfonts/fonts/roboto-v20-latin-regular.woff2":     "font/woff2",
		"assets/google-webfonts/montserrat.css":                           "text/css",
		"assets/google-webfonts/roboto.css":                               "text/css",
		"assets/highlight.js/css/atom-one-dark.min.css":                   "text/css",
		"assets/highlight.js/js/highlight.js":                             "application/javascript",
		"assets/highlight.js/js/languages/json.min.js":                    "application/javascript",
		"assets/highlight.js/js/languages/plaintext.min.js":               "application/javascript",
		"assets/images/favicon.ico":                                       "image/x-icon",
		"assets/images/favicon.png":                                       "image/png",
		"assets/images/logo.svg":                                          "image/svg+xml",
		"assets/js/apps_mobile_access.js":                                 "application/javascript",
		"assets/js/apps_sso.js":                                           "application/javascript",
		"assets/js/generic.js":                                            "application/javascript",
		"assets/js/login.js":                                              "application/javascript",
		"assets/js/mfa_add_app.js":                                        "application/javascript",
		"assets/js/mfa_add_u2f.js":                                        "application/javascript",
		"assets/js/mfa_test_u2f.js":                                       "application/javascript",
		"assets/js/portal.js":                                             "application/javascript",
		"assets/js/register.js":                                           "application/javascript",
		"assets/js/sandbox.js":                                            "application/javascript",
		"assets/js/sandbox_mfa_add_app.js":                                "application/javascript",
		"assets/js/sandbox_mfa_u2f.js":                                    "application/javascript",
		"assets/js/settings.js":                                           "application/javascript",
		"assets/js/whoami.js":                                             "application/javascript",
		"assets/line-awesome/fonts/la-brands-400.eot":                     "application/vnd.ms-fontobject",
		"assets/line-awesome/fonts/la-brands-400.svg":                     "image/svg+xml",
		"assets/line-awesome/fonts/la-brands-400.ttf":                     "font/ttf",
		"assets/line-awesome/fonts/la-brands-400.woff":                    "font/woff",
		"assets/line-awesome/fonts/la-brands-400.woff2":                   "font/woff2",
		"assets/line-awesome/fonts/la-regular-400.eot":                    "application/vnd.ms-fontobject",
		"assets/line-awesome/fonts/la-regular-400.svg":                    "image/svg+xml",
		"assets/line-awesome/fonts/la-regular-400.ttf":                    "font/ttf",
		"assets/line-awesome/fonts/la-regular-400.woff":                   "font/woff",
		"assets/line-awesome/fonts/la-regular-400.woff2":                  "font/woff2",
		"assets/line-awesome/fonts/la-solid-900.eot":                      "application/vnd.ms-fontobject",
		"assets/line-awesome/fonts/la-solid-900.svg":                      "image/svg+xml",
		"assets/line-awesome/fonts/la-solid-900.ttf":                      "font/ttf",
		"assets/line-awesome/fonts/la-solid-900.woff":                     "font/woff",
		"assets/line-awesome/fonts/la-solid-900.woff2":                    "font/woff2",
		"assets/line-awesome/line-awesome.css":                            "text/css",
		"assets/material-icons/MaterialIcons-Regular.eot":                 "application/vnd.ms-fontobject",
		"assets/material-icons/MaterialIcons-Regular.svg":                 "image/svg+xml",
		"assets/material-icons/MaterialIcons-Regular.ttf":                 "font/ttf",
		"assets/material-icons/MaterialIcons-Regular.woff":                "font/woff",
		"assets/material-icons/MaterialIcons-Regular.woff2":               "font/woff2",
		"assets/material-icons/material-icons.css":                        "text/css",
		"assets/materialize-css/css/materialize.css":                      "text/css",
		"assets/materialize-css/css/materialize.min.css":                  "text/css",
		"assets/materialize-css/js/materialize.js":                        "application/javascript",
		"assets/materialize-css/js/materialize.min.js":                    "application/javascript",
	}

	gotContentTypes := make(map[string]string)
	for _, path := range gotPaths {
		asset, err := sal.GetAsset(path)
		if err != nil {
			t.Fatalf("failed to extract asset %s, got error: %v", path, err)
		}
		gotContentTypes[path] = asset.ContentType
	}

	if !reflect.DeepEqual(gotContentTypes, wantContentTypes) {
		t.Error("Content type mismatch detected:")

		for path, wantType := range wantContentTypes {
			if gotType, exists := gotContentTypes[path]; !exists {
				t.Errorf("  [-] Expected path missing from the library: %s", path)
			} else if gotType != wantType {
				t.Errorf("  [M] Mismatched type for %s:\n      want: %s\n      got:  %s", path, wantType, gotType)
			}
		}

		for path := range gotContentTypes {
			if _, exists := wantContentTypes[path]; !exists {
				t.Errorf("  [+] Found unexpected path: %s", path)
			}
		}
	}

	t.Log("Static Asset Library initialized successfully")
}
