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

package bypass

import (
	"net/http"
	"net/url"
	"testing"
)

func TestMatchPathTraversal(t *testing.T) {
	cfgs := []*Config{
		{
			MatchType: "prefix",
			URI:       "/public/",
		},
	}
	for _, cfg := range cfgs {
		if err := cfg.Validate(); err != nil {
			t.Fatalf("failed to validate config: %v", err)
		}
	}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "legitimate public path matches",
			path: "/public/assets/style.css",
			want: true,
		},
		{
			name: "non-public path does not match",
			path: "/admin/dashboard",
			want: false,
		},
		{
			name: "path traversal out of public must not match",
			path: "/public/../../admin",
			want: false,
		},
		{
			name: "encoded traversal must not match",
			path: "/public/../../../etc/passwd",
			want: false,
		},
		{
			name: "dot segment at end cleaned correctly",
			path: "/public/./file.txt",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{
				URL: &url.URL{Path: tt.path},
			}
			got := Match(r, cfgs)
			if got != tt.want {
				t.Errorf("Match(path=%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
