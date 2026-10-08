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

package openapi

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var releaseVersion = regexp.MustCompile(`^1\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// CheckVersion binds the bundled contract to the repository release authority.
// Generation checks the authored YAML; only version-sync changes its version.
func CheckVersion(repository string, data []byte) error {
	raw, err := os.ReadFile(filepath.Join(repository, "VERSION"))
	if err != nil {
		return err
	}
	version := strings.TrimSuffix(string(raw), "\n")
	if !releaseVersion.MatchString(version) {
		return fmt.Errorf("VERSION must be exactly 1.<minor>.<patch>, without leading zeros or suffixes")
	}
	for part := range strings.SplitSeq(version, ".") {
		n, err := strconv.ParseUint(part, 10, 64)
		if err != nil || n == ^uint64(0) {
			return fmt.Errorf("VERSION components must leave room for a versioned increment")
		}
	}
	var doc struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("read OpenAPI version: %w", err)
	}
	if doc.Info.Version != version {
		return fmt.Errorf("OpenAPI info.version %q differs from VERSION %s; run make version-sync", doc.Info.Version, version)
	}
	return nil
}
