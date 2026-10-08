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
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// ReviewedSources records the exact HTTP implementation reviewed for the YAML.
// It deliberately excludes absolute checkout paths and timestamps.
type ReviewedSources struct {
	Module string            `json:"module" xml:"module" yaml:"module"`
	Files  map[string]string `json:"files" xml:"files" yaml:"files"`
}

// Sources inventories this checkout's HTTP contract implementation. It does not
// select a dependency or inspect sibling worktrees. Paths are repository-relative.
func Sources(ctx context.Context, repository string) (*ReviewedSources, error) {
	result := &ReviewedSources{Module: "github.com/greenpau/go-authcrunch", Files: map[string]string{}}
	local, err := filepath.Glob(filepath.Join(repository, "*.go"))
	if err != nil {
		return nil, err
	}
	for _, file := range local {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		if err := result.add(file, filepath.Base(file)); err != nil {
			return nil, err
		}
	}
	// Recursive walks detect new dispatchers, handlers, validators and serializers.
	for _, relative := range []string{"pkg/authn", "pkg/apiauth", "pkg/oidc", "pkg/identity", "pkg/system", "pkg/kms", "pkg/requests", "pkg/authz", "pkg/registry", "pkg/ids", "pkg/idp", "pkg/sso", "pkg/user", "pkg/authchal", "pkg/tagging", "pkg/httpserver", "cmd/authdb", "pkg/redirects", "pkg/waf", "pkg/util/addr", "pkg/util/validate", "pkg/util/charset", "pkg/util/random.go", "pkg/util/request_id.go", "pkg/util/redirect.go", "pkg/util/sanitizer.go"} {
		err := filepath.WalkDir(filepath.Join(repository, relative), func(file string, entry fs.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(file, ".go") || strings.HasSuffix(file, "_test.go") {
				return nil
			}
			name, err := filepath.Rel(repository, file)
			if err != nil {
				return err
			}
			return result.add(file, filepath.ToSlash(name))
		})
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

// Release automation owns these metadata literals. Normalize only their values
// so a version bump does not require a semantic HTTP source review. All other
// bytes, including constructors and serializers in these files, remain tracked.
var releaseMetadata = regexp.MustCompile(`app\.Set(Version|GitBranch|GitCommit)\((appVersion|gitBranch|gitCommit), "[^"\n]*"\)`)

func (s *ReviewedSources) add(file, key string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	if key == "pkg/identity/database.go" || key == "cmd/authdb/main.go" {
		data = releaseMetadata.ReplaceAll(data, []byte(`app.Set${1}(${2}, "<release-metadata>")`))
	}
	s.Files[key] = fmt.Sprintf("%x", sha256.Sum256(data))
	return nil
}

// CheckSources reports every added, changed or removed contract input. Updating
// the review record is a separate, explicit editorial step after source review.
func CheckSources(ctx context.Context, repository string) error {
	current, err := Sources(ctx, repository)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(repository, "assets/openapi/reviewed-sources.yaml"))
	if err != nil {
		return err
	}
	reviewed, err := readReviewedSources(data)
	if err != nil {
		return err
	}
	return compareSources(reviewed, current)
}

func readReviewedSources(data []byte) (*ReviewedSources, error) {
	var reviewed ReviewedSources
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&reviewed); err != nil {
		return nil, err
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("reviewed-sources.yaml must contain exactly one YAML document")
	}
	return &reviewed, nil
}

func compareSources(reviewed, current *ReviewedSources) error {
	var changed []string
	if reviewed.Module != current.Module {
		changed = append(changed, "module: "+reviewed.Module+" -> "+current.Module)
	}
	for file, hash := range current.Files {
		if reviewed.Files[file] != hash {
			changed = append(changed, file)
		}
	}
	for file := range reviewed.Files {
		if _, found := current.Files[file]; !found {
			changed = append(changed, file+" (removed)")
		}
	}
	if len(changed) == 0 {
		return nil
	}
	slices.Sort(changed)
	return fmt.Errorf("OpenAPI source review required:\n  %s\nFollow .codex/skills/openapi-generation/SKILL.md; update YAML and tests before refreshing reviewed-sources.yaml", strings.Join(changed, "\n  "))
}
