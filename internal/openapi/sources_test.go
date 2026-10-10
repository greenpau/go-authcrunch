// Copyright 2026 Paul Greenberg greenpau@outlook.com
// SPDX-License-Identifier: Apache-2.0

package openapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSourceReleaseMetadataNormalization(t *testing.T) {
	file := filepath.Join(t.TempDir(), "main.go")
	record := &ReviewedSources{Files: map[string]string{}}
	original := `app.SetVersion(appVersion, "1.3.11")
app.SetGitBranch(gitBranch, "")
app.SetGitCommit(gitCommit, "")
func handler() { response(200) }
`
	changed := `app.SetVersion(appVersion, "1.3.12")
app.SetGitBranch(gitBranch, "")
app.SetGitCommit(gitCommit, "")
func handler() { response(200) }
`
	for _, key := range []string{"cmd/authdb/main.go", "pkg/identity/database.go", "pkg/authn/handler.go"} {
		if err := os.WriteFile(file, []byte(original), 0600); err != nil {
			t.Fatal(err)
		}
		if err := record.add(file, key); err != nil {
			t.Fatal(err)
		}
		before := record.Files[key]
		if err := os.WriteFile(file, []byte(changed), 0600); err != nil {
			t.Fatal(err)
		}
		if err := record.add(file, key); err != nil {
			t.Fatal(err)
		}
		equal := before == record.Files[key]
		if equal != (key != "pkg/authn/handler.go") {
			t.Fatal("metadata normalization scope changed")
		}
		if err := os.WriteFile(file, []byte(changed+"// real source change\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := record.add(file, key); err != nil {
			t.Fatal(err)
		}
		if before == record.Files[key] {
			t.Fatal("semantic drift escaped review")
		}
	}
}
func TestSourcesUsesLocalOwners(t *testing.T) {
	sources, err := Sources(t.Context(), filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if sources.Module != "github.com/greenpau/go-authcrunch" {
		t.Fatal("wrong source module")
	}
	for _, path := range []string{"plugins/registration-workflows/sqlite/workflow.go", "internal/sqlitedb/database.go", "server.go", "pkg/authn/handle_provider_login.go", "pkg/httpserver/server.go", "cmd/authdb/main.go", "pkg/registry/local_user_registry.go", "pkg/redirects/redirect_match.go", "pkg/util/addr/utils.go", "pkg/util/redirect.go", "pkg/util/sanitizer.go", "pkg/waf/malformed_input_check.go"} {
		if sources.Files[path] == "" {
			t.Fatalf("missing local owner %s", path)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Sources(ctx, filepath.Join("..", "..")); err == nil {
		t.Fatal("cancellation ignored")
	}
}
