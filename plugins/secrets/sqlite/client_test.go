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

package sqlite

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func fixture(t *testing.T) (*Client, *Config) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Name: "fixture", Path: filepath.Join(dir, "secrets.db"), Record: "keys"}
	c, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, cfg
}
func TestSecretsIsolationPersistenceAndTypes(t *testing.T) {
	c, cfg := fixture(t)
	if cfg.Timeout != "" {
		t.Fatal("mutated config")
	}
	if value, err := c.GetSecrets(t.Context()); value != nil || !errors.Is(err, ErrNotFound) {
		t.Fatal("missing record returned a value")
	}
	values := map[string]any{"secret": "synthetic-value", "null": nil, "number": json.Number("9007199254740993"), "bool": true, "object": map[string]any{"values": []any{"initial", false}}}
	if err := c.Put(t.Context(), values); err != nil {
		t.Fatal(err)
	}
	values["secret"] = "changed"
	got, err := c.GetSecrets(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got["secret"] != "synthetic-value" || got["number"] != json.Number("9007199254740993") {
		t.Fatal("values lost")
	}
	got["object"].(map[string]any)["values"].([]any)[0] = "changed"
	again, err := c.GetSecrets(t.Context())
	if err != nil || again["object"].(map[string]any)["values"].([]any)[0] != "initial" {
		t.Fatal("shared nested value")
	}
	if value, err := c.GetSecret(t.Context(), "null"); value != nil || err != nil {
		t.Fatal("null became missing")
	}
	if _, err := c.GetSecret(t.Context(), "object.values"); !errors.Is(err, ErrNotFound) {
		t.Fatal("traversed a literal key")
	}
	for _, key := range []string{"null", "number", "bool", "object"} {
		if value, err := c.GetString(t.Context(), key); value != "" || !errors.Is(err, ErrInvalid) {
			t.Fatal("coerced a credential")
		}
	}
	metadata, _ := json.Marshal(c.GetConfig())
	if strings.Contains(string(metadata), "synthetic-value") || strings.Contains(string(metadata), cfg.Path) {
		t.Fatal("metadata leaked private data")
	}
	otherCfg := *cfg
	otherCfg.Record = "other"
	other, err := New(t.Context(), &otherCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.GetSecrets(t.Context()); !errors.Is(err, ErrNotFound) {
		t.Fatal("record binding lost")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if s, err := reopened.GetString(t.Context(), "secret"); err != nil || s != "synthetic-value" {
		t.Fatal("restart lost secret", err)
	}
	if err := reopened.Delete(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.GetSecrets(t.Context()); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted record survived")
	}
}
func TestSecretsValidationCancellationAndConcurrency(t *testing.T) {
	c, _ := fixture(t)
	for _, values := range []map[string]any{nil, {}, {"": "bad"}, {"key": math.NaN()}, {"key": strings.Repeat("x", 65536)}} {
		if err := c.Put(t.Context(), values); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid record accepted", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := c.Put(ctx, map[string]any{"secret": "hidden"}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := c.Put(t.Context(), map[string]any{"secret": "initial"}); err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 5 {
				if err := c.Put(t.Context(), map[string]any{"secret": "next"}); err != nil {
					t.Error(err)
				}
				if value, err := c.GetString(t.Context(), "secret"); err != nil || value == "" {
					t.Error("incomplete snapshot", err)
				}
			}
		})
	}
	workers.Wait()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetSecret(t.Context(), "secret"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed client accepted", err)
	}
	for _, cfg := range []*Config{nil, {}, {Name: "x", Record: "x", Path: "relative"}, {Name: "x", Record: "x", Path: "/file", Timeout: "0s"}} {
		if client, err := New(t.Context(), cfg); client != nil || err == nil {
			t.Fatal("invalid config accepted")
		}
	}
}
