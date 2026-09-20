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

package state_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/state"
	"github.com/greenpau/go-authcrunch/pkg/state/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

type persistentTestSnapshot struct {
	Message string
	Data    []byte
}

func TestE2EStateProcessRestart(t *testing.T) {
	if dir := os.Getenv("AUTHCRUNCH_STATE_TEST_CHILD"); dir != "" {
		cfg, err := parser.NewStateConfigFromDirectives([]string{cfgutil.EncodeArgs([]string{"directory", dir})})
		if err != nil {
			t.Fatal(err)
		}
		s, err := state.Open(cfg)
		if err != nil {
			t.Fatal(err)
		}
		r, err := s.OpenRecord("test", "same")
		if err != nil {
			t.Fatal(err)
		}
		if err = r.Encode(func() {}); err == nil {
			t.Fatal("unsupported snapshot encoded")
		}
		if err = r.Encode(persistentTestSnapshot{Message: "previous authority"}); err != nil {
			t.Fatal(err)
		}
		if _, err = r.PrepareEncode(persistentTestSnapshot{Data: make([]byte, 65<<20)}); !errors.Is(err, state.ErrCapacity) {
			t.Fatalf("oversized candidate error: %v", err)
		}
		if err = r.Err(); err != nil {
			t.Fatalf("capacity preflight poisoned storage: %v", err)
		}
		if err = r.Encode(persistentTestSnapshot{Message: "committed before abrupt exit"}); err != nil {
			t.Fatal(err)
		}
		os.Exit(0) // No Close, defer, or shutdown hook: success was already durable.
	}
	dir := filepath.Join(t.TempDir(), "new", "nested", "state")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestE2EStateProcessRestart$")
	cmd.Env = append(os.Environ(), "AUTHCRUNCH_STATE_TEST_CHILD="+dir)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child failed: %v %s", err, output)
	}
	cfg, err := parser.NewStateConfigFromDirectives([]string{cfgutil.EncodeArgs([]string{"directory", dir})})
	if err != nil {
		t.Fatal(err)
	}
	s, err := state.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r, err := s.OpenRecord("test", "same")
	if err != nil {
		t.Fatal(err)
	}
	var snapshot persistentTestSnapshot
	found, err := r.Decode(&snapshot)
	if err != nil || !found || snapshot.Message != "committed before abrupt exit" {
		t.Fatal("committed state did not survive process death")
	}
}
