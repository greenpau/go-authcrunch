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

package tests

import (
	"context"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Exercise the real test-binary boundary, including a failing inner test.
func TestE2EIsolateCapacityTest(t *testing.T) {
	const fixtureEnv = "AUTHCRUNCH_CAPACITY_FIXTURE"
	const parentEnv = "AUTHCRUNCH_CAPACITY_FIXTURE_PARENT"
	if mode := os.Getenv(fixtureEnv); mode != "" {
		if os.Getenv(capacityTestChild) != t.Name() {
			t.Setenv(parentEnv, strconv.Itoa(os.Getpid()))
		}
		if IsolateCapacityTest(t) {
			return
		}
		if parent := os.Getenv(parentEnv); parent == "" || parent == strconv.Itoa(os.Getpid()) {
			t.Fatal("capacity test did not run in a separate process")
		}
		if mode == "fail" {
			t.Fatal("intentional capacity fixture failure")
		}
		t.Log("capacity child executed")
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"pass", "fail"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			args := []string{"-test.run=^TestE2EIsolateCapacityTest$", "-test.count=1", "-test.timeout=10s", "-test.v"}
			var counters string
			var before []string
			if coverage := flag.Lookup("test.gocoverdir"); coverage != nil && coverage.Value.String() != "" {
				directory := coverage.Value.String()
				args = append(args, "-test.gocoverdir="+directory)
				counters = filepath.Join(directory, "covcounters.*")
				before, err = filepath.Glob(counters)
				if err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.CommandContext(ctx, executable, args...)
			cmd.Env = append(os.Environ(), fixtureEnv+"="+mode)
			output, runErr := cmd.CombinedOutput()
			if mode == "fail" {
				if runErr == nil || !strings.Contains(string(output), "capacity test child failed:") || !strings.Contains(string(output), "intentional capacity fixture failure") {
					t.Fatalf("child failure was not propagated: %v\n%s", runErr, output)
				}
			} else if runErr != nil || !strings.Contains(string(output), "capacity child executed") {
				t.Fatalf("isolated test did not complete: %v\n%s", runErr, output)
			}
			if counters != "" {
				after, err := filepath.Glob(counters)
				if err != nil {
					t.Fatal(err)
				}
				if len(after) < len(before)+2 {
					t.Fatal("wrapper and isolated child did not both preserve coverage counters")
				}
			}
		})
	}
}
