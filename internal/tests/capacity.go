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
	"regexp"
	"testing"
	"time"
)

const capacityTestChild = "AUTHCRUNCH_CAPACITY_TEST_CHILD"

// IsolateCapacityTest runs a large snapshot journey in the same
// instrumented binary, then releases its Go and race-detector memory before
// later browser tests start. The child retains the resource guard's environment
// and remains in its monitored process tree. Call this at the start of a
// top-level test and return when it reports true; false selects the child body.
func IsolateCapacityTest(t *testing.T) bool {
	t.Helper()
	if os.Getenv(capacityTestChild) == t.Name() {
		return false
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	args := []string{"-test.run=^" + regexp.QuoteMeta(t.Name()) + "$", "-test.count=1", "-test.timeout=5m", "-test.v"}
	// Let the parent's coverage teardown merge the child's counters. Do not
	// pass -test.coverprofile: the child must not overwrite the final profile.
	if coverage := flag.Lookup("test.gocoverdir"); coverage != nil && coverage.Value.String() != "" {
		args = append(args, "-test.gocoverdir="+coverage.Value.String())
	}
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Env = append(os.Environ(), capacityTestChild+"="+t.Name())
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("capacity test child failed: %v\n%s", err, output)
	}
	t.Logf("capacity journey:\n%s", output)
	return true
}
