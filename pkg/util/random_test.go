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

package util_test

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/util"
)

const randomCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func TestRandomString(t *testing.T) {
	for _, tc := range []struct {
		name       string
		generate   func() string
		minLength  int
		maxLength  int
		characters string
	}{
		{"fixed", func() string { return util.GetRandomString(64) }, 64, 64, randomCharacters},
		{"default length", func() string { return util.GetRandomString(0) }, 40, 40, randomCharacters},
		{"ascending range", func() string { return util.GetRandomStringFromRange(12, 24) }, 12, 23, randomCharacters},
		{"descending range", func() string { return util.GetRandomStringFromRange(24, 12) }, 12, 23, randomCharacters},
		{"equal range", func() string { return util.GetRandomStringFromRange(16, 16) }, 16, 16, randomCharacters},
		{"single character", func() string { return util.GetRandomStringFromRangeWithCharset(32, 33, "x") }, 32, 32, "x"},
		{"custom charset", func() string { return util.GetRandomStringFromRangeWithCharset(32, 33, "ab") }, 32, 32, "ab"},
		{"large custom charset", func() string { return util.GetRandomStringFromRangeWithCharset(32, 33, strings.Repeat("a", 256)+"b") }, 32, 32, "ab"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for range 100 {
				got := tc.generate()
				if len(got) < tc.minLength || len(got) > tc.maxLength {
					t.Fatalf("length = %d, want [%d,%d]", len(got), tc.minLength, tc.maxLength)
				}
				for _, ch := range got {
					if !strings.ContainsRune(tc.characters, ch) {
						t.Fatalf("generated character %q outside %q", ch, tc.characters)
					}
				}
			}
		})
	}
}

func TestRandomEncodedStringFromRange(t *testing.T) {
	got := util.GetRandomEncodedStringFromRange(32, 33)
	decoded, err := base32.StdEncoding.DecodeString(got)
	if err != nil {
		t.Fatalf("decode generated value: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("decoded length = %d, want 32", len(decoded))
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("injected entropy failure")
}

func TestE2ERandomAPIFailsClosedOnEntropyFailure(t *testing.T) {
	if os.Getenv("AUTHCRUNCH_RANDOM_FAILURE_CHILD") == "1" {
		rand.Reader = failingReader{}
		_, _ = io.WriteString(os.Stdout, "calling public random API\n")
		_ = util.GetRandomString(32)
		_, _ = io.WriteString(os.Stdout, "random API returned\n")
		return
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestE2ERandomAPIFailsClosedOnEntropyFailure$")
	cmd.Env = append(os.Environ(), "AUTHCRUNCH_RANDOM_FAILURE_CHILD=1")
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("entropy failure child did not terminate: %v", ctx.Err())
	}
	if err == nil {
		t.Fatalf("random API returned after entropy failure: %s", output)
	}
	if !strings.Contains(string(output), "crypto/rand: failed to read random data") {
		t.Fatalf("child did not report crypto/rand failure: %s", output)
	}
	if strings.Contains(string(output), "random API returned") {
		t.Fatalf("random API continued after entropy failure: %s", output)
	}
}
