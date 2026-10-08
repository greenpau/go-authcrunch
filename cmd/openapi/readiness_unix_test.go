//go:build unix

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

package main

import (
	"bufio"
	"errors"
	"strings"
	"testing"
	"testing/iotest"
)

func TestReadOpenAPIReadyAddress(t *testing.T) {
	const address = "http://127.0.0.1:43210/"
	const ready = "OpenAPI reference: " + address + " (Ctrl-C to stop)\n"
	for _, tc := range []struct {
		name, output, want, wantErr string
	}{
		{name: "direct CLI", output: ready, want: address},
		{
			name: "recursive make",
			output: "make[2]: Entering directory '/tmp/checkout with spaces'\n" +
				"make[3]: Entering directory '/tmp/checkout with spaces'\n\n" + ready,
			want: address,
		},
		{
			name: "unrelated URL",
			output: "See http://example.test/ for help\n" +
				"echo OpenAPI reference: http://example.test/\n" + ready,
			want: address,
		},
		{name: "final line without newline", output: strings.TrimSuffix(ready, "\n"), want: address},
		{name: "empty output", wantErr: "exited before reporting its address"},
		{name: "no readiness", output: "make: entering checkout\n", wantErr: "exited before reporting its address"},
		{name: "missing address", output: "OpenAPI reference: \n", wantErr: "invalid documentation server ready message"},
		{name: "invalid address", output: "OpenAPI reference: unavailable\n", wantErr: "invalid documentation server ready message"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readOpenAPIReadyAddress(iotest.HalfReader(strings.NewReader(tc.output)))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) || got != "" {
					t.Fatalf("got %q, %v; want error containing %q", got, err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	t.Run("read error", func(t *testing.T) {
		want := errors.New("startup pipe failed")
		got, err := readOpenAPIReadyAddress(iotest.ErrReader(want))
		if got != "" || !errors.Is(err, want) {
			t.Fatalf("got %q, %v; want wrapped read error", got, err)
		}
	})
	t.Run("oversized line", func(t *testing.T) {
		got, err := readOpenAPIReadyAddress(strings.NewReader(strings.Repeat("x", bufio.MaxScanTokenSize)))
		if got != "" || !errors.Is(err, bufio.ErrTooLong) {
			t.Fatalf("got %q, %v; want bounded line failure", got, err)
		}
	})
}
