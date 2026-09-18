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

package util

import (
	"strconv"
	"testing"
)

func TestRandomLengthPreservesIntBounds(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	for _, tc := range []struct {
		a, b int
		want int
	}{
		{maxInt - 1, maxInt, maxInt - 1},
		{maxInt, maxInt, maxInt},
	} {
		if got := randomLength(tc.a, tc.b); got != tc.want {
			t.Fatalf("randomLength(%d, %d) on %d-bit int = %d, want %d", tc.a, tc.b, strconv.IntSize, got, tc.want)
		}
	}
}

func BenchmarkGetRandomString(b *testing.B) {
	for b.Loop() {
		_ = GetRandomString(40)
	}
}
