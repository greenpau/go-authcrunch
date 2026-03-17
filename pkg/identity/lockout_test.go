// Copyright 2022 Paul Greenberg greenpau@outlook.com
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

package identity

import (
	"testing"
	"time"
)

func TestNewLockoutState(t *testing.T) {
	NewLockoutState()
}

func TestLockoutState(t *testing.T) {
	ls := NewLockoutState()
	ls.Lock(15 * time.Minute)
	if !ls.Enabled {
		t.Fatalf("expected Enabled after Lock")
	}
	if ls.EndTime.Before(ls.StartTime) {
		t.Fatalf("unexpected EndTime before StartTime")
	}
	if !ls.IsLocked() {
		t.Fatalf("expected IsLocked to return true during active lockout")
	}

	ls2 := NewLockoutState()
	if ls2.IsLocked() {
		t.Fatalf("expected IsLocked to return false when not enabled")
	}

	ls3 := NewLockoutState()
	ls3.Lock(1 * time.Millisecond)
	time.Sleep(2 * time.Millisecond)
	if ls3.IsLocked() {
		t.Fatalf("expected IsLocked to return false after expiry")
	}
}
