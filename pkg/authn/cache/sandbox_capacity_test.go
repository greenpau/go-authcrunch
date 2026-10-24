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

package cache

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/user"
)

func TestSandboxCapacityAdmission(t *testing.T) {
	c := NewSandboxCache()
	if c.SetMaxEntries(0) == nil {
		t.Fatal("zero capacity accepted")
	}
	if err := c.SetMaxEntries(2); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 36)
	original := &user.User{Authenticator: user.Authenticator{TempSecret: "original"}}
	if err := c.Add(id, original); err != nil {
		t.Fatal(err)
	}
	if err := c.Add(id, &user.User{}); err == nil {
		t.Fatal("live sandbox overwritten")
	}
	lease, err := c.Acquire(id, "original")
	if err != nil {
		t.Fatal("duplicate admission destroyed original proof")
	}
	lease.Release()
	second := strings.Repeat("b", 36)
	third := strings.Repeat("c", 36)
	if err := c.Add(second, &user.User{}); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(c.Add(third, &user.User{}), ErrSandboxCapacity) {
		t.Fatal("live capacity not enforced")
	}
	if _, err := c.Get(id); err != nil {
		t.Fatal("capacity evicted live proof")
	}
	c.Entries[second].createdAt = time.Now().Add(-301 * time.Second)
	if err := c.Add(third, &user.User{}); err != nil {
		t.Fatal("expired entry blocked admission")
	}
	if _, ok := c.Entries[second]; ok {
		t.Fatal("expired entry retained at capacity")
	}
	c.Expire(id)
	if err := c.Add(id, original); err != nil {
		t.Fatal("expired duplicate cannot be replaced")
	}
	if err := c.SetMaxEntries(1); err != nil {
		t.Fatal(err)
	}
	if len(c.Entries) != 2 || !errors.Is(c.Add(second, &user.User{}), ErrSandboxCapacity) {
		t.Fatal("lowering capacity evicted live records")
	}
	if err := c.Delete(third); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(id); err != nil {
		t.Fatal(err)
	}
	if err := c.Add(second, &user.User{}); err != nil {
		t.Fatal("completion did not free capacity")
	}
}

func TestSandboxCapacityConcurrentAdmission(t *testing.T) {
	c := NewSandboxCache()
	if err := c.SetMaxEntries(3); err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int32
	var unexpected atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range 32 {
		wg.Go(func() {
			<-start
			err := c.Add(fmt.Sprintf("%036d", i), &user.User{})
			if err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, ErrSandboxCapacity) {
				unexpected.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()
	if accepted.Load() != 3 || unexpected.Load() != 0 || len(c.Entries) != 3 {
		t.Fatal("concurrent admissions exceeded atomic capacity")
	}
}
