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
	"github.com/greenpau/go-authcrunch/pkg/user"
	"sync"
	"testing"
	"time"
)

func TestTokenCacheClose(t *testing.T) {
	c := NewTokenCache(1)
	usr, err := user.NewUser(map[string]any{"sub": "alice", "exp": time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	usr.Token = "synthetic"
	if err := c.Add(usr); err != nil {
		t.Fatal(err)
	}
	if c.Get(usr.Token) == nil {
		t.Fatal("live cache omitted token")
	}
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(c.Close)
	}
	wg.Wait()
	select {
	case <-c.done:
	default:
		t.Fatal("worker survived Close")
	}
	if c.Get(usr.Token) != nil {
		t.Fatal("Close retained cached credentials")
	}
	if err := c.Add(usr); err == nil {
		t.Fatal("closed cache accepted credentials")
	}
	(*TokenCache)(nil).Close()
	(&TokenCache{}).Close()
}
