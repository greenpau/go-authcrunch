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

package authcrunch

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

type lifecycleErrorCloser struct{ close func() error }

func (c lifecycleErrorCloser) Close() error { return c.close() }

type lifecycleVoidCloser struct{ close func() }

func (c lifecycleVoidCloser) Close() { c.close() }

func TestServerCloseOwnership(t *testing.T) {
	var order []int
	first, second := errors.New("first cleanup"), errors.New("second cleanup")
	var mu sync.Mutex
	record := func(i int) { mu.Lock(); defer mu.Unlock(); order = append(order, i) }
	srv := &Server{nameRefs: newRefMap()}
	srv.own(lifecycleErrorCloser{func() error { record(1); return first }})
	srv.own(struct{}{}) // Existing dispatchers need not implement lifecycle APIs.
	srv.own(lifecycleVoidCloser{func() { record(2) }})
	srv.own(lifecycleErrorCloser{func() error { record(3); return second }})
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			err := srv.Close()
			if !errors.Is(err, first) || !errors.Is(err, second) {
				t.Error("cleanup errors lost")
			}
		})
	}
	wg.Wait()
	if !reflect.DeepEqual(order, []int{3, 2, 1}) {
		t.Fatalf("disposal order = %v", order)
	}
	if _, err := srv.GetPortalByName("missing"); !errors.Is(err, ErrServerClosed) {
		t.Fatal("closed portal lookup did not fail closed")
	}
	if _, err := srv.GetGatekeeperByName("missing"); !errors.Is(err, ErrServerClosed) {
		t.Fatal("closed gatekeeper lookup did not fail closed")
	}
	if err := (*Server)(nil).Close(); err != nil {
		t.Fatal(err)
	}
}

func TestServerConcurrentCloseWaits(t *testing.T) {
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	srv := &Server{}
	srv.own(lifecycleVoidCloser{func() { close(entered); <-release }})
	go func() { _ = srv.Close(); close(finished) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("Close did not enter owned component")
	}
	other := make(chan struct{})
	go func() { _ = srv.Close(); close(other) }()
	select {
	case <-finished:
		t.Fatal("first Close returned before disposal")
	case <-other:
		t.Fatal("second Close returned before disposal")
	default:
	}
	once.Do(func() { close(release) })
	for _, done := range []<-chan struct{}{finished, other} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("Close did not finish")
		}
	}
}
