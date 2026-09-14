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

package validator

import (
	"github.com/greenpau/go-authcrunch/pkg/authz/cache"
	"sync"
	"testing"
)

func TestTokenValidatorClosedAuthorization(t *testing.T) {
	v := &TokenValidator{cache: cache.NewTokenCache(0)}
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(v.Close)
	}
	wg.Wait()
	if _, err := v.Authorize(t.Context(), nil, nil); err == nil {
		t.Fatal("closed validator authorized")
	}
	(*TokenValidator)(nil).Close()
}
