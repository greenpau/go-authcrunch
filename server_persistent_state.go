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

package authcrunch

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/greenpau/go-authcrunch/pkg/state"
)

// One configuration epoch also retires records belonging to removed components.
// A later return to an old configuration cannot restore their stale authority.
// Generated signing keys deliberately retain independent stable bindings.
func (s *Server) persistentStateBinding(config *Config) (string, error) {
	snapshot := *config
	snapshot.State = nil
	// Diagnostic suppression carries no authentication or authorization policy.
	// Changing it must not retire otherwise valid persisted sessions.
	snapshot.Logging = nil
	binding, err := state.Binding(&snapshot)
	if err != nil {
		return "", err
	}
	record, err := s.state.OpenRecord("runtime-configuration", binding)
	if err != nil {
		return "", err
	}
	epoch, err := record.Load()
	if err != nil {
		return "", err
	}
	if len(epoch) == 0 {
		epoch = make([]byte, 32)
		rand.Read(epoch)
		if err := record.Save(epoch); err != nil {
			return "", err
		}
	}
	if len(epoch) != 32 {
		return "", fmt.Errorf("invalid runtime configuration epoch")
	}
	return hex.EncodeToString(epoch), nil
}
