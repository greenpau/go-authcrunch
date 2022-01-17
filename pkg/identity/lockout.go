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
	"time"
)

// LockoutState indicates whether user identity is temporarily
// disabled. If the identity is lockedout, when does the
// lockout end.
type LockoutState struct {
	Enabled   bool      `json:"enabled,omitempty" xml:"enabled,omitempty" yaml:"enabled,omitempty"`
	StartTime time.Time `json:"start_time,omitempty" xml:"start_time,omitempty" yaml:"start_time,omitempty"`
	EndTime   time.Time `json:"end_time,omitempty" xml:"end_time,omitempty" yaml:"end_time,omitempty"`
}

// NewLockoutState returns an instance of LockoutState.
func NewLockoutState() *LockoutState {
	return &LockoutState{}
}
