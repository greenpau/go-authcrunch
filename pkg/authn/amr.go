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

package authn

import (
	"github.com/greenpau/go-authcrunch/pkg/user"
)

// deriveAmrFromCheckpoints maps the types of passed checkpoints to RFC 8176
// amr values for the access token.
func deriveAmrFromCheckpoints(checkpoints []*user.Checkpoint) []string {
	var passed []string
	for _, cp := range checkpoints {
		if cp == nil || !cp.Passed {
			continue
		}
		passed = append(passed, cp.Type)
	}
	return user.ToAuthMethodReferences(passed)
}
