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

package authn

import (
	"encoding/json"
	"errors"
	"net/http"
)

const maxAdminAPIRequestBodySize int64 = 1 << 20

func decodeAdminAPIRequest(w http.ResponseWriter, r *http.Request, dst any) (int, error) {
	if r.Body == nil {
		return 0, nil
	}
	defer r.Body.Close()
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAdminAPIRequestBodySize)).Decode(dst)
	if err == nil {
		return 0, nil
	}
	if _, oversized := errors.AsType[*http.MaxBytesError](err); oversized {
		return http.StatusRequestEntityTooLarge, err
	}
	return http.StatusBadRequest, err
}
