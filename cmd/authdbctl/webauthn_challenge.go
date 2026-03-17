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

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type webauthnChallenge struct {
	Challenge        string              `json:"challenge"`
	RPName           string              `json:"rp_name"`
	Timeout          int                 `json:"timeout"`
	UserVerification string              `json:"user_verification"`
	ExtUVM           bool                `json:"ext_uvm"`
	ExtLoc           bool                `json:"ext_loc"`
	TxAuthSimple     string              `json:"tx_auth_simple"`
	Credentials      []map[string]string `json:"credentials"`
}

func decodeWebauthnChallenge(encodedStr string) (*webauthnChallenge, error) {
	jsonBytes, err := base64.StdEncoding.DecodeString(encodedStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	var challenge webauthnChallenge
	if err := json.Unmarshal(jsonBytes, &challenge); err != nil {
		return nil, fmt.Errorf("failed to unmarshal json: %w", err)
	}

	return &challenge, nil
}
