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
	"bytes"
	"fmt"
	"github.com/urfave/cli/v2"
	"net/http"
	"os"
)

func listRealms(c *cli.Context) error {
	wr := new(wrapper)
	if err := wr.configure(c); err != nil {
		return err
	}
	wr.logger.Debug("listing realms")

	var reqData = []byte(`{
		"name": "",
		"job": "leader"
	}`)

	req, _ := http.NewRequest(http.MethodPost, wr.config.BaseURL+"/api/realms", bytes.NewBuffer(reqData))
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("Authorization", "access_token="+wr.config.token)
	respBody, _, err := wr.browser.Do(req)
	if err != nil {
		return fmt.Errorf("failed listing realms: %v", err)
	}
	fmt.Fprintf(os.Stdout, "%s\n", respBody)

	return nil
}
