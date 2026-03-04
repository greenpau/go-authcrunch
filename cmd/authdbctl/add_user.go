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
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

var (
	addSubcmd = []*cli.Command{
		{
			Name: "user",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "realm",
					Usage:    "The realm to retrieve users from",
					Required: true,
				},
				&cli.StringFlag{
					Name:     "username",
					Usage:    "Username",
					Required: true,
				},
				&cli.StringFlag{
					Name:     "name",
					Usage:    "Name",
					Required: true,
				},
				&cli.StringFlag{
					Name:     "email",
					Usage:    "Email address",
					Required: true,
				},
				&cli.StringSliceFlag{
					Name:     "roles",
					Usage:    "Roles",
					Required: true,
				},
			},
			Action: addUser,
		},
	}
)

type addUserRequest struct {
	Realm string         `json:"realm"`
	User  map[string]any `json:"user"`
}

func addUser(c *cli.Context) error {
	wr := new(wrapper)
	if err := wr.configure(c); err != nil {
		return err
	}
	endpointURL := wr.config.BaseURL + "/api/server/user"
	wr.logger.Debug("add user",
		zap.String("endpoint_url", endpointURL),
		zap.String("username", c.String("username")),
		zap.String("name", c.String("name")),
		zap.String("email", c.String("email")),
		zap.Strings("roles", c.StringSlice("roles")),
		zap.String("realm", c.String("realm")),
	)

	payload := addUserRequest{
		Realm: c.String("realm"),
		User: map[string]any{
			"username": c.String("username"),
			"name":     c.String("name"),
			"email":    c.String("email"),
			"roles":    c.StringSlice("roles"),
		},
	}

	reqData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal add user request: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, endpointURL, bytes.NewBuffer(reqData))
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("Authorization", "access_token="+wr.config.token)
	respBody, resp, err := wr.browser.Do(req)
	if err != nil {
		return fmt.Errorf("failed adding user: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ailed adding user, server responsed with %d", resp.StatusCode)
	}

	var data map[string]any
	if err := json.Unmarshal([]byte(respBody), &data); err != nil {
		return fmt.Errorf("failed to parse JSON response: %v", err)
	}

	fmt.Fprintf(os.Stdout, "%s\n", respBody)
	return nil
}
