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
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

var (
	fetchUserInfoSubcmd = &cli.Command{
		Name:   "user",
		Usage:  "get info about user",
		Action: fetchUserInfo,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "realm",
				Usage:    "The realm to get info from",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "username",
				Usage:    "Username",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "email",
				Usage:    "Email address",
				Required: true,
			},
		},
	}
)

func fetchUserInfo(c *cli.Context) error {
	wr := new(wrapper)
	if err := wr.configure(c); err != nil {
		return err
	}
	endpointURL := wr.config.BaseURL + "/api/server/user"
	wr.logger.Debug(
		"fetching database user info",
		zap.String("endpoint_url", endpointURL),
		zap.String("realm", c.String("realm")),
		zap.String("username", c.String("username")),
		zap.String("email", c.String("email")),
	)

	payload := userRequest{
		Realm:     c.String("realm"),
		Operation: "info",
		User: map[string]any{
			"username": c.String("username"),
			"email":    c.String("email"),
		},
	}

	reqData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal add user request: %v", err)
	}

	respBody, err := wr.doRequestWithRetry(c, http.MethodPost, endpointURL, reqData)
	if err != nil {
		return fmt.Errorf("failed fetching database %q realm info: %w", c.String("realm"), err)
	}

	var data map[string]any
	if err := json.Unmarshal([]byte(respBody), &data); err != nil {
		return fmt.Errorf("failed to parse JSON response: %v", err)
	}

	fmt.Fprintf(os.Stdout, "%s\n", respBody)
	return nil
}
