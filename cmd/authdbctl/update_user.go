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
	updateUserSubcmd = &cli.Command{

		Name: "user",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "realm",
				Usage:    "The realm to update user in",
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
			&cli.BoolFlag{
				Name:  "disable",
				Usage: "Disable the user account",
			},
			&cli.BoolFlag{
				Name:  "enable",
				Usage: "Enable the user account",
			},
			&cli.BoolFlag{
				Name:  "reset-password",
				Usage: "Generate a new password for the user",
			},
			&cli.StringSliceFlag{
				Name:  "overwrite-roles",
				Usage: "Replace existing roles with these (comma-separated or multiple flags)",
			},
			&cli.StringSliceFlag{
				Name:  "add-roles",
				Usage: "Append these roles to the existing ones",
			},
			&cli.StringSliceFlag{
				Name:  "overwrite-auth-challenges",
				Usage: "Replace existing auth challenge rules with these (comma-separated or multiple flags)",
			},
		},
		Action: updateUser,
	}
)

func updateUser(c *cli.Context) error {
	wr := new(wrapper)
	if err := wr.configure(c); err != nil {
		return err
	}
	endpointURL := wr.config.BaseURL + "/api/server/user"
	wr.logger.Debug("updating user",
		zap.String("endpoint_url", endpointURL),
		zap.String("username", c.String("username")),
		zap.String("email", c.String("email")),
		zap.String("realm", c.String("realm")),
	)

	payload := userRequest{
		Realm:     c.String("realm"),
		Operation: "update",
		User: map[string]any{
			"username": c.String("username"),
			"email":    c.String("email"),
		},
	}

	if c.Bool("disable") {
		payload.Operation = "disable"
	}

	if c.Bool("enable") {
		payload.Operation = "enable"
	}

	if c.Bool("reset-password") {
		payload.Operation = "reset_password"
	}

	// Supports --overwrite-roles "a","b" or --overwrite-roles "a" --overwrite-roles "b"
	if c.IsSet("overwrite-roles") {
		payload.Operation = "overwrite_roles"
		payload.User["roles"] = c.StringSlice("overwrite-roles")
	}

	if c.IsSet("add-roles") {
		payload.Operation = "add_roles"
		payload.User["roles"] = c.StringSlice("add-roles")
	}

	if c.IsSet("overwrite-auth-challenges") {
		payload.Operation = "overwrite_auth_challenges"
		payload.User["challenges"] = c.StringSlice("overwrite-auth-challenges")
	}

	reqData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal update user request: %v", err)
	}

	respBody, err := wr.doRequestWithRetry(c, http.MethodPost, endpointURL, reqData)
	if err != nil {
		return fmt.Errorf("failed updating %q user to %q realm: %w", c.String("username"), c.String("realm"), err)
	}

	var data map[string]any
	if err := json.Unmarshal([]byte(respBody), &data); err != nil {
		return fmt.Errorf("failed to parse JSON response: %v", err)
	}

	fmt.Fprintf(os.Stdout, "%s\n", respBody)
	return nil
}
