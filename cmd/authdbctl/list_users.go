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
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

var (
	listUsersSubcmd = &cli.Command{
		Name:   "users",
		Action: listUsers,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "realm",
				Usage:    "The realm to retrieve users from",
				Required: true,
			},
		},
	}
)

type realmUser struct {
	Username string   `json:"username,omitempty" xml:"username,omitempty" yaml:"username,omitempty"`
	Password string   `json:"password,omitempty" xml:"password,omitempty" yaml:"password,omitempty"`
	Name     string   `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Email    string   `json:"email,omitempty" xml:"email,omitempty" yaml:"email,omitempty"`
	Roles    []string `json:"roles,omitempty" xml:"roles,omitempty" yaml:"roles,omitempty"`
	Disabled bool     `json:"disabled,omitempty" xml:"disabled,omitempty" yaml:"disabled,omitempty"`
}

type listUsersResponse struct {
	Count     int         `json:"count"`
	Users     []realmUser `json:"users"`
	Timestamp string      `json:"timestamp"`
}

func listUsers(c *cli.Context) error {
	wr := new(wrapper)
	if err := wr.configure(c); err != nil {
		return err
	}
	endpointURL := wr.config.BaseURL + "/api/server/users"
	wr.logger.Debug("listing realms", zap.String("endpoint_url", endpointURL), zap.String("realm", c.String("realm")))

	var reqData = []byte(`{
		"realm": "` + c.String("realm") + `",
		"query": "all"
	}`)

	respBody, err := wr.doRequestWithRetry(c, http.MethodPost, endpointURL, nil, reqData)
	if err != nil {
		return fmt.Errorf("failed fetching database info: %w", err)
	}

	var data listUsersResponse
	if err := json.Unmarshal([]byte(respBody), &data); err != nil {
		return fmt.Errorf("failed to parse JSON response: %v", err)
	}

	switch {
	case c.String("format") == "csv":
		writer := csv.NewWriter(os.Stdout)
		writer.Write([]string{"username", "name", "email", "roles", "disabled"})
		for _, usr := range data.Users {
			writer.Write([]string{usr.Username, usr.Name, usr.Email, strings.Join(usr.Roles, ";"), strconv.FormatBool(usr.Disabled)})
		}
		writer.Flush()
		return writer.Error()
	case c.String("format") == "table":
		table := tablewriter.NewWriter(os.Stdout)
		table.Header("username", "name", "email", "roles", "disabled")
		for _, usr := range data.Users {
			table.Append([]string{usr.Username, usr.Name, usr.Email, strings.Join(usr.Roles, ";"), strconv.FormatBool(usr.Disabled)})
		}
		table.Render()
	default:
		fmt.Fprintf(os.Stdout, "%s\n", respBody)
	}
	return nil
}
