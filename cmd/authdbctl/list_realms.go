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

	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

var (
	listRealmsSubcmd = &cli.Command{
		Name:   "realms",
		Action: listRealms,
	}
)

type realmEntry struct {
	Realm string `json:"realm"`
	Kind  string `json:"kind"`
	Name  string `json:"name"`
}

type listRealmsResponse struct {
	Count     int          `json:"count"`
	Realms    []realmEntry `json:"realms"`
	Timestamp string       `json:"timestamp"`
}

func listRealms(c *cli.Context) error {
	wr := new(wrapper)
	if err := wr.configure(c); err != nil {
		return err
	}
	endpointURL := wr.config.BaseURL + "/api/server/realms"
	wr.logger.Debug("listing realms", zap.String("endpoint_url", endpointURL))

	var reqData = []byte(`{
		"query": "all"
	}`)

	respBody, err := wr.doRequestWithRetry(c, http.MethodPost, endpointURL, reqData)
	if err != nil {
		return fmt.Errorf("failed fetching database info: %w", err)
	}

	var data listRealmsResponse
	if err := json.Unmarshal([]byte(respBody), &data); err != nil {
		return fmt.Errorf("failed to parse JSON response: %v", err)
	}

	switch {
	case c.String("format") == "csv":
		writer := csv.NewWriter(os.Stdout)
		writer.Write([]string{"realm", "kind", "name"})
		for _, r := range data.Realms {
			writer.Write([]string{r.Realm, r.Kind, r.Name})
		}
		writer.Flush()
		return writer.Error()
	case c.String("format") == "table":
		table := tablewriter.NewWriter(os.Stdout)
		table.Header("realm", "kind", "name")
		for _, r := range data.Realms {
			table.Append([]string{r.Realm, r.Kind, r.Name})
		}
		table.Render()
	default:
		fmt.Fprintf(os.Stdout, "%s\n", respBody)
	}
	return nil
}
