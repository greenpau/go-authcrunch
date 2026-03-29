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
	"strings"
	"time"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

type userRequest struct {
	Realm     string         `json:"realm"`
	Operation string         `json:"operation"`
	User      map[string]any `json:"user"`
}

type requestOpts struct {
	disableAccessToken bool
	maxAttempts        int
}

func (wr *wrapper) doRequestWithRetry(c *cli.Context, method, url string, opts *requestOpts, body []byte) (string, error) {
	var respBody string
	var resp *http.Response
	var err error

	if opts == nil {
		opts = &requestOpts{}
	}

	if !opts.disableAccessToken {
		if wr.config.accessToken == "" {
			if authErr := wr.authenticate(); authErr != nil {
				return "", fmt.Errorf("authentication failed: %v", authErr)
			}
		}
	}

	maxAttempts := c.Int("retries")
	if opts.maxAttempts > 0 {
		maxAttempts = opts.maxAttempts
	}
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	for i := 1; i <= maxAttempts; i++ {
		req, _ := http.NewRequest(method, url, bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json; charset=UTF-8")
		if !opts.disableAccessToken {
			req.Header.Set("Authorization", wr.config.accessTokenName+"="+wr.config.accessToken)
		}

		respBody, resp, err = wr.browser.Do(req)

		if err == nil && resp != nil && resp.StatusCode == http.StatusOK {
			return respBody, nil
		}

		var errorData map[string]any
		_ = json.Unmarshal([]byte(respBody), &errorData)

		wr.logger.Debug("request attempt failed",
			zap.Int("attempt", i),
			zap.Int("max_attempts", maxAttempts),
			zap.String("url", url),
			zap.Error(err),
			zap.Any("server_response", errorData),
			zap.String("access_token_name", wr.config.accessTokenName),
			zap.String("access_token", wr.config.accessToken),
		)

		if msg, ok := errorData["message"].(string); ok && strings.ToLower(msg) == "access denied" {
			wr.logger.Debug("access denied detected, attempting to re-authenticate", zap.Int("attempt", i), zap.String("response_body", respBody))
			if authErr := wr.authenticate(); authErr != nil {
				return "", fmt.Errorf("re-authentication failed: %v", authErr)
			}
		}

		if msg, ok := errorData["message"].(string); ok && strings.ToLower(msg) == "not implemented" {
			return "", fmt.Errorf("operation is %s", msg)
		}

		if msg, ok := errorData["message"].(string); ok && strings.ToLower(msg) == "forbidden" {
			return "", fmt.Errorf("operation is %s", msg)
		}

		if i == maxAttempts {
			if err != nil {
				return "", fmt.Errorf("request failed after %d attempts: %v", maxAttempts, err)
			}
			return "", fmt.Errorf("server responded with %d after %d attempts", resp.StatusCode, maxAttempts)
		}

		time.Sleep(c.Duration("retry-interval"))
	}

	return respBody, nil
}
