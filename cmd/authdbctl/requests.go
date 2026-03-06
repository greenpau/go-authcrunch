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
	"time"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

func (wr *wrapper) doRequestWithRetry(c *cli.Context, method, url string, body []byte) (string, error) {
	var respBody string
	var resp *http.Response
	var err error

	maxAttempts := c.Int("retries")
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	for i := 1; i <= maxAttempts; i++ {
		req, _ := http.NewRequest(method, url, bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json; charset=UTF-8")
		req.Header.Set("Authorization", c.String("access-token-name")+"="+wr.config.token)

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
		)

		if msg, ok := errorData["message"].(string); ok && msg == "Access denied" {
			wr.logger.Info("access denied detected, attempting to re-authenticate", zap.Int("attempt", i))
			if authErr := wr.authenticate(); authErr != nil {
				return "", fmt.Errorf("re-authentication failed: %v", authErr)
			}
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
