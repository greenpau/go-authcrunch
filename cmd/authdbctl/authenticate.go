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
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"go.uber.org/zap"
	"golang.org/x/term"
)

func (wr *wrapper) readUserInputWithTimeout(prompt string, timeout time.Duration) (string, error) {
	wr.logger.Debug("prompted user for input", zap.String("prompt", prompt), zap.Duration("timeout", timeout))
	fmt.Print(prompt)

	type result struct {
		pw  string
		err error
	}

	resChan := make(chan result, 1)
	fd := int(os.Stdin.Fd())

	go func() {
		byteInput, err := term.ReadPassword(fd)
		resChan <- result{string(byteInput), err}
	}()

	select {
	case res := <-resChan:
		fmt.Println()
		if res.err != nil {
			return "", res.err
		}
		return res.pw, nil

	case <-time.After(timeout):
		wr.logger.Error("user input timed out")
		return "", errors.New("user input timed out")
	}
}

func (wr *wrapper) authenticate() error {
	apiEndpoint := "/login"
	var authRequest *apiauth.AuthRequest
	var authResponse *apiauth.AuthResponse

	var counter int
	for {
		counter++
		if counter > 10 {
			return fmt.Errorf("reached max attempts threshold")
		}

		if authRequest == nil {
			authRequest = &apiauth.AuthRequest{}
		}
		authRequest.Username = wr.config.Username
		authRequest.Realm = wr.config.Realm

		jsonData, err := json.Marshal(authRequest)
		if err != nil {
			return fmt.Errorf("failed to marshal auth request: %v", err)
		}

		wr.logger.Debug("making authentication request", zap.Any("auth_request", authRequest))

		req, _ := http.NewRequest(http.MethodPost, wr.config.BaseURL+apiEndpoint, bytes.NewBuffer(jsonData))
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Content-Type", "application/json")
		respBody, resp, err := wr.browser.Do(req)
		if err != nil {
			return fmt.Errorf("failed connecting to auth portal sandbox: %v", err)
		}

		if resp.StatusCode != 200 {
			authErrorResponse := &apiauth.AuthErrorResponse{}
			if err := json.Unmarshal([]byte(respBody), authErrorResponse); err != nil {
				return fmt.Errorf("failed to parse auth error response: %s: %v", respBody, err)
			}
			wr.logger.Debug("authentication error", zap.Int("status_code", resp.StatusCode), zap.Any("auth_response", authErrorResponse))
			return fmt.Errorf("authentication failed, status_code: %d", resp.StatusCode)
		}

		if authResponse == nil {
			authResponse = &apiauth.AuthResponse{}
		}

		if err := json.Unmarshal([]byte(respBody), authResponse); err != nil {
			return fmt.Errorf("failed to parse auth response: %s: %v", respBody, err)
		}

		wr.logger.Debug("parsed authentication response", zap.Any("auth_response", authResponse))

		if authResponse.SandboxID != "" {
			authRequest.SandboxID = authResponse.SandboxID
			authRequest.SandboxSecret = authResponse.SandboxSecret
		}

		if authResponse.Authenticated {
			wr.config.tokenAcquired = true
			wr.config.accessToken = authResponse.AccessToken
			if authResponse.RefreshToken != "" {
				wr.config.refreshToken = authResponse.RefreshToken
			}
			break
		}

		authRequest.SandboxID = authResponse.SandboxID
		authRequest.SandboxSecret = authResponse.SandboxSecret

		switch {
		case authResponse.NextChallenge == "password":
			authRequest.ChallengeKind = authResponse.NextChallenge
			if wr.config.Password != "" {
				authRequest.ChallengeResponse = wr.config.Password
			} else {
				userInput, err := wr.readUserInputWithTimeout("Please enter password: ", 30*time.Second)
				if err != nil {
					return err
				}
				authRequest.ChallengeResponse = userInput
			}
		case authResponse.NextChallenge == "totp":
			authRequest.ChallengeKind = authResponse.NextChallenge
			if wr.config.TotpSecret != "" {
				passcode, err := generateTOTP(wr.config.TotpSecret, wr.config.TotpCodeLength, wr.config.TotpCodeLifetime)
				if err != nil {
					return err
				}
				authRequest.ChallengeResponse = passcode
			} else {
				userInput, err := wr.readUserInputWithTimeout("Please authenticator app code: ", 30*time.Second)
				if err != nil {
					return err
				}
				authRequest.ChallengeResponse = userInput
			}
		case authResponse.NextChallenge == "u2f":
			authRequest.ChallengeKind = authResponse.NextChallenge
			// TODO: authRequest.ChallengeResponse = u2f
			return fmt.Errorf("the handling of %s 2 is not implemented", authResponse.NextChallenge)
		case authResponse.NextChallenge == "mfa":
			authRequest.ChallengeKind = authResponse.NextChallenge
			// TODO: authRequest.ChallengeResponse = either app or u2f
			return fmt.Errorf("the handling of %s 3 is not implemented", authResponse.NextChallenge)
		default:
			return fmt.Errorf("the handling of %s is not implemented", authResponse.NextChallenge)
		}
	}

	if wr.config.tokenAcquired {
		wr.logger.Debug(
			"auth token acquired",
			zap.String("access_token", wr.config.accessToken),
			zap.String("access_token_name", wr.config.accessTokenName),
			zap.String("refresh_token", wr.config.refreshToken),
		)
		if err := wr.commitToken(); err != nil {
			return err
		}
		log.Printf("auth token acquired: %s", wr.config.TokenPath)
		return nil
	}

	return fmt.Errorf("not implemented")
}
