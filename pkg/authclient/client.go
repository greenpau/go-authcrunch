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

package authclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/greenpau/go-authcrunch/pkg/apiauth"
)

const (
	maxAuthRequests = 10
	maxResponseSize = 1 << 20
	defaultTimeout  = 10 * time.Second
)

// Options supplies application dependencies. A nil Prompt permits authentication
// with configured credentials only. HTTPClient is copied; its Transport and Jar
// remain shared. A missing Jar is created.
// Redirects are always disabled to prevent forwarding login bodies. A nil
// HTTPClient uses the standard transport and a ten-second request timeout.
type Options struct {
	HTTPClient *http.Client `json:"-" xml:"-" yaml:"-"`
	Prompt     PromptFunc   `json:"-" xml:"-" yaml:"-"`
	UserAgent  string       `json:"-" xml:"-" yaml:"-"`
}

// Client performs portal logins and returns credentials to its caller. Its HTTP
// cookie jar retains portal cookies across calls. Use one client per identity,
// and serialize Authenticate calls when the supplied prompt interacts with a
// terminal or another stateful input source.
type Client struct {
	config    Config
	http      *http.Client
	prompt    PromptFunc
	userAgent string
}

// NewClient validates a copy of cfg, leaving the caller's configuration unchanged.
func NewClient(cfg *Config, opts Options) (*Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("authentication configuration is required")
	}
	config := *cfg
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if strings.ContainsAny(opts.UserAgent, "\r\n") {
		return nil, fmt.Errorf("invalid user agent")
	}
	hc := http.Client{Timeout: defaultTimeout}
	if opts.HTTPClient != nil {
		hc = *opts.HTTPClient
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if hc.Jar == nil {
		// cookiejar.New always returns a nil error; options only set the suffix list.
		hc.Jar, _ = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	}
	return &Client{config: config, http: &hc, prompt: opts.Prompt, userAgent: opts.UserAgent}, nil
}

// Authenticate runs the JSON /login challenge exchange or API key login. It never calls the admin
// API, reads configuration files, prompts directly, or persists credentials.
// Every call starts with a new sandbox exchange, bounded to ten HTTP requests.
// Context cancellation applies to HTTP requests and is passed to the prompt.
func (c *Client) Authenticate(ctx context.Context) (*Credentials, error) {
	request := apiauth.AuthRequest{Username: c.config.Username, Realm: c.config.Realm, APIKey: c.config.APIKey}
	for attempt := 0; attempt < maxAuthRequests; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		response, err := c.exchange(ctx, &request)
		if err != nil {
			return nil, err
		}
		if response.Authenticated {
			credentials := &Credentials{
				AccessToken: response.AccessToken, AccessTokenName: c.config.AccessTokenName,
				RefreshToken: response.RefreshToken, RefreshTokenName: response.RefreshTokenName,
				SessionID: response.SessionID, AccessExpiresAt: response.AccessExpiresAt,
				RefreshExpiresAt: response.RefreshExpiresAt, SessionExpiresAt: response.SessionExpiresAt,
				CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
			}
			if response.AccessTokenName != "" {
				credentials.AccessTokenName = strings.ToLower(response.AccessTokenName)
			}
			if err := credentials.Validate(); err != nil {
				return nil, fmt.Errorf("invalid authentication credentials: %w", err)
			}
			return credentials, nil
		}
		if c.config.APIKey != "" {
			return nil, fmt.Errorf("API key authentication did not return credentials")
		}
		if response.SandboxID == "" || response.SandboxSecret == "" || response.NextChallenge == "" {
			return nil, fmt.Errorf("incomplete authentication challenge")
		}
		if attempt == maxAuthRequests-1 {
			break
		}
		answer, err := c.answer(ctx, response.NextChallenge)
		if err != nil {
			return nil, err
		}
		request.SandboxID = response.SandboxID
		request.SandboxSecret = response.SandboxSecret
		request.ChallengeKind = response.NextChallenge
		request.ChallengeResponse = answer
	}
	return nil, fmt.Errorf("reached maximum authentication requests")
}

func (c *Client) exchange(ctx context.Context, request *apiauth.AuthRequest) (*apiauth.AuthResponse, error) {
	// AuthRequest contains only strings and has no custom marshaler.
	data, _ := json.Marshal(request)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.BaseURL+"/login", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("create authentication request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connect to authentication portal: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPError{StatusCode: resp.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("read authentication response: %w", err)
	}
	if len(body) > maxResponseSize {
		return nil, fmt.Errorf("authentication response exceeds size limit")
	}
	// Use a fresh response each time; omitted fields must not reuse earlier state.
	var response apiauth.AuthResponse
	if err := json.Unmarshal(body, &response); err != nil {
		// JSON type errors may include server-controlled values containing secrets.
		return nil, errors.New("invalid authentication response JSON")
	}
	return &response, nil
}

// HTTPError reports a failed login's status without exposing the response body.
type HTTPError struct {
	StatusCode int `json:"status_code,omitempty" xml:"status_code,omitempty" yaml:"status_code,omitempty"`
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("authentication failed, status_code: %d", e.StatusCode)
}
