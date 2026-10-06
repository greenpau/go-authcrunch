// Copyright 2026 Paul Greenberg greenpau@outlook.com
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

package httpjson

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/greenpau/go-authcrunch/pkg/authz/external"
)

const maxResponseBytes = 4096

// ErrResponseTooLarge identifies a deterministic response-size rejection.
var ErrResponseTooLarge = errors.New("HTTP JSON authorization response exceeds size limit")

// Backend sends one POST per decision, with no decision cache or application
// retries. It is safe for concurrent use. Errors never include endpoint URLs,
// identity attributes, response bodies or transport diagnostics.
type Backend struct {
	config  Config
	client  *http.Client
	owned   *http.Transport
	timeout time.Duration
	closed  atomic.Bool
}

var _ external.Backend = (*Backend)(nil)

// New snapshots config and client settings. A nil client creates an owned
// transport using system TLS trust and no ambient proxy. An injected transport
// supports private roots or mTLS; the caller owns and must not mutate it while
// serving. Cookies and redirects are disabled even on injected clients.
func New(config *Config, client *http.Client) (*Backend, error) {
	if config == nil {
		return nil, external.ErrUnavailable
	}
	c := *config
	if err := c.Validate(); err != nil {
		return nil, err
	}
	timeout, _ := time.ParseDuration(c.Timeout)
	b := &Backend{config: c, timeout: timeout}
	var copyClient http.Client
	if client != nil {
		copyClient = *client
	}
	if copyClient.Transport == nil {
		b.owned = &http.Transport{
			DialContext:       (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2: true, MaxIdleConns: 16, IdleConnTimeout: 90 * time.Second,
			TLSHandshakeTimeout: 5 * time.Second, ExpectContinueTimeout: time.Second,
		}
		copyClient.Transport = b.owned
	}
	copyClient.Jar = nil
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if copyClient.Timeout == 0 || copyClient.Timeout > timeout {
		copyClient.Timeout = timeout
	}
	b.client = &copyClient
	return b, nil
}

// Close rejects new decisions and closes idle connections on owned transports.
// Drain requests before disposal; injected transports remain caller-owned.
func (b *Backend) Close() {
	if b != nil && b.closed.CompareAndSwap(false, true) && b.owned != nil {
		b.owned.CloseIdleConnections()
	}
}

// Decide posts a detached, bounded JSON request. Only HTTP 200 application/json
// with one explicit policy/version-bound allow or deny result is accepted.
func (b *Backend) Decide(ctx context.Context, input external.Request) (*external.Result, error) {
	if b == nil || b.client == nil || b.closed.Load() || ctx == nil {
		return nil, external.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	input, err := input.Snapshot()
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(input)
	if err != nil {
		return nil, external.ErrUnavailable
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.config.Endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, external.ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := b.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, external.ErrUnavailable
	}
	defer resp.Body.Close()
	if resp.ContentLength > maxResponseBytes {
		return nil, ErrResponseTooLarge
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode != http.StatusOK || err != nil || media != "application/json" {
		return nil, external.ErrUnavailable
	}
	data, err = io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if len(data) > maxResponseBytes {
		return nil, ErrResponseTooLarge
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, external.ErrUnavailable
	}
	result, err := decodeResult(data)
	if err != nil || result.Validate(input) != nil {
		return nil, external.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if deadline, _ := ctx.Deadline(); !time.Now().Before(deadline) {
		return nil, context.DeadlineExceeded
	}
	if b.closed.Load() {
		return nil, external.ErrUnavailable
	}
	return result, nil
}

// Exact keys and duplicate rejection avoid ambiguous grants and unsupported
// obligations. The complete response is already bounded before decoding.
func decodeResult(data []byte) (*external.Result, error) {
	if !utf8.Valid(data) {
		return nil, external.ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, external.ErrUnavailable
	}
	r := &external.Result{}
	seen := make(map[string]bool)
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] {
			return nil, external.ErrUnavailable
		}
		seen[name] = true
		var field *string
		switch name {
		case "decision":
			field = &r.Decision
		case "policy":
			field = &r.Policy
		case "version":
			field = &r.Version
		default:
			return nil, external.ErrUnavailable
		}
		if d.Decode(field) != nil {
			return nil, external.ErrUnavailable
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return nil, external.ErrUnavailable
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, external.ErrUnavailable
	}
	return r, nil
}
