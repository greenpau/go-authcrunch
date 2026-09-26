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

package util

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"time"
)

// MaxHTTPResponseBodySize is the largest response accepted by Browser.Do.
// Management list responses can be substantially larger than authentication
// responses, so retain a generous finite boundary for all current consumers.
const MaxHTTPResponseBodySize int64 = 16 << 20

// ErrHTTPResponseBodyTooLarge indicates that an HTTP response exceeded the
// Browser.Do allocation boundary.
var ErrHTTPResponseBodyTooLarge = errors.New("HTTP response body exceeds size limit")

// Browser represents a browser instance.
type Browser struct {
	client              *http.Client
	maxResponseBodySize int64
}

// NewBrowser returns an instance of a browser.
func NewBrowser() (*Browser, error) {
	cj, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	b := &Browser{
		maxResponseBodySize: MaxHTTPResponseBodySize,
		client: &http.Client{
			Jar:       cj,
			Timeout:   time.Second * 10,
			Transport: tr,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	return b, nil
}

// Do makes HTTP requests and parses responses.
func (b *Browser) Do(req *http.Request) (string, *http.Response, error) {
	req.Header.Set("User-Agent", "authdbctl/1.0.16")
	resp, err := b.client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()

	if resp.ContentLength > b.maxResponseBodySize {
		return "", nil, ErrHTTPResponseBodyTooLarge
	}
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, b.maxResponseBodySize+1))
	if err != nil {
		return "", nil, err
	}
	if int64(len(respBody)) > b.maxResponseBodySize {
		return "", nil, ErrHTTPResponseBodyTooLarge
	}

	return string(respBody), resp, nil
}

// SetTimeout sets timeout on HTTP requests.
func (b *Browser) SetTimeout(duration time.Duration) {
	b.client.Timeout = duration
}
