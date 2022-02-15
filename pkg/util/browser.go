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
	"io/ioutil"
	"net"
	"net/http"
	"net/http/cookiejar"
	"time"
)

// Browser represents a browser instance.
type Browser struct {
	client *http.Client
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

	respBody, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return "", nil, err
	}

	return string(respBody), resp, nil
}
