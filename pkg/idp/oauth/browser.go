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

package oauth

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

type browserConfig struct {
	TLSInsecureSkipVerify bool
}

func (b *IdentityProvider) newBrowser() (*http.Client, error) {
	/*
	   cj, err := cookiejar.New(nil)
	   if err != nil {
	       return nil, err
	   }
	*/
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
	}

	if b.browserConfig != nil {
		if b.browserConfig.TLSInsecureSkipVerify == true {
			if tr.TLSClientConfig == nil {
				tr.TLSClientConfig = &tls.Config{
					InsecureSkipVerify: true,
				}
			} else {
				tr.TLSClientConfig.InsecureSkipVerify = true
			}
		}
	}

	return &http.Client{
		//Jar:       cj,
		Timeout:   time.Second * 10,
		Transport: tr,
	}, nil
}
