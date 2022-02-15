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
	"fmt"
	"github.com/greenpau/go-authcrunch/pkg/util"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"golang.org/x/net/html"
	"log"
	"net/http"
	"net/url"
	"strings"
)

func connect(c *cli.Context) error {
	wr := new(wrapper)
	if err := wr.configure(c); err != nil {
		return err
	}

	browser, err := util.NewBrowser()
	if err != nil {
		return err
	}

	var formKind, formURI string
	var formData url.Values
	var counter int
	for {
		counter++
		if counter > 25 {
			return fmt.Errorf("reached max attempts threshold")
		}

		if formKind == "" {
			formKind = "login"
			formURI = "/login"
			formData = url.Values{}
			formData.Set("username", wr.config.Username)
			formData.Set("realm", wr.config.Realm)

			req, _ := http.NewRequest(http.MethodGet, wr.config.BaseURL+"/", nil)
			browser.Do(req)
		}

		req, _ := http.NewRequest(http.MethodPost, wr.config.BaseURL+formURI, strings.NewReader(formData.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		respBody, resp, err := browser.Do(req)
		if err != nil {
			return fmt.Errorf("failed connecting to auth portal sandbox: %v", err)
		}

		redirectURL := resp.Header.Get("Location")

		if redirectURL != "" {
			wr.logger.Debug("request redirected", zap.String("redirect_url", redirectURL))
			req, _ := http.NewRequest(http.MethodGet, redirectURL, nil)
			respBody, resp, err = browser.Do(req)
			for _, cookie := range resp.Cookies() {
				if cookie.Name == wr.config.CookieName {
					wr.config.token = cookie.Value
				}
			}

		}

		respData, err := parseResponse(respBody)
		if err != nil {
			return fmt.Errorf("failed parsing auth portal sandbox response: %v", err)
		}

		if len(respData) > 0 {
			wr.logger.Debug("received response data", zap.Any("data", respData))
		}

		formKind = respData["form_kind"]
		var terminateLoop, continueLoop bool
		switch formKind {
		case "login", "password-auth":
			formURI = respData["form_action"]
		case "":
			if redirectURL != "" && !strings.Contains(redirectURL, "/sandbox/") {
				continueLoop = true
			} else {
				// Inspect headers and cookies for the presence of auth token.
				terminateLoop = true
			}
		default:
			return fmt.Errorf("the %q form is unsupported", formKind)
		}

		if terminateLoop {
			wr.logger.Debug("logged in successfully")
			break
		}

		if continueLoop {
			continue
		}

		formData = url.Values{}
		for k, v := range respData {
			if !strings.HasPrefix(k, "input_") {
				continue
			}
			k = strings.TrimPrefix(k, "input_")
			if v != "" {
				formData.Set(k, v)
			} else {
				switch {
				case (k == "secret") && (formKind == "password-auth") && (wr.config.Password == ""):
					input, err := wr.readUserInput("password")
					if err != nil {
						return err
					}
					formData.Set(k, string(input))
				case (k == "secret") && (formKind == "password-auth"):
					formData.Set(k, wr.config.Password)
				default:
					return fmt.Errorf("the %q input in %q form is unsupported: %v", k, formKind, respData)
				}
			}
		}

		wr.logger.Debug(
			"prepared form inputs",
			zap.String("form_kind", formKind),
			zap.String("form_uri", formURI),
			zap.Any("data", formData),
		)
	}

	if wr.config.token != "" {
		wr.logger.Debug(
			"auth token found",
			zap.String("token", wr.config.token),
		)
		if err := wr.commitToken(); err != nil {
			return err
		}
		log.Printf("auth token found: %s", wr.config.TokenPath)
		return nil
	}
	return fmt.Errorf("failed to obtain auth token")
}

func parseResponse(s string) (map[string]string, error) {
	m := make(map[string]string)
	doc, err := html.Parse(strings.NewReader(s))
	if err != nil {
		return nil, err
	}

	var f func(*html.Node) error
	f = func(n *html.Node) error {
		if n.Type == html.ElementNode && n.Data == "form" {
			if err := parseResponseForm(m, n); err != nil {
				return err
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if err := f(c); err != nil {
				return err
			}
		}
		return nil
	}
	if err := f(doc); err != nil {
		return nil, err
	}

	return m, nil
}

func parseResponseForm(m map[string]string, doc *html.Node) error {
	var formKind string
	for _, a := range doc.Attr {
		switch a.Key {
		case "class", "action":
			m["form_"+a.Key] = a.Val
		}
		if a.Key == "action" {
			switch {
			case strings.HasSuffix(a.Val, "/password-auth"):
				formKind = "password-auth"
			default:
				return fmt.Errorf("detected unsupported form: %s", a.Val)
			}
			m["form_kind"] = formKind
		}
	}

	if _, exists := m["form_kind"]; !exists {
		return fmt.Errorf("failed to identify form kind")
	}

	var f func(*html.Node) error
	f = func(n *html.Node) error {
		if n.Data == "input" {
			var elemKey, elemVal string
			elem := make(map[string]string)
			for _, a := range n.Attr {
				switch a.Key {
				case "id", "name", "value":
					elem[a.Key] = a.Val
				}
			}
			if _, exists := elem["name"]; !exists {
				return fmt.Errorf("input has no name field: %v", elem)
			}
			elemKey = elem["name"]

			if v, exists := elem["value"]; exists {
				elemVal = v
			}
			m["input_"+elemKey] = elemVal
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if err := f(c); err != nil {
				return err
			}
		}
		return nil
	}
	if err := f(doc); err != nil {
		return err
	}
	return nil
}
