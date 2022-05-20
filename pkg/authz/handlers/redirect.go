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

package handlers

import (
	"fmt"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
	"html/template"
	"net/http"
	"net/url"
	"strings"
)

var jsRedirTmpl = template.Must(template.New("js_redir").Parse(`
<html>
    <body>
        <p>User Unauthorized. Redirecting to login.</p>
        <script>
        var auth_url_path = "{{.AuthURLPath}}";
        var sep = "{{.Sep}}";
        var redir_param = "{{.RedirParam}}";
        var redir_url = "{{.RedirURL}}";
        if (window.location.hash) {
            redir_url = redir_url + "#" + window.location.hash.substr(1);
        }
        var final_url = auth_url_path;
        if (redir_param) {
            final_url = auth_url_path + sep + redir_param + "=" + encodeURIComponent(redir_url);
        }
        window.location = final_url;
        </script>
    </body>
</html>
`))

// HandleLocationHeaderRedirect redirects the requests to configured auth URL
// by setting Location header and sending 302.
func HandleLocationHeaderRedirect(w http.ResponseWriter, r *http.Request, rr *requests.AuthorizationRequest) {
	configureRedirect(w, r, rr)
	if !rr.Redirect.Enabled {
		return
	}

	if rr.Redirect.QueryDisabled {
		w.Header().Set("Location", rr.Redirect.AuthURL)
	} else {
		var sb strings.Builder
		sb.WriteString(rr.Redirect.AuthURL)
		sb.WriteString(rr.Redirect.Separator)
		sb.WriteString(rr.Redirect.QueryParameter)
		sb.WriteString("=")
		sb.WriteString(url.QueryEscape(rr.Redirect.URL))
		w.Header().Set("Location", sb.String())
	}

	if rr.Redirect.StatusCode == 0 {
		rr.Redirect.StatusCode = 302
	}

	w.WriteHeader(rr.Redirect.StatusCode)
	w.Write([]byte(http.StatusText(rr.Redirect.StatusCode)))
	return
}

// HandleJavascriptRedirect redirects the requests to configured auth URL by
// responding Javascript-enabled HTML performing script-based redirection.
func HandleJavascriptRedirect(w http.ResponseWriter, r *http.Request, rr *requests.AuthorizationRequest) {
	configureRedirect(w, r, rr)
	if !rr.Redirect.Enabled {
		return
	}

	if rr.Redirect.StatusCode == 0 {
		rr.Redirect.StatusCode = 401
	}

	w.WriteHeader(rr.Redirect.StatusCode)
	jsRedirTmpl.Execute(w, map[string]string{
		"AuthURLPath": rr.Redirect.AuthURL,
		"Sep":         rr.Redirect.Separator,
		"RedirParam":  rr.Redirect.QueryParameter,
		"RedirURL":    rr.Redirect.URL,
	})
	return
}

func configureRedirect(w http.ResponseWriter, r *http.Request, rr *requests.AuthorizationRequest) {
	if strings.Contains(r.RequestURI, rr.Redirect.QueryParameter) {
		rr.Redirect.Enabled = false
		return
	}

	rr.Redirect.Enabled = true

	if rr.Redirect.QueryDisabled {
		return
	}

	if strings.HasPrefix(r.RequestURI, "/") {
		u, err := addrutil.GetCurrentURLWithSuffix(r, "")
		if err != nil {
			return
		}
		rr.Redirect.URL = u
	} else {
		rr.Redirect.URL = r.RequestURI
	}

	rr.Redirect.Separator = "?"

	if strings.Contains(rr.Redirect.AuthURL, "?") {
		rr.Redirect.Separator = "&"
	}

	if len(rr.Redirect.LoginHint) > 0 {
		loginHint := rr.Redirect.LoginHint
		escapedLoginHint := url.QueryEscape(loginHint)
		rr.Redirect.AuthURL = fmt.Sprintf("%s%slogin_hint=%s", rr.Redirect.AuthURL, rr.Redirect.Separator, escapedLoginHint)
	}

	if len(rr.Redirect.AdditionalScopes) > 0 {
		additionalScopes := rr.Redirect.AdditionalScopes
		escapedAdditionalScopes := url.QueryEscape(additionalScopes)
		rr.Redirect.AuthURL = fmt.Sprintf("%s%sadditional_scopes=%s", rr.Redirect.AuthURL, rr.Redirect.Separator, escapedAdditionalScopes)
	}

	return
}
