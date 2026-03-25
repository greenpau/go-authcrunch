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

package cookie

import (
	"net"
	"strings"

	"golang.org/x/net/publicsuffix"
)

func (f *Factory) evalHost(h string) *DomainConfig {
	i := strings.IndexByte(h, ':')
	if i > 0 {
		if strings.Count(h, ":") > 1 {
			// IPv6 address found.
			return nil
		}
		// There is a host:port separator.
		h = h[:i]
	}
	if addr := net.ParseIP(h); addr != nil {
		// This is IP address.
		return nil
	}

	if strings.Count(h, ".") == 0 {
		// This is hostname without domain.
		return nil
	}

	if len(f.domains) > 0 {
		var candidate *DomainConfig
		for _, k := range f.domains {
			if h == k {
				return f.config.Domains[k]
			}
			if strings.HasSuffix(h, "."+k) {
				candidate = f.config.Domains[k]
			}
		}
		if candidate != nil {
			// Partial match between the provided hostname and the config domain.
			return candidate
		}
	}

	c := &DomainConfig{}

	if f.config.GuessDomainEnabled {
		if strings.Count(h, ".") == 1 {
			c.Domain = string(h)
		} else {
			i = strings.IndexByte(h, '.')
			c.Domain = string(h[i+1:])
		}

		// Validate extracted domain is not a public suffix.
		// Browsers reject cookies set to PSL entries (co.uk, fly.dev, etc.).
		// If invalid, omit domain attribute so the browser defaults to exact FQDN.
		if _, err := publicsuffix.EffectiveTLDPlusOne(c.Domain); err != nil {
			c.Domain = ""
		}
	}

	if f.config.StripDomainEnabled {
		c.Domain = ""
	}

	c.Path = f.config.Path
	c.Lifetime = f.config.Lifetime
	c.Insecure = f.config.Insecure
	c.SameSite = f.config.SameSite
	return c
}
