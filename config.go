package aaasf

import (
	"github.com/greenpau/aaasf/pkg/authn"
	"github.com/greenpau/aaasf/pkg/authz"
	"github.com/greenpau/aaasf/pkg/credentials"
)

// Config is a configuration of Server.
type Config struct {
	Credentials []*credentials.Config `json:"credentials,omitempty" xml:"credentials,omitempty" yaml:"credentials,omitempty"`
	Portals     []*authn.PortalConfig `json:"auth_portal_config,omitempty" xml:"auth_portal_config,omitempty" yaml:"auth_portal_config,omitempty"`
	Policies    []*authz.PolicyConfig `json:"authz_policy_config,omitempty" xml:"authz_policy_config,omitempty" yaml:"authz_policy_config,omitempty"`
	credMap     map[string]*credentials.Config
}

// NewConfig returns an instance of Config.
func NewConfig() *Config {
	return &Config{
		credMap: make(map[string]*credentials.Config),
	}
}
