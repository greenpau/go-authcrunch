package aaasf

import (
	"github.com/greenpau/aaasf/pkg/credentials"
)

// Config is a configuration of Server.
type Config struct {
	Credentials []*credentials.Config `json:"credentials,omitempty" xml:"credentials,omitempty" yaml:"credentials,omitempty"`
	credMap     map[string]*credentials.Config
}

// NewConfig returns an instance of Config.
func NewConfig() *Config {
	return &Config{
		credMap: make(map[string]*credentials.Config),
	}
}
