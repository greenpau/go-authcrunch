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

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunFlags(t *testing.T) {
	t.Setenv("AUTHDB_CONFIG_PATH", filepath.Join(t.TempDir(), "absent.json"))
	for _, tc := range []struct {
		args     []string
		fail     bool
		contains string
	}{
		{nil, false, "COMMANDS:"},
		{[]string{"--help"}, false, "GLOBAL OPTIONS:"},
		{[]string{"-h"}, false, "COMMANDS:"},
		{[]string{"help"}, false, "COMMANDS:"},
		{[]string{"h", "run"}, false, "authdb run"},
		{[]string{"help", "run"}, false, "--config PATH"},
		{[]string{"run", "--help"}, false, "--debug"},
		{[]string{"run", "-h"}, false, "authdb run"},
		{[]string{"help", "version"}, false, "authdb version"},
		{[]string{"--version"}, false, "authdb "},
		{[]string{"-v"}, false, "authdb "},
		{[]string{"version"}, false, "authdb "},
		{[]string{"--config", "absent", "--debug", "version"}, false, "authdb "},
		{[]string{"--unknown"}, true, ""},
		{[]string{"unexpected"}, true, ""},
		{[]string{"help", "unknown"}, true, ""},
		{[]string{"run", "--unknown"}, true, ""},
		{[]string{"run", "unexpected"}, true, ""},
		{[]string{"version", "unexpected"}, true, ""},
		{[]string{"run", "--config"}, true, ""},
		{[]string{"run", "--debug=invalid"}, true, ""},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			var out, stderr bytes.Buffer
			err := run(t.Context(), tc.args, &out, &stderr)
			if (err != nil) != tc.fail {
				t.Fatalf("args %v: %v", tc.args, err)
			}
			if !strings.Contains(out.String(), tc.contains) {
				t.Fatalf("missing stdout output %q", tc.contains)
			}
			if !tc.fail && stderr.Len() != 0 {
				t.Fatal("help/version wrote to stderr")
			}
		})
	}
}

func TestRunConfigurationFlags(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("AUTHDB_CONFIG_PATH", "")
	if err := os.Unsetenv("AUTHDB_CONFIG_PATH"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, environment, want string
		args                    []string
	}{
		{"default", "", "authdb.json", []string{"run"}},
		{"environment", "environment.json", "environment.json", []string{"run"}},
		{"global", "environment.json", "global.json", []string{"--config", "global.json", "run"}},
		{"command", "environment.json", "command.json", []string{"run", "--config", "command.json"}},
		{"global alias", "environment.json", "global.json", []string{"-c", "global.json", "run"}},
		{"command alias", "environment.json", "command.json", []string{"run", "-c", "command.json"}},
		{"command overrides global", "environment.json", "command.json", []string{"-c", "global.json", "run", "--config", "command.json"}},
		{"explicit empty", "environment.json", "", []string{"run", "--config="}},
		{"fresh invocation", "", "authdb.json", []string{"run"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.environment != "" {
				t.Setenv("AUTHDB_CONFIG_PATH", tc.environment)
			}
			var output bytes.Buffer
			err := run(t.Context(), tc.args, &output, &output)
			var pathError *os.PathError
			if !errors.As(err, &pathError) || pathError.Path != tc.want {
				t.Fatalf("configuration path: want %q, got %v", tc.want, err)
			}
		})
	}
}

func TestVersionCommandsAgree(t *testing.T) {
	for _, args := range [][]string{{"--version"}, {"-v"}, {"version"}} {
		var stdout, stderr bytes.Buffer
		if err := run(t.Context(), args, &stdout, &stderr); err != nil {
			t.Fatal(err)
		}
		if stdout.String() != app.Banner()+"\n" || stderr.Len() != 0 {
			t.Fatal("version command did not preserve the versioned build banner")
		}
	}
}

func TestLoggerLevels(t *testing.T) {
	for _, debug := range []bool{false, true} {
		var output bytes.Buffer
		logger := newLogger(debug, &output)
		logger.Debug("debug message")
		logger.Info("info message")
		if err := logger.Sync(); err != nil {
			t.Fatal(err)
		}
		var levels []string
		for line := range strings.SplitSeq(strings.TrimSpace(output.String()), "\n") {
			var record map[string]any
			if err := json.Unmarshal([]byte(line), &record); err != nil {
				t.Fatal("log record is not JSON")
			}
			if record["time"] == "" || record["time"] == nil {
				t.Fatal("log record is missing its timestamp")
			}
			levels = append(levels, record["level"].(string))
		}
		want := "info"
		if debug {
			want = "debug,info"
		}
		if strings.Join(levels, ",") != want {
			t.Fatalf("log levels: got %v, want %s", levels, want)
		}
	}
}

func TestLoadConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		valid      bool
	}{
		{"minimal", `{"http":{"insecure_http":true,"portals":[{"name":"portal","path":"/auth"}]},"security":{}}`, true},
		{"missing HTTP", `{"security":{}}`, false},
		{"missing security", `{"http":{"insecure_http":true,"portals":[{"name":"portal","path":"/auth"}]}}`, false},
		{"null", `null`, false},
		{"multiple", `{} {}`, false},
		{"malformed", `{"SECRET`, false},
		{"unknown", `{"SECRET":"hidden"}`, false},
		{"nested unknown", `{"http":{"SECRET":"hidden"},"security":{}}`, false},
		{"security unknown", `{"http":{},"security":{"SECRET":"hidden"}}`, false},
		{"type mismatch", `{"http":{"listen_address":42}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), "server.json")
			if err := os.WriteFile(filename, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := loadConfiguration(filename)
			if (err == nil) != tc.valid || (err != nil && cfg != nil) {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
			if err != nil && strings.Contains(err.Error(), "SECRET") {
				t.Fatal("configuration error leaked input")
			}
		})
	}
	if _, err := loadConfiguration(t.TempDir()); err == nil {
		t.Fatal("directory accepted")
	}
	path := filepath.Join(t.TempDir(), "large.json")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxConfigBytes + 1); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if _, err := loadConfiguration(path); err == nil {
		t.Fatal("oversized config accepted")
	}
}
