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

package file

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ReadCertFile reads certificate files and returns the base64 content between tags.
func ReadCertFile(filePath string) (string, error) {
	fp, err := expandHomePath(filePath)
	if err != nil {
		return "", err
	}

	fileHandle, err := os.Open(fp)
	if err != nil {
		return "", err
	}
	defer fileHandle.Close()

	var sb strings.Builder
	var recordingEnabled bool
	scanner := bufio.NewScanner(fileHandle)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "-----") {
			if strings.Contains(line, "BEGIN CERTIFICATE") {
				recordingEnabled = true
				continue
			}
			if strings.Contains(line, "END CERTIFICATE") {
				break
			}
		}
		if recordingEnabled {
			sb.WriteString(strings.TrimSpace(line))
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return sb.String(), nil
}

// ReadFile reads a file and returns its content as a single stripped string.
func ReadFile(filePath string) (string, error) {
	fp, err := expandHomePath(filePath)
	if err != nil {
		return "", err
	}

	fileHandle, err := os.Open(fp)
	if err != nil {
		return "", err
	}
	defer fileHandle.Close()

	var sb strings.Builder
	scanner := bufio.NewScanner(fileHandle)
	for scanner.Scan() {
		sb.WriteString(strings.TrimSpace(scanner.Text()))
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return sb.String(), nil
}

// expandHomePath handles tilde expansion safely.
func expandHomePath(fp string) (string, error) {
	if fp == "" {
		return "", errors.New("cannot expand an empty path")
	}

	// Only expand if it starts with ~
	if fp[0] != '~' {
		return fp, nil
	}

	// Ensure it's either just "~" or starts with "~/" or "~\"
	if len(fp) > 1 && fp[1] != os.PathSeparator && fp[1] != '/' {
		return fp, nil
	}

	hd, err := os.UserHomeDir()
	if err != nil {
		return fp, fmt.Errorf("failed to get home directory: %w", err)
	}

	return filepath.Join(hd, fp[1:]), nil
}

// ReadFileBytes expands home directory and reads a file into a byte slice.
func ReadFileBytes(fp string) ([]byte, error) {
	expanded, err := expandHomePath(fp)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(expanded)
}

// ExpandPath expands file system path or returns the original if expansion fails.
func ExpandPath(s string) string {
	p, err := expandHomePath(s)
	if err != nil {
		return s
	}
	return p
}
