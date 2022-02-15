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
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// ReadCertFile reads certificate files.
func ReadCertFile(filePath string) (string, error) {
	var buffer bytes.Buffer
	var RecordingEnabled bool
	fileHandle, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer fileHandle.Close()

	scanner := bufio.NewScanner(fileHandle)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "-----") {
			if strings.Contains(line, "BEGIN CERTIFICATE") {
				RecordingEnabled = true
				continue
			}
			if strings.Contains(line, "END CERTIFICATE") {
				break
			}
		}
		if RecordingEnabled {
			buffer.WriteString(strings.TrimSpace(line))
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return buffer.String(), nil
}

// ReadFile reads a file.
func ReadFile(filePath string) (string, error) {
	var buffer bytes.Buffer
	fileHandle, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer fileHandle.Close()

	scanner := bufio.NewScanner(fileHandle)
	for scanner.Scan() {
		line := scanner.Text()
		buffer.WriteString(strings.TrimSpace(line))
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return buffer.String(), nil
}

func expandHomePath(fp string) (string, error) {
	if fp[0] != '~' {
		return fp, nil
	}
	hd, err := os.UserHomeDir()
	if err != nil {
		return fp, err
	}
	fp = filepath.Join(hd, fp[1:])
	return fp, nil
}

// ReadFileBytes expands home directory and reads a file.
func ReadFileBytes(fp string) ([]byte, error) {
	var err error
	fp, err = expandHomePath(fp)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadFile(fp)
}

// ExpandPath expands file system path.
func ExpandPath(s string) string {
	p, err := expandHomePath(s)
	if err != nil {
		return s
	}
	return p
}
