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

package tag

import (
	"bufio"
	"fmt"
	"github.com/greenpau/aaasf/internal/tests"
	"github.com/greenpau/aaasf/pkg/credentials"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTagCompliance(t *testing.T) {
	testcases := []struct {
		name      string
		entry     interface{}
		opts      *Options
		shouldErr bool
		err       error
	}{
		{
			name:  "test credentials.SMTP",
			entry: &credentials.SMTP{},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs, err := GetTagCompliance(tc.entry, tc.opts)
			if tests.EvalErrWithLog(t, err, nil, tc.shouldErr, tc.err, msgs) {
				return
			}
		})
	}
}

func TestStructTagCompliance(t *testing.T) {
	var files []string
	structMap := make(map[string]bool)
	walkFn := func(path string, fileInfo os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fileInfo.IsDir() {
			return nil
		}
		fileName := filepath.Base(path)
		fileExt := filepath.Ext(fileName)
		if fileExt != ".go" {
			return nil
		}
		if strings.Contains(fileName, "_test.go") {
			return nil
		}
		if strings.Contains(path, "/tag/") || strings.Contains(path, "/errors/") {
			return nil
		}
		// t.Logf("%s %d", path, fileInfo.Size())
		files = append(files, path)
		return nil
	}
	if err := filepath.Walk("../../", walkFn); err != nil {
		t.Error(err)
	}

	for _, fp := range files {
		// t.Logf("file %s", fp)
		var pkgFound bool
		var pkgName string
		fh, _ := os.Open(fp)
		defer fh.Close()
		scanner := bufio.NewScanner(fh)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "package ") {
				pkgFound = true
				pkgName = strings.Split(line, " ")[1]
				// t.Logf("package %s", pkgName)
				continue
			}
			if !pkgFound {
				continue
			}
			if strings.HasPrefix(line, "type") && strings.Contains(line, "struct") {
				structName := strings.Split(line, " ")[1]
				// t.Logf("%s.%s", pkgName, structName)
				structMap[pkgName+"."+structName] = false
			}

			//fmt.Println(scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			t.Errorf("failed reading %q: %v", fp, err)
		}
	}

	fp := "../../internal/tag/tag_test.go"
	fh, _ := os.Open(fp)
	defer fh.Close()
	scanner := bufio.NewScanner(fh)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		for k := range structMap {
			if strings.Contains(line, k+"{}") {
				structMap[k] = true
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Errorf("failed reading %q: %v", fp, err)
	}

	if len(structMap) > 0 {
		var msgs []string
		for k, v := range structMap {
			if v == false {
				t.Logf("Found struct %s", k)
				msgs = append(msgs, fmt.Sprintf("{\nname: \"test %s struct\",\nentry: &%s{},\nopts: &Options{},\n},", k, k))
			}
		}
		if len(msgs) > 0 {
			t.Logf("Add the following tests:\n" + strings.Join(msgs, "\n"))
			t.Fatal("Fix above structs")
		}
	}
}
