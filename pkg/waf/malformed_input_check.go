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

package waf

import (
	"strconv"
	"unicode"
)

var protoCharsetTable = &unicode.RangeTable{
	R16: []unicode.Range16{
		{0x0061, 0x007a, 1}, // a-z, where a is hex 61
		{0x0030, 0x0039, 1}, // 0-9, where 0 is hex 30
	},
	R32: []unicode.Range32{
		{0x0061, 0x007a, 1}, // a-z, where a is hex 61
		{0x0030, 0x0039, 1}, // 0-9, where 0 is hex 30
	},
	LatinOffset: 1,
}

var fwdAddrCharsetTable = &unicode.RangeTable{
	R16: []unicode.Range16{
		{0x0020, 0x0020, 1}, // space
		{0x002c, 0x002c, 1}, // comma
		{0x002e, 0x002e, 1}, // dot
		{0x0030, 0x0039, 1}, // 0-9
		{0x003a, 0x003a, 1}, // colon
		{0x0041, 0x0046, 1}, // A-F
		{0x0061, 0x0066, 1}, // a-f
	},
	LatinOffset: 1,
}

var realAddrCharsetTable = &unicode.RangeTable{
	R16: []unicode.Range16{
		{0x002e, 0x002e, 1}, // dot
		{0x0030, 0x0039, 1}, // 0-9
		{0x003a, 0x003a, 1}, // colon
		{0x0041, 0x0046, 1}, // A-F
		{0x005b, 0x005b, 1}, // Left square bracket
		{0x005d, 0x005d, 1}, // Right square bracket
		{0x0061, 0x0066, 1}, // a-f
	},
	LatinOffset: 1,
}

// IsMalformedForwardedHost checks whether the provided X-Forwarded-Host
// string is malformed.
func IsMalformedForwardedHost(s string, a, b int) bool {
	switch {
	case len(s) == 0:
		return false
	case (len(s) < a) || (len(s) > b):
		return true
	}
	for _, char := range s {
		if unicode.IsLetter(char) {
			continue
		}
		if unicode.IsNumber(char) {
			continue
		}
		if char == '.' || char == ':' || char == '-' {
			continue
		}
		return true
	}
	return false
}

// IsMalformedForwardedProto checks whether the provided X-Forwarded-Proto
// string is malformed.
func IsMalformedForwardedProto(s string, a, b int) bool {
	switch {
	case len(s) == 0:
		return false
	case (len(s) < a) || (len(s) > b):
		return true
	}
	for _, char := range s {
		if unicode.In(char, protoCharsetTable) {
			continue
		}
		return true
	}
	switch s {
	case "http", "https":
	default:
		return true
	}
	return false
}

// IsMalformedForwardedPort checks whether the provided X-Forwarded-Port
// string is malformed.
func IsMalformedForwardedPort(s string, a, b int) bool {
	switch {
	case len(s) == 0:
		return false
	case (len(s) < a) || (len(s) > b):
		return true
	}
	for _, char := range s {
		if !unicode.IsNumber(char) {
			return true
		}
	}
	// Check the bounds 80 - 65535
	i, _ := strconv.Atoi(s)
	if i > 65535 || i < 80 {
		return true
	}
	return false
}

// IsMalformedRealIP checks whether the provided X-Real-IP
// string is malformed.
func IsMalformedRealIP(s string, a, b int) bool {
	switch {
	case len(s) == 0:
		return false
	case (len(s) < a) || (len(s) > b):
		return true
	}
	for _, char := range s {
		if unicode.In(char, realAddrCharsetTable) {
			continue
		}
		return true
	}
	return false
}

// IsMalformedForwardedFor checks whether the provided X-Forwarded-For
// string is malformed.
func IsMalformedForwardedFor(s string, a, b int) bool {
	switch {
	case len(s) == 0:
		return false
	case (len(s) < a) || (len(s) > b):
		return true
	}
	for _, char := range s {
		if unicode.In(char, fwdAddrCharsetTable) {
			continue
		}
		return true
	}
	return false
}
