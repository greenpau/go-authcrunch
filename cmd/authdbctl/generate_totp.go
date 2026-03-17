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
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

func generateTOTP(secret string, codeLength int, codeLifetime int) (string, error) {
	counter := uint64(time.Now().Unix() / int64(codeLifetime))
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	h := hmac.New(sha1.New, []byte(secret))
	h.Write(buf)
	sum := h.Sum(nil)

	// Get the last 4 bits of the hash to use as an offset (RFC 4226)
	offset := sum[len(sum)-1] & 0xf

	// Extract a 4-byte slice starting at the offset
	// Use a 31-bit mask (0x7fffffff) to keep the number positive
	binaryCode := binary.BigEndian.Uint32(sum[offset : offset+4])
	binaryCode &= 0x7fffffff

	divisor := uint32(math.Pow10(codeLength))
	otp := binaryCode % divisor

	return fmt.Sprintf("%0*d", codeLength, otp), nil
}
