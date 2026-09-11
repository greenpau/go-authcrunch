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

package authclient

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

// generateTOTP uses raw secret bytes, matching AuthCrunch's identity.MfaToken
// and the existing authdbctl configuration (not a base32-encoded OTP URI secret).
// Config.Validate bounds digits and period before this helper is called.
func generateTOTP(secret string, digits, period int, at time.Time) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(at.Unix()/int64(period)))
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0xf
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", digits, code%uint32(math.Pow10(digits)))
}
