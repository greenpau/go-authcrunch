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

package identity

import "fmt"

const (
	// PasswordAlgorithmBcrypt identifies legacy bcrypt password records.
	PasswordAlgorithmBcrypt = "bcrypt"
	// PasswordAlgorithmArgon2 identifies Argon2id v19 password records.
	PasswordAlgorithmArgon2 = "argon2"

	defaultArgon2Memory      = 64 * 1024
	defaultArgon2Iterations  = 3
	defaultArgon2Parallelism = 4
	argon2SaltSize           = 16
	argon2KeySize            = 32
	maxArgon2Memory          = 256 * 1024
	maxArgon2Iterations      = 10
	maxArgon2Parallelism     = 16
	maxArgon2Work            = 1024 * 1024 // KiB-passes, in addition to individual bounds.
)

// PasswordHashConfig configures password generation. Zero fields select defaults:
// bcrypt cost 10, or Argon2id with 65536 KiB, three passes and four lanes.
// Imported hashes carry their own parameters and do not use these settings.
type PasswordHashConfig struct {
	Algorithm   string `json:"algorithm,omitempty" xml:"algorithm,omitempty" yaml:"algorithm,omitempty"`
	Cost        int    `json:"cost,omitempty" xml:"cost,omitempty" yaml:"cost,omitempty"`
	Memory      int    `json:"memory,omitempty" xml:"memory,omitempty" yaml:"memory,omitempty"`
	Iterations  int    `json:"iterations,omitempty" xml:"iterations,omitempty" yaml:"iterations,omitempty"`
	Parallelism int    `json:"parallelism,omitempty" xml:"parallelism,omitempty" yaml:"parallelism,omitempty"`
}

// Validate applies defaults and bounds CPU, memory and parallelism before hashing.
// Custom Argon2 parameters may be weaker than the defaults; callers own tuning.
func (c *PasswordHashConfig) Validate() error {
	if c == nil {
		return fmt.Errorf("password hash configuration is required")
	}
	if c.Algorithm == "" {
		c.Algorithm = PasswordAlgorithmBcrypt
	}
	switch c.Algorithm {
	case PasswordAlgorithmBcrypt:
		if c.Memory != 0 || c.Iterations != 0 || c.Parallelism != 0 {
			return fmt.Errorf("argon2 parameters require the argon2 algorithm")
		}
		if c.Cost == 0 {
			c.Cost = 10
		}
		if c.Cost < 8 || c.Cost > 31 {
			return fmt.Errorf("bcrypt cost must be between 8 and 31")
		}
	case PasswordAlgorithmArgon2:
		if c.Cost != 0 {
			return fmt.Errorf("bcrypt cost cannot be used with argon2")
		}
		if c.Memory == 0 {
			c.Memory = defaultArgon2Memory
		}
		if c.Iterations == 0 {
			c.Iterations = defaultArgon2Iterations
		}
		if c.Parallelism == 0 {
			c.Parallelism = defaultArgon2Parallelism
		}
		return validateArgon2Parameters(c.Memory, c.Iterations, c.Parallelism)
	default:
		return fmt.Errorf("unsupported password hash algorithm")
	}
	return nil
}

func validateArgon2Parameters(memory, iterations, parallelism int) error {
	if parallelism < 1 || parallelism > maxArgon2Parallelism {
		return fmt.Errorf("argon2 parallelism must be between 1 and 16")
	}
	if memory < 8*parallelism || memory > maxArgon2Memory {
		return fmt.Errorf("argon2 memory must be at least 8 KiB per lane and at most 262144 KiB")
	}
	if iterations < 1 || iterations > maxArgon2Iterations {
		return fmt.Errorf("argon2 iterations must be between 1 and 10")
	}
	if memory*iterations > maxArgon2Work {
		return fmt.Errorf("argon2 memory and iterations exceed the work limit")
	}
	return nil
}
