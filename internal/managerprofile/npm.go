// Package managerprofile owns pure package-manager interpretation checks.
package managerprofile

import (
	"strconv"
	"strings"
)

// NPMRange selects the bounded npm 10/11 lockfile interpretation without
// asserting which producer wrote the input. Actual formats are validated later.
const NPMRange = "npm@10-11"

// SupportsNPM admits stable npm 10.x/11.x interpretations and the legacy
// npm 8 anchor. It grants neither producer authentication nor origin authority.
func SupportsNPM(profile string) bool {
	if profile == NPMRange || profile == "npm@8.19.4" {
		return true
	}
	if len(profile) > 38 || !strings.HasPrefix(profile, "npm@") {
		return false
	}
	parts := strings.Split(profile[4:], ".")
	if len(parts) != 3 || parts[0] != "10" && parts[0] != "11" {
		return false
	}
	for _, part := range parts[1:] {
		if part == "" || len(part) > 1 && part[0] == '0' {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}
	return true
}
