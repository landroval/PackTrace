package managerprofile

import (
	"strconv"
	"strings"
)

const BunRange = "bun@1.3.x"

// SupportsBun selects the bounded text-lock interpretation, not a producer proof.
func SupportsBun(profile string) bool {
	if profile == BunRange || profile == "bun@1.4.2" {
		return true
	}
	const prefix = "bun@1.3."
	if len(profile) > 38 || !strings.HasPrefix(profile, prefix) {
		return false
	}
	patch := profile[len(prefix):]
	n, err := strconv.ParseUint(patch, 10, 32)
	return err == nil && strconv.FormatUint(n, 10) == patch
}
