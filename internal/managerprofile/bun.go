package managerprofile

import (
	"strconv"
	"strings"
)

// BunRange selects a bounded text-format interpretation, not a producer identity.
const BunRange = "bun@1.2-1.4"

// SupportsBun selects the bounded text-lock interpretation, not a producer proof.
func SupportsBun(profile string) bool {
	if profile == BunRange || profile == "bun@1.2.x" || profile == "bun@1.3.x" || profile == "bun@1.4.x" {
		return true
	}
	const prefix = "bun@1."
	if len(profile) > 38 || !strings.HasPrefix(profile, prefix) {
		return false
	}
	parts := strings.Split(profile[len(prefix):], ".")
	if len(parts) != 2 || parts[0] != "2" && parts[0] != "3" && parts[0] != "4" {
		return false
	}
	n, err := strconv.ParseUint(parts[1], 10, 32)
	return err == nil && strconv.FormatUint(n, 10) == parts[1]
}

// BunTextVersionMax keeps older-family interpretations out of newer formats.
// The family-range view can inspect all admitted formats without naming a producer.
func BunTextVersionMax(profile string) int {
	if !SupportsBun(profile) {
		return -1
	}
	if profile == BunRange || strings.HasPrefix(profile, "bun@1.4.") {
		return 3
	}
	return 1
}
