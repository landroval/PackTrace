package managerprofile

import (
	"strconv"
	"strings"
)

// PNPMFormat9 names a format interpretation, never a producer identity.
const PNPMFormat9 = "pnpm@lockfile-9"

func SupportsPNPM(profile string) bool { return profile == PNPMFormat9 }

// PNPMHint admits canonical stable producer hints only for the bounded family.
func PNPMHint(hint string) bool {
	if len(hint) > 38 || !strings.HasPrefix(hint, "pnpm@") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(hint, "pnpm@"), ".")
	if len(parts) != 3 || parts[0] != "9" && parts[0] != "10" && parts[0] != "11" && parts[0] != "12" {
		return false
	}
	for _, p := range parts {
		n, e := strconv.ParseUint(p, 10, 32)
		if e != nil || strconv.FormatUint(n, 10) != p {
			return false
		}
	}
	return true
}
