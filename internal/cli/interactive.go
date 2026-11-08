package cli

import (
	"errors"
	"strings"
)

// Parent-approved display projection, not a serialized Report or source authority.
// The viewer cannot perform a scan, change policy, fetch data or reconstruct seals.
type InteractiveRow struct{ Name, Version, State, Details string }
type InteractiveView struct {
	Summary string
	Rows    []InteractiveRow
	Exit    int
}

const MaxInteractiveBytes = 8 << 20

func ValidateInteractiveView(v InteractiveView) error {
	if len(v.Rows) > 4096 || len(v.Summary) > 1<<20 || v.Exit != 0 && v.Exit != 1 && v.Exit != 2 && v.Exit != 3 && v.Exit != 130 {
		return errors.New("scan: invalid-interactive-view")
	}
	n := len(v.Summary)
	safe := func(s string) bool { return !strings.ContainsAny(s, "\x1b\x00\r") }
	if !safe(v.Summary) {
		return errors.New("scan: invalid-interactive-view")
	}
	for _, r := range v.Rows {
		n += len(r.Name) + len(r.Version) + len(r.State) + len(r.Details)
		if n > MaxInteractiveBytes || len(r.Name) > 256 || len(r.Version) > 256 || r.State != "FINDING" && r.State != "REVIEW" || !safe(r.Name) || !safe(r.Version) || !safe(r.Details) {
			return errors.New("scan: invalid-interactive-view")
		}
	}
	return nil
}
