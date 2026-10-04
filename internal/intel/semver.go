package intel

import (
	"cmp"
	"strings"
)

// SemVer owns exact strict concrete-version text, not matching or safety evidence.
// Only successful parser values and their copies qualify for comparison.
type SemVer struct {
	text       string
	core       [3]string
	prerelease string
	qualified  bool
}

// ParseSemVer qualifies exact SemVer 2.0.0 text within a 1 MiB work allowance.
// It does not clean spellings or impose a machine-integer magnitude ceiling.
func ParseSemVer(text string) (SemVer, error) {
	if len(text) > 1<<20 {
		return SemVer{}, &ParseError{Code: "limit-exceeded"}
	}
	main, build, hasBuild := strings.Cut(text, "+")
	if hasBuild && !semverIdentifiers(build, false) {
		return SemVer{}, &ParseError{Code: "invalid-semver"}
	}
	core, pre, hasPre := strings.Cut(main, "-")
	parts := strings.SplitN(core, ".", 4)
	if len(parts) != 3 {
		return SemVer{}, &ParseError{Code: "invalid-semver"}
	}
	for _, part := range parts {
		if !semverNumeric(part) {
			return SemVer{}, &ParseError{Code: "invalid-semver"}
		}
	}
	if hasPre && !semverIdentifiers(pre, true) {
		return SemVer{}, &ParseError{Code: "invalid-semver"}
	}
	// Re-slice owned storage rather than retain a larger caller backing string.
	owned := strings.Clone(text)
	main, _, _ = strings.Cut(owned, "+")
	core, pre, _ = strings.Cut(main, "-")
	parts = strings.SplitN(core, ".", 4)
	return SemVer{text: owned, core: [3]string{parts[0], parts[1], parts[2]}, prerelease: pre, qualified: true}, nil
}

// Text returns the original spelling; empty zero-value text is unqualified.
func (v SemVer) Text() string { return v.text }

func semverNumeric(text string) bool {
	if text == "" || len(text) > 1 && text[0] == '0' {
		return false
	}
	for i := 0; i < len(text); i++ {
		if text[i] < '0' || text[i] > '9' {
			return false
		}
	}
	return true
}

func semverIdentifiers(text string, prerelease bool) bool {
	for {
		id, rest, more := strings.Cut(text, ".")
		if id == "" {
			return false
		}
		numeric := true
		for i := 0; i < len(id); i++ {
			b := id[i]
			digit := b >= '0' && b <= '9'
			if !digit && !(b >= 'A' && b <= 'Z') && !(b >= 'a' && b <= 'z') && b != '-' {
				return false
			}
			if !digit {
				numeric = false
			}
		}
		if prerelease && numeric && len(id) > 1 && id[0] == '0' {
			return false
		}
		if !more {
			return true
		}
		text = rest
	}
}

func semverNumericCompare(left, right string) int {
	if n := cmp.Compare(len(left), len(right)); n != 0 {
		return n
	}
	return strings.Compare(left, right)
}

// CompareSemVer orders qualified values, ignoring build metadata for precedence.
// Zero with an error is not equality; successful comparison is not matching.
func CompareSemVer(left, right SemVer) (int, error) {
	if !left.qualified || !right.qualified {
		return 0, &ParseError{Code: "invalid-shape"}
	}
	for i := 0; i < 3; i++ {
		if n := semverNumericCompare(left.core[i], right.core[i]); n != 0 {
			return n, nil
		}
	}
	a, b := left.prerelease, right.prerelease
	if a == b {
		return 0, nil
	}
	if a == "" {
		return 1, nil
	}
	if b == "" {
		return -1, nil
	}
	for {
		x, ar, am := strings.Cut(a, ".")
		y, br, bm := strings.Cut(b, ".")
		xn, yn := semverNumeric(x), semverNumeric(y)
		if xn && !yn {
			return -1, nil
		}
		if !xn && yn {
			return 1, nil
		}
		n := strings.Compare(x, y)
		if xn && yn {
			n = semverNumericCompare(x, y)
		}
		if n != 0 {
			return n, nil
		}
		if am != bm {
			if am {
				return 1, nil
			}
			return -1, nil
		}
		if !am {
			return 0, nil
		}
		a, b = ar, br
	}
}
