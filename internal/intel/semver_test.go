package intel

import (
	"errors"
	"strings"
	"testing"
)

func semverTestError(t *testing.T, err error, code string) {
	t.Helper()
	var e *ParseError
	if !errors.As(err, &e) || e.Code != code || err.Error() != "intel: "+code {
		t.Fatal("wrong fixed private error")
	}
}

func semverTestValue(t *testing.T, text string) SemVer {
	t.Helper()
	v, err := ParseSemVer(text)
	if err != nil || !v.qualified || v.Text() != text {
		t.Fatal("expected exact qualified value")
	}
	return v
}

func TestSemVerSyntax(t *testing.T) {
	cases := []struct {
		id, text string
		valid    bool
	}{
		{"S01", "0.0.0", true}, {"S02", "1.2.3", true},
		{"S03", "1.2.3-alpha.1", true}, {"S04", "1.2.3-0", true},
		{"S05", "1.2.3-001x", true}, {"S06", "1.2.3--", true},
		{"S07", "1.2.3-Alpha", true}, {"S08", "1.2.3+001", true},
		{"S09", "1.2.3-alpha.1+build.001", true},
		{"S10", "18446744073709551616.0.0", true},
		{"S11", "1.0.0-18446744073709551616", true},
		{"S12", "", false}, {"S13", "0", false}, {"S14", "1.2", false},
		{"S15", "1.2.3.4", false}, {"S16", "01.2.3", false},
		{"S17", "1.02.3", false}, {"S18", "1.2.03", false},
		{"S19", "1.2.3-01", false}, {"S20", "1.2.3-alpha..1", false},
		{"S21", "1.2.3-", false}, {"S22", "1.2.3+", false},
		{"S23", "1.2.3+build..1", false}, {"S24", "1.2.3+one+two", false},
		{"S25", "v1.2.3", false}, {"S26", "=1.2.3", false},
		{"S27", " 1.2.3", false}, {"S28", "1.2.3\n", false},
		{"S29", "1.2.3-α", false}, {"S30", "1.2.3_alpha", false},
		{"S31", "^1.2.0", false}, {"S32", "*", false},
		{"S33", "-1.2.3", false}, {"S34", "1e2.0.0", false},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			if tc.valid {
				semverTestValue(t, tc.text)
				return
			}
			v, err := ParseSemVer(tc.text)
			semverTestError(t, err, "invalid-semver")
			if v != (SemVer{}) {
				t.Fatal("nonzero rejection")
			}
		})
	}
}

func TestSemVerPrecedence(t *testing.T) {
	cases := []struct {
		id, left, right string
		order           int
	}{
		{"O01", "1.9.0", "1.10.0", -1}, {"O02", "2.0.0", "1.99.99", 1},
		{"O03", "1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"O04", "1.0.0-alpha.1", "1.0.0-alpha.beta", -1},
		{"O05", "1.0.0-alpha.beta", "1.0.0-beta", -1},
		{"O06", "1.0.0-beta.2", "1.0.0-beta.11", -1},
		{"O07", "1.0.0-rc.1", "1.0.0", -1}, {"O08", "1.0.0-1", "1.0.0-alpha", -1},
		{"O09", "1.0.0-A", "1.0.0-a", -1}, {"O10", "1.0.0+one", "1.0.0+two", 0},
		{"O11", "1.0.0-alpha+001", "1.0.0-alpha", 0},
		{"O12", "18446744073709551615.0.0", "18446744073709551616.0.0", -1},
		{"O13", "1.0.0-18446744073709551615", "1.0.0-18446744073709551616", -1},
		{"O14", "1.0.0", "1.0.0", 0},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			a, b := semverTestValue(t, tc.left), semverTestValue(t, tc.right)
			n, err := CompareSemVer(a, b)
			if err != nil || n != tc.order {
				t.Fatal("wrong reference precedence")
			}
			for i := 0; i < 3; i++ {
				r, e := CompareSemVer(b, a)
				if e != nil || r != -tc.order {
					t.Fatal("wrong reversed reference")
				}
				fresh := semverTestValue(t, tc.left)
				if fresh != a {
					t.Fatal("unstable qualified value")
				}
			}
			if a.Text() != tc.left || b.Text() != tc.right {
				t.Fatal("source text changed")
			}
		})
	}
	t.Run("O15", func(t *testing.T) {
		v, err := ParseSemVer("v1.0.0")
		semverTestError(t, err, "invalid-semver")
		if v != (SemVer{}) {
			t.Fatal("nonzero rejected spelling")
		}
		n, err := CompareSemVer(v, semverTestValue(t, "1.0.0"))
		semverTestError(t, err, "invalid-shape")
		if n != 0 {
			t.Fatal("ordering on rejection")
		}
	})
	t.Run("O16", func(t *testing.T) {
		// Null/unavailable stays with the caller; no string coercion.
		n, err := CompareSemVer(SemVer{}, semverTestValue(t, "1.0.0"))
		semverTestError(t, err, "invalid-shape")
		if n != 0 {
			t.Fatal("ordering unavailable evidence")
		}
	})
}

func TestSemVerBoundaries(t *testing.T) {
	cases := []struct{ id, text, code string }{
		{"P01", strings.Repeat("1", 1048572) + ".0.0", ""},
		{"P02", strings.Repeat("1", 1048573) + ".0.0", "limit-exceeded"},
		{"P03", "1.0.0-" + strings.Repeat("1", 1048570), ""},
		{"P04", "1.0.0+" + strings.Repeat("0", 1048570), ""},
		{"P05", strings.Repeat("!", 1048577), "limit-exceeded"},
		{"P06", strings.Repeat("1", 1048571) + ".0.0", ""},
		{"P08", "1.0.0-a-b", ""}, {"P09", "1.0.0+001.000", ""},
		{"P10", "1.0.0-0.1", ""}, {"P11", "1.0.0-00", "invalid-semver"},
		{"P12", "1.0.0\x00", "invalid-semver"},
		{"P13", string([]byte{0x31, 0x2e, 0x30, 0x2e, 0x30, 0x2d, 0xff}), "invalid-semver"},
		{"P14", "１.0.0", "invalid-semver"},
		{"P15-extra-plus", "1.0.0++", "invalid-semver"},
		{"P15-empty-pre", "1.0.0-+x", "invalid-semver"},
		{"P24", "1.0.0-private-marker!", "invalid-semver"},
		{"P25", "1.0.0-" + strings.Repeat("a.", 524284) + "a", ""},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			if tc.code == "" {
				semverTestValue(t, tc.text)
				return
			}
			v, err := ParseSemVer(tc.text)
			semverTestError(t, err, tc.code)
			if v != (SemVer{}) {
				t.Fatal("partial rejected value")
			}
		})
	}
	pairs := []struct {
		id, left, right string
		order           int
	}{
		{"P07", strings.Repeat("1", 1048571) + ".0.0", strings.Repeat("1", 1048572) + ".0.0", -1},
		{"P16", "1.0.0-x+build", "1.0.0-x+other", 0},
		{"P17", "1.0.0-001x", "1.0.0-1", 1},
		{"P18", "1.0.0--", "1.0.0-0", 1},
		{"P19", "1.0.0-a.1", "1.0.0-a.1.0", -1},
		{"P26", "1.0.0-" + strings.Repeat("a.", 524284) + "a", "1.0.0-" + strings.Repeat("a.", 524283) + "a", 1},
	}
	for _, tc := range pairs {
		t.Run(tc.id, func(t *testing.T) {
			a, b := semverTestValue(t, tc.left), semverTestValue(t, tc.right)
			n, err := CompareSemVer(a, b)
			if err != nil || n != tc.order {
				t.Fatal("wrong boundary precedence")
			}
			if a.Text() != tc.left || b.Text() != tc.right {
				t.Fatal("changed boundary text")
			}
		})
	}
	t.Run("P20", func(t *testing.T) {
		v := semverTestValue(t, "0.0.0")
		for _, p := range [][2]SemVer{{{}, v}, {v, {}}, {{}, {}}} {
			n, err := CompareSemVer(p[0], p[1])
			semverTestError(t, err, "invalid-shape")
			if n != 0 {
				t.Fatal("ordering unqualified operand")
			}
		}
	})
	t.Run("P21", func(t *testing.T) {
		if (SemVer{}).Text() != "" {
			t.Fatal("invented zero text")
		}
	})
	t.Run("P22", func(t *testing.T) {
		source := "1.0.0-alpha+original"
		original := semverTestValue(t, source)
		copied := original
		source = "different"
		original = SemVer{}
		if source == copied.Text() || original.qualified || copied.Text() != "1.0.0-alpha+original" {
			t.Fatal("copy text lost")
		}
		n, err := CompareSemVer(copied, semverTestValue(t, "1.0.0-alpha+original"))
		if err != nil || n != 0 {
			t.Fatal("copy qualification lost")
		}
	})
	t.Run("P23", func(t *testing.T) {
		a, b := semverTestValue(t, "1.0.0-beta.2"), semverTestValue(t, "1.0.0-beta.11")
		for i := 0; i < 3; i++ {
			x := semverTestValue(t, "1.0.0-beta.2")
			if x != a {
				t.Fatal("nondeterministic parse")
			}
			n, e := CompareSemVer(a, b)
			r, f := CompareSemVer(b, a)
			if e != nil || f != nil || n != -1 || r != 1 {
				t.Fatal("nondeterministic directional order")
			}
		}
	})
}

// Independent decisive axes catch omitted patch comparison and decimal coercion.
func TestSemVerCoreAxes(t *testing.T) {
	cases := []struct {
		name, left, right string
		order             int
	}{
		{"patch-length", "1.2.9", "1.2.10", -1},
		{"patch-same-width", "1.2.2", "1.2.3", -1},
		{"minor-large", "1.18446744073709551615.0", "1.18446744073709551616.0", -1},
		{"patch-large", "1.2.18446744073709551615", "1.2.18446744073709551616", -1},
		{"core-before-prerelease", "1.2.10-alpha", "1.2.9", 1},
		{"nonnumeric-leading-zero", "1.0.0-00x", "1.0.0-001x", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := semverTestValue(t, tc.left), semverTestValue(t, tc.right)
			n, err := CompareSemVer(a, b)
			r, reversedErr := CompareSemVer(b, a)
			if err != nil || reversedErr != nil || n != tc.order || r != -tc.order {
				t.Fatal("wrong independent axis precedence")
			}
			if a.Text() != tc.left || b.Text() != tc.right {
				t.Fatal("axis source text changed")
			}
		})
	}
}
