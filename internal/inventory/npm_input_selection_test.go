package inventory

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func assertNPMInputError(t *testing.T, got NPMInputSelection, err error) {
	t.Helper()
	pe, ok := err.(*ParseError)
	if !ok || pe.Code != "invalid-shape" || pe.Error() != "inventory: invalid-shape" {
		t.Fatal("expected the exact private invalid-shape ParseError")
	}
	if got != (NPMInputSelection{}) {
		t.Fatal("fatal result was not whole-zero")
	}
}

func TestSelectNPMInputReference(t *testing.T) {
	// Literal outcomes transcribed from the approved contract, not the selector.
	rows := []struct {
		id, profile string
		s, p        NPMInputState
		q           bool
		c           NPMInputCandidate
		state       NPMInputSelectionState
		d           NPMInputDiagnostic
	}{
		{"C01", "npm@8.19.4", NPMInputState{2, 1}, NPMInputState{2, 1}, true, 1, 1, 1},
		{"C02", "npm@10.9.4", NPMInputState{2, 1}, NPMInputState{2, 1}, true, 1, 1, 1},
		{"C03", "npm@11.6.2", NPMInputState{2, 1}, NPMInputState{2, 1}, true, 1, 1, 1},
		{"C04", "npm@11.6.2", NPMInputState{1, 0}, NPMInputState{2, 1}, true, 2, 1, 1},
		{"C05", "npm@11.6.2", NPMInputState{1, 0}, NPMInputState{1, 0}, true, 0, 4, 7},
		{"C06", "npm@11.6.2", NPMInputState{0, 0}, NPMInputState{2, 1}, true, 0, 3, 3},
		{"C07", "npm@11.6.2", NPMInputState{0, 2}, NPMInputState{2, 1}, true, 0, 3, 3},
		{"C08", "npm@11.6.2", NPMInputState{0, 3}, NPMInputState{2, 1}, true, 0, 3, 3},
		{"C09", "npm@11.6.2", NPMInputState{2, 0}, NPMInputState{2, 1}, true, 1, 3, 5},
		{"C10", "npm@11.6.2", NPMInputState{2, 2}, NPMInputState{2, 1}, true, 1, 2, 6},
		{"C11", "npm@11.6.2", NPMInputState{2, 3}, NPMInputState{2, 1}, true, 1, 2, 6},
		{"C12", "npm@11.6.2", NPMInputState{2, 4}, NPMInputState{2, 1}, true, 1, 2, 6},
		{"C13", "npm@11.6.2", NPMInputState{2, 5}, NPMInputState{2, 1}, true, 1, 2, 6},
		{"C14", "npm@11.6.2", NPMInputState{1, 0}, NPMInputState{0, 0}, true, 0, 3, 4},
		{"C15", "npm@11.6.2", NPMInputState{1, 0}, NPMInputState{0, 2}, true, 0, 3, 4},
		{"C16", "npm@11.6.2", NPMInputState{1, 0}, NPMInputState{0, 3}, true, 0, 3, 4},
		{"C17", "npm@11.6.2", NPMInputState{1, 0}, NPMInputState{2, 0}, true, 2, 3, 5},
		{"C18", "npm@11.6.2", NPMInputState{1, 0}, NPMInputState{2, 2}, true, 2, 2, 6},
		{"C19", "npm@11.6.2", NPMInputState{1, 0}, NPMInputState{2, 3}, true, 2, 2, 6},
		{"C20", "npm@11.6.2", NPMInputState{1, 0}, NPMInputState{2, 4}, true, 2, 2, 6},
		{"C21", "npm@11.6.2", NPMInputState{1, 0}, NPMInputState{2, 5}, true, 2, 2, 6},
		{"C22", "npm@11.6.2", NPMInputState{2, 1}, NPMInputState{0, 2}, true, 1, 1, 1},
		{"C23", "npm@11.6.2", NPMInputState{2, 1}, NPMInputState{2, 5}, true, 1, 1, 1},
		{"C24", "", NPMInputState{0, 0}, NPMInputState{0, 0}, false, 0, 3, 2},
		{"C25", "npm", NPMInputState{2, 1}, NPMInputState{2, 1}, false, 0, 3, 2},
		{"C26", "auto", NPMInputState{1, 0}, NPMInputState{2, 1}, false, 0, 3, 2},
		{"C27", "npm@12.1.0", NPMInputState{2, 1}, NPMInputState{2, 1}, false, 0, 3, 2},
		{"C28", "npm@11.6.3", NPMInputState{2, 1}, NPMInputState{2, 1}, false, 0, 3, 2},
		{"C29", "NPM@11.6.2", NPMInputState{2, 1}, NPMInputState{2, 1}, false, 0, 3, 2},
		{"C30", " npm@11.6.2", NPMInputState{2, 1}, NPMInputState{2, 1}, false, 0, 3, 2},
		{"C31", "bun@1.4.2", NPMInputState{1, 0}, NPMInputState{2, 1}, false, 0, 3, 2},
	}
	for _, tc := range rows {
		t.Run(tc.id, func(t *testing.T) {
			beforeS, beforeP := tc.s, tc.p
			got, err := SelectNPMInput(tc.profile, tc.s, tc.p)
			want := NPMInputSelection{tc.profile, tc.q, tc.s, tc.p, tc.c, tc.state, tc.d}
			if err != nil || got != want {
				t.Fatalf("literal reference lost: got=%#v err=%v want=%#v", got, err, want)
			}
			if tc.s != beforeS || tc.p != beforeP {
				t.Fatal("caller states changed")
			}
		})
	}
	guards := []struct {
		id, profile string
		s, p        NPMInputState
	}{
		{"G01", "npm@11.6.2", NPMInputState{255, 0}, NPMInputState{2, 1}},
		{"G02", "npm@11.6.2", NPMInputState{2, 255}, NPMInputState{2, 1}},
		{"G03", "npm@11.6.2", NPMInputState{1, 1}, NPMInputState{2, 1}},
		{"G04", "npm@11.6.2", NPMInputState{1, 2}, NPMInputState{2, 1}},
		{"G05", "npm@11.6.2", NPMInputState{0, 1}, NPMInputState{2, 1}},
		{"G06", "npm@11.6.2", NPMInputState{0, 4}, NPMInputState{2, 1}},
		{"G07", "npm@11.6.2", NPMInputState{0, 5}, NPMInputState{2, 1}},
		{"G08", "npm@11.6.2", NPMInputState{2, 1}, NPMInputState{1, 5}},
		{"G09", "npm@12.1.0", NPMInputState{255, 0}, NPMInputState{1, 0}},
		{"G10", "", NPMInputState{1, 0}, NPMInputState{255, 0}},
	}
	for _, tc := range guards {
		t.Run(tc.id, func(t *testing.T) {
			beforeS, beforeP := tc.s, tc.p
			got, err := SelectNPMInput(tc.profile, tc.s, tc.p)
			assertNPMInputError(t, got, err)
			if tc.s != beforeS || tc.p != beforeP {
				t.Fatal("fatal call changed inputs")
			}
		})
	}
}

func TestSelectNPMInputLayouts(t *testing.T) {
	// Independent literal validity for all defined pairs; no production guard oracle.
	valid := [3][6]bool{
		{true, false, true, true, false, false},
		{true, false, false, false, false, false},
		{true, true, true, true, true, true},
	}
	profiles := []string{"npm@8.19.4", "npm@10.9.4", "npm@11.6.2", "", "npm@12.1.0"}
	for pi, profile := range profiles {
		for slot := range 2 {
			for presence := range 3 {
				for usability := range 6 {
					t.Run(fmt.Sprintf("profile%d/slot%d/p%d/u%d", pi, slot, presence, usability), func(t *testing.T) {
						s, p := NPMInputState{2, 1}, NPMInputState{2, 1}
						input := NPMInputState{NPMInputPresence(presence), NPMInputUsability(usability)}
						if slot == 0 {
							s = input
						} else {
							p = input
						}
						beforeS, beforeP := s, p
						got, err := SelectNPMInput(profile, s, p)
						if !valid[presence][usability] {
							assertNPMInputError(t, got, err)
						} else if err != nil || got.Profile != profile || got.Shrinkwrap != s || got.PackageLock != p || got.State == 0 || got.Diagnostic == 0 {
							t.Fatal("valid pair or retained scalar state lost")
						}
						if s != beforeS || p != beforeP {
							t.Fatal("layout preflight changed inputs")
						}
					})
				}
			}
			for bi, bad := range []NPMInputState{{3, 0}, {255, 0}, {2, 6}, {2, 255}} {
				t.Run(fmt.Sprintf("profile%d/slot%d/outside%d", pi, slot, bi), func(t *testing.T) {
					s, p := NPMInputState{2, 1}, NPMInputState{2, 1}
					if slot == 0 {
						s = bad
					} else {
						p = bad
					}
					got, err := SelectNPMInput(profile, s, p)
					assertNPMInputError(t, got, err)
				})
			}
		}
	}
}

func TestSelectNPMInputPrecedence(t *testing.T) {
	rows := []struct {
		id    string
		s, p  NPMInputState
		c     NPMInputCandidate
		state NPMInputSelectionState
		d     NPMInputDiagnostic
	}{
		{"unknown", NPMInputState{0, 0}, NPMInputState{2, 1}, 0, 3, 3},
		{"lookup-unreadable", NPMInputState{0, 2}, NPMInputState{2, 1}, 0, 3, 3},
		{"lookup-unsafe", NPMInputState{0, 3}, NPMInputState{2, 1}, 0, 3, 3},
		{"present-unqualified", NPMInputState{2, 0}, NPMInputState{2, 1}, 1, 3, 5},
		{"present-unreadable", NPMInputState{2, 2}, NPMInputState{2, 1}, 1, 2, 6},
		{"present-unsafe", NPMInputState{2, 3}, NPMInputState{2, 1}, 1, 2, 6},
		{"present-unsupported", NPMInputState{2, 4}, NPMInputState{2, 1}, 1, 2, 6},
		{"present-invalid", NPMInputState{2, 5}, NPMInputState{2, 1}, 1, 2, 6},
		{"package-lock", NPMInputState{1, 0}, NPMInputState{2, 1}, 2, 1, 1},
		{"both-absent", NPMInputState{1, 0}, NPMInputState{1, 0}, 0, 4, 7},
		{"package-unknown", NPMInputState{1, 0}, NPMInputState{0, 0}, 0, 3, 4},
		{"lower-unknown-retained", NPMInputState{2, 1}, NPMInputState{0, 2}, 1, 1, 1},
		{"lower-invalid-retained", NPMInputState{2, 1}, NPMInputState{2, 5}, 1, 1, 1},
	}
	for _, profile := range []string{"npm@8.19.4", "npm@10.9.4", "npm@11.6.2"} {
		for _, tc := range rows {
			t.Run(profile+"/"+tc.id, func(t *testing.T) {
				got, err := SelectNPMInput(profile, tc.s, tc.p)
				want := NPMInputSelection{profile, true, tc.s, tc.p, tc.c, tc.state, tc.d}
				if err != nil || got != want {
					t.Fatal("precedence, governing candidate or retained evidence lost")
				}
			})
		}
	}
}

func TestSelectNPMInputProfiles(t *testing.T) {
	profiles := []string{
		"", "auto", "npm", "npm@12.1.0", "npm@11.6.3", "NPM@11.6.2",
		" npm@11.6.2", "npm@11.6.2 ", "npm@11.6.2\n", "npm@11.6.2\x00",
		"npm@11.6.02", "npm@11.6", "npm@v11.6.2", "npm@11.6.2-rc.1",
		"npm@11.6.2+build", "bun@1.4.2", "yarn", "pnpm", "ｎｐｍ@11.6.2", "\xff\xfe",
		"https://user:PACKTRACE-SYNTHETIC-PRIVATE@invalid.example/profile",
		strings.Repeat("PACKTRACE-SYNTHETIC-OPAQUE", 1<<15),
	}
	for i, profile := range profiles {
		t.Run(fmt.Sprintf("opaque%d", i), func(t *testing.T) {
			s, p := NPMInputState{2, 1}, NPMInputState{2, 1}
			got, err := SelectNPMInput(profile, s, p)
			want := NPMInputSelection{profile, false, s, p, 0, 3, 2}
			if err != nil || got != want {
				t.Fatal("opaque profile was normalized/qualified or scalar evidence lost")
			}
		})
		for slot := range 2 {
			t.Run(fmt.Sprintf("opaque%d/bad-slot%d", i, slot), func(t *testing.T) {
				s, p := NPMInputState{2, 1}, NPMInputState{2, 1}
				if slot == 0 {
					s = NPMInputState{0, 1}
				} else {
					p = NPMInputState{1, 5}
				}
				got, err := SelectNPMInput(profile, s, p)
				assertNPMInputError(t, got, err)
			})
		}
	}
}

func TestSelectNPMInputCoherentPairs(t *testing.T) {
	states := []NPMInputState{{0, 0}, {0, 2}, {0, 3}, {1, 0}, {2, 0}, {2, 1}, {2, 2}, {2, 3}, {2, 4}, {2, 5}}
	// Fixed candidate/state/diagnostic triples for every coherent pair.
	// This literal matrix is independent of the production guard/decision.
	outcomes := [10][10]string{
		{"033", "033", "033", "033", "033", "033", "033", "033", "033", "033"},
		{"033", "033", "033", "033", "033", "033", "033", "033", "033", "033"},
		{"033", "033", "033", "033", "033", "033", "033", "033", "033", "033"},
		{"034", "034", "034", "047", "235", "211", "226", "226", "226", "226"},
		{"135", "135", "135", "135", "135", "135", "135", "135", "135", "135"},
		{"111", "111", "111", "111", "111", "111", "111", "111", "111", "111"},
		{"126", "126", "126", "126", "126", "126", "126", "126", "126", "126"},
		{"126", "126", "126", "126", "126", "126", "126", "126", "126", "126"},
		{"126", "126", "126", "126", "126", "126", "126", "126", "126", "126"},
		{"126", "126", "126", "126", "126", "126", "126", "126", "126", "126"},
	}
	for _, profile := range []string{"npm@8.19.4", "npm@10.9.4", "npm@11.6.2"} {
		for si, s := range states {
			for pi, p := range states {
				t.Run(fmt.Sprintf("%s/s%d/p%d", profile, si, pi), func(t *testing.T) {
					literal := outcomes[si][pi]
					want := NPMInputSelection{
						Profile: profile, ProfileQualified: true, Shrinkwrap: s, PackageLock: p,
						Candidate:  NPMInputCandidate(literal[0] - '0'),
						State:      NPMInputSelectionState(literal[1] - '0'),
						Diagnostic: NPMInputDiagnostic(literal[2] - '0'),
					}
					got, err := SelectNPMInput(profile, s, p)
					if err != nil || got != want {
						t.Fatal("coherent pair classification or retained state changed")
					}
				})
			}
		}
	}
}

func TestSelectNPMInputOwnership(t *testing.T) {
	t.Run("inputs-and-results", func(t *testing.T) {
		profile := "npm@11.6.2"
		s, p := NPMInputState{2, 1}, NPMInputState{0, 2}
		beforeS, beforeP := s, p
		want := NPMInputSelection{profile, true, s, p, 1, 1, 1}
		got, err := SelectNPMInput(profile, s, p)
		if err != nil || got != want || s != beforeS || p != beforeP {
			t.Fatal("initial owned value/evidence lost")
		}
		profile, s, p = "opaque", NPMInputState{}, NPMInputState{1, 0}
		if got != want {
			t.Fatal("saved result aliases reassigned caller scalars")
		}
		got.Profile, got.PackageLock, got.Candidate = "altered", NPMInputState{1, 0}, 2
		if profile != "opaque" || s != (NPMInputState{}) || p != (NPMInputState{1, 0}) {
			t.Fatal("result mutation changed caller scalars")
		}
		fresh, err := SelectNPMInput(want.Profile, beforeS, beforeP)
		if err != nil || fresh != want {
			t.Fatal("second call changed or lower-priority unknown evidence lost")
		}
	})
}

func TestSelectNPMInputSeparation(t *testing.T) {
	t.Run("source-purity", func(t *testing.T) {
		f, err := parser.ParseFile(token.NewFileSet(), "npm_input_selection.go", nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(f.Imports) != 0 {
			t.Fatal("pure decision must have no production imports")
		}
		for _, d := range f.Decls {
			if decl, ok := d.(*ast.GenDecl); ok && decl.Tok == token.VAR {
				t.Fatal("unexpected package mutable state")
			}
			if decl, ok := d.(*ast.FuncDecl); ok && decl.Name.Name == "init" {
				t.Fatal("unexpected package initialization")
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				id, ok := call.Fun.(*ast.Ident)
				if !ok || id.Name != "validNPMInputState" {
					t.Error("unexpected production call/printing/IO")
				}
			}
			return true
		})
	})
	t.Run("private-whole-zero", func(t *testing.T) {
		profile := "https://user:PACKTRACE-SYNTHETIC-PRIVATE@invalid.example/profile"
		got, err := SelectNPMInput(profile, NPMInputState{255, 0}, NPMInputState{2, 1})
		assertNPMInputError(t, got, err)
		if strings.Contains(err.Error(), "PACKTRACE-SYNTHETIC-PRIVATE") || strings.Contains(err.Error(), profile) {
			t.Fatal("raw caller text leaked into the fatal diagnostic")
		}
	})
}
