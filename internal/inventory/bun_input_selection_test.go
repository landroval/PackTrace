package inventory

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func assertBunInputError(t *testing.T, got BunInputSelection, err error) {
	t.Helper()
	pe, ok := err.(*ParseError)
	if !ok || pe == nil || pe.Code != "invalid-shape" || pe.Error() != "inventory: invalid-shape" {
		t.Fatal("expected the exact private invalid-shape ParseError")
	}
	if got != (BunInputSelection{}) {
		t.Fatal("fatal result was not whole-zero")
	}
}

func TestSelectBunInputCoherentPairs(t *testing.T) {
	// Ten literal valid states and outcomes from the approved presence/usability tables.
	states := []BunInputState{{0, 0}, {0, 2}, {0, 3}, {1, 0}, {2, 0}, {2, 1}, {2, 2}, {2, 3}, {2, 4}, {2, 5}}
	outcomes := [10][10]string{
		{"033", "033", "033", "033", "033", "033", "033", "033", "033", "033"},
		{"033", "033", "033", "033", "033", "033", "033", "033", "033", "033"},
		{"033", "033", "033", "033", "033", "033", "033", "033", "033", "033"},
		{"034", "034", "034", "049", "228", "228", "228", "228", "228", "228"},
		{"034", "034", "034", "136", "035", "035", "035", "035", "035", "035"},
		{"034", "034", "034", "111", "035", "035", "035", "035", "035", "035"},
		{"034", "034", "034", "127", "035", "035", "035", "035", "035", "035"},
		{"034", "034", "034", "127", "035", "035", "035", "035", "035", "035"},
		{"034", "034", "034", "127", "035", "035", "035", "035", "035", "035"},
		{"034", "034", "034", "127", "035", "035", "035", "035", "035", "035"},
	}
	profiles := []struct {
		text      string
		qualified bool
	}{
		{"bun@1.3.2", true}, {"bun@1.4.2", true}, {"", false},
	}
	for pi, profile := range profiles {
		for ti, text := range states {
			for bi, binary := range states {
				t.Run(fmt.Sprintf("p%d/t%d/b%d", pi, ti, bi), func(t *testing.T) {
					literal := outcomes[ti][bi]
					if !profile.qualified {
						literal = "032"
					}
					want := BunInputSelection{
						Profile: profile.text, ProfileQualified: profile.qualified,
						Text: text, Binary: binary,
						Candidate:  BunInputCandidate(literal[0] - '0'),
						State:      BunInputSelectionState(literal[1] - '0'),
						Diagnostic: BunInputDiagnostic(literal[2] - '0'),
					}
					got, err := SelectBunInput(profile.text, text, binary)
					if err != nil || got != want {
						t.Fatal("literal decision or retained scalar evidence changed")
					}
				})
			}
		}
	}
}

func TestSelectBunInputLayouts(t *testing.T) {
	valid := [3][6]bool{
		{true, false, true, true, false, false},
		{true, false, false, false, false, false},
		{true, true, true, true, true, true},
	}
	for pi, profile := range []string{"bun@1.3.2", "bun@1.4.2", ""} {
		for slot := range 2 {
			for presence := range 3 {
				for usability := range 6 {
					t.Run(fmt.Sprintf("p%d/slot%d/pres%d/use%d", pi, slot, presence, usability), func(t *testing.T) {
						text, binary := BunInputState{2, 1}, BunInputState{1, 0}
						state := BunInputState{BunInputPresence(presence), BunInputUsability(usability)}
						if slot == 0 {
							text = state
						} else {
							binary = state
						}
						got, err := SelectBunInput(profile, text, binary)
						if !valid[presence][usability] {
							assertBunInputError(t, got, err)
						} else if err != nil || got.Profile != profile || got.Text != text || got.Binary != binary || got.State == 0 || got.Diagnostic == 0 {
							t.Fatal("valid shape or retained classification lost")
						}
					})
				}
			}
			t.Run(fmt.Sprintf("p%d/slot%d/closed-enums", pi, slot), func(t *testing.T) {
				for presence := 3; presence <= 255; presence++ {
					text, binary := BunInputState{2, 1}, BunInputState{1, 0}
					bad := BunInputState{BunInputPresence(presence), 0}
					if slot == 0 {
						text = bad
					} else {
						binary = bad
					}
					got, err := SelectBunInput(profile, text, binary)
					assertBunInputError(t, got, err)
				}
				for usability := 6; usability <= 255; usability++ {
					text, binary := BunInputState{2, 1}, BunInputState{1, 0}
					bad := BunInputState{2, BunInputUsability(usability)}
					if slot == 0 {
						text = bad
					} else {
						binary = bad
					}
					got, err := SelectBunInput(profile, text, binary)
					assertBunInputError(t, got, err)
				}
			})
		}
	}
}

func TestSelectBunInputProfiles(t *testing.T) {
	profiles := []string{
		"", "auto", "bun", "bun@1.4.3", "bun@1.3.3", "BUN@1.4.2",
		" bun@1.4.2", "bun@1.4.2 ", "bun@1.4.2\n", "bun@1.4.2\x00",
		"bun@1.04.2", "bun@1.4", "bun@v1.4.2", "bun@1.4.2-rc.1",
		"bun@1.4.2+build", "npm@11.6.2", "yarn", "pnpm", "ｂｕｎ@1.4.2", "\xff\xfe",
		"https://user:PACKTRACE-SYNTHETIC-PRIVATE@invalid.example/profile",
		strings.Repeat("PACKTRACE-SYNTHETIC-OPAQUE", 1<<15),
	}
	for pi, profile := range profiles {
		t.Run(fmt.Sprintf("opaque%d", pi), func(t *testing.T) {
			text, binary := BunInputState{2, 1}, BunInputState{1, 0}
			got, err := SelectBunInput(profile, text, binary)
			want := BunInputSelection{profile, false, text, binary, 0, 3, 2}
			if err != nil || got != want {
				t.Fatal("opaque profile was normalized, qualified or lost")
			}
		})
		for slot := range 2 {
			t.Run(fmt.Sprintf("opaque%d/bad-slot%d", pi, slot), func(t *testing.T) {
				text, binary := BunInputState{2, 1}, BunInputState{1, 0}
				if slot == 0 {
					text = BunInputState{0, 1}
				} else {
					binary = BunInputState{1, 5}
				}
				got, err := SelectBunInput(profile, text, binary)
				assertBunInputError(t, got, err)
			})
		}
	}
}

func TestSelectBunInputSeparation(t *testing.T) {
	t.Run("source-purity", func(t *testing.T) {
		// Static call-boundary guard, not runtime network/native/producer proof.
		f, err := parser.ParseFile(token.NewFileSet(), "bun_input_selection.go", nil, 0)
		if err != nil {
			t.Fatal("owned source parse failed")
		}
		if len(f.Imports) != 0 {
			t.Fatal("pure decision gained production imports")
		}
		for _, d := range f.Decls {
			if decl, ok := d.(*ast.GenDecl); ok && decl.Tok == token.VAR {
				t.Fatal("package mutable state added")
			}
			if decl, ok := d.(*ast.FuncDecl); ok && decl.Name.Name == "init" {
				t.Fatal("package initialization added")
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.GoStmt, *ast.DeferStmt, *ast.FuncLit:
				t.Error("asynchronous/deferred/callback behavior added")
			case *ast.CallExpr:
				id, ok := node.Fun.(*ast.Ident)
				if !ok || id.Name != "validBunInputState" {
					t.Error("unexpected production call/printing/IO")
				}
			}
			return true
		})
	})
	t.Run("private-whole-zero", func(t *testing.T) {
		profile := "https://user:PACKTRACE-SYNTHETIC-PRIVATE@invalid.example/profile"
		got, err := SelectBunInput(profile, BunInputState{255, 0}, BunInputState{2, 1})
		assertBunInputError(t, got, err)
		if strings.Contains(err.Error(), "PACKTRACE-SYNTHETIC-PRIVATE") || strings.Contains(err.Error(), profile) {
			t.Fatal("private caller text leaked into the fatal diagnostic")
		}
	})
}
