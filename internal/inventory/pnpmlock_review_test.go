package inventory

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestPNPMReviewBoundsRepeatedProjectedScalars(t *testing.T) {
	var input strings.Builder
	input.WriteString(pnpmEmpty + "packages:\n  a@1.0.0:\n    resolution:\n      integrity: " + strings.Repeat("x", 64<<10) + "\nsnapshots:\n")
	for i := 0; i < 140; i++ {
		fmt.Fprintf(&input, "  a@1.0.0(peer@1.0.%d): {}\n", i)
	}
	if input.Len() > 1<<20 {
		t.Fatal("reproducer must fit raw input budget")
	}
	_, err := ParsePNPMLock([]byte(input.String()))
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Code != "limit-exceeded" {
		t.Fatalf("snapshot fan-out bypassed aggregate byte bound: %v", err)
	}
}

func TestPNPMReviewResolvedImporterPeerVersionsRemainUsable(t *testing.T) {
	for _, reference := range []string{"1.0.0", "actual@1.0.0", "actual@1.0.0(peer@2.0.0)"} {
		input := "lockfileVersion: '9.0'\nimporters:\n  .:\n    peerDependencies:\n      actual:\n        specifier: '*'\n        version: '" + reference + "'\n"
		p := pnpmProject(t, input)
		if len(p.Importers) != 1 || p.Importers[0].Unsupported {
			t.Fatalf("valid resolved peer reference refused: %s", reference)
		}
	}
}

func TestPNPMReviewExplicitSourceIDRemainsUnsupported(t *testing.T) {
	for _, body := range []string{
		"packages: {a@1.0.0: {id: 'git+https://example.invalid/repo'}}\nsnapshots: {a@1.0.0: {}}\n",
		"packages: {a@1.0.0: {}}\nsnapshots: {a@1.0.0: {id: 'git+https://example.invalid/repo'}}\n",
	} {
		p := pnpmProject(t, pnpmEmpty+body)
		if len(p.Records) != 1 || !p.Records[0].Unsupported || p.Records[0].Problem == "" {
			t.Fatalf("source claim discarded: %+v", p.Records)
		}
	}
}
