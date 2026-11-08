package integrityscan

import (
	"bytes"
	"regexp"
	"testing"
	"time"
)

func TestTerminalColorPreservesValidatedPlainEvidence(t *testing.T) {
	for _, privacy := range []string{"local", "portable"} {
		plan, inv, info, a := candidateReportFixture(t, privacy)
		r := BuildReportWithPolicy(plan, nil, Summary{}, Resources{}, false, false, &inv, &info, &a, nil, false, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
		plain, err := Render(r, "terminal")
		if err != nil {
			t.Fatal(err)
		}
		before, err := Render(r, "json")
		if err != nil {
			t.Fatal(err)
		}
		color, err := Render(r, "terminal-color")
		if err != nil {
			t.Fatal("validated color view missing", err)
		}
		ansi := regexp.MustCompile(`\x1b\[[0-9;]*m`)
		if !bytes.Contains(color, []byte("\x1b[")) || !bytes.Equal(ansi.ReplaceAll(color, nil), plain) {
			t.Fatal("color changed labels/evidence")
		}
		if !bytes.Contains(color, []byte("\x1b[1;32m")) || !bytes.Contains(color, []byte("\x1b[1;35m")) || !bytes.Contains(color, []byte("\x1b[37m")) {
			t.Fatal("scoped OK/review/not-run states not distinguished")
		}
		for _, line := range bytes.Split(color, []byte("\n")) {
			if bytes.Contains(line, []byte("\x1b[1;32m")) && (!bytes.Contains(line, []byte("[OK]")) || bytes.Contains(line, []byte("eligible match rows")) || bytes.Contains(line, []byte("Candidate rows"))) {
				t.Fatal("green used for an unsupported safety conclusion", string(line))
			}
		}
		if privacy == "portable" && (bytes.Contains(color, []byte("left-pad")) || bytes.Contains(color, []byte("MAL-2026-1"))) {
			t.Fatal("color bypassed privacy")
		}
		after, err := Render(r, "json")
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("color changed JSON")
		}
		r.Policy = nil
		if _, err := Render(r, "terminal-color"); err == nil {
			t.Fatal("color bypassed frozen authority")
		}
	}
}
