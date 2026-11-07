package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestIntelligenceHelpNamesExplicitPreparationAndReadonlyScan(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want []string
	}{{[]string{"--help"}, []string{"intel sync", "intel import", "intel export", "intel status", "intel pin", "intel unpin", "cache prune"}}, {[]string{"scan", "--help"}, []string{"--state-dir", "--trusted-snapshot-digest", "never initializes", "bounded locked npm advisory matching"}}} {
		var out, diag bytes.Buffer
		if code := runMain(tc.args, forbiddenReader{}, &out, &diag); code != 0 || diag.Len() != 0 {
			t.Fatal("help executed action", code, diag.String())
		}
		for _, want := range tc.want {
			if !strings.Contains(out.String(), want) {
				t.Fatal("delivered command/help mismatch", want, out.String())
			}
		}
	}
}
