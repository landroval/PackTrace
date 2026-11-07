package main

import (
	"bytes"
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"packtrace/internal/integrityscan"
)

func TestScanExplainsFirstVersionBlockerWithoutChangingVerdict(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned native authored scan")
	}
	t.Parallel()
	for _, version := range []string{"1.0.0", "2.0.0"} {
		for _, privacy := range []string{"portable", "local"} {
			t.Run(version+"/"+privacy, func(t *testing.T) {
				t.Parallel()
				target, policy, state, policyPin, snapshotPin := matchingScanFixtureBundle(t, version, true, "explanation.bundle")
				args := []string{"scan", "--policy", policy, "--trusted-policy-digest", policyPin, "--trusted-snapshot-digest", snapshotPin, "--state-dir", state, "--checks", "malicious", "--privacy", privacy, "--format", "json", target}
				var out, diag bytes.Buffer
				code := runMain(args, forbiddenReader{}, &out, &diag)
				if code != 3 || diag.Len() != 0 || strings.Contains(out.String(), "PRIVATE") {
					t.Fatal("scan/private values", code, diag.String())
				}
				var report integrityscan.Report
				if e := json.Unmarshal(out.Bytes(), &report); e != nil || report.SchemaVersion != "1.7" || report.Advisories == nil || report.Advisories.State != "observed" {
					t.Fatal("explanation report", e)
				}
				observed := 0
				for _, d := range report.Advisories.Decisions {
					p := d.FirstVersionProblem
					if p == nil {
						continue
					}
					observed++
					if p.Scope != "affected" || p.Kind != "version-outside-profile" || p.Version != 1 || p.Range != -1 || p.Event != -1 || d.FullyEvaluated {
						t.Fatal("wrong first problem", d)
					}
					if version == "1.0.0" {
						if d.Outcome != "match" || !d.EnforcementEligible || len(d.Support) != 1 {
							t.Fatal("lost partial positive", d)
						}
					} else if d.Outcome != "indeterminate" || d.EnforcementEligible {
						t.Fatal("unsupported condition became negative", d)
					}
				}
				if observed != 1 {
					t.Fatal("unbound or missing diagnostic", observed)
				}
			})
		}
	}
}
