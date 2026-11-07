package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"packtrace/internal/integrityscan"
)

func TestScanExplicitOfflineCandidatesNeverBecomeFindings(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned native authored scan")
	}
	t.Parallel()
	for _, tc := range []struct {
		name, privacy string
		enabled       bool
	}{{"optout", "portable", false}, {"optin-portable", "portable", true}, {"optin-local", "local", true}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			target, policy, state, _, snapshotPin := matchingScanFixture(t, "1.0.0", false)
			lock := filepath.Join(target, "package-lock.json")
			raw, e := os.ReadFile(lock)
			if e != nil {
				t.Fatal(e)
			}
			raw = bytes.ReplaceAll(raw, []byte("https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz"), []byte("https://PRIVATE-user:PRIVATE-token@private.invalid/left-pad-1.0.0.tgz"))
			if e = os.WriteFile(lock, raw, 0600); e != nil {
				t.Fatal(e)
			}
			raw, e = os.ReadFile(policy)
			if e != nil {
				t.Fatal(e)
			}
			var p integrityscan.Policy
			if json.Unmarshal(raw, &p) != nil {
				t.Fatal("owned policy")
			}
			p.AdvisoryCandidates = tc.enabled
			raw, e = json.Marshal(p)
			if e != nil || os.WriteFile(policy, raw, 0600) != nil {
				t.Fatal("owned candidate policy", e)
			}
			digest := sha256.Sum256(raw)
			policyPin := "sha256-" + base64.StdEncoding.EncodeToString(digest[:])
			args := []string{"scan", "--policy", policy, "--trusted-policy-digest", policyPin, "--trusted-snapshot-digest", snapshotPin, "--state-dir", state, "--checks", "malicious", "--privacy", tc.privacy, "--format", "json", target}
			var out, diag bytes.Buffer
			if code := runMain(args, forbiddenReader{}, &out, &diag); code != 3 || diag.Len() != 0 {
				t.Fatal("candidate scan", code, diag.String())
			}
			for _, secret := range []string{"PRIVATE-user", "PRIVATE-token", target, policy, policyPin} {
				if strings.Contains(out.String(), secret) {
					t.Fatal("candidate disclosure")
				}
			}
			var report integrityscan.Report
			if e = json.Unmarshal(out.Bytes(), &report); e != nil || report.SchemaVersion != "1.7" || report.Advisories == nil || report.Advisories.State != "observed" {
				t.Fatal("candidate report", e)
			}
			a := report.Advisories
			if a.Findings != 0 || report.Findings != 0 {
				t.Fatal("candidate became finding", a.Findings, report.Findings)
			}
			candidates := 0
			for _, d := range a.Decisions {
				if d.EnforcementEligible || d.Outcome != "indeterminate" || d.Origin != "unqualified" || d.LockedObservation != 0 {
					t.Fatal("ambiguous origin gained authority", d)
				}
				if d.Candidate {
					candidates++
					if !tc.enabled || d.VersionOutcome != "match" || d.Activity != "not-withdrawn" || d.Profile == "unknown" {
						t.Fatal("invalid active candidate", d)
					}
				}
			}
			if tc.enabled {
				if candidates != 2 || a.Candidates != 2 || a.Summary.BytesRead == 0 {
					t.Fatal("expected locked and own-manifest candidates", candidates, a.Candidates, a.Summary)
				}
			} else if candidates != 0 || a.Candidates != 0 || a.Summary.BytesRead != 0 {
				t.Fatal("optout performed lookup", a)
			}
			if tc.privacy == "portable" && (bytes.Contains(out.Bytes(), []byte("left-pad")) || bytes.Contains(out.Bytes(), []byte("MAL-2026-1"))) {
				t.Fatal("private identity escaped portable mode")
			}
			if tc.privacy == "local" && (!bytes.Contains(out.Bytes(), []byte("left-pad")) || !bytes.Contains(out.Bytes(), []byte("MAL-2026-1"))) {
				t.Fatal("explicit local candidate is not actionable")
			}
		})
	}
}
