package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"packtrace/internal/integrityscan"
)

func TestScanPackageAndAdvisoryAliasesRemainIndependent(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned native authored scan")
	}
	t.Parallel()
	for _, mode := range []string{"alias-optout", "alias-local", "alias-portable", "public-control"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			target, policy, state, _, snapshotPin := matchingScanFixtureBundle(t, "1.0.0", false, "aliases.bundle")
			write := func(path string, v any) {
				raw, e := json.Marshal(v)
				if e != nil || os.WriteFile(path, raw, 0600) != nil {
					t.Fatal("owned fixture", e)
				}
			}
			alias := mode != "public-control"
			if alias {
				write(filepath.Join(target, "package.json"), map[string]any{"name": "owned-alias-root", "version": "1.0.0", "packageManager": "npm@10.9.4", "dependencies": map[string]string{"alias": "npm:left-pad@1.0.0"}})
				write(filepath.Join(target, "package-lock.json"), map[string]any{"lockfileVersion": 3, "packages": map[string]any{"": map[string]any{"name": "owned-alias-root", "version": "1.0.0", "dependencies": map[string]string{"alias": "npm:left-pad@1.0.0"}}, "node_modules/alias": map[string]any{"name": "left-pad", "version": "1.0.0", "resolved": "https://private.invalid/left-pad.tgz"}}})
				if e := os.Rename(filepath.Join(target, "node_modules/left-pad"), filepath.Join(target, "node_modules/alias")); e != nil {
					t.Fatal(e)
				}
			}
			raw, e := os.ReadFile(policy)
			if e != nil {
				t.Fatal(e)
			}
			var p integrityscan.Policy
			if json.Unmarshal(raw, &p) != nil {
				t.Fatal("owned policy")
			}
			p.AdvisoryCandidates = mode != "alias-optout"
			if !alias {
				p.NPMRegistry = "https://registry.npmjs.org"
			}
			write(policy, p)
			raw, e = os.ReadFile(policy)
			if e != nil {
				t.Fatal(e)
			}
			sum := sha256.Sum256(raw)
			pin := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
			privacy := "local"
			if mode == "alias-portable" || mode == "alias-optout" {
				privacy = "portable"
			}
			var out, diag bytes.Buffer
			code := runMain([]string{"scan", "--policy", policy, "--trusted-policy-digest", pin, "--trusted-snapshot-digest", snapshotPin, "--state-dir", state, "--checks", "malicious", "--privacy", privacy, "--format", "json", target}, forbiddenReader{}, &out, &diag)
			if code != 3 || diag.Len() != 0 {
				t.Fatal("actual alias scan", code, diag.String())
			}
			var report integrityscan.Report
			if json.Unmarshal(out.Bytes(), &report) != nil || report.Advisories == nil || report.Advisories.State != "observed" {
				t.Fatal("alias report")
			}
			a := report.Advisories
			if a.Summary.Observations != 1 || a.Summary.TotalObservations != 1 || a.Summary.InstalledObservations != 1 || a.Summary.TotalInstalledObservations != 1 {
				t.Fatal("alias lock or installed observation disappeared", a.Summary)
			}
			if mode == "alias-optout" {
				if a.Candidates != 0 || a.Findings != 0 || a.Summary.BytesRead != 0 || len(a.Decisions) != 2 {
					t.Fatal("alias optout lookup", a)
				}
				return
			}
			positive, negative, lockedUnknown := 0, 0, 0
			ids := map[int]bool{}
			perClass := map[[2]string]int{}
			localOrigins := map[int]integrityscan.LocalAdvisory{}
			localObservations := map[uint32]integrityscan.LocalObservation{}
			if privacy == "local" {
				if a.Local == nil || len(a.Local.Advisories) != 2 {
					t.Fatal("missing bound original identities")
				}
				expectedHashes := map[string]string{"MAL-2026-51": "de8ac282823a0850a2e084549d40ad9430abe0f22f07c74faf0a2e9cedd6d7bf", "MAL-2026-52": "ec60d5917e1e0e9bdafdc98c2acb73a8919a3ad429175f9c4c3d1ec4f8bb7a91"}
				for _, original := range a.Local.Advisories {
					if expectedHashes[original.ID] != original.SHA256 {
						t.Fatal("original provenance was merged", original.ID)
					}
					localOrigins[original.Advisory] = original
				}
				for _, observation := range a.Local.Observations {
					localObservations[observation.Observation] = observation
				}
			}
			observations := map[uint32]string{}
			for _, o := range report.Inventory.Observations {
				observations[o.ID] = o.Class
			}
			for _, d := range a.Decisions {
				if alias && observations[d.Observation] == "locked" {
					lockedUnknown++
					originGap := false
					for _, gap := range d.Gaps {
						originGap = originGap || gap == "origin-unqualified"
					}
					if d.Advisory != 0 || d.Candidate || d.Outcome != "indeterminate" || d.EnforcementEligible || !originGap {
						t.Fatal("locked alias reinterpreted", d)
					}
					continue
				}
				if d.Advisory == 0 {
					continue
				}
				ids[d.Advisory] = true
				perClass[[2]string{observations[d.Observation], d.VersionOutcome}]++
				if !d.FullyEvaluated || d.VersionOutcome == "match" && (len(d.Support) != 1 || d.Support[0].Version != 0 || d.Support[0].Range != -1) || d.VersionOutcome == "no-match" && len(d.Support) != 0 {
					t.Fatal("original condition support was borrowed", d)
				}
				if privacy == "local" {
					original := localOrigins[d.Advisory]
					want := map[string]string{"MAL-2026-51": "match", "MAL-2026-52": "no-match"}[original.ID]
					if want == "" || d.VersionOutcome != want {
						t.Fatal("outcome no longer belongs to bound original", original.ID, d)
					}
					if alias && d.Candidate {
						observation := localObservations[d.Observation]
						if observation.Name != "left-pad" || observation.Location != "node_modules/alias" || observations[d.Observation] != "installed" {
							t.Fatal("candidate lost its own alias-slot manifest", d.Observation)
						}
					}
				}
				if d.VersionOutcome == "match" {
					positive++
					if alias && (!d.Candidate || d.Outcome != "indeterminate" || d.EnforcementEligible || d.Origin != "unqualified" || d.LockedObservation != 0) {
						t.Fatal("own-manifest alias candidate missing or promoted", d)
					}
				}
				if d.VersionOutcome == "no-match" {
					negative++
					if d.Candidate || alias && d.Outcome != "indeterminate" || !alias && d.Outcome != "no-match" {
						t.Fatal("alias range was merged", d)
					}
				}
			}
			expected := 1
			if !alias {
				expected = 2
			}
			if len(ids) != 2 || positive != expected || negative != expected {
				t.Fatal("distinct originals/conditions lost", len(ids), positive, negative)
			}
			for _, class := range []string{"locked", "installed"} {
				want := 1
				if alias && class == "locked" {
					want = 0
				}
				if perClass[[2]string{class, "match"}] != want || perClass[[2]string{class, "no-match"}] != want {
					t.Fatal("per-original conditions mixed between observation classes", class, perClass)
				}
			}
			if alias {
				if lockedUnknown != 1 {
					t.Fatal("required indeterminate alias lock row missing", lockedUnknown)
				}
				if a.Candidates != 1 || a.Findings != 0 {
					t.Fatal("candidate/finding alias counts", a.Candidates, a.Findings)
				}
				if privacy != "local" && (bytes.Contains(out.Bytes(), []byte("left-pad")) || bytes.Contains(out.Bytes(), []byte("node_modules/alias")) || bytes.Contains(out.Bytes(), []byte("MAL-2026-5"))) {
					t.Fatal("portable alias disclosure")
				}
			} else if a.Findings != 2 || a.Candidates != 0 {
				t.Fatal("qualified originals were merged", a.Findings, a.Candidates)
			}
		})
	}
}
