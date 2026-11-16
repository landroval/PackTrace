package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"packtrace/internal/integrityscan"
	"packtrace/internal/intel"
	"packtrace/internal/intelstore"
)

// The oracle is fullMatchingSourceRecords, not a completed flag or scanner output:
// npmfixture-0002 has one active malicious explicit 1.0.0 record;
// npmfixture-0003 has one active reviewed vulnerability [0,2.0.0) record.
// Neither has the extra withdrawn/corrected/unknown-source rows for 0001.
// left-pad has no record in full.bundle (only in matching.bundle).
// Completion here means the selected snapshot, never current knowledge or safety.
func TestScanAdvisoryCompletenessSelectedSnapshot(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned supervised native inputs; not platform qualification")
	}
	for _, tc := range []struct {
		name, pkg, version, category string
		findings                     int
	}{
		{"malicious-positive", "npmfixture-0002", "1.0.0", "malicious", 2},
		{"vulnerability-positive", "npmfixture-0003", "1.0.0", "vulnerability", 2},
		{"malicious-version-negative", "npmfixture-0002", "2.0.0", "malicious", 0},
		{"vulnerability-version-negative", "npmfixture-0003", "2.0.0", "vulnerability", 0},
		{"verified-snapshot-absence", "left-pad", "1.0.0", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target, policy, state, policyPin, snapshotPin := advisoryCompletenessFixture(t, tc.pkg, tc.version, "full.bundle", "")
			before := wholeIntegrityTree(t, target)
			if tc.category == "" {
				// Independently establish genuine absence in the imported original
				// index/catalog. The CLI's empty/placeholder decisions are no oracle.
				store, err := intelstore.Open(context.Background(), state, intelstore.ReadOnly)
				if err != nil {
					t.Fatal(err)
				}
				defer store.Close()
				snapshot, err := store.ReadPinned(context.Background(), nil)
				if err != nil {
					t.Fatal(err)
				}
				defer snapshot.Close()
				evidence, err := snapshot.ReadIdentity(context.Background(), tc.pkg)
				if err != nil || len(evidence.Records) != 0 || evidence.BlockState != intel.SnapshotStreamStructured || evidence.CatalogState != intel.SnapshotStreamStructured || evidence.Declaration != intel.SnapshotDeclarationVerified {
					t.Fatal("fixture does not prove selected-snapshot absence", evidence, err)
				}
			}
			var portable integrityscan.Report
			for _, privacy := range []string{"portable", "local"} {
				args := []string{"--policy", policy, "--trusted-policy-digest", policyPin,
					"--trusted-snapshot-digest", snapshotPin, "--state-dir", state, "--checks", "malicious,vulnerability",
					"--fail-on", "malicious,vulnerability", "--format", "json", target}
				if privacy == "local" {
					args = append([]string{"--privacy", "local"}, args...)
				}
				r, raw := runPolicyAcceptanceJSON(t, args...)
				if r.Privacy != privacy {
					t.Fatalf("privacy=%q want=%q", r.Privacy, privacy)
				}
				advisoryCompletenessIndependent(t, r, "operator-designated")
				a := r.Advisories
				if a == nil || a.State != "observed" || a.Summary.Observations != 1 || a.Summary.InstalledObservations != 1 || a.Findings != tc.findings || a.Candidates != 0 || r.Policy.EnforcedUnaccepted != tc.findings {
					t.Fatalf("selected scope/findings/enforcement not observed: %s", raw)
				}
				// Exactly the locked and associated installed observation are evaluated.
				// Absence must instead be justified by the admitted index/catalog, not
				// by pretending an empty decision list itself establishes completion.
				if tc.category != "" && len(a.Decisions) != 2 {
					t.Fatalf("decisions=%d want=2: %s", len(a.Decisions), raw)
				}
				classes := map[string]int{}
				for _, d := range a.Decisions {
					if tc.category == "" {
						if d.EnforcementEligible || d.Outcome == "match" || d.Candidate {
							t.Fatalf("absence manufactured finding/candidate: %+v", d)
						}
						continue
					}
					outcome := "no-match"
					if tc.findings != 0 {
						outcome = "match"
					}
					class := r.Inventory.Observations[d.Observation-1].Class
					classes[class]++
					if d.Category != tc.category || d.Outcome != outcome || d.VersionOutcome != outcome || !d.FullyEvaluated || d.Candidate || d.Source != "qualified" || d.Activity != "not-withdrawn" || d.EnforcementEligible != (tc.findings != 0) || class == "installed" && d.LockedObservation == 0 {
						t.Fatalf("original-based oracle mismatch: %+v", d)
					}
				}
				if tc.category != "" && (classes["locked"] != 1 || classes["installed"] != 1) {
					t.Fatal("locked/installed scope lost", classes)
				}
				advisoryCompletenessPrivacy(t, raw, privacy, target, policy, state, policyPin, snapshotPin)
				if privacy == "portable" {
					portable = r
				} else if !reflect.DeepEqual(portable.Advisories.Decisions, a.Decisions) || !reflect.DeepEqual(portable.Coverage, r.Coverage) || portable.Advisories.Findings != a.Findings || portable.Policy.EnforcedUnaccepted != r.Policy.EnforcedUnaccepted {
					t.Error("privacy changed decisions, coverage or enforcement")
				}
				// Deliberately checked after causal evidence: baseline RED must be
				// these assertions, not a missing source, panic or compile failure.
				wholeIntegrityCoverage(t, r, "inventory", "completed")
				wholeIntegrityCoverage(t, r, "malicious", "completed")
				wholeIntegrityCoverage(t, r, "vulnerability", "completed")
			}
			if !reflect.DeepEqual(before, wholeIntegrityTree(t, target)) {
				t.Error("scan changed owned target")
			}
		})
	}
}

func TestScanAdvisoryCompletenessConservative(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned supervised native inputs; not platform qualification")
	}
	for _, mode := range []string{"candidate-no-origin", "unqualified-generation", "withdrawn-corrected", "unknown-original-source", "unlocked-declaration", "unlocked-installed", "installed-manifest-missing", "missing-original", "corrupt-original"} {
		t.Run(mode, func(t *testing.T) {
			pkg, bundle := "npmfixture-0002", "full.bundle"
			if mode == "withdrawn-corrected" {
				pkg, bundle = "left-pad", "matching.bundle"
			}
			if mode == "unknown-original-source" {
				pkg = "npmfixture-0001"
			}
			target, policy, state, policyPin, snapshotPin := advisoryCompletenessFixture(t, pkg, "1.0.0", bundle, mode)
			before := wholeIntegrityTree(t, target)
			args := []string{"--policy", policy, "--trusted-policy-digest", policyPin, "--state-dir", state, "--checks", "malicious,vulnerability", "--fail-on", "malicious,vulnerability", "--format", "json", target}
			provenance := "unqualified"
			if mode != "unqualified-generation" {
				args = append([]string{"--trusted-snapshot-digest", snapshotPin}, args...)
				provenance = "operator-designated"
			}
			r, raw := runPolicyAcceptanceJSON(t, args...)
			advisoryCompletenessIndependent(t, r, provenance)
			if r.Advisories == nil || r.Advisories.State != "observed" {
				t.Fatalf("control did not reach matching: %s", raw)
			}
			wholeIntegrityCoverage(t, r, "malicious", "incomplete")
			if mode == "missing-original" || mode == "corrupt-original" {
				failed := 0
				for _, d := range r.Advisories.Decisions {
					for _, gap := range d.Gaps {
						if (gap == "identity-read-failed" || gap == "binding-unqualified") && d.Outcome == "indeterminate" && !d.EnforcementEligible {
							failed++
						}
					}
				}
				if failed != 2 || r.Advisories.Findings != 0 {
					t.Fatal("failed original lookup was not distinguished from snapshot absence", r.Advisories)
				}
			}
			// Unknown original category/source must not be discarded to complete
			// the other selected category without independent routing proof.
			if mode != "withdrawn-corrected" {
				wholeIntegrityCoverage(t, r, "vulnerability", "incomplete")
			}
			if mode == "candidate-no-origin" || mode == "unqualified-generation" {
				if r.Advisories.Findings != 0 || r.Policy.EnforcedUnaccepted != 0 {
					t.Error("unqualified evidence became enforceable")
				}
				for _, d := range r.Advisories.Decisions {
					if d.EnforcementEligible || d.Outcome != "indeterminate" {
						t.Errorf("unqualified decision promoted: %+v", d)
					}
				}
				if mode == "candidate-no-origin" && r.Advisories.Candidates != 2 {
					t.Error("candidate control did not actually look up locked and installed identities")
				}
			}
			if mode == "withdrawn-corrected" {
				withdrawn, corrected := false, false
				for _, d := range r.Advisories.Decisions {
					withdrawn = withdrawn || d.Activity == "withdrawn" && !d.EnforcementEligible
					corrected = corrected || d.VersionOutcome == "match" && d.Outcome == "indeterminate" && !d.EnforcementEligible
				}
				if !withdrawn || !corrected || r.Advisories.Findings != 2 || r.Policy.EnforcedUnaccepted != 2 {
					t.Error("withdrawal/correction lost or suppressed independent eligible finding")
				}
			}
			advisoryCompletenessPrivacy(t, raw, "portable", target, policy, state, policyPin, snapshotPin)
			if !reflect.DeepEqual(before, wholeIntegrityTree(t, target)) {
				t.Error("scan changed owned target")
			}
		})
	}
}

func advisoryCompletenessFixture(t *testing.T, pkg, version, bundle, mode string) (string, string, string, string, string) {
	t.Helper()
	target, policy, state, _, snapshotPin := matchingScanFixtureBundle(t, version, false, bundle)
	for _, name := range []string{"package.json", "package-lock.json", "node_modules/left-pad/package.json"} {
		path := filepath.Join(target, filepath.FromSlash(name))
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		raw = bytes.ReplaceAll(raw, []byte("left-pad"), []byte(pkg))
		if mode == "unlocked-declaration" && name == "package.json" {
			raw = bytes.Replace(raw, []byte(`"dependencies":{`), []byte(`"dependencies":{"PRIVATE-unlocked":"*",`), 1)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if pkg != "left-pad" {
		if err := os.Rename(filepath.Join(target, "node_modules/left-pad"), filepath.Join(target, "node_modules", pkg)); err != nil {
			t.Fatal(err)
		}
	}
	if mode == "installed-manifest-missing" {
		if err := os.Remove(filepath.Join(target, "node_modules", pkg, "package.json")); err != nil {
			t.Fatal(err)
		}
	}
	if mode == "unlocked-installed" {
		dir := filepath.Join(target, "node_modules/PRIVATE-extra")
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"PRIVATE-extra","version":"1.0.0"}`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if mode == "missing-original" || mode == "corrupt-original" {
		// Exact authored MAL-2026-3 original from fullMatchingSourceRecords;
		// the existing content-addressed store layout is not a new authority.
		const original = "6a9bb9b129de770646ebc2543f1d2a599352372f99496bb6660524147f984b91"
		path := filepath.Join(state, "objects", original[:2], original)
		var err error
		if mode == "missing-original" {
			err = os.Remove(path)
		} else {
			err = os.WriteFile(path, []byte("owned inert corrupt original"), 0600)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(policy)
	if err != nil {
		t.Fatal(err)
	}
	var p integrityscan.Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	p.RequiredChecks = []string{"malicious", "vulnerability"}
	p.NPMRegistry = "https://registry.npmjs.org"
	if mode == "candidate-no-origin" {
		p.NPMRegistry, p.AdvisoryCandidates = "", true
	}
	raw, err = json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policy, raw, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return target, policy, state, "sha256-" + base64.StdEncoding.EncodeToString(sum[:]), snapshotPin
}

func advisoryCompletenessIndependent(t *testing.T, r integrityscan.Report, provenance string) {
	t.Helper()
	if r.Intelligence == nil || r.Intelligence.State != "available" || r.Intelligence.Provenance != provenance || r.Intelligence.ID == "" {
		t.Fatal("source selection/authority not independently available", r.Intelligence)
	}
	// Imported October fixtures have no renewed local acquisition authority.
	// Their original check/reconciliation times must remain unknown or expired.
	if r.Intelligence.CheckAge == "current" || r.Intelligence.ReconciliationAge == "current" {
		t.Fatal("import or designation renewed historical freshness", r.Intelligence)
	}
	wholeIntegrityCoverage(t, r, "intelligence-access", "completed")
	wholeIntegrityCoverage(t, r, "intelligence-freshness", "incomplete")
	wholeIntegrityCoverage(t, r, "native-qualification", "incomplete")
	wholeIntegrityCoverage(t, r, "resident-observation", "incomplete")
}

func advisoryCompletenessPrivacy(t *testing.T, raw []byte, privacy string, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("absolute selector or authority pin leaked: %q", secret)
		}
	}
	// Local is opt-in identity disclosure, never raw originals, credentials or pins.
	for _, secret := range []string{"withdrawn_versions", "malicious-packages-origins", "PRIVATE-owned-case", "PRIVATE-authored-inert-source"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("private original/policy content leaked: %q", secret)
		}
	}
	if privacy == "portable" {
		for _, secret := range []string{"PRIVATE", "npmfixture-", "left-pad", "GHSA-", "MAL-2026-", "node_modules/", "registry.npmjs.org", "sha256-"} {
			if strings.Contains(string(raw), secret) {
				t.Errorf("portable identity leak: %q", secret)
			}
		}
	}
}
