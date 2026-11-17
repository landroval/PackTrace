package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"packtrace/internal/integrityscan"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"packtrace/internal/intel"
	"packtrace/internal/intelstore"
)

// Run explicitly with externally authored inert bundles from
// TestConstructionScaleBundles. These tests exercise the actual supervised CLI,
// not a synthetic receipt. No producer, sockets or live source is involved.
func TestScanAdvisoryScale(t *testing.T) {
	dir := os.Getenv("PACKTRACE_SCALE_FIXTURES")
	if dir == "" {
		t.Skip("explicit owned scale fixture directory required")
	}
	for _, count := range []int{1105, 4105} {
		for _, tc := range []struct {
			name, pkg, version string
			findings           int
		}{
			{"malicious", "npmfixture-0002", "1.0.0", 2},
			{"vulnerability", "npmfixture-0003", "1.0.0", 2},
			{"version-negative", "npmfixture-0003", "2.0.0", 0},
			{"malicious-version-negative", "npmfixture-0002", "2.0.0", 0},
			{"no-known-record", "left-pad", "1.0.0", 0},
		} {
			t.Run(fmt.Sprintf("%d/%s", count, tc.name), func(t *testing.T) {
				target, policy, state, pp, sp := advisoryCompletenessFixture(t, tc.pkg, tc.version, filepath.Join(dir, fmt.Sprintf("scale-%d-false.bundle", count)), "")
				assertScaleOriginalCatalog(t, state, count, tc.pkg)
				before := wholeIntegrityTree(t, target)
				var portable integrityscan.Report
				for _, privacy := range []string{"portable", "local"} {
					t.Run(privacy, func(t *testing.T) {
						r, raw := runPolicyAcceptanceJSON(t, "--privacy", privacy, "--policy", policy, "--trusted-policy-digest", pp, "--trusted-snapshot-digest", sp, "--state-dir", state, "--checks", "malicious,vulnerability", "--fail-on", "malicious,vulnerability", "--format", "json", target)
						advisoryCompletenessIndependent(t, r, "operator-designated")
						assertScaleDecisionOracle(t, r, tc.pkg, tc.findings)
						advisoryCompletenessPrivacy(t, raw, privacy, target, policy, state, pp, sp)
						if r.Privacy != privacy || r.Advisories == nil || r.Advisories.Findings != tc.findings || r.Policy.EnforcedUnaccepted != tc.findings {
							t.Fatalf("findings/privacy/enforcement: %s", raw)
						}
						wholeIntegrityCoverage(t, r, "malicious", "completed")
						wholeIntegrityCoverage(t, r, "vulnerability", "completed")
						a := r.Advisories
						if a.SelectedScope == nil || a.ScopeAttempt == nil {
							t.Fatalf("no scope: %s", raw)
						}
						// Catalog/metadata + selected blocks/originals + replay all count.
						if a.ScopeAttempt.Work > 32 || a.ScopeAttempt.BytesRead > 4<<20 || a.ScopeAttempt.BytesRead+a.Summary.BytesRead > integrityscan.MaxAdvisoryReadBytes {
							t.Fatalf("whole-corpus cost: %+v", a.ScopeAttempt)
						}
						if privacy == "portable" {
							portable = r
						} else if !reflect.DeepEqual(portable.Advisories.Decisions, r.Advisories.Decisions) || !reflect.DeepEqual(portable.Advisories.Summary, r.Advisories.Summary) || !reflect.DeepEqual(portable.Advisories.SelectedScope, r.Advisories.SelectedScope) || !reflect.DeepEqual(portable.Advisories.ScopeAttempt, r.Advisories.ScopeAttempt) || !reflect.DeepEqual(portable.Coverage, r.Coverage) {
							t.Fatal("privacy changed admitted comparison")
						}
						t.Logf("catalog=%d attemptBytes=%d attemptWork=%d matchingBytes=%d matchingWork=%d", count, a.ScopeAttempt.BytesRead, a.ScopeAttempt.Work, a.Summary.BytesRead, a.Summary.Work)
					})
				}
				if !reflect.DeepEqual(before, wholeIntegrityTree(t, target)) {
					t.Fatal("scan modified target")
				}
			})
		}
	}
}

func TestScanAdvisoryScaleBun(t *testing.T) {
	dir := os.Getenv("PACKTRACE_SCALE_FIXTURES")
	if dir == "" {
		t.Skip("explicit owned scale fixture directory required")
	}
	for _, pkg := range []string{"npmfixture-0002", "npmfixture-0003"} {
		t.Run(pkg, func(t *testing.T) {
			target, policy, state, _, sp := advisoryCompletenessFixture(t, pkg, "1.0.0", filepath.Join(dir, "scale-4105-false.bundle"), "")
			assertScaleOriginalCatalog(t, state, 4105, pkg)
			if err := os.Remove(filepath.Join(target, "package-lock.json")); err != nil {
				t.Fatal(err)
			}
			write := func(path string, value any) []byte {
				t.Helper()
				raw, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				return raw
			}
			deps := map[string]string{pkg: "1.0.0"}
			write(filepath.Join(target, "package.json"), map[string]any{"name": "PRIVATE-root", "packageManager": "bun@1.3.0", "dependencies": deps})
			write(filepath.Join(target, "bun.lock"), map[string]any{"lockfileVersion": 1, "workspaces": map[string]any{"": map[string]any{"dependencies": deps}}, "packages": map[string]any{pkg: []any{pkg + "@1.0.0", "", map[string]any{}, "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}}})
			raw, err := os.ReadFile(policy)
			if err != nil {
				t.Fatal(err)
			}
			var p integrityscan.Policy
			if err := json.Unmarshal(raw, &p); err != nil {
				t.Fatal(err)
			}
			p.Manager, p.NPMRegistry, p.NPMOrigins = "bun@1.3.x", "", nil
			p.BunOrigins = []integrityscan.BunOriginRule{{Location: pkg, Name: pkg, Version: "1.0.0", Origin: "https://registry.npmjs.org/" + pkg + "/-/" + pkg + "-1.0.0.tgz"}}
			sum := sha256.Sum256(write(policy, p))
			pp := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
			before := wholeIntegrityTree(t, target)
			for _, privacy := range []string{"portable", "local"} {
				r, raw := runPolicyAcceptanceJSON(t, "--privacy", privacy, "--policy", policy, "--trusted-policy-digest", pp, "--trusted-snapshot-digest", sp, "--state-dir", state, "--checks", "malicious,vulnerability", "--fail-on", "malicious,vulnerability", "--format", "json", target)
				advisoryCompletenessIndependent(t, r, "operator-designated")
				assertScaleDecisionOracle(t, r, pkg, 2)
				advisoryCompletenessPrivacy(t, raw, privacy, target, policy, state, pp, sp)
				if r.Advisories == nil || r.Advisories.Findings != 2 || r.Policy.EnforcedUnaccepted != 2 {
					t.Fatalf("Bun findings: %s", raw)
				}
				wholeIntegrityCoverage(t, r, "malicious", "completed")
				wholeIntegrityCoverage(t, r, "vulnerability", "completed")
			}
			if !reflect.DeepEqual(before, wholeIntegrityTree(t, target)) {
				t.Fatal("Bun scan modified target")
			}
		})
	}
}

func TestScanAdvisoryScaleUnroutable(t *testing.T) {
	dir := os.Getenv("PACKTRACE_SCALE_FIXTURES")
	if dir == "" {
		t.Skip("explicit owned scale fixture directory required")
	}
	target, policy, state, pp, sp := advisoryCompletenessFixture(t, "npmfixture-0002", "1.0.0", filepath.Join(dir, "scale-4105-true.bundle"), "")
	assertScaleOriginalCatalog(t, state, 4105, "npmfixture-0002")
	before := wholeIntegrityTree(t, target)
	r, raw := runPolicyAcceptanceJSON(t, "--policy", policy, "--trusted-policy-digest", pp, "--trusted-snapshot-digest", sp, "--state-dir", state, "--checks", "malicious,vulnerability", "--format", "json", target)
	advisoryCompletenessIndependent(t, r, "operator-designated")
	wholeIntegrityCoverage(t, r, "malicious", "incomplete")
	wholeIntegrityCoverage(t, r, "vulnerability", "incomplete")
	if r.Advisories == nil || r.Advisories.SelectedScope != nil {
		t.Fatalf("unroutable became absence: %s", raw)
	}
	if !reflect.DeepEqual(before, wholeIntegrityTree(t, target)) {
		t.Fatal("unroutable scan modified target")
	}
}

// ReadPinned verifies actual catalog bytes, row cardinality, digest and length;
// filenames and generation declarations alone are not this size oracle.
func assertScaleOriginalCatalog(t *testing.T, state string, count int, pkg string) {
	t.Helper()
	ctx := context.Background()
	store, err := intelstore.Open(ctx, state, intelstore.ReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	snapshot, err := store.ReadPinned(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	observation, err := snapshot.Observe(ctx, time.Now(), nil)
	if err != nil || observation.Records != uint64(count) {
		t.Fatalf("verified catalog records=%d want=%d err=%v", observation.Records, count, err)
	}
	evidence, err := snapshot.ReadIdentity(ctx, pkg)
	if err != nil || evidence.BlockState != intel.SnapshotStreamStructured || evidence.CatalogState != intel.SnapshotStreamStructured || evidence.Declaration != intel.SnapshotDeclarationVerified {
		t.Fatal("original index/catalog unavailable", err)
	}
	if pkg == "left-pad" {
		if len(evidence.Records) != 0 {
			t.Fatal("authored snapshot absence not observed")
		}
		return
	}
	id := "MAL-2026-3"
	if pkg == "npmfixture-0003" {
		id = "GHSA-2225-2345-6789"
	}
	if len(evidence.Records) != 1 || evidence.Records[0].Header.ID.Value != id {
		t.Fatal("wrong authored selected original", pkg)
	}
}

func assertScaleDecisionOracle(t *testing.T, r integrityscan.Report, pkg string, findings int) {
	t.Helper()
	if r.Advisories == nil || r.Inventory == nil {
		t.Fatal("missing actual observations/decisions")
	}
	category, outcome := "malicious", "no-match"
	if pkg == "npmfixture-0003" {
		category = "vulnerability"
	}
	if findings != 0 {
		outcome = "match"
	}
	classes := map[string]int{}
	for _, d := range r.Advisories.Decisions {
		if d.Observation == 0 || int(d.Observation) > len(r.Inventory.Observations) {
			t.Fatal("bad observation join", d)
		}
		o := r.Inventory.Observations[d.Observation-1]
		if o.Class == "locked" && o.Kind == "workspace" && d.Advisory == 0 && d.Outcome == "indeterminate" && len(d.Gaps) == 2 && !d.EnforcementEligible {
			continue
		}
		classes[o.Class]++
		if pkg == "left-pad" {
			if d.Advisory != 0 || d.Outcome != "indeterminate" || d.EnforcementEligible || d.Candidate || len(d.Gaps) != 1 || d.Gaps[0] != "identity-empty" {
				t.Fatal("absence manufactured evaluation", d)
			}
			continue
		}
		if d.Category != category || d.Outcome != outcome || d.VersionOutcome != outcome || !d.FullyEvaluated || d.Candidate || d.Source != "qualified" || d.Activity != "not-withdrawn" || d.EnforcementEligible != (findings != 0) || o.Class == "installed" && d.LockedObservation == 0 {
			t.Fatal("category/version/original association oracle", d)
		}
	}
	if classes["locked"] != 1 || classes["installed"] != 1 || len(classes) != 2 {
		t.Fatal("locked/installed scope not exact", classes)
	}
}
