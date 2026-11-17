package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"packtrace/internal/integrityscan"
	"path/filepath"
	"reflect"
	"testing"
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
				before := wholeIntegrityTree(t, target)
				var portable integrityscan.Report
				for _, privacy := range []string{"portable", "local"} {
					t.Run(privacy, func(t *testing.T) {
						r, raw := runPolicyAcceptanceJSON(t, "--privacy", privacy, "--policy", policy, "--trusted-policy-digest", pp, "--trusted-snapshot-digest", sp, "--state-dir", state, "--checks", "malicious,vulnerability", "--fail-on", "malicious,vulnerability", "--format", "json", target)
						advisoryCompletenessIndependent(t, r, "operator-designated")
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
	r, raw := runPolicyAcceptanceJSON(t, "--policy", policy, "--trusted-policy-digest", pp, "--trusted-snapshot-digest", sp, "--state-dir", state, "--checks", "malicious,vulnerability", "--format", "json", target)
	advisoryCompletenessIndependent(t, r, "operator-designated")
	wholeIntegrityCoverage(t, r, "malicious", "incomplete")
	wholeIntegrityCoverage(t, r, "vulnerability", "incomplete")
	if r.Advisories == nil || r.Advisories.SelectedScope != nil {
		t.Fatalf("unroutable became absence: %s", raw)
	}
}
