package integrityscan

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPolicyReviewExposesCopyableProjectAndTypedEvidenceWithoutOrigin(t *testing.T) {
	m := engineMaterial()
	m.Scope.Origin = "https://PRIVATE-user:PRIVATE-secret@private.invalid/PRIVATE-resource"
	r := localPolicyReview(m)
	data, err := json.Marshal(r)
	if err != nil || r.Project != m.Scope.Project || r.RootManifestSHA256 != m.Project.ManifestSHA256 || r.SelectedLockSHA256 != m.Project.LockSHA256 || r.OriginalSHA256 != m.OriginalSHA256 || r.Advisory != m.Scope.Advisory || r.OriginFingerprint == "" {
		t.Fatalf("review material lost: %v %+v", err, r)
	}
	for _, forbidden := range []string{"PRIVATE", "private.invalid", "https://", "physicalTarget", "policyFile", "trustedPolicyDigest"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("local review leaked %q", forbidden)
		}
	}
}

func TestIntegrityExceptionIdentityDoesNotBorrowAdvisorySemverOrCaseRules(t *testing.T) {
	m := engineMaterial()
	m.Scope.Category, m.Scope.Rule, m.Scope.Class = "integrity", "integrity-drift", "installed"
	m.Scope.Path, m.Scope.Change, m.Scope.Advisory = "index.js", "modified", ""
	m.Scope.Package, m.Scope.Version, m.Scope.Origin = "PRIVATE-pkg", "owned-reference-revision", "fixture:private"
	if !scopeShape(m.Scope) || TrackingFingerprint(m) == "" {
		t.Fatal("exact bounded private integrity identity rejected as npm advisory")
	}
	first := TrackingFingerprint(m)
	m.Scope.Package = strings.ToLower(m.Scope.Package)
	if TrackingFingerprint(m) == first {
		t.Fatal("integrity identity was case-normalized")
	}
	m.Scope.Category, m.Scope.Rule, m.Scope.Advisory, m.Scope.Path, m.Scope.Change = "malicious", "osv-npm", "MAL-2026-1", "", ""
	if scopeShape(m.Scope) {
		t.Fatal("non-semver revision became an advisory version")
	}
}
