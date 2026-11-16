package integrityscan

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"packtrace/internal/cli"
	lockinventory "packtrace/internal/inventory"
	"packtrace/internal/nativefs"
	"testing"

	"packtrace/internal/projectinventory"
)

func bunEligibleFixture(t *testing.T, info Intelligence) (Plan, matchingFixture) {
	t.Helper()
	f := matchingInstalledFixture()
	f.inv.Selection.Family, f.inv.Selection.Profile, f.inv.Selection.File = "bun", "bun@1.3.x", "bun.lock"
	f.inv.Model.Evidence[0].Location = "bun.lock"
	f.inv.Model.Evidence[0].SHA256 = sha256.Sum256([]byte("original bun.lock"))
	f.inv.Model.Evidence[2].SHA256 = sha256.Sum256([]byte("original installed manifest"))
	f.inv.Model.Evidence = append(f.inv.Model.Evidence, projectinventory.Evidence{ID: 4, Scope: 1, Location: "package.json", Method: "native-input-lease", Complete: true, SHA256: sha256.Sum256([]byte("original root manifest"))})
	o := &f.inv.Model.Observations[0]
	o.Kind, o.Location, o.Origin = "package", "left-pad", ""
	o.Fields = map[string]string{"name-state": "value", "resolution-state": "value", "registry-state": "value", "integrity-state": "value", "integrity": "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==", "tuple-key": "left-pad", "git-tag": "", "matching-context": "supported"}
	f.inv.Model.Relations[0].Kind, f.inv.Model.Relations[0].Status = "candidate-correspondence", "indeterminate"
	p := matchingPinnedPlan(t, info)
	p.Manager, p.Policy.Manager, p.Policy.NPMOrigins = "bun@1.3.x", "bun@1.3.x", nil
	p.Policy.BunOrigins = []BunOriginRule{{Location: "left-pad", Name: "left-pad", Version: "1.0.0", Origin: npmTarballOrigin("left-pad", "1.0.0"), Registry: ""}}
	return p, f
}

func TestBunEligibleExactNewGrant(t *testing.T) {
	snapshot, info := matchingSnapshot(t)
	p, f := bunEligibleFixture(t, info)
	var rows []AdvisoryDecision
	s, err := MatchInventory(context.Background(), p, f.inv, snapshot, info, matchingNow, func(d AdvisoryDecision) error { rows = append(rows, d); return nil })
	if err != nil {
		t.Fatal(err)
	}
	positives := 0
	for _, d := range rows {
		if d.EnforcementEligible {
			positives++
		}
		if d.Origin != "operator-bun-rule" || d.Rule != 1 || d.Candidate {
			t.Fatal("exact Bun grant not used", d)
		}
		if d.Observation == 2 && d.LockedObservation != 1 {
			t.Fatal("installed join", d)
		}
		if err := ValidateAdvisoryDecision(p, projectinventory.PortableMatching(f.inv), info, d); err != nil {
			t.Fatal("parent", d, err)
		}
	}
	if positives != 2 {
		t.Fatal("expected locked and installed malicious matches", positives, rows)
	}
	if err := ValidateAdvisorySummary(s, rows, projectinventory.PortableMatching(f.inv)); err != nil {
		t.Fatal(err)
	}
}

func TestBunEligibilityRefusesAmbiguousEvidence(t *testing.T) {
	_, info := matchingSnapshot(t)
	for _, tc := range []struct {
		name          string
		installedOnly bool
		mutate        func(*Plan, *matchingFixture)
	}{
		{"old-bun-pin", false, func(p *Plan, _ *matchingFixture) { p.Policy.BunOrigins = nil }},
		{"candidate-only-pin", false, func(p *Plan, _ *matchingFixture) { p.Policy.BunOrigins = nil; p.Policy.AdvisoryCandidates = true }},
		{"no-pin", false, func(p *Plan, _ *matchingFixture) { p.TrustedPolicyDigest = "" }},
		{"wrong-version-grant", false, func(p *Plan, _ *matchingFixture) {
			p.Policy.BunOrigins[0].Version = "2.0.0"
			p.Policy.BunOrigins[0].Origin = npmTarballOrigin("left-pad", "2.0.0")
		}},
		{"private-source", false, func(_ *Plan, f *matchingFixture) {
			f.inv.Model.Observations[0].Origin = "https://private.invalid/pkg.tgz"
		}},
		{"default-is-not-explicit-source", false, func(p *Plan, _ *matchingFixture) { p.Policy.BunOrigins[0].Registry = p.Policy.BunOrigins[0].Origin }},
		{"alias-tuple", false, func(_ *Plan, f *matchingFixture) { f.inv.Model.Observations[0].Fields["tuple-key"] = "alias" }},
		{"nested-context", false, func(_ *Plan, f *matchingFixture) { f.inv.Model.Observations[0].Location = "parent/left-pad" }},
		{"peer", false, func(_ *Plan, f *matchingFixture) {
			f.inv.Model.Observations[0].Requirements = []lockinventory.DependencyGroup{{Name: "peerDependencies", State: lockinventory.FieldValue, Entries: []lockinventory.DeclaredDependency{{Name: "peer", Requirement: "1.0.0", State: lockinventory.FieldValue}}}}
		}},
		{"alias-declaration", false, func(_ *Plan, f *matchingFixture) {
			f.inv.Model.Observations[0].Requirements = []lockinventory.DependencyGroup{{Name: "dependencies", State: lockinventory.FieldValue, Entries: []lockinventory.DeclaredDependency{{Name: "alias", Requirement: "npm:left-pad@1.0.0", State: lockinventory.FieldValue}}}}
		}},
		{"workspace", false, func(_ *Plan, f *matchingFixture) {
			f.inv.Model.Scopes = append(f.inv.Model.Scopes, projectinventory.Scope{ID: 2, Parent: 1, Kind: "workspace"})
		}},
		{"context-info", false, func(_ *Plan, f *matchingFixture) { f.inv.Model.Observations[0].Fields["os"] = `"linux"` }},
		{"original-context-missing", false, func(_ *Plan, f *matchingFixture) { delete(f.inv.Model.Observations[0].Fields, "matching-context") }},
		{"original-context-unsupported", false, func(_ *Plan, f *matchingFixture) {
			f.inv.Model.Observations[0].Fields["matching-context"] = "unsupported"
		}},
		{"unknown-kind", false, func(_ *Plan, f *matchingFixture) { f.inv.Model.Observations[0].Kind = "unknown" }},
		{"duplicate-name", false, func(_ *Plan, f *matchingFixture) {
			o := f.inv.Model.Observations[0]
			o.ID = 3
			f.inv.Model.Observations = append(f.inv.Model.Observations, o)
		}},
		{"selected-lock-incomplete", false, func(_ *Plan, f *matchingFixture) { f.inv.Model.Evidence[0].Complete = false }},
		{"selected-lock-wrong-location", false, func(_ *Plan, f *matchingFixture) { f.inv.Model.Evidence[0].Location = "other.lock" }},
		{"root-original-missing", false, func(_ *Plan, f *matchingFixture) { f.inv.Model.Evidence[3].Complete = false }},
		{"dropped-requirement", false, func(_ *Plan, f *matchingFixture) {
			f.inv.Model.Gaps = []projectinventory.Gap{{Code: "requirement-limit"}}
		}},
		{"native-manifest-conflict", true, func(_ *Plan, f *matchingFixture) { f.inv.Model.Observations[1].Version = "2.0.0" }},
		{"native-alias", true, func(_ *Plan, f *matchingFixture) { f.inv.Model.Observations[1].Fields["installation-name"] = "alias" }},
		{"native-link", true, func(_ *Plan, f *matchingFixture) { f.inv.Model.Observations[1].Kind = "link" }},
		{"missing-metadata", true, func(_ *Plan, f *matchingFixture) { f.inv.Model.Evidence[1].Complete = false }},
		{"missing-manifest", true, func(_ *Plan, f *matchingFixture) { f.inv.Model.Evidence[2].Complete = false }},
		{"wrong-manifest-path", true, func(_ *Plan, f *matchingFixture) {
			f.inv.Model.Evidence[2].Location = "node_modules/other/package.json"
		}},
		{"missing-relation", true, func(_ *Plan, f *matchingFixture) { f.inv.Model.Relations = nil }},
		{"duplicate-relation", true, func(_ *Plan, f *matchingFixture) {
			f.inv.Model.Relations = append(f.inv.Model.Relations, f.inv.Model.Relations[0])
		}},
		{"wrong-relation-witness", true, func(_ *Plan, f *matchingFixture) { f.inv.Model.Relations[0].Evidence = 2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, f := bunEligibleFixture(t, info)
			tc.mutate(&p, &f)
			got := indexedMatchingOrigins(p, f.inv)
			if _, ok := got[2]; ok {
				t.Fatal("ambiguous installed authority", got)
			}
			if !tc.installedOnly && len(got) != 0 {
				t.Fatal("ambiguous locked authority", got)
			}
		})
	}
}

func TestBunOriginPolicyStrictPinnedAndNonUpgrade(t *testing.T) {
	p, _ := bunEligibleFixture(t, UnavailableIntelligence())
	raw, err := json.Marshal(p.Policy)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePolicy(raw)
	if err != nil || !reflect.DeepEqual(parsed, p.Policy) {
		t.Fatal("roundtrip", err)
	}
	for _, tc := range []struct{ old, new string }{
		{`"bunOrigins":[`, `"BunOrigins":[`},
		{`"bunOrigins":[`, `"bunOrigins":null,"ignored":[`},
		{`"bunOrigins":[`, `"bunOrigins":[],"bunOrigins":[`},
		{`"registry":""`, `"registry":null`},
		{`"registry":""`, `"registry":"","Registry":""`},
		{`"registry":""`, `"registry":"","registry":""`},
	} {
		if _, err := ParsePolicy([]byte(strings.Replace(string(raw), tc.old, tc.new, 1))); err == nil {
			t.Fatal("ambiguous policy admitted", tc)
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Policy)
	}{
		{"npm", func(p *Policy) { p.Manager = "npm@10.9.4" }},
		{"pnpm", func(p *Policy) { p.Manager = "pnpm@lockfile-9" }},
		{"duplicate", func(p *Policy) { p.BunOrigins = append(p.BunOrigins, p.BunOrigins[0]) }},
		{"limit", func(p *Policy) { p.BunOrigins = make([]BunOriginRule, 65) }},
		{"location", func(p *Policy) { p.BunOrigins[0].Location = "node_modules/left-pad" }},
		{"private", func(p *Policy) { p.BunOrigins[0].Registry = "https://private.invalid" }},
		{"npm-grant-not-bun", func(p *Policy) { p.NPMRegistry = "https://registry.npmjs.org" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var q Policy
			_ = json.Unmarshal(raw, &q)
			tc.mutate(&q)
			if ValidatePolicy(q) == nil {
				t.Fatal("bad grant")
			}
		})
	}
	r := cli.ScanArgumentRequest{PolicyPath: "policy.json", Manager: "bun", Output: "-", Checks: p.Checks, FailOn: p.FailOn, Privacy: "portable"}
	if _, err := Configure(r, p.Policy); err == nil {
		t.Fatal("unpinned new authority")
	}
	r.TrustedPolicyDigest = sourceSRI(raw)
	configured, err := Configure(r, p.Policy)
	if err != nil || !reflect.DeepEqual(configured.Policy.BunOrigins, p.Policy.BunOrigins) {
		t.Fatal("grant dropped", err)
	}
	if ValidatePlanPolicy(configured) != nil {
		t.Fatal("configured grant rejected")
	}
	configured.TrustedPolicyDigest = ""
	if ValidatePlanPolicy(configured) == nil {
		t.Fatal("parent accepted unpinned grant")
	}
	old := p.Policy
	old.BunOrigins = nil
	oldRaw, _ := json.Marshal(old)
	if policyPinMatches(context.Background(), sourceSRI(oldRaw), raw) {
		t.Fatal("old pin upgraded")
	}
	builtin, err := ConfigureBuiltin(cli.ScanArgumentRequest{Manager: "bun", Output: "-", Checks: p.Checks})
	if err != nil || len(builtin.Policy.BunOrigins) != 0 {
		t.Fatal("builtin gained authority", err)
	}
}

func TestBunNativeOwnedTupleMatching(t *testing.T) {
	snapshot, info := matchingSnapshot(t)
	dir := t.TempDir()
	files := map[string]string{
		"package.json":                       `{"name":"root","dependencies":{"left-pad":"1.0.0"}}`,
		"bun.lock":                           `{"lockfileVersion":1,"workspaces":{"":{"name":"root","dependencies":{"left-pad":"1.0.0"}}},"packages":{"left-pad":["left-pad@1.0.0","",{},"sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="]}}`,
		"node_modules/left-pad/package.json": `{"name":"left-pad","version":"1.0.0"}`,
	}
	for name, data := range files {
		file := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := nativefs.OpenRoot(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	inv, err := projectinventory.Collect(context.Background(), root, projectinventory.Options{Profile: "bun@1.3.x", ExplicitManager: true})
	if err != nil {
		t.Fatal(err)
	}
	p, _ := bunEligibleFixture(t, info)
	// Exercise the production collector, never reconstruct a discarded original
	// context from projected fields in this test.
	locked := 0
	for _, o := range inv.Model.Observations {
		if o.Class == "locked" && o.Kind == "package" {
			locked++
			if o.Fields["matching-context"] != "supported" {
				t.Fatal("collector lost original context", o)
			}
		}
	}
	if locked != 1 || len(indexedMatchingOrigins(p, inv)) != 2 {
		t.Fatal("collected locked/native endpoints did not qualify", inv)
	}
	p.Privacy = "local"
	var rows []AdvisoryDecision
	var materials []PolicyMaterial
	_, err = MatchInventoryWithPolicyEvidence(context.Background(), p, inv, snapshot, info, matchingNow, func(d AdvisoryDecision) error { rows = append(rows, d); return nil }, nil, func(m PolicyMaterial) error { materials = append(materials, m); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(materials) != 2 {
		t.Fatalf("native evidence did not yield locked+installed receipts: %+v; inv=%+v", rows, inv)
	}
	public := projectinventory.PortableMatching(inv)
	for _, d := range rows {
		if ValidateAdvisoryDecision(p, public, info, d) != nil {
			t.Fatal("native parent decision", d)
		}
	}
	if err := ValidatePolicyMaterials(p, public, nil, rows, materials); err != nil {
		t.Fatal("native parent material", err, materials)
	}
}
