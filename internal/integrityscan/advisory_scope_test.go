package integrityscan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"packtrace/internal/cli"
	"packtrace/internal/intel"
	"packtrace/internal/intelstore"
	"packtrace/internal/nativefs"
	"packtrace/internal/projectinventory"
)

func selectedAdvisoryFixture(t *testing.T, name, version, declaration string, extraManifest ...string) (Plan, projectinventory.PublicInventory) {
	t.Helper()
	path := t.TempDir()
	files := map[string]string{
		"package.json":                           `{"name":"private-project","dependencies":{"` + name + `":"` + declaration + `"}}`,
		"package-lock.json":                      `{"lockfileVersion":3,"packages":{"":{"dependencies":{"` + name + `":"` + declaration + `"}},"node_modules/` + name + `":{"name":"` + name + `","version":"` + version + `","resolved":"` + npmTarballOrigin(name, version) + `"}}}`,
		"node_modules/" + name + "/package.json": `{"name":"` + name + `","version":"` + version + `"}`,
	}
	if len(extraManifest) != 0 {
		files["package.json"] = strings.Replace(files["package.json"], `"dependencies":{`, `"dependencies":{"unlocked":"`+extraManifest[0]+`",`, 1)
	}
	for name, body := range files {
		p := filepath.Join(path, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := nativefs.OpenRoot(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	inv, err := projectinventory.Collect(context.Background(), root, projectinventory.Options{Profile: "npm@10.9.4", ExplicitManager: true, RetainIntegrityOriginals: true})
	if err != nil {
		t.Fatal(err)
	}
	public := projectinventory.PortableMatching(inv)
	if projectinventory.ValidateOriginalClaims(public) != nil || len(extraManifest) == 0 && !operationalInventoryComplete(&public) {
		t.Fatal("original fixture not closed", inv)
	}
	plan := matchingPlan(t)
	plan.Checks = cli.ArgumentCheckMalicious | cli.ArgumentCheckVulnerability
	plan.Policy.RequiredChecks = []string{"malicious", "vulnerability"}
	plan.Policy.NPMOrigins = []NPMOriginRule{}
	plan.Policy.NPMRegistry = "https://registry.npmjs.org"
	return plan, public
}

func selectedAdvisoryRows(t *testing.T, p Plan, inv projectinventory.PublicInventory, snapshotName string) (AdvisoryReport, Intelligence, func(AdvisoryReport) AdvisoryReport) {
	t.Helper()
	return selectedAdvisoryRowsAt(t, p, inv, snapshotName, matchingNow)
}

func selectedAdvisoryRowsAt(t *testing.T, p Plan, inv projectinventory.PublicInventory, snapshotName string, now time.Time) (AdvisoryReport, Intelligence, func(AdvisoryReport) AdvisoryReport) {
	t.Helper()
	snap, initial := matchingSnapshotNamed(t, snapshotName)
	sum, err := intel.ParseSnapshotDigest(matchingPinnedPlan(t, initial).TrustedSnapshotDigest)
	if err != nil {
		t.Fatal(err)
	}
	id := intelstore.ID(sum)
	observed, observeErr := snap.Observe(context.Background(), now, &id)
	if observeErr != nil {
		t.Fatal(observeErr)
	}
	info := SnapshotIntelligence(observed, "expected-digest")
	p.TrustedSnapshotDigest = matchingPinnedPlan(t, info).TrustedSnapshotDigest
	a := AdvisoryReport{State: "observed", Decisions: []AdvisoryDecision{}}
	a.Summary, err = MatchInventory(context.Background(), p, *inv.OriginalClaims, snap, info, now, func(d AdvisoryDecision) error {
		a.Decisions = append(a.Decisions, d)
		if d.EnforcementEligible {
			a.Findings++
		}
		if d.Candidate {
			a.Candidates++
		}
		return nil
	})
	if err != nil || !validateAdvisoryReport(p, inv, info, a) {
		t.Fatal("matching fixture", err, a)
	}
	return a, info, func(a AdvisoryReport) AdvisoryReport {
		return AdmitSelectedAdvisoryScope(context.Background(), p, inv, info, a, snap, now, 0)
	}
}

func TestSelectedAdvisoryOriginalScope(t *testing.T) {
	for _, tc := range []struct {
		name, version string
		findings      int
	}{
		{"npmfixture-0002", "1.0.0", 2}, {"npmfixture-0003", "1.0.0", 2},
		{"npmfixture-0002", "2.0.0", 0}, {"npmfixture-0003", "2.0.0", 0}, {"left-pad", "1.0.0", 0},
	} {
		t.Run(tc.name+tc.version, func(t *testing.T) {
			p, inv := selectedAdvisoryFixture(t, tc.name, tc.version, tc.version)
			a, info, admit := selectedAdvisoryRows(t, p, inv, "full.bundle")
			if a.Findings != tc.findings {
				t.Fatal("findings", a.Findings)
			}
			if !hasMatchingGap(a.Summary.Gaps, "declared-unassessed") || !hasMatchingGap(a.Summary.Gaps, "index-completeness") {
				t.Fatal("historical invariants changed")
			}
			a = admit(a)
			if a.SelectedScope == nil {
				t.Fatal("selected originals not admitted", a.ScopeAttempt)
			}
			p.TrustedSnapshotDigest = matchingPinnedPlan(t, info).TrustedSnapshotDigest
			r := BuildReportWithPolicy(p, nil, Summary{}, Resources{}, false, false, &inv, &info, &a, nil, false, matchingNow)
			for _, c := range r.Coverage {
				if (c.Check == "malicious" || c.Check == "vulnerability") && c.Outcome != "completed" {
					t.Fatalf("selected original scope not completed: %+v", c)
				}
			}
			for _, format := range []string{"json", "terminal", "sarif"} {
				if _, err := Render(r, format); err != nil {
					t.Fatal("admitted frozen report not renderable", format, err)
				}
			}
			if ReportConditions(r).ReportPreventingError {
				t.Fatal("invalid frozen comparison")
			}
			a.SelectedScope.Contract = "changed-after-seal"
			if ReportConditions(r).ReportPreventingError {
				t.Fatal("caller alias mutated frozen scope")
			}
			var imported Report
			raw, _ := json.Marshal(r)
			if err := json.Unmarshal(raw, &imported); err != nil {
				t.Fatal(err)
			}
			if _, err := Render(imported, "json"); err == nil {
				t.Fatal("public JSON recreated operational authority")
			}
		})
	}
}

func TestSelectedAdvisoryExpiredSnapshotKeepsIndependentFreshness(t *testing.T) {
	p, inv := selectedAdvisoryFixture(t, "npmfixture-0002", "1.0.0", "1.0.0")
	now := matchingNow.Add(30 * 24 * time.Hour)
	a, info, admit := selectedAdvisoryRowsAt(t, p, inv, "full.bundle", now)
	if info.CheckAge != "expired" || info.ReconciliationAge != "expired" {
		t.Fatal("fixture must actually be expired", info)
	}
	a = admit(a)
	if a.SelectedScope == nil || len(a.Summary.Gaps) != 1 || a.Summary.Gaps[0] != "source-stale" {
		t.Fatal("snapshot proof erased or conflated freshness", a)
	}
	p.TrustedSnapshotDigest = matchingPinnedPlan(t, info).TrustedSnapshotDigest
	r := BuildReportWithPolicy(p, nil, Summary{}, Resources{}, false, false, &inv, &info, &a, nil, false, now)
	for _, c := range r.Coverage {
		if (c.Check == "malicious" || c.Check == "vulnerability") && c.Outcome != "completed" || c.Check == "intelligence-freshness" && c.Outcome != "incomplete" {
			t.Fatal("independent scope/freshness coverage", c)
		}
	}
	if _, err := Render(r, "json"); err != nil {
		t.Fatal("expired finite comparison not renderable", err)
	}
}

func TestSelectedAdvisoryBunExactDeclarationContext(t *testing.T) {
	for _, name := range []string{"npmfixture-0002", "npmfixture-0003", "left-pad"} {
		t.Run(name, func(t *testing.T) {
			path := t.TempDir()
			files := map[string]string{
				"package.json":                           `{"dependencies":{"` + name + `":"1.0.0"}}`,
				"bun.lock":                               `{"lockfileVersion":1,"configVersion":1,"workspaces":{"":{"dependencies":{"` + name + `":"1.0.0"}}},"packages":{"` + name + `":["` + name + `@1.0.0","",{},"sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="]}}`,
				"node_modules/" + name + "/package.json": `{"name":"` + name + `","version":"1.0.0"}`,
			}
			for file, body := range files {
				p := filepath.Join(path, filepath.FromSlash(file))
				if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			root, err := nativefs.OpenRoot(context.Background(), path)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			original, err := projectinventory.Collect(context.Background(), root, projectinventory.Options{Profile: "bun@1.3.x", ExplicitManager: true, RetainBunOriginals: true})
			if err != nil {
				t.Fatal(err)
			}
			inv := projectinventory.PortableMatching(original)
			if projectinventory.ValidateOriginalClaims(inv) != nil || !operationalInventoryComplete(&inv) {
				t.Fatal("Bun original collection", original)
			}
			p := matchingPlan(t)
			p.Manager = "bun@1.3.x"
			p.Policy.Manager = p.Manager
			p.Policy.NPMOrigins = nil
			p.Policy.BunOrigins = []BunOriginRule{{Location: name, Name: name, Version: "1.0.0", Origin: npmTarballOrigin(name, "1.0.0")}}
			p.Checks = cli.ArgumentCheckMalicious | cli.ArgumentCheckVulnerability
			p.Policy.RequiredChecks = []string{"malicious", "vulnerability"}
			a, info, admit := selectedAdvisoryRows(t, p, inv, "full.bundle")
			a = admit(a)
			if a.SelectedScope == nil {
				t.Fatal("Bun original exact scope did not close", a.ScopeAttempt, a.Decisions)
			}
			p.TrustedSnapshotDigest = matchingPinnedPlan(t, info).TrustedSnapshotDigest
			r := BuildReportWithPolicy(p, nil, Summary{}, Resources{}, false, false, &inv, &info, &a, nil, false, matchingNow)
			for _, c := range r.Coverage {
				if (c.Check == "malicious" || c.Check == "vulnerability") && c.Outcome != "completed" {
					t.Fatal("Bun scope incomplete", c)
				}
			}
			if _, err := Render(r, "json"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSelectedAdvisoryMustBindEachOriginalManifestDeclaration(t *testing.T) {
	p, inv := selectedAdvisoryFixture(t, "npmfixture-0002", "1.0.0", "1.0.0", "1.0.0")
	// The manifest has an additional declaration absent from the original lock.
	// Validating only locked requirement groups silently drops this obligation.
	if exactDeclaredScope(*inv.OriginalClaims, indexedMatchingOrigins(p, *inv.OriginalClaims)) {
		t.Fatal("original manifest-only declaration silently excluded")
	}
}

func TestSelectedAdvisoryAbstains(t *testing.T) {
	for _, tc := range []struct{ name, requirement, bundle string }{
		{"npmfixture-0001", "1.0.0", "full.bundle"}, // relevant unknown source and correction
		{"left-pad", "1.0.0", "matching.bundle"},
		{"npmfixture-0002", "^1.0.0", "full.bundle"}, // bounded exact subset, not resolver
		{"npmfixture-0002", "2.0.0", "full.bundle"},  // unsatisfied declaration
	} {
		t.Run(tc.name+tc.requirement+tc.bundle, func(t *testing.T) {
			p, inv := selectedAdvisoryFixture(t, tc.name, "1.0.0", tc.requirement)
			a, _, admit := selectedAdvisoryRows(t, p, inv, tc.bundle)
			result := admit(a)
			if result.SelectedScope != nil {
				t.Fatal("unsupported scope completed")
			}
			if len(result.Decisions) != len(a.Decisions) || result.Findings != a.Findings {
				t.Fatal("lost findings")
			}
		})
	}
}

func TestSelectedAdvisoryOriginalRoutingMustBePositive(t *testing.T) {
	for _, tc := range []struct {
		packageJSON, affected string
		want                  bool
	}{
		{`{"ecosystem":"npm","name":"left-pad"}`, "", true},
		{`{"ecosystem":"PyPI","name":"left-pad"}`, "", false},
		{`{"ecosystem":"npm"}`, "", false},
		{`{"ecosystem":"npm","name":null}`, "", false},
		{`{"ecosystem":"npm","name":"UPPER"}`, "", false},
		{"", `"affected":[]`, false},
		{"", `"affected":null`, false},
	} {
		raw := `{"id":"OWNED","modified":"2026-10-02T00:00:00Z",` + tc.affected + `}`
		if tc.packageJSON != "" {
			raw = `{"id":"OWNED","modified":"2026-10-02T00:00:00Z","affected":[{"package":` + tc.packageJSON + `,"versions":["1.0.0"]}]}`
		}
		doc, err := intel.ParseOSVRecord([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		h, he := intel.ProjectOSVHeader(doc)
		a, ae := intel.ProjectOSVAffected(doc)
		i, ie := intel.QualifyOSVNPMIdentities(h, a)
		times, te := intel.ProjectOSVTimes(doc)
		if he != nil || ae != nil || ie != nil || te != nil {
			t.Fatal("projection fixture failed")
		}
		record := intel.SnapshotOriginalEvidence{State: intel.SnapshotOriginalVerified, SHA256: doc.SHA256, Raw: []byte(raw), Header: h, Affected: a, Identity: i, Times: times}
		if advisoryOriginalRoutable(record) != tc.want {
			t.Fatalf("routing=%s affected=%s want=%t", tc.packageJSON, tc.affected, tc.want)
		}
	}
}

func TestSelectedAdvisoryIndexBindingsCannotBeOmittedOrSubstituted(t *testing.T) {
	snapshot, _ := matchingSnapshotNamed(t, "full.bundle")
	e, err := snapshot.ReadIdentity(context.Background(), "npmfixture-0002")
	if err != nil {
		t.Fatal(err)
	}
	expected := map[advisoryIndexKey]bool{}
	for _, r := range e.Records {
		for _, b := range r.Bindings {
			expected[advisoryIndexKey{r.SHA256, b.SourceOrdinal, b.AffectedIndex}] = true
		}
	}
	if len(expected) != 1 || !selectedIndexMatches(e.Name, e, expected) {
		t.Fatal("positive binding missing")
	}
	for name, mutate := range map[string]func(*intel.SnapshotNPMEvidence){
		"index-omission": func(e *intel.SnapshotNPMEvidence) { e.Records = nil },
		"identity":       func(e *intel.SnapshotNPMEvidence) { e.Name = "other" },
		"identity-hash":  func(e *intel.SnapshotNPMEvidence) { e.IdentityHash[0]++ },
		"block":          func(e *intel.SnapshotNPMEvidence) { e.BlockIndex++ },
		"original":       func(e *intel.SnapshotNPMEvidence) { e.Records[0].SHA256[0]++ },
		"source-ordinal": func(e *intel.SnapshotNPMEvidence) { e.Records[0].Bindings[0].SourceOrdinal++ },
		"affected":       func(e *intel.SnapshotNPMEvidence) { e.Records[0].Bindings[0].AffectedIndex++ },
		"unverified":     func(e *intel.SnapshotNPMEvidence) { e.Records[0].State = intel.SnapshotOriginalUnavailable },
		"unbound":        func(e *intel.SnapshotNPMEvidence) { e.Records[0].Bindings[0].State = intel.SnapshotBindingGap },
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(e)
			var copy intel.SnapshotNPMEvidence
			if json.Unmarshal(raw, &copy) != nil {
				t.Fatal("fixture copy")
			}
			mutate(&copy)
			if selectedIndexMatches(e.Name, copy, expected) {
				t.Fatal("substituted binding accepted")
			}
		})
	}
	empty, err := snapshot.ReadIdentity(context.Background(), "left-pad")
	if err != nil {
		t.Fatal(err)
	}
	if !selectedIndexMatches("left-pad", empty, map[advisoryIndexKey]bool{}) || selectedIndexMatches("left-pad", empty, expected) {
		t.Fatal("absence not bound to original accounting")
	}
}

func TestSelectedAdvisoryWrongSnapshotAndCancellation(t *testing.T) {
	p, inv := selectedAdvisoryFixture(t, "npmfixture-0002", "1.0.0", "1.0.0")
	a, info, _ := selectedAdvisoryRows(t, p, inv, "full.bundle")
	p.TrustedSnapshotDigest = matchingPinnedPlan(t, info).TrustedSnapshotDigest
	wrong, _ := matchingSnapshot(t)
	got := AdmitSelectedAdvisoryScope(context.Background(), p, inv, info, a, wrong, matchingNow, 0)
	if got.SelectedScope != nil {
		t.Fatal("wrong retained generation admitted")
	}
	snapshot, _ := matchingSnapshotNamed(t, "full.bundle")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got = AdmitSelectedAdvisoryScope(ctx, p, inv, info, a, snapshot, matchingNow, 0)
	if got.SelectedScope != nil {
		t.Fatal("cancelled proof admitted")
	}
	got = AdmitSelectedAdvisoryScope(context.Background(), p, inv, info, a, snapshot, matchingNow, maxMatchingBytes-a.Summary.BytesRead-1)
	if got.SelectedScope != nil || got.ScopeAttempt == nil || got.ScopeAttempt.BytesRead != maxMatchingBytes-a.Summary.BytesRead {
		t.Fatal("proof read limits not cumulative", got.ScopeAttempt)
	}
	// Failed proof cannot be retried with a fresh allowance on the same report.
	retry := AdmitSelectedAdvisoryScope(context.Background(), p, inv, info, got, snapshot, matchingNow, 0)
	if retry.SelectedScope != nil {
		t.Fatal("failed allowance silently renewed")
	}
}

func TestSelectedAdvisoryOriginalReplayRejectsPlausibleChildClaims(t *testing.T) {
	p, inv := selectedAdvisoryFixture(t, "npmfixture-0002", "1.0.0", "1.0.0")
	a, info, admit := selectedAdvisoryRows(t, p, inv, "full.bundle")
	p.TrustedSnapshotDigest = matchingPinnedPlan(t, info).TrustedSnapshotDigest
	for name, mutate := range map[string]func(*AdvisoryReport){
		"category-profile": func(a *AdvisoryReport) {
			for i := range a.Decisions {
				a.Decisions[i].Category = "vulnerability"
				a.Decisions[i].Profile = "osv-github-reviewed-v1"
			}
		},
		"read-undercount": func(a *AdvisoryReport) { a.Summary.BytesRead-- },
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(a)
			var forged AdvisoryReport
			if json.Unmarshal(raw, &forged) != nil {
				t.Fatal("copy")
			}
			mutate(&forged)
			if !validateAdvisoryReport(p, inv, info, forged) {
				t.Fatal("control must pass historical shape before original replay")
			}
			got := admit(forged)
			if got.SelectedScope != nil {
				t.Fatal("self-consistent claimed evidence admitted")
			}
			if got.ScopeAttempt == nil || got.ScopeAttempt.BytesRead == 0 {
				t.Fatal("independent original verification not attempted")
			}
		})
	}
}

func TestSelectedAdvisoryReceiptSubstitutions(t *testing.T) {
	p, inv := selectedAdvisoryFixture(t, "npmfixture-0002", "1.0.0", "1.0.0")
	a, info, admit := selectedAdvisoryRows(t, p, inv, "full.bundle")
	a = admit(a)
	if a.SelectedScope == nil {
		t.Fatal("positive admission unavailable", a.ScopeAttempt)
	}
	p.TrustedSnapshotDigest = matchingPinnedPlan(t, info).TrustedSnapshotDigest
	for name, mutate := range map[string]func(*Plan, *projectinventory.PublicInventory, *Intelligence, *AdvisoryReport){
		"category": func(_ *Plan, _ *projectinventory.PublicInventory, _ *Intelligence, a *AdvisoryReport) {
			a.Decisions[0].Category = "vulnerability"
		},
		"source": func(_ *Plan, _ *projectinventory.PublicInventory, i *Intelligence, _ *AdvisoryReport) {
			i.ID = strings.Repeat("a", 64)
		},
		"observation": func(_ *Plan, _ *projectinventory.PublicInventory, _ *Intelligence, a *AdvisoryReport) {
			a.Decisions[0].Observation++
		},
		"identity-original": func(_ *Plan, inv *projectinventory.PublicInventory, _ *Intelligence, _ *AdvisoryReport) {
			inv.OriginalClaims.Model.Observations[0].Name = "other"
		},
		"policy": func(p *Plan, _ *projectinventory.PublicInventory, _ *Intelligence, _ *AdvisoryReport) {
			p.Policy.NPMRegistry = ""
		},
		"omitted": func(_ *Plan, _ *projectinventory.PublicInventory, _ *Intelligence, a *AdvisoryReport) {
			a.Decisions = a.Decisions[:1]
		},
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(struct {
				P Plan
				I projectinventory.PublicInventory
				O *projectinventory.Result
				N Intelligence
				A AdvisoryReport
			}{p, inv, inv.OriginalClaims, info, a})
			var copy struct {
				P Plan
				I projectinventory.PublicInventory
				O *projectinventory.Result
				N Intelligence
				A AdvisoryReport
			}
			if err := json.Unmarshal(raw, &copy); err != nil {
				t.Fatal(err)
			}
			copy.I.OriginalClaims = copy.O
			copy.A.scopeReceipt = a.scopeReceipt
			mutate(&copy.P, &copy.I, &copy.N, &copy.A)
			if validSelectedAdvisoryScope(copy.P, copy.I, copy.N, copy.A) {
				t.Fatal("substitution admitted")
			}
		})
	}
	raw, _ := json.Marshal(a)
	var public AdvisoryReport
	if err := json.Unmarshal(raw, &public); err != nil {
		t.Fatal(err)
	}
	if validateAdvisoryReport(p, inv, info, public) {
		t.Fatal("public JSON recreated private authority")
	}
}
