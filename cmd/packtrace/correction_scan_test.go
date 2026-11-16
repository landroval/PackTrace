package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"packtrace/internal/integrityscan"
	"packtrace/internal/intelstore"
	"packtrace/internal/nativefs"
)

// These expectations come from fullMatchingSourceRecords and the checked-in
// transports, not from scanner output. All corrected originals have a new
// modified timestamp; unchanged-original acceptance is tested on retained full.
func TestScanCorrectionRevokesOnlyChangedEvidence(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("requires owned nativefs temp-fixture support; not platform qualification")
	}
	target, policyPath, state, policyPin, fullPin := fullScanFixture(t, 80)
	const fullID = "54da5521f1cce480bb34e8930e3167393d000948f1fa2da28b94ce65a945cefd"
	const correctedID = "a7f46531e25952da50287d31d5170565eb48434728fc978533f3c15ef5609ef7"
	pinFor := func(id string) string {
		raw, err := hex.DecodeString(id)
		if err != nil {
			t.Fatal(err)
		}
		return "sha256-" + base64.StdEncoding.EncodeToString(raw)
	}
	if fullPin != pinFor(fullID) {
		t.Fatal("full fixture generation changed")
	}
	ctx := context.Background()
	fixtures, err := filepath.Abs("../../internal/execution/testdata/intel")
	if err != nil {
		t.Fatal(err)
	}
	root, err := nativefs.OpenRoot(ctx, fixtures)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	importBundle := func(path, bundle, id string) {
		t.Helper()
		input, err := root.OpenDistributionInput(ctx, bundle)
		if err != nil {
			t.Fatal(err)
		}
		defer input.Close()
		store, err := intelstore.Open(ctx, path, intelstore.CreateOwned)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		received, err := store.Import(ctx, input, intelstore.ImportOptions{})
		if err != nil || hex.EncodeToString(received.Generation[:]) != id {
			t.Fatalf("import %s: %v %v", bundle, received, err)
		}
	}
	// An independent owned historical store permits another actual CLI scan even
	// after the primary store's current generation changes. Pins are never widened.
	historical := filepath.Join(t.TempDir(), "PRIVATE-retained-state")
	importBundle(historical, "full.bundle", fullID)
	var privateEvidence []string
	run := func(path, id, privacy string) (integrityscan.Report, []byte) {
		t.Helper()
		report, raw := runPolicyAcceptanceJSON(t, "--policy", policyPath, "--trusted-policy-digest", policyPin,
			"--state-dir", path, "--trusted-snapshot-digest", pinFor(id), "--checks", "malicious,vulnerability",
			"--fail-on", "malicious,vulnerability", "--privacy", privacy, "--format", "json", target)
		if report.Intelligence == nil || report.Intelligence.ID != id || report.Intelligence.State != "available" || report.Advisories == nil || report.Advisories.State != "observed" {
			t.Fatalf("selected generation not actually read: %s", raw)
		}
		for _, name := range []string{"native-qualification", "resident-observation"} {
			found := false
			for _, c := range report.Coverage {
				if c.Check == name {
					found = c.Required && c.Outcome == "incomplete"
				}
			}
			if !found {
				t.Fatalf("missing genuine required gap %s", name)
			}
		}
		if privacy == "portable" {
			for _, secret := range append(privateEvidence, []string{"PRIVATE", "npmfixture-", "GHSA-", "MAL-2026-", "node_modules/", "registry.npmjs.org", "sha256-", target, policyPath, path}...) {
				if strings.Contains(string(raw), secret) {
					t.Fatalf("portable leak %q", secret)
				}
			}
			if report.Advisories.Local != nil {
				t.Fatal("portable local sidecar")
			}
		}
		return report, raw
	}
	type expected struct{ pkg, id, oldHash, newHash, category, outcome, activity string }
	cases := []expected{
		{"npmfixture-0001", "GHSA-2223-2345-6789", "8e7a1c4cf06b33aa268a88146ba971ee3c71529552a2628662c32a8e3817903e", "d3cdb542791d3b69162faf848c894f16358e8f18d9a0bcd06d344d742f285afd", "vulnerability", "no-match", "not-withdrawn"},
		{"npmfixture-0002", "MAL-2026-3", "6a9bb9b129de770646ebc2543f1d2a599352372f99496bb6660524147f984b91", "a31d686114f2b0f837e4a5966f61a59153d1403afa5654656d6709654aaca91e", "malicious", "match", "not-withdrawn"},
		{"npmfixture-0079", "GHSA-225x-2345-6789", "858cb1624aec988df77f83a472c0e182cf0d658c4cc13f4d659ff76d5e4ef051", "4bd0d19a4df1d550219ae5fb5f2f3a251c598207426034195c2b84f3a027a8fd", "vulnerability", "no-match", "withdrawn"},
	}
	for _, want := range cases {
		privateEvidence = append(privateEvidence, want.oldHash, want.newHash)
	}
	check := func(r integrityscan.Report, corrected bool) integrityscan.PolicyFinding {
		t.Helper()
		if r.Advisories.Local == nil || r.Inventory == nil {
			t.Fatal("missing local causal evidence")
		}
		var selected integrityscan.PolicyFinding
		for _, want := range cases {
			advisory := 0
			hash := want.oldHash
			outcome, activity := "match", "not-withdrawn"
			if corrected {
				hash, outcome, activity = want.newHash, want.outcome, want.activity
			}
			for _, a := range r.Advisories.Local.Advisories {
				if a.ID == want.id {
					if a.SHA256 != hash {
						t.Fatalf("%s original: %s != %s", want.id, a.SHA256, hash)
					}
					advisory = a.Advisory
				}
			}
			if advisory == 0 {
				t.Fatalf("missing original %s", want.id)
			}
			// 80 declarations, then root + 80 sorted lock records; installed
			// enumeration omits fixture indexes 0 and 41.
			locators := map[string][2]uint32{"npmfixture-0001": {83, 162}, "npmfixture-0002": {84, 163}, "npmfixture-0079": {161, 239}}
			for classIndex, class := range []string{"locked", "installed"} {
				var observation uint32
				for _, o := range r.Advisories.Local.Observations {
					if o.Name == want.pkg && r.Inventory.Observations[o.Observation-1].Class == class {
						if observation != 0 || o.Version != "1.0.0" || o.Location != "node_modules/"+want.pkg {
							t.Fatalf("unexpected %s %s observation: %+v", want.pkg, class, o)
						}
						observation = o.Observation
					}
				}
				if observation != locators[want.pkg][classIndex] {
					t.Fatalf("%s %s observation=%d want=%d", want.pkg, class, observation, locators[want.pkg][classIndex])
				}
				found := 0
				for i, d := range r.Advisories.Decisions {
					if d.Observation != observation || d.Advisory != advisory {
						continue
					}
					found++
					versionOutcome := outcome
					if activity == "withdrawn" {
						versionOutcome = "match"
					}
					if d.VersionOutcome != versionOutcome || d.Candidate || d.Origin != "operator-npm-registry" || d.Source != "qualified" || d.Sequence != i || d.Affected != 0 || d.Category != want.category || d.Outcome != outcome || d.Activity != activity || d.EnforcementEligible != (outcome == "match") || !d.FullyEvaluated || (class == "installed" && d.LockedObservation == 0) {
						t.Fatalf("%s %s corrected=%t: %+v", want.id, class, corrected, d)
					}
					policyRows := 0
					for _, f := range r.Policy.Findings {
						if f.Decision != i {
							continue
						}
						policyRows++
						if f.Accepted && !(want.pkg == "npmfixture-0002" && class == "locked") {
							t.Fatal("exception widened to unrelated finding")
						}
						if outcome != "match" || f.Review == nil || f.Review.OriginalSHA256 != hash || f.Review.Advisory != want.id {
							t.Fatalf("wrong policy material: %+v", f)
						}
						if want.pkg == "npmfixture-0002" && class == "locked" {
							selected = f
						}
					}
					if (outcome == "match" && policyRows != 1) || (outcome != "match" && policyRows != 0) {
						t.Fatalf("%s %s policy rows=%d", want.id, class, policyRows)
					}
				}
				if found != 1 {
					t.Fatalf("%s %s decisions=%d", want.id, class, found)
				}
			}
		}
		if selected.Review == nil || selected.Acceptance == "" || selected.Tracking == "" {
			t.Fatal("missing selected review")
		}
		return selected
	}
	initial, _ := run(state, fullID, "local")
	finding := check(initial, false)
	privateEvidence = append(privateEvidence, finding.Acceptance, finding.Tracking, finding.Review.Project)
	if finding.Accepted {
		t.Fatal("unreviewed initial finding accepted")
	}
	data, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	var policy integrityscan.Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	policy.Exceptions = []integrityscan.Exception{{ID: "PRIVATE-causal-review", Reason: "PRIVATE-owned-inert-original-review", Owner: "PRIVATE-reviewer",
		ApprovedAt: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Acceptance: finding.Acceptance,
		Scope: integrityscan.FindingScope{Project: finding.Review.Project, Category: "malicious", Rule: "osv-npm", Class: "locked", Package: "npmfixture-0002", Version: "1.0.0", Origin: "https://registry.npmjs.org/npmfixture-0002/-/npmfixture-0002-1.0.0.tgz", Instance: "node_modules/npmfixture-0002", Advisory: "MAL-2026-3"}}}
	data, err = json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	policyPin = "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	accepted, _ := run(state, fullID, "local")
	acceptedFinding := check(accepted, false)
	if !acceptedFinding.Accepted || acceptedFinding.Acceptance != finding.Acceptance || accepted.Policy.Exceptions[0].Disposition != "applied" || accepted.Policy.EnforcedUnaccepted != initial.Policy.EnforcedUnaccepted-1 {
		t.Fatal("unchanged original lost acceptance")
	}
	portable, _ := run(state, fullID, "portable")
	if !reflect.DeepEqual(portable.Advisories.Decisions, accepted.Advisories.Decisions) || len(portable.Policy.Findings) != len(accepted.Policy.Findings) || !portable.Policy.Findings[acceptedFinding.Ordinal-1].Accepted {
		t.Fatal("portable presentation changed decisions/acceptance")
	}
	importBundle(state, "corrected.bundle", correctedID)
	corrected, _ := run(state, correctedID, "local")
	changed := check(corrected, true)
	if changed.Accepted || changed.Acceptance == finding.Acceptance || changed.Tracking != finding.Tracking || corrected.Policy.Exceptions[0].Disposition != "unmatched" || corrected.Policy.EnforcedUnaccepted != len(corrected.Policy.Findings) {
		t.Fatal("changed original inherited acceptance or changed stable tracking")
	}
	privateEvidence = append(privateEvidence, changed.Acceptance)
	correctedPortable, _ := run(state, correctedID, "portable")
	if !reflect.DeepEqual(correctedPortable.Advisories.Decisions, corrected.Advisories.Decisions) || correctedPortable.Policy.Exceptions[0].Disposition != "unmatched" {
		t.Fatal("portable correction differs")
	}
	retained, _ := run(historical, fullID, "local")
	old := check(retained, false)
	if !old.Accepted || old.Acceptance != finding.Acceptance || !reflect.DeepEqual(retained.Advisories.Decisions, accepted.Advisories.Decisions) {
		t.Fatal("retained generation changed or acceptance was revoked")
	}
	// Also read/export the old generation from the corrected primary store: import
	// must not rewrite history even though subsequent CLI scans select current.
	store, err := intelstore.Open(ctx, state, intelstore.ReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	rawID, _ := hex.DecodeString(fullID)
	var oldID intelstore.ID
	copy(oldID[:], rawID)
	snapshot, err := store.ReadPinned(ctx, &oldID)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	var exported bytes.Buffer
	if err := store.Export(ctx, snapshot, &exported); err != nil {
		t.Fatal(err)
	}
	if got := sha256.Sum256(exported.Bytes()); hex.EncodeToString(got[:]) != "f520b12b829709f7440a63d581b97341464a265a8428bf2f4b6df6b7fb31b18c" {
		t.Fatal("historical full transport changed")
	}
}
