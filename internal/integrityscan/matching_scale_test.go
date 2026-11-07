package integrityscan

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"

	"packtrace/internal/projectinventory"
)

func matchingScaleFixture(names []string) matchingFixture {
	f := newMatchingFixture()
	f.inv.Model.Observations = nil
	for i, name := range names {
		location := fmt.Sprintf("node_modules/copy-%d/node_modules/%s", i, name)
		lock := projectinventory.Observation{ID: uint32(2*i + 1), Workspace: 1, Source: 1, Class: "locked", Kind: "url", Status: "complete", Location: location, Name: name, Version: "1.0.0", Origin: npmTarballOrigin(name, "1.0.0"), Fields: map[string]string{"installation-name": name, "name-qualification": "installation-claim", "version-state": "value", "origin-state": "value"}}
		metadata := uint32(len(f.inv.Model.Evidence) + 1)
		manifest := metadata + 1
		f.inv.Model.Evidence = append(f.inv.Model.Evidence, projectinventory.Evidence{ID: metadata, Scope: 1, Location: location, Method: "native-metadata-lease", Complete: true}, projectinventory.Evidence{ID: manifest, Scope: 1, Location: location + "/package.json", Method: "native-input-lease", Complete: true})
		installed := projectinventory.Observation{ID: lock.ID + 1, Workspace: 1, Source: manifest, Class: "installed", Kind: "directory", Status: "complete", Location: location, Name: name, Version: "1.0.0", Fields: map[string]string{"installation-name": name, "physical-target": location, "metadata-evidence": fmt.Sprint(metadata), "name-state": "value", "version-state": "value"}}
		f.inv.Model.Observations = append(f.inv.Model.Observations, lock, installed)
		f.inv.Model.Relations = append(f.inv.Model.Relations, projectinventory.Relation{From: lock.ID, To: installed.ID, Evidence: manifest, Kind: "locked-correspondence", Status: "claim-agreement"})
	}
	return f
}

func TestMatchingFiveHundredPhysicalCopiesEvaluateVersionOnce(t *testing.T) {
	snapshot, info := matchingSnapshot(t)
	plan := matchingPinnedPlan(t, info)
	plan.Policy.NPMOrigins = nil
	plan.Policy.NPMRegistry = "https://registry.npmjs.org"
	names := make([]string, 500)
	for i := range names {
		names[i] = "left-pad"
	}
	f := matchingScaleFixture(names)
	var rows []AdvisoryDecision
	s, err := MatchInventory(context.Background(), plan, f.inv, snapshot, info, matchingNow, func(d AdvisoryDecision) error { rows = append(rows, d); return nil })
	if err != nil || s.Observations != 500 || s.InstalledObservations != 500 || s.TotalObservations != 500 || s.TotalInstalledObservations != 500 || s.Decisions != 3000 || s.Work != 3003 {
		t.Fatal(s, err)
	}
	one, err := MatchInventory(context.Background(), plan, newMatchingFixture().inv, snapshot, info, matchingNow, func(AdvisoryDecision) error { return nil })
	if err != nil || s.BytesRead == 0 || s.BytesRead != one.BytesRead {
		t.Fatal("physical copies re-read raw evidence", s.BytesRead, one.BytesRead, err)
	}
	public := projectinventory.PortableMatching(f.inv)
	if ValidateAdvisorySummary(s, rows, public) != nil {
		t.Fatal("scale closure", s)
	}
	for _, d := range rows {
		if d.Origin != "operator-npm-registry" || d.Rule != 0 || ValidateAdvisoryDecision(plan, public, info, d) != nil {
			t.Fatal("scale decision", d)
		}
	}
}

func TestMatchingFiveHundredNamesUseBoundedGroupedWindows(t *testing.T) {
	snapshot, info := matchingSnapshot(t)
	plan := matchingPinnedPlan(t, info)
	plan.Policy.NPMOrigins = nil
	plan.Policy.NPMRegistry = "https://registry.npmjs.org"
	// More than 64 distinct identities in the SAME block forces multiple windows.
	bucket := sha256.Sum256([]byte("npm\x00left-pad"))
	names := []string{"left-pad"}
	for i := 0; len(names) < 500; i++ {
		name := fmt.Sprintf("scale-%d", i)
		h := sha256.Sum256([]byte("npm\x00" + name))
		if h[0] == bucket[0] {
			names = append(names, name)
		}
	}
	f := matchingScaleFixture(names)
	var rows []AdvisoryDecision
	s, err := MatchInventory(context.Background(), plan, f.inv, snapshot, info, matchingNow, func(d AdvisoryDecision) error { rows = append(rows, d); return nil })
	if err != nil || s.Observations != 500 || s.InstalledObservations != 500 || s.Decisions != 1004 || s.Work != 1007 || hasMatchingGap(s.Gaps, "observation-limit") || hasMatchingGap(s.Gaps, "evaluation-limit") {
		t.Fatal(s, err)
	}
	// Measure, rather than infer, the former per-identity block-read baseline.
	var baseline uint64
	for _, name := range names {
		_, used, e := snapshot.ReadIdentityLimited(context.Background(), name, maxMatchingBytes)
		if e != nil {
			t.Fatal(e)
		}
		baseline += used
	}
	if s.BytesRead == 0 || s.BytesRead >= baseline/4 {
		t.Fatal("grouping did not reduce actual reads", s.BytesRead, baseline)
	}
	if ValidateAdvisorySummary(s, rows, projectinventory.PortableMatching(f.inv)) != nil {
		t.Fatal("grouped closure", s)
	}
	t.Logf("500 identities/1000 physical observations: grouped actual bytes=%d per-name baseline=%d work=%d", s.BytesRead, baseline, s.Work)
}

func TestMatchingSharedTotalRowAndEvaluationBudget(t *testing.T) {
	plan := matchingPlan(t)
	f := newMatchingFixture()
	for i := 1; i < 4100; i++ {
		o := f.inv.Model.Observations[0]
		o.ID = uint32(i + 1)
		f.inv.Model.Observations = append(f.inv.Model.Observations, o)
	}
	var rows []AdvisoryDecision
	s, err := MatchInventory(context.Background(), plan, f.inv, nil, UnavailableIntelligence(), matchingNow, func(d AdvisoryDecision) error { rows = append(rows, d); return nil })
	if err != nil || s.Work != 4096 || s.Decisions != 4096 || s.Observations != 4096 || s.TotalObservations != 4100 || !hasMatchingGap(s.Gaps, "evaluation-limit") {
		t.Fatal(s, err)
	}
	if ValidateAdvisorySummary(s, rows, projectinventory.Portable(f.inv)) != nil {
		t.Fatal("row-cap closure")
	}

	snapshot, info := matchingSnapshot(t)
	plan = matchingPinnedPlan(t, info)
	plan.Policy.NPMOrigins = nil
	plan.Policy.NPMRegistry = "https://registry.npmjs.org"
	f = newMatchingFixture()
	f.inv.Model.Observations = nil
	for i := 0; i < 1000; i++ {
		o := newMatchingFixture().inv.Model.Observations[0]
		o.ID = uint32(i + 1)
		o.Version = fmt.Sprintf("1.0.%d", i)
		o.Origin = npmTarballOrigin(o.Name, o.Version)
		f.inv.Model.Observations = append(f.inv.Model.Observations, o)
	}
	rows = nil
	s, err = MatchInventory(context.Background(), plan, f.inv, snapshot, info, matchingNow, func(d AdvisoryDecision) error { rows = append(rows, d); return nil })
	if err != nil || s.Work > 4096 || s.Work <= s.Decisions || s.Observations >= 1000 || !hasMatchingGap(s.Gaps, "evaluation-limit") {
		t.Fatal("evaluations not charged globally", s, err)
	}
	if ValidateAdvisorySummary(s, rows, projectinventory.Portable(f.inv)) != nil {
		t.Fatal("evaluation-cap closure", s)
	}
	for _, d := range rows {
		if ValidateAdvisoryDecision(plan, projectinventory.Portable(f.inv), info, d) != nil {
			t.Fatal("budget decision", d)
		}
	}
}
