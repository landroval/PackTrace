package integrityscan

import (
	"encoding/json"
	"strings"
	"testing"

	"packtrace/internal/intel"
	"packtrace/internal/projectinventory"
)

func TestFirstAdvisoryVersionProblemEvaluation(t *testing.T) {
	for _, tc := range []struct {
		name, conditions, kind     string
		version, rangeIndex, event int
		outcome                    intel.OSVVersionOutcome
		full                       bool
	}{
		{"partial-positive", `"versions":["1.0.0","PRIVATE-RAW-BOUND"]`, "version-outside-profile", 1, -1, -1, intel.OSVVersionMatch, false},
		{"unsupported-only", `"versions":["PRIVATE-RAW-BOUND"]`, "version-outside-profile", 0, -1, -1, intel.OSVVersionIndeterminate, false},
		{"partial-negative", `"versions":["2.0.0","PRIVATE-RAW-BOUND"]`, "version-outside-profile", 1, -1, -1, intel.OSVVersionIndeterminate, false},
		{"full-negative", `"versions":["2.0.0"]`, "", -1, -1, -1, intel.OSVVersionNoMatch, true},
		{"ranges-list", `"ranges":null`, "range-structure", -1, -1, -1, intel.OSVVersionIndeterminate, false},
		{"range", `"ranges":[null]`, "range-structure", -1, 0, -1, intel.OSVVersionIndeterminate, false},
		{"range-type", `"ranges":[{"type":"GIT","events":[{"introduced":"0"}]}]`, "range-outside-profile", -1, 0, -1, intel.OSVVersionIndeterminate, false},
		{"bound", `"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"PRIVATE-RAW-BOUND"}]}]`, "bound-outside-profile", -1, 0, 0, intel.OSVVersionIndeterminate, false},
		{"tie", `"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0+a"},{"fixed":"1.0.0+b"}]}]`, "precedence-tie", -1, 0, 0, intel.OSVVersionIndeterminate, false},
		{"versions-list", `"versions":null`, "versions-uninspectable", -1, -1, -1, intel.OSVVersionIndeterminate, false},
		{"empty", `"versions":[]`, "no-usable-condition", -1, -1, -1, intel.OSVVersionIndeterminate, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := strings.Replace(matchingRaw, `"versions":["1.0.0"]`, tc.conditions, 1)
			doc, err := intel.ParseOSVRecord([]byte(raw))
			if err != nil {
				t.Fatal(err)
			}
			h, err := intel.ProjectOSVHeader(doc)
			if err != nil {
				t.Fatal(err)
			}
			a, err := intel.ProjectOSVAffected(doc)
			if err != nil {
				t.Fatal(err)
			}
			q, _ := intel.ParseSemVer("1.0.0")
			result, err := intel.EvaluateOSVNPMVersionConditions(h, a, q)
			if err != nil {
				t.Fatal(err)
			}
			if result.Entries[0].Outcome != tc.outcome || result.Entries[0].FullyEvaluated != tc.full {
				t.Fatal(result)
			}
			p := firstAdvisoryVersionProblem(result, 0)
			if tc.kind == "" {
				if p != nil {
					t.Fatal(p)
				}
			} else if p == nil || *p != (AdvisoryVersionProblem{"affected", tc.kind, tc.version, tc.rangeIndex, tc.event}) {
				t.Fatalf("unexpected first problem: %+v", p)
			}
			encoded, err := json.Marshal(p)
			if err != nil || strings.Contains(string(encoded), "PRIVATE") {
				t.Fatal(string(encoded), err)
			}
		})
	}
}

func TestFirstAdvisoryVersionProblemGlobalSlotAndCopy(t *testing.T) {
	slot := intel.OSVVersionProblem{Kind: "version-outside-profile", VersionIndex: 7, RangeIndex: -1, EventIndex: -1}
	result := intel.OSVVersionConditions{Entries: []intel.OSVVersionEntryDecision{{Index: 0}, {Index: 1, Problems: []intel.OSVVersionProblem{slot}}}}
	if firstAdvisoryVersionProblem(result, 0) != nil || firstAdvisoryVersionProblem(result, -1) != nil || firstAdvisoryVersionProblem(result, 2) != nil {
		t.Fatal("borrowed sibling or unbound problem")
	}
	p := firstAdvisoryVersionProblem(result, 1)
	if p == nil || p.Version != 7 || p.Scope != "affected" {
		t.Fatal(p)
	}
	copy := cloneAdvisoryVersionProblem(p)
	copy.Version = 9
	if p.Version != 7 || cloneAdvisoryVersionProblem(nil) != nil {
		t.Fatal("shared pointer")
	}
	result.Problems = []intel.OSVVersionProblem{{Kind: "header-unsupported", VersionIndex: -1, RangeIndex: -1, EventIndex: -1}, {Kind: "query-unqualified", VersionIndex: -1, RangeIndex: -1, EventIndex: -1}}
	p = firstAdvisoryVersionProblem(result, 1)
	if p == nil || *p != (AdvisoryVersionProblem{"global", "header-unsupported", -1, -1, -1}) {
		t.Fatal(p)
	}
	result.Entries[1].FullyEvaluated = true
	if firstAdvisoryVersionProblem(result, 1) != nil {
		t.Fatal("full row received blocker")
	}
	result.Entries[0].Index = 8
	if firstAdvisoryVersionProblem(result, 0) != nil {
		t.Fatal("mismatched slot")
	}
}

func TestAdvisoryVersionProblemShapes(t *testing.T) {
	for _, tc := range []struct {
		scope, kind                string
		version, rangeIndex, event int
	}{
		{"global", "header-unsupported", -1, -1, -1}, {"global", "query-unqualified", -1, -1, -1}, {"global", "affected-uninspectable", -1, -1, -1},
		{"affected", "affected-uninspectable", -1, -1, -1}, {"affected", "ecosystem-outside-profile", -1, -1, -1}, {"affected", "versions-uninspectable", -1, -1, -1}, {"affected", "no-usable-condition", -1, -1, -1},
		{"affected", "version-outside-profile", 19999, -1, -1}, {"affected", "version-limit", 0, -1, -1},
		{"affected", "range-structure", -1, -1, -1}, {"affected", "range-structure", -1, 19999, -1}, {"affected", "range-outside-profile", -1, 0, -1},
		{"affected", "bound-outside-profile", -1, 0, 19999}, {"affected", "bound-limit", -1, 19999, 0}, {"affected", "precedence-tie", -1, 0, 0},
	} {
		p := AdvisoryVersionProblem{tc.scope, tc.kind, tc.version, tc.rangeIndex, tc.event}
		if !advisoryVersionProblemShape(&p) {
			t.Fatal(p)
		}
		for _, change := range []func(*AdvisoryVersionProblem){
			func(p *AdvisoryVersionProblem) { p.Kind = "PRIVATE" },
			func(p *AdvisoryVersionProblem) { p.Scope = "sibling" },
			func(p *AdvisoryVersionProblem) { p.Version = -2 },
			func(p *AdvisoryVersionProblem) { p.Range = 20000 },
			func(p *AdvisoryVersionProblem) { p.Event = 20000 },
		} {
			bad := p
			change(&bad)
			if advisoryVersionProblemShape(&bad) {
				t.Fatal("forged shape", bad)
			}
		}
	}
	for _, p := range []AdvisoryVersionProblem{
		{"global", "range-structure", -1, -1, -1}, {"affected", "header-unsupported", -1, -1, -1},
		{"global", "header-unsupported", 0, -1, -1}, {"affected", "versions-uninspectable", 0, -1, -1},
		{"affected", "version-limit", -1, -1, -1}, {"affected", "version-limit", 0, 0, -1},
		{"affected", "range-structure", -1, 0, 0}, {"affected", "range-outside-profile", -1, -1, -1},
		{"affected", "bound-limit", -1, 0, -1}, {"affected", "precedence-tie", 0, 0, 0},
		{"affected", "version-limit", 20000, -1, -1},
	} {
		if advisoryVersionProblemShape(&p) {
			t.Fatal("invalid kind-specific locator", p)
		}
	}
}

func TestAdvisoryVersionProblemParentValidation(t *testing.T) {
	plan := matchingPlan(t)
	inv := projectinventory.Portable(newMatchingFixture().inv)
	n := uint64(1)
	info := Intelligence{ID: strings.Repeat("1", 64), State: "available", Selection: "current", Provenance: "operator-designated", CheckAge: "current", ReconciliationAge: "current", Records: &n, Gaps: []string{"advisory-originals-lazy", "storage-usage-not-observed"}}
	d := AdvisoryDecision{Observation: 1, Advisory: 1, Affected: 0, Rule: 1, VersionOutcome: "indeterminate", Outcome: "indeterminate", Category: "malicious", Profile: "osv-openssf-malicious-v1", Activity: "not-withdrawn", Origin: "operator-npm-rule", Source: "qualified", Support: []AdvisorySupport{}, Gaps: []string{"version-unsupported"}, FirstVersionProblem: &AdvisoryVersionProblem{"affected", "version-outside-profile", 0, -1, -1}}
	if err := ValidateAdvisoryDecision(plan, inv, info, d); err != nil {
		t.Fatal("valid partial row", err)
	}
	positive := d
	positive.VersionOutcome, positive.Outcome, positive.EnforcementEligible = "match", "match", true
	positive.Support = []AdvisorySupport{{Version: 1, Range: -1}}
	if err := ValidateAdvisoryDecision(plan, inv, info, positive); err != nil {
		t.Fatal("partial positive lost", err)
	}
	for _, change := range []func(*AdvisoryDecision){
		func(d *AdvisoryDecision) { d.FirstVersionProblem.Kind = "PRIVATE" },
		func(d *AdvisoryDecision) { d.FirstVersionProblem.Scope = "other" },
		func(d *AdvisoryDecision) { d.FirstVersionProblem.Event = 0 },
		func(d *AdvisoryDecision) { d.FirstVersionProblem.Range = 20000 },
		func(d *AdvisoryDecision) { d.Gaps = []string{} },
		func(d *AdvisoryDecision) { d.Advisory = 0; d.Affected = -1 },
		func(d *AdvisoryDecision) { d.Affected = -1 },
		func(d *AdvisoryDecision) {
			d.FullyEvaluated = true
			d.VersionOutcome = "no-match"
			d.Outcome = "no-match"
		},
	} {
		bad := d
		bad.FirstVersionProblem = cloneAdvisoryVersionProblem(d.FirstVersionProblem)
		change(&bad)
		if ValidateAdvisoryDecision(plan, inv, info, bad) == nil {
			t.Fatal("forged parent accepted", bad)
		}
	}
	d.FirstVersionProblem = nil
	if ValidateAdvisoryDecision(plan, inv, info, d) != nil {
		t.Fatal("optional absence rejected")
	}
	base := baseAdvisory(newMatchingFixture().inv.Model.Observations[0], UnavailableIntelligence())
	if base.FirstVersionProblem != nil {
		t.Fatal("unqualified row invented blocker")
	}
	encoded, err := json.Marshal(base)
	if err != nil || strings.Contains(string(encoded), "firstVersionProblem") {
		t.Fatal("nil field not omitted", string(encoded), err)
	}
}
