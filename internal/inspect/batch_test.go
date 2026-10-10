package inspect

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func batchPacket(lock string, ads ...string) string {
	return `{"lockfile":` + lock + `,"advisories":[` + strings.Join(ads, ",") + `]}`
}

// Catches reused result pointers, advisory correlation/deduplication and discarded
// valid siblings. Expected comparisons and source positions are hand-derived.
func TestBatchRetainsSiblingEvidence(t *testing.T) {
	withdrawn := strings.Replace(literalAd, `"modified":`, `"withdrawn":"2026-01-02T00:00:00Z","modified":`, 1)
	input := batchPacket(literalLock, literalAd, `42`, withdrawn, literalAd)
	got, e := ReadBatch(strings.NewReader(input))
	if e != nil {
		t.Fatal(e)
	}
	if got.Schema != "packtrace.inspect.batch.v1" || !got.Experimental || got.Scope != "supplied-metadata" || got.Privacy != "portable" || got.ExitCode != 3 || got.LockedEntries != 1 || len(got.Advisories) != 4 || got.CandidateCount != 2 || got.Findings == nil || len(got.Findings) != 0 {
		t.Fatal("sibling result lost", got)
	}
	for i, want := range []struct {
		state      string
		count      int
		withdrawal string
	}{{"usable", 1, "not-declared"}, {"invalid-advisory", 0, ""}, {"usable", 0, "reported"}, {"usable", 1, "not-declared"}} {
		entry := got.Advisories[i]
		ref := fmt.Sprintf("advisory-%d", i)
		if entry.Reference != ref || entry.State != want.state {
			t.Fatal("advisory source order mixed", entry)
		}
		if want.state == "invalid-advisory" {
			if entry.Report != nil {
				t.Fatal("invalid record fabricated report")
			}
			continue
		}
		r := entry.Report
		if r == nil || r.AdvisoryReference != ref || len(r.Candidates) != want.count || r.ExitCode != 3 || len(r.Evaluations) != 1 || r.Evaluations[0].Withdrawal != want.withdrawal {
			t.Fatal("advisory evidence mixed", entry)
		}
		for _, c := range r.Candidates {
			if c.Kind != "identity-version-only" || c.EnforcementEligible {
				t.Fatal("candidate promoted")
			}
		}
	}
	incomplete := false
	for _, c := range got.Coverage {
		if c.Check == "advisory-records" && c.Outcome == "incomplete" {
			incomplete = true
		}
	}
	if !incomplete {
		t.Fatal("invalid sibling gap hidden")
	}
	for _, format := range []string{"terminal", "json"} {
		out, e := RenderBatch(got, format)
		if e != nil {
			t.Fatal(e)
		}
		for _, secret := range []string{privateName, "PRIVATE", "1.2.3", "https://", fmt.Sprintf("%x", sha256.Sum256([]byte(literalLock))), fmt.Sprintf("%x", sha256.Sum256([]byte(literalAd)))} {
			if bytes.Contains(out, []byte(secret)) {
				t.Fatal("portable batch leak", secret)
			}
		}
		if format == "json" {
			var decoded BatchResult
			if json.Unmarshal(out, &decoded) != nil || !reflect.DeepEqual(decoded, got) {
				t.Fatal("JSON model differs")
			}
		} else {
			for _, text := range []string{"advisory-0: usable", "advisory-1: invalid-advisory", "advisory-2: usable", "advisory-3: usable", "Candidate comparisons: 2", "Required coverage: incomplete", "Confirmed findings: 0"} {
				if !bytes.Contains(out, []byte(text)) {
					t.Fatal("terminal gap/source/count lost", text)
				}
			}
		}
	}
}

func TestBatchCrossAdvisoryAndSlotIsolation(t *testing.T) {
	other := strings.Replace(literalAd, privateName, "other-package", 1)
	fixed := strings.Replace(literalAd, `"fixed":"2.0.0"`, `"fixed":"1.2.3"`, 1)
	got, e := ReadBatch(strings.NewReader(batchPacket(literalLock, other, fixed)))
	if e != nil || got.CandidateCount != 0 || len(got.Advisories) != 2 {
		t.Fatal("cross-advisory join", got, e)
	}
	if got.Advisories[0].Report.Evaluations[0].IdentityComparison != "different" || got.Advisories[0].Report.Evaluations[0].VersionOutcome != "match" || got.Advisories[1].Report.Evaluations[0].IdentityComparison != "equal" || got.Advisories[1].Report.Evaluations[0].VersionOutcome != "no-match" {
		t.Fatal("evidence correlations lost")
	}
	cross := `{"id":"OWNED","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"other"},"versions":["1.2.3"]},{"package":{"ecosystem":"npm","name":"private-marker-package"},"versions":["9.9.9"]}]}`
	got, e = ReadBatch(strings.NewReader(batchPacket(literalLock, cross)))
	if e != nil || got.CandidateCount != 0 || len(got.Advisories[0].Report.Evaluations) != 2 {
		t.Fatal("cross-slot join", got, e)
	}
}

func TestBatchProfileAndUnknownEvidence(t *testing.T) {
	unnamed := `{"lockfileVersion":3,"packages":{"node_modules/private-marker-package":{"version":"1.2.3"}}}`
	for _, tc := range []struct {
		name, lock, ad, profile, kind string
		count                         int
	}{
		{"default", unnamed, literalAd, "explicit-only", "", 0},
		{"hypothesis", unnamed, literalAd, "npm-lock-v2-v3", "installation-name-version-only", 1},
		{"alias-block", strings.Replace(unnamed, `"packages":{`, `"packages":{"":{"dependencies":{"private-marker-package":"npm:other@^1"}},`, 1), literalAd, "npm-lock-v2-v3", "", 0},
		{"unknown-withdrawal", literalLock, strings.Replace(literalAd, `"modified":`, `"withdrawn":null,"modified":`, 1), "explicit-only", "", 0},
		{"unsupported", literalLock, strings.Replace(literalAd, `"SEMVER"`, `"ECOSYSTEM"`, 1), "explicit-only", "", 0},
		{"empty-inventory", `{"lockfileVersion":3,"packages":{"":{}}}`, literalAd, "explicit-only", "", 0},
		{"empty-affected", literalLock, `{"id":"OWNED","modified":"2026-01-01T00:00:00Z","affected":[]}`, "explicit-only", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, e := ReadBatchProfile(strings.NewReader(batchPacket(tc.lock, tc.ad)), tc.profile)
			if e != nil || got.ExitCode != 3 || got.CandidateCount != tc.count || len(got.Advisories) != 1 || got.Advisories[0].Report == nil {
				t.Fatal("profile/unknown/empty scope lost", got, e)
			}
			r := got.Advisories[0].Report
			if tc.count == 1 && (r.Candidates[0].Kind != tc.kind || r.Candidates[0].EnforcementEligible) {
				t.Fatal("hypothesis promoted")
			}
			if tc.name == "hypothesis" {
				found := false
				for _, c := range r.Coverage {
					if c.Check == "canonical-name-correspondence" && c.Outcome == "incomplete" {
						found = true
					}
				}
				if !found {
					t.Fatal("canonical gap lost")
				}
			}
		})
	}
}

func TestBatchAllUnusableNotClean(t *testing.T) {
	got, e := ReadBatch(strings.NewReader(batchPacket(literalLock, `null`, `[]`, `{"id":"PRIVATE"}`)))
	if e != nil || got.ExitCode != 3 || got.CandidateCount != 0 || len(got.Advisories) != 3 || got.LockedEntries != 1 || got.Findings == nil {
		t.Fatal("invalid advisory batch hidden", got, e)
	}
	for _, a := range got.Advisories {
		if a.State != "invalid-advisory" || a.Report != nil {
			t.Fatal("invalid record qualified")
		}
	}
	for _, c := range got.Coverage {
		if c.Check == "advisory-records" && c.Outcome == "completed" {
			t.Fatal("all-unusable batch clean")
		}
	}
	if b, e := RenderBatch(got, "PRIVATE"); e == nil || b != nil || strings.Contains(e.Error(), "PRIVATE") {
		t.Fatal("format privacy")
	}
}

func TestBatchStrictWireAndPrivateFailures(t *testing.T) {
	good := batchPacket(literalLock, literalAd)
	for _, input := range []string{"", `null`, `[]`, good + `{}`, `{"lockfile":{},"advisories":null}`, `{"lockfile":null,"advisories":[42]}`, batchPacket(literalLock), strings.Replace(good, `"advisories":`, `"advisory":`, 1), strings.Replace(good, `"lockfile":`, `"PRIVATE":1,"lockfile":`, 1), strings.Replace(good, `"id":"PRIVATE-AD-ID"`, `"id":"PRIVATE-AD-ID","id":"PRIVATE"`, 1), strings.Replace(good, `"lockfileVersion":3`, `"lockfileVersion":1`, 1), strings.Replace(good, `"id":"PRIVATE-AD-ID"`, `"id":"\ud800"`, 1), string([]byte{0xff}), strings.Repeat(`{"a":`, 129) + `0` + strings.Repeat(`}`, 129)} {
		r, e := ReadBatch(strings.NewReader(input))
		if e == nil || !reflect.DeepEqual(r, BatchResult{}) || strings.Contains(e.Error(), "PRIVATE") {
			t.Fatal("strict wire accepted/leaked", e)
		}
	}
	if r, e := ReadBatch(brokenReader{}); e == nil || !reflect.DeepEqual(r, BatchResult{}) || strings.Contains(e.Error(), "PRIVATE") {
		t.Fatal("reader failure leaked")
	}
	exact := good + strings.Repeat(" ", 1048576-len(good))
	if _, e := ReadBatch(strings.NewReader(exact)); e != nil {
		t.Fatal("exact wire rejected", e)
	}
	counter := &countingReader{reader: strings.NewReader(exact + strings.Repeat(" ", 500))}
	if r, e := ReadBatch(counter); e == nil || !reflect.DeepEqual(r, BatchResult{}) || counter.n != 1048577 {
		t.Fatal("bounded read failed", counter.n, e)
	}
	counter = &countingReader{reader: strings.NewReader(good)}
	if _, e := ReadBatchProfile(counter, "PRIVATE"); e == nil || counter.n != 0 || strings.Contains(e.Error(), "PRIVATE") {
		t.Fatal("profile rejected after read/leaked")
	}
}

func TestBatchAdvisoryAndAggregateBudgets(t *testing.T) {
	for _, n := range []int{16, 17} {
		ads := make([]string, n)
		for i := range ads {
			ads[i] = literalAd
		}
		r, e := ReadBatch(strings.NewReader(batchPacket(literalLock, ads...)))
		if n == 16 {
			if e != nil || r.CandidateCount != 16 || len(r.Advisories) != 16 {
				t.Fatal("advisory exact cap", e)
			}
		} else if e == nil || !reflect.DeepEqual(r, BatchResult{}) {
			t.Fatal("advisory cap bypass")
		}
	}
	makeAd := func(n int) string {
		return `{"id":"OWNED","modified":"2026-01-01T00:00:00Z","affected":[` + strings.TrimSuffix(strings.Repeat(`{"package":{"ecosystem":"npm","name":"private-marker-package"},"versions":["1.2.3"]},`, n), ",") + `]}`
	}
	records := []string{}
	for i := 0; i < 64; i++ {
		records = append(records, fmt.Sprintf(`"node_modules/%03d":{"name":"private-marker-package","version":"1.2.3"}`, i))
	}
	lock := `{"lockfileVersion":3,"packages":{` + strings.Join(records, ",") + `}}`
	for _, n := range []int{32, 33} {
		r, e := ReadBatch(strings.NewReader(batchPacket(lock, makeAd(32), makeAd(n))))
		if n == 32 {
			if e != nil || r.LockedEntries != 64 || r.CandidateCount != 4096 || len(r.Advisories[0].Report.Evaluations) != 2048 || len(r.Advisories[1].Report.Evaluations) != 2048 {
				t.Fatal("aggregate exact cap", e)
			}
		} else if e == nil || !reflect.DeepEqual(r, BatchResult{}) {
			t.Fatal("aggregate affected cap bypass")
		}
	}
	badLate := `{"affected":[null]}`
	if r, e := ReadBatch(strings.NewReader(batchPacket(literalLock, makeAd(64), badLate))); e == nil || !reflect.DeepEqual(r, BatchResult{}) {
		t.Fatal("invalid late record evaded global budget")
	}
	overLock := strings.Replace(lock, `"packages":{`, `"packages":{"":{},`, 1)
	if r, e := ReadBatch(strings.NewReader(batchPacket(overLock, literalAd))); e == nil || !reflect.DeepEqual(r, BatchResult{}) {
		t.Fatal("root record budget omitted")
	}
	excessive := `{"id":"OWNED","modified":"2026-01-01T00:00:00Z","affected":[{"versions":[` + strings.Repeat(`"",`, 20000) + `""]}]}`
	if r, e := ReadBatch(strings.NewReader(batchPacket(literalLock, literalAd, excessive))); e == nil || !reflect.DeepEqual(r, BatchResult{}) {
		t.Fatal("nested guard swallowed as advisory gap")
	}
}

func TestBatchDeterministicAndOwnedReports(t *testing.T) {
	input := batchPacket(literalLock, literalAd, literalAd)
	a, e := ReadBatch(strings.NewReader(input))
	if e != nil {
		t.Fatal(e)
	}
	b, e := ReadBatch(strings.NewReader(input))
	if e != nil || !reflect.DeepEqual(a, b) {
		t.Fatal("nondeterministic batch", e)
	}
	a.Advisories[0].Report.Evaluations[0].VersionOutcome = "changed"
	if a.Advisories[1].Report.Evaluations[0].VersionOutcome != "match" || b.Advisories[0].Report.Evaluations[0].VersionOutcome != "match" {
		t.Fatal("shared report backing")
	}
}
