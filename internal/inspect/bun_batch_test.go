package inspect

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func bunBatchPacket(t *testing.T, text string, ads ...string) string {
	t.Helper()
	raw := make([]json.RawMessage, len(ads))
	for i, ad := range ads {
		raw[i] = json.RawMessage(ad)
	}
	data, e := json.Marshal(map[string]any{"lockfile_text": text, "advisories": raw})
	if e != nil {
		t.Fatal(e)
	}
	return string(data)
}

// Catches dropping valid siblings, mixing references or leaking raw tuple claims.
func TestBunBatchRetainsSiblingEvidence(t *testing.T) {
	r, e := ReadBunBatch(strings.NewReader(bunBatchPacket(t, bunLockText, literalAd, `{"id":1}`, literalAd)))
	if e != nil {
		t.Fatal(e)
	}
	if r.Schema != "packtrace.inspect.bun-batch.v1" || r.IdentityProfile != "" || r.Privacy != "portable" || r.LockedEntries != 1 || r.CandidateCount != 2 || len(r.Findings) != 0 || r.ExitCode != 3 {
		t.Fatal("wrong batch summary", r)
	}
	states := []string{"usable", "invalid-advisory", "usable"}
	for i, entry := range r.Advisories {
		if entry.Reference != fmt.Sprintf("advisory-%d", i) || entry.State != states[i] || (entry.Report != nil) != (i != 1) {
			t.Fatal("position/state lost", i, entry)
		}
		if entry.Report != nil && (entry.Report.AdvisoryReference != entry.Reference || entry.Report.Schema != "packtrace.inspect.bun.v1" || entry.Report.Inventory[0].TupleKind != "npm") {
			t.Fatal("nested Bun report not rebound", entry.Report)
		}
	}
	if r.Coverage[0].Check != "advisory-records" || r.Coverage[0].Outcome != "incomplete" {
		t.Fatal("unusable sibling hidden", r.Coverage)
	}
	for _, f := range []string{"terminal", "json"} {
		b, e := RenderBatch(r, f)
		if e != nil {
			t.Fatal(e)
		}
		for _, secret := range []string{"PRIVATE", "private-marker-package", "1.2.3", "lockfile_text", "identity_profile: explicit"} {
			if strings.Contains(string(b), secret) {
				t.Fatal("portable leak", f, secret)
			}
		}
	}
}

func TestBunBatchAllUsableAndAllInvalid(t *testing.T) {
	r, e := ReadBunBatch(strings.NewReader(bunBatchPacket(t, bunLockText, literalAd)))
	if e != nil || r.Coverage[0].Outcome != "completed" || r.CandidateCount != 1 {
		t.Fatal("usable batch", r, e)
	}
	r, e = ReadBunBatch(strings.NewReader(bunBatchPacket(t, bunLockText, `{}`, `null`)))
	if e != nil || r.CandidateCount != 0 || r.Coverage[0].Outcome != "incomplete" || r.ExitCode != 3 {
		t.Fatal("all-unusable batch looked clean", r, e)
	}
}

func TestBunBatchStrictWireAndPrivateFailures(t *testing.T) {
	p := bunBatchPacket(t, bunLockText, literalAd)
	cases := map[string]string{
		"null":              `null`,
		"array":             `[]`,
		"no-advisories":     `{"lockfile_text":"x"}`,
		"extra":             strings.Replace(p, `"advisories":`, `"extra":1,"advisories":`, 1),
		"duplicate":         strings.Replace(p, `"advisories":`, `"lockfile_text":"PRIVATE","advisories":`, 1),
		"empty-advisories":  `{"lockfile_text":"PRIVATE","advisories":[]}`,
		"advisories-object": `{"lockfile_text":"PRIVATE","advisories":{}}`,
		"text-null":         `{"lockfile_text":null,"advisories":[{}]}`,
		"text-number":       `{"lockfile_text":42,"advisories":[{}]}`,
		"text-empty":        `{"lockfile_text":"","advisories":[{}]}`,
		"lockfile-object":   `{"lockfile":{},"advisories":[{}]}`,
		"invalid-bun-lock":  bunBatchPacket(t, "PRIVATE", literalAd),
		"trailing":          p + "{}",
		"lone-surrogate":    `{"lockfile_text":"\ud800","advisories":[{}]}`,
		"invalid-utf8":      string([]byte{0xff}),
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			r, e := ReadBunBatch(strings.NewReader(bad))
			if e == nil || !reflect.DeepEqual(r, BatchResult{}) || !strings.HasPrefix(e.Error(), "inspect-bun-batch:") || strings.Contains(e.Error(), "PRIVATE") {
				t.Fatal("fatal/private input", e)
			}
		})
	}
	if r, e := ReadBunBatch(brokenReader{}); e == nil || e.Error() != "inspect-bun-batch: read-failed" || !reflect.DeepEqual(r, BatchResult{}) {
		t.Fatal("reader failure", e)
	}
	for _, n := range []int{1_048_576, 1_048_577} {
		_, e := ReadBunBatch(strings.NewReader(p + strings.Repeat(" ", n-len(p))))
		if (e != nil) != (n == 1_048_577) || (e != nil && e.Error() != "inspect-bun-batch: limit-exceeded") {
			t.Fatal("wire boundary", n, e)
		}
	}
	counter := &bunReadCounter{}
	if _, e := ReadBunBatch(counter); e == nil || counter.n != 1_048_577 {
		t.Fatal("unbounded wire read", counter.n, e)
	}
}

func TestBunBatchBudgets(t *testing.T) {
	makeAd := func(n int) string {
		return `{"id":"OWNED","modified":"2026-01-01T00:00:00Z","affected":[` + strings.TrimSuffix(strings.Repeat(`{"package":{"ecosystem":"npm","name":"private-marker-package"},"versions":["1.2.3"]},`, n), ",") + `]}`
	}
	makeLock := func(packages, workspaces int) string {
		p, w := []string{}, []string{}
		for i := range packages {
			p = append(p, fmt.Sprintf(`"%03d":["private-marker-package@1.2.3","",{},"digest"]`, i))
		}
		for i := range workspaces {
			w = append(w, fmt.Sprintf(`"ws/%03d":{}`, i))
		}
		return `{"lockfileVersion":1,"workspaces":{` + strings.Join(w, ",") + `},"packages":{` + strings.Join(p, ",") + `}}`
	}
	expectLimit := func(t *testing.T, packet string) {
		t.Helper()
		r, e := ReadBunBatch(strings.NewReader(packet))
		if e == nil || e.Error() != "inspect-bun-batch: limit-exceeded" || !reflect.DeepEqual(r, BatchResult{}) {
			t.Fatal("bound bypassed", e)
		}
	}
	t.Run("advisories", func(t *testing.T) {
		ads := make([]string, 16)
		for i := range ads {
			ads[i] = literalAd
		}
		if r, e := ReadBunBatch(strings.NewReader(bunBatchPacket(t, bunLockText, ads...))); e != nil || len(r.Advisories) != 16 {
			t.Fatal("advisory exact cap", e)
		}
		expectLimit(t, bunBatchPacket(t, bunLockText, append(ads, literalAd)...))
	})
	t.Run("lockfile", func(t *testing.T) {
		if r, e := ReadBunBatch(strings.NewReader(bunBatchPacket(t, makeLock(64, 64), literalAd))); e != nil || r.LockedEntries != 64 {
			t.Fatal("lockfile exact caps", e)
		}
		expectLimit(t, bunBatchPacket(t, makeLock(65, 0), literalAd))
		expectLimit(t, bunBatchPacket(t, makeLock(1, 65), literalAd))
	})
	t.Run("aggregate-slots", func(t *testing.T) {
		r, e := ReadBunBatch(strings.NewReader(bunBatchPacket(t, makeLock(64, 0), makeAd(32), makeAd(32))))
		if e != nil || r.CandidateCount != 4096 || len(r.Advisories[1].Report.Evaluations) != 2048 {
			t.Fatal("aggregate exact cap", e)
		}
		expectLimit(t, bunBatchPacket(t, makeLock(64, 0), makeAd(32), makeAd(33)))
		expectLimit(t, bunBatchPacket(t, bunLockText, makeAd(64), `{"affected":[null]}`))
	})
	t.Run("root-not-counted", func(t *testing.T) {
		text := strings.Replace(makeLock(63, 0), `"packages":{`, `"packages":{"":["@root:",{}],`, 1)
		if r, e := ReadBunBatch(strings.NewReader(bunBatchPacket(t, text, literalAd))); e != nil || r.LockedEntries != 63 {
			t.Fatal("root tuple counted as locked entry", e)
		}
	})
}

func TestBunBatchDeterministic(t *testing.T) {
	p := bunBatchPacket(t, bunLockText, literalAd, literalAd)
	a, e1 := ReadBunBatch(strings.NewReader(p))
	b, e2 := ReadBunBatch(strings.NewReader(p))
	if e1 != nil || e2 != nil || !reflect.DeepEqual(a, b) {
		t.Fatal("nondeterministic batch")
	}
	a.Advisories[0].Report.Candidates[0].Kind = "changed"
	if b.Advisories[0].Report.Candidates[0].Kind == "changed" || a.Advisories[1].Report.Candidates[0].Kind == "changed" {
		t.Fatal("duplicate advisories share reports")
	}
}
