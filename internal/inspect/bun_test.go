package inspect

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
)

const bunLockText = `// PRIVATE-COMMENT
{"lockfileVersion":1,"workspaces":{},"packages":{"PRIVATE-KEY":["private-marker-package@1.2.3","https://PRIVATE-REGISTRY",{"dependencies":{"PRIVATE-DEP":"PRIVATE-REQ"}},"PRIVATE-INTEGRITY"]},}`

func bunPacket(t *testing.T, text string, advisory json.RawMessage) []byte {
	t.Helper()
	data, e := json.Marshal(map[string]any{"lockfile_text": text, "advisory": advisory})
	if e != nil {
		t.Fatal(e)
	}
	return data
}

// Catches losing tuple-kind/provenance or exporting the raw internal analysis.
func TestBunPortableKindsAndIdentity(t *testing.T) {
	p := bunPacket(t, bunLockText, json.RawMessage(literalAd))
	r, e := ReadBun(strings.NewReader(string(p)))
	if e != nil {
		t.Fatal(e)
	}
	if r.Schema != "packtrace.inspect.bun.v1" || r.IdentityProfile != "bun-npm-tuples" || r.Privacy != "portable" || r.Scope != "supplied-metadata" || len(r.Candidates) != 1 || len(r.Findings) != 0 || r.ExitCode != 3 {
		t.Fatal("wrong Bun report", r)
	}
	if r.Inventory[0].TupleKind != "npm" || r.Inventory[0].IdentitySource != "bun-tuple" || r.Inventory[0].IdentityQualification != "tuple-claim" || r.Evaluations[0].IdentityComparison != "tuple-claim-equal" || r.Candidates[0].Kind != "bun-tuple-name-version-only" {
		t.Fatal("source qualification omitted/promoted", r)
	}
	for _, f := range []string{"terminal", "json"} {
		b, e := Render(r, f)
		if e != nil {
			t.Fatal(e)
		}
		for _, secret := range []string{"PRIVATE", "private-marker-package", "1.2.3", "source_index", "source_sha256", "lock_sha256", "advisory_id", "lockfile_text"} {
			if strings.Contains(string(b), secret) {
				t.Fatal("portable leak", secret)
			}
		}
		if !strings.Contains(string(b), "npm") || !strings.Contains(string(b), "bun-tuple") || !strings.Contains(string(b), "incomplete") {
			t.Fatal("kind/provenance/gaps hidden")
		}
	}
	text := strings.Replace(bunLockText, `"https://PRIVATE-REGISTRY"`, `null`, 1)
	r, e = ReadBun(strings.NewReader(string(bunPacket(t, text, json.RawMessage(literalAd)))))
	if e != nil {
		t.Fatal(e)
	}
	if r.Inventory[0].TupleKind != "unknown" || r.Evaluations[0].IdentityComparison != "indeterminate" || len(r.Candidates) != 0 {
		t.Fatal("unknown tuple equality promoted", r)
	}
}

type bunReadCounter struct{ n int }

func (r *bunReadCounter) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	r.n += len(p)
	return len(p), nil
}

func TestBunWireAndPrivateFailures(t *testing.T) {
	p := string(bunPacket(t, bunLockText, json.RawMessage(literalAd)))
	for _, bad := range []string{`null`, `[]`, `{"lockfile_text":null,"advisory":{}}`, `{"lockfile_text":42,"advisory":{}}`, `{"lockfile_text":"PRIVATE","advisory":null}`, p + "{}", strings.Replace(p, `"advisory":`, `"extra":42,"advisory":`, 1), strings.Replace(p, `"lockfile_text":`, `"lockfile_text":"PRIVATE","lockfile_text":`, 1), `{"lockfile_text":"\ud800","advisory":{}}`, string([]byte{0xff}), string(bunPacket(t, "PRIVATE", json.RawMessage(literalAd)))} {
		r, e := ReadBun(strings.NewReader(bad))
		if e == nil || r.Schema != "" || !strings.HasPrefix(e.Error(), "inspect-bun:") || strings.Contains(e.Error(), "PRIVATE") {
			t.Fatal("fatal/private input", e)
		}
	}
	r, e := ReadBun(brokenReader{})
	if e == nil || r.Schema != "" || strings.Contains(e.Error(), "PRIVATE") {
		t.Fatal("reader failure")
	}
	for _, n := range []int{1_048_576, 1_048_577} {
		r, e := ReadBun(strings.NewReader(p + strings.Repeat(" ", n-len(p))))
		if (e != nil) != (n == 1_048_577) || (e == nil && r.ExitCode != 3) {
			t.Fatal("wire boundary", n, e)
		}
	}
	counter := &bunReadCounter{}
	_, e = ReadBun(counter)
	if e == nil || counter.n != 1_048_577 {
		t.Fatal("unbounded wire read", counter.n, e)
	}
	if _, e = Render(Result{}, "PRIVATE"); e == nil || strings.Contains(e.Error(), "PRIVATE") {
		t.Fatal("format failure")
	}
}

func TestBunAffectedPairLimitsAndEmpty(t *testing.T) {
	for _, slots := range []int{0, 64, 65} {
		ad := `{"id":"X","modified":"2026-01-01T00:00:00Z","affected":[` + strings.TrimSuffix(strings.Repeat(`{"package":{"ecosystem":"npm","name":"private-marker-package"},"versions":["1.2.3"]},`, slots), ",") + `]}`
		packages := ""
		for i := 0; i < 64; i++ {
			packages += fmt.Sprintf(`%q:["private-marker-package@1.2.3","",{},"digest"],`, fmt.Sprint(i))
		}
		text := `{"lockfileVersion":1,"workspaces":{},"packages":{` + strings.TrimSuffix(packages, ",") + `}}`
		r, e := ReadBun(strings.NewReader(string(bunPacket(t, text, json.RawMessage(ad)))))
		if (e != nil) != (slots == 65) {
			t.Fatal("affected budget", slots, e)
		}
		if e == nil && (len(r.Evaluations) != 64*slots || len(r.Candidates) != 64*slots || r.ExitCode != 3) {
			t.Fatal("pairs truncated", slots)
		}
		if slots == 0 {
			for _, c := range r.Coverage {
				if c.Check == "version-conditions" && c.Outcome != "incomplete" {
					t.Fatal("no affected vacuously complete")
				}
			}
		}
	}
	// Force inner JSONC validation rather than assuming the strict outer wire is sufficient.
	for _, text := range []string{`{"lockfileVersion":1,"workspaces":{},"packages":{"x":["\ud800"]}}`, `{"lockfileVersion":1,"workspaces":{},"packages":{},"packages":{}}`} {
		r, e := ReadBun(strings.NewReader(string(bunPacket(t, text, json.RawMessage(literalAd)))))
		if e == nil || r.Schema != "" {
			t.Fatal("invalid inner source accepted")
		}
	}
}

// Preserves source resolution state separately from whether it is a query.
func TestBunResolutionFieldStates(t *testing.T) {
	for _, tc := range []struct{ tuple, state string }{{`[]`, "absent"}, {`[null]`, "null"}, {`[42]`, "invalid-type"}, {`["private-marker-package@link:PRIVATE",{}]`, "value"}, {`["private-marker-package@1.2.3","",{},"digest"]`, "value"}} {
		text := `{"lockfileVersion":1,"workspaces":{},"packages":{"key":` + tc.tuple + `}}`
		r, e := ReadBun(strings.NewReader(string(bunPacket(t, text, json.RawMessage(literalAd)))))
		if e != nil {
			t.Fatal(e)
		}
		b, e := Render(r, "json")
		if e != nil {
			t.Fatal(e)
		}
		var public struct{ Inventory []map[string]any }
		if json.Unmarshal(b, &public) != nil || public.Inventory[0]["resolution_qualification"] != tc.state {
			t.Fatal("resolution state discarded behind query qualification", string(b))
		}
	}
}

var _ io.Reader = (*bunReadCounter)(nil)
