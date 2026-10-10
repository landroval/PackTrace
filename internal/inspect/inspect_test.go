package inspect

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
)

const privateName = "private-marker-package"
const literalLock = `{"lockfileVersion":3,"packages":{"":{},"node_modules/PRIVATE-PATH":{"name":"private-marker-package","version":"1.2.3","resolved":"https://user:PRIVATE-SECRET@internal.example/a"}}}`
const literalAd = `{"id":"PRIVATE-AD-ID","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"private-marker-package"},"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]}]}`

func packet(lock, ad string) string { return `{"lockfile":` + lock + `,"advisory":` + ad + `}` }

func TestInspectOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name, lock, ad, outcome, withdrawal string
		candidates                          int
		full                                bool
	}{
		{"positive", literalLock, literalAd, "match", "not-declared", 1, true},
		{"fixed", strings.Replace(literalLock, `"1.2.3"`, `"2.0.0"`, 1), literalAd, "no-match", "not-declared", 0, true},
		{"unsupported", literalLock, strings.Replace(literalAd, `"SEMVER"`, `"ECOSYSTEM"`, 1), "indeterminate", "not-declared", 0, false},
		{"withdrawn", literalLock, strings.Replace(literalAd, `"modified":`, `"withdrawn":"2026-01-02T00:00:00Z","modified":`, 1), "match", "reported", 0, true},
		{"unknown-withdrawal", literalLock, strings.Replace(literalAd, `"modified":`, `"withdrawn":null,"modified":`, 1), "match", "unknown", 0, true},
		{"missing-name", strings.Replace(literalLock, `"name":"private-marker-package",`, "", 1), literalAd, "match", "not-declared", 0, true},
		{"bad-version", strings.Replace(literalLock, `"1.2.3"`, `"PRIVATE-INVALID"`, 1), literalAd, "not-evaluated", "not-declared", 0, false},
		{"link", strings.Replace(literalLock, `"name":`, `"link":true,"name":`, 1), literalAd, "match", "not-declared", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Read(strings.NewReader(packet(tc.lock, tc.ad)))
			if err != nil {
				t.Fatal(err)
			}
			if got.Schema != "packtrace.inspect.v1" || !got.Experimental || got.Scope != "supplied-metadata" || got.Privacy != "portable" || got.ExitCode != 3 || len(got.Inventory) != 1 || len(got.Evaluations) != 1 || len(got.Candidates) != tc.candidates || got.Findings == nil || len(got.Findings) != 0 {
				t.Fatal("wrong scope/result", got)
			}
			e := got.Evaluations[0]
			if e.PackageIndex != 0 || e.AffectedIndex != 0 || e.VersionOutcome != tc.outcome || e.VersionFullyEvaluated != tc.full || e.Withdrawal != tc.withdrawal {
				t.Fatal("evidence lost", e)
			}
			if tc.name == "positive" && (got.Candidates[0].EnforcementEligible || got.Candidates[0].Kind != "identity-version-only") {
				t.Fatal("candidate promoted")
			}
			for _, format := range []string{"terminal", "json"} {
				b, err := Render(got, format)
				if err != nil {
					t.Fatal(err)
				}
				for _, secret := range []string{privateName, "PRIVATE", "1.2.3", "2.0.0", "https://", fmt.Sprintf("%x", sha256.Sum256([]byte(tc.lock))), fmt.Sprintf("%x", sha256.Sum256([]byte(tc.ad)))} {
					if bytes.Contains(b, []byte(secret)) {
						t.Fatal("portable leak", secret)
					}
				}
				if format == "terminal" && tc.name == "positive" && !bytes.Contains(b, []byte("support: version[-1] range[0]")) {
					t.Fatal("terminal support locator lost")
				}
				if format == "json" {
					var decoded Result
					if json.Unmarshal(b, &decoded) != nil || !reflect.DeepEqual(decoded, got) {
						t.Fatal("JSON differs from model")
					}
				} else if !bytes.Contains(b, []byte(fmt.Sprintf("Candidates: %d", tc.candidates))) || !bytes.Contains(b, []byte("Required coverage: incomplete")) {
					t.Fatal("terminal differs", string(b))
				}
			}
		})
	}
}

func TestInspectSameSlotAndEmpty(t *testing.T) {
	other := `{"id":"OWNED","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"other-package"},"versions":["1.2.3"]},{"package":{"ecosystem":"npm","name":"private-marker-package"},"versions":["9.9.9"]}]}`
	r, err := Read(strings.NewReader(packet(literalLock, other)))
	if err != nil || len(r.Candidates) != 0 || len(r.Evaluations) != 2 || r.Evaluations[0].IdentityComparison != "different" || r.Evaluations[1].IdentityComparison != "equal" || r.Evaluations[0].VersionOutcome != "match" || r.Evaluations[1].VersionOutcome != "no-match" {
		t.Fatal("cross-slot correlation", r, err)
	}
	for _, p := range []string{packet(`{"lockfileVersion":3,"packages":{"":{}}}`, literalAd), packet(literalLock, `{"id":"OWNED","modified":"2026-01-01T00:00:00Z","affected":[]}`)} {
		r, err := Read(strings.NewReader(p))
		if err != nil || r.ExitCode != 3 || len(r.Candidates) != 0 {
			t.Fatal(r, err)
		}
		for _, c := range r.Coverage {
			if c.Check == "version-conditions" && c.Outcome == "completed" {
				t.Fatal("empty scope completed")
			}
		}
	}
}

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, errors.New("PRIVATE-READ") }

type countingReader struct {
	n      int
	reader io.Reader
}

func (r *countingReader) Read(p []byte) (int, error) { n, e := r.reader.Read(p); r.n += n; return n, e }
func TestInspectFailuresAndWireLimit(t *testing.T) {
	for _, p := range []string{"", `[]`, `null`, packet(literalLock, literalAd) + `{}`, `{"lockfile":null,"advisory":{}}`, `{"lockfile":{},"advisory":null}`, `{"lockfile":{}}`, strings.Replace(packet(literalLock, literalAd), `"lockfile":`, `"PRIVATE":true,"lockfile":`, 1), strings.Replace(packet(literalLock, literalAd), `"name":"private-marker-package"`, `"name":"private-marker-package","name":"PRIVATE"`, 1), strings.Replace(packet(literalLock, literalAd), `"lockfileVersion":3`, `"lockfileVersion":1`, 1), strings.Replace(packet(literalLock, literalAd), `"id":"PRIVATE-AD-ID"`, `"id":"\ud800"`, 1), string([]byte{0xff})} {
		got, err := Read(strings.NewReader(p))
		if err == nil || !reflect.DeepEqual(got, Result{}) || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("invalid input accepted/leaked", err)
		}
	}
	if got, err := Read(brokenReader{}); err == nil || !reflect.DeepEqual(got, Result{}) || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("read error hidden/leaked")
	}
	good := packet(literalLock, literalAd)
	exact := good + strings.Repeat(" ", 1048576-len(good))
	if _, err := Read(strings.NewReader(exact)); err != nil {
		t.Fatal("exact wire bound rejected", err)
	}
	counter := &countingReader{reader: strings.NewReader(exact + strings.Repeat(" ", 10000))}
	if got, err := Read(counter); err == nil || !reflect.DeepEqual(got, Result{}) || counter.n != 1048577 {
		t.Fatal("wire limit/read ceiling", counter.n, err)
	}
	if _, err := Read(strings.NewReader(strings.Repeat(`{"a":`, 129) + `0` + strings.Repeat(`}`, 129))); err == nil {
		t.Fatal("depth limit ignored")
	}
}

func TestInspectRecordAndAffectedLimits(t *testing.T) {
	for _, n := range []int{64, 65} {
		var records, affected []string
		for i := 0; i < n; i++ {
			records = append(records, fmt.Sprintf(`"node_modules/%03d":{"name":"private-marker-package","version":"1.2.3"}`, i))
			affected = append(affected, `{"package":{"ecosystem":"npm","name":"private-marker-package"},"versions":["1.2.3"]}`)
		}
		lock := `{"lockfileVersion":3,"packages":{` + strings.Join(records, ",") + `}}`
		ad := `{"id":"OWNED","modified":"2026-01-01T00:00:00Z","affected":[` + strings.Join(affected, ",") + `]}`
		got, err := Read(strings.NewReader(packet(lock, ad)))
		if n == 64 {
			if err != nil || len(got.Inventory) != 64 || len(got.Evaluations) != 4096 || len(got.Candidates) != 4096 {
				t.Fatal("exact scope bound", len(got.Evaluations), err)
			}
		} else if err == nil || !reflect.DeepEqual(got, Result{}) {
			t.Fatal("overflow scope accepted")
		}
		if n == 65 {
			for _, p := range []string{packet(lock, literalAd), packet(literalLock, ad)} {
				if _, err := Read(strings.NewReader(p)); err == nil {
					t.Fatal("independent scope cap ignored")
				}
			}
		}
	}
}

func TestInspectAdditionalShapes(t *testing.T) {
	for _, tc := range []struct {
		name, lock, ad string
		candidates     int
	}{
		{"npm-v2", strings.Replace(literalLock, `"lockfileVersion":3`, `"lockfileVersion":2`, 1), literalAd, 1},
		{"null-version", strings.Replace(literalLock, `"version":"1.2.3"`, `"version":null`, 1), literalAd, 0},
		{"invalid-version-type", strings.Replace(literalLock, `"version":"1.2.3"`, `"version":3`, 1), literalAd, 0},
		{"affected-absent", literalLock, `{"id":"OWNED","modified":"2026-01-01T00:00:00Z"}`, 0},
		{"affected-null", literalLock, `{"id":"OWNED","modified":"2026-01-01T00:00:00Z","affected":null}`, 0},
		{"affected-bad-type", literalLock, `{"id":"OWNED","modified":"2026-01-01T00:00:00Z","affected":false}`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Read(strings.NewReader(packet(tc.lock, tc.ad)))
			if err != nil || got.ExitCode != 3 || len(got.Inventory) != 1 || len(got.Candidates) != tc.candidates {
				t.Fatal("shape not retained", got, err)
			}
		})
	}
	versions := strings.Repeat(`"",`, 20000) + `""`
	ad := `{"id":"OWNED","modified":"2026-01-01T00:00:00Z","affected":[{"versions":[` + versions + `]}]}`
	lock := strings.Replace(literalLock, `"1.2.3"`, `"INVALID"`, 1)
	if _, err := Read(strings.NewReader(packet(lock, ad))); err == nil {
		t.Fatal("nested guard bypassed on unusable query")
	}
	for _, data := range []string{strings.Replace(packet(literalLock, literalAd), `"modified":`, `"PRIVATE":1,"PRIVATE":2,"modified":`, 1), strings.Replace(packet(literalLock, literalAd), `"id":"PRIVATE-AD-ID"`, `"id":"\udc00"`, 1)} {
		if _, err := Read(strings.NewReader(data)); err == nil {
			t.Fatal("duplicate/surrogate bypass")
		}
	}
}

func TestInspectDeterministic(t *testing.T) {
	a, e := Read(strings.NewReader(packet(literalLock, literalAd)))
	if e != nil {
		t.Fatal(e)
	}
	b, e := Read(strings.NewReader(packet(literalLock, literalAd)))
	if e != nil || !reflect.DeepEqual(a, b) {
		t.Fatal("nondeterministic")
	}
	a.Inventory[0].Reference = "mutated"
	c, e := Read(strings.NewReader(packet(literalLock, literalAd)))
	if e != nil || !reflect.DeepEqual(b, c) {
		t.Fatal("shared result")
	}
}
