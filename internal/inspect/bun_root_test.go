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

func bunRootEnvelope(manifest, workspaces string) []byte {
	text := `{"lockfileVersion":1,"workspaces":` + workspaces + `,"packages":{}}`
	encoded, _ := json.Marshal(text)
	return []byte(`{"manifest":` + manifest + `,"lockfile_text":` + string(encoded) + `}`)
}

func TestBunRootOutcomeSummary(t *testing.T) {
	input := bunRootEnvelope(`{"dependencies":{"same":"1","changed":"^1","monly":"*","invalid":null}}`, `{"":{"dependencies":{"same":"1","changed":"1.x","lonly":"2","invalid":"1"}}}`)
	r, err := ReadBunRoot(bytes.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if r.Schema != "packtrace.compare.bun-root.v1" || !r.Experimental || r.Scope != "supplied-root-metadata" || r.Privacy != "portable" || !r.RootPresent || r.ComparisonComplete || r.ExitCode != 3 || len(r.Groups) != 4 {
		t.Fatal("incorrect comparison scope", r)
	}
	if r.Groups[0].Counts != (BunRootCounts{Equal: 1, ManifestOnly: 1, LockOnly: 1, TextChanged: 1, Indeterminate: 1}) || r.Groups[0].ComparisonComplete {
		t.Fatal("literal five-outcome oracle failed", r.Groups[0])
	}
	for i, name := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
		if r.Groups[i].Name != name {
			t.Fatal("group order changed", r.Groups)
		}
		if i > 0 && (!r.Groups[i].ComparisonComplete || r.Groups[i].ManifestState != "absent" || r.Groups[i].LockState != "absent" || r.Groups[i].Counts != (BunRootCounts{})) {
			t.Fatal("absent declarations were not retained", r.Groups[i])
		}
	}
}

func TestBunRootPresenceAndStates(t *testing.T) {
	for _, tc := range []struct {
		name, manifest, workspaces, ms, ls string
		present, complete                  bool
		counts                             BunRootCounts
	}{
		{"missing", `{"dependencies":{"p":"1"}}`, `{}`, "", "", false, false, BunRootCounts{}},
		{"non-root", `{"dependencies":{"p":"1"}}`, `{"packages/ws":{"dependencies":{"p":"1"}}}`, "", "", false, false, BunRootCounts{}},
		{"empty-root", `{"dependencies":{"p":"1"}}`, `{"":{}}`, "value", "absent", true, true, BunRootCounts{ManifestOnly: 1}},
		{"decoded-equality", `{"dependencies":{"p":"\u005e1"}}`, `{"":{"dependencies":{"p":"^1"}}}`, "value", "value", true, true, BunRootCounts{Equal: 1}},
		{"text-not-semantics", `{"dependencies":{"p":"1.x"}}`, `{"":{"dependencies":{"p":">=1 <2"}}}`, "value", "value", true, true, BunRootCounts{TextChanged: 1}},
		{"null-group", `{"dependencies":null}`, `{"":{"dependencies":{"PRIVATE":"1"}}}`, "null", "value", true, false, BunRootCounts{}},
		{"invalid-group", `{"dependencies":{"PRIVATE":"1"}}`, `{"":{"dependencies":[]}}`, "value", "invalid-type", true, false, BunRootCounts{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := ReadBunRoot(bytes.NewReader(bunRootEnvelope(tc.manifest, tc.workspaces)))
			if err != nil {
				t.Fatal(err)
			}
			if r.RootPresent != tc.present || r.ComparisonComplete != tc.complete || r.ExitCode != 3 || r.Groups == nil {
				t.Fatal("root presence/completeness changed", r)
			}
			if !tc.present {
				if len(r.Groups) != 0 {
					t.Fatal("missing root manufactured groups", r.Groups)
				}
			} else if len(r.Groups) != 4 || r.Groups[0].ManifestState != tc.ms || r.Groups[0].LockState != tc.ls || r.Groups[0].Counts != tc.counts || r.Groups[0].ComparisonComplete != tc.complete {
				t.Fatal("source state or counts lost", r.Groups)
			}
		})
	}
}

type bunRootFailReader struct{}

func (bunRootFailReader) Read([]byte) (int, error) { return 0, errors.New("PRIVATE-READ") }

func TestBunRootPrivateFailures(t *testing.T) {
	for _, input := range [][]byte{
		nil, []byte(`[]`), []byte(`null`), []byte(`{"manifest":null,"lockfile_text":"x"}`),
		[]byte(`{"manifest":{},"lockfile_text":null}`), []byte(`{"manifest":{},"lockfile_text":""}`),
		[]byte(`{"manifest":{},"manifest":{},"lockfile_text":"x"}`), []byte(`{"manifest":{},"lockfile_text":"x","PRIVATE":1}`),
		[]byte(`{"manifest":{"dependencies":{"x":1,"x":2}},"lockfile_text":"x"}`),
		[]byte(`{"manifest":{"name":"\ud800"},"lockfile_text":"x"}`), []byte{0xff},
		append(bunRootEnvelope(`{}`, `{}`), []byte(`{}`)...),
	} {
		r, err := ReadBunRoot(bytes.NewReader(input))
		if !reflect.DeepEqual(r, BunRootResult{}) || err == nil || err.Error() != "compare-bun-root: invalid-input" {
			t.Fatal("invalid wire accepted, partial or disclosed", r, err)
		}
	}
	for _, tc := range []struct {
		reader io.Reader
		code   string
	}{
		{bunRootFailReader{}, "read-failed"},
		{strings.NewReader(`{"manifest":{},"lockfile_text":"PRIVATE"}`), "invalid-metadata"},
		{bytes.NewReader(bunRootEnvelope(`{}`, `{"":{},"":{}}`)), "invalid-metadata"},
		{strings.NewReader(strings.Repeat(`{"x":`, 129) + `0` + strings.Repeat(`}`, 129)), "limit-exceeded"},
	} {
		r, err := ReadBunRoot(tc.reader)
		if !reflect.DeepEqual(r, BunRootResult{}) || err == nil || err.Error() != "compare-bun-root: "+tc.code {
			t.Fatal("private whole-zero failure contract", r, err)
		}
	}
}

func TestBunRootOriginalJSONC(t *testing.T) {
	for _, tc := range []struct{ name, text, code string }{
		{"comments-and-trailing-commas", `{/* PRIVATE */"lockfileVersion":1,"workspaces":{"":{"dependencies":{"PRIVATE":"1",},},},"packages":{},}`, ""},
		{"inner-surrogate", `{"lockfileVersion":1,"workspaces":{"":{"name":"\ud800"}},"packages":{}}`, "invalid-metadata"},
		{"inner-depth", `{"lockfileVersion":1,"workspaces":{},"packages":{},"extra":` + strings.Repeat("[", 129) + "0" + strings.Repeat("]", 129) + "}", "limit-exceeded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := json.Marshal(tc.text)
			if err != nil {
				t.Fatal(err)
			}
			input := []byte(`{"manifest":{"dependencies":{"PRIVATE":"1"}},"lockfile_text":` + string(encoded) + `}`)
			r, err := ReadBunRoot(bytes.NewReader(input))
			if tc.code != "" {
				if err == nil || err.Error() != "compare-bun-root: "+tc.code || !reflect.DeepEqual(r, BunRootResult{}) {
					t.Fatal("inner text validation bypassed", r, err)
				}
			} else if err != nil || !r.RootPresent || !r.ComparisonComplete || len(r.Groups) != 4 || r.Groups[0].Counts != (BunRootCounts{Equal: 1}) {
				t.Fatal("original JSONC text was not interpreted", r, err)
			}
		})
	}
}

func TestBunRootLimits(t *testing.T) {
	base := bunRootEnvelope(`{}`, `{"":{}}`)
	exact := append(base, bytes.Repeat([]byte{' '}, (1<<20)-len(base))...)
	if _, err := ReadBunRoot(bytes.NewReader(exact)); err != nil {
		t.Fatal("exact wire limit rejected", err)
	}
	counter := &countingReader{reader: bytes.NewReader(append(exact, bytes.Repeat([]byte{' '}, 100)...))}
	if r, err := ReadBunRoot(counter); err == nil || err.Error() != "compare-bun-root: limit-exceeded" || counter.n != (1<<20)+1 || !reflect.DeepEqual(r, BunRootResult{}) {
		t.Fatal("wire/read cap bypassed", counter.n, r, err)
	}
	for _, n := range []int{20000, 20001} {
		declarations := make(map[string]string, n)
		for i := range n {
			declarations[fmt.Sprintf("p%05d", i)] = "1"
		}
		group, err := json.Marshal(map[string]any{"dependencies": declarations})
		if err != nil {
			t.Fatal(err)
		}
		for _, lockSide := range []bool{false, true} {
			input := bunRootEnvelope(string(group), `{"":{}}`)
			if lockSide {
				input = bunRootEnvelope(`{}`, `{"":`+string(group)+`}`)
			}
			if len(input) >= 1<<20 {
				t.Fatal("membership fixture exceeded wire cap")
			}
			r, err := ReadBunRoot(bytes.NewReader(input))
			if n == 20001 {
				if err == nil || err.Error() != "compare-bun-root: limit-exceeded" || !reflect.DeepEqual(r, BunRootResult{}) {
					t.Fatal("projection allowance bypassed", lockSide, err)
				}
			} else {
				want := BunRootCounts{ManifestOnly: 20000}
				if lockSide {
					want = BunRootCounts{LockOnly: 20000}
				}
				if err != nil || !r.ComparisonComplete || len(r.Groups) != 4 || r.Groups[0].Counts != want {
					t.Fatal("exact projection allowance rejected/truncated", lockSide, r, err)
				}
			}
		}
	}
}

func TestBunRootRenderPrivacyAndAgreement(t *testing.T) {
	input := bunRootEnvelope(`{"dependencies":{"PRIVATE-PACKAGE":"git+ssh://PRIVATE-PATH"}}`, `{"":{}}`)
	r, err := ReadBunRoot(bytes.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"terminal", "json"} {
		data, err := RenderBunRoot(r, format)
		if err != nil || len(data) == 0 || data[len(data)-1] != '\n' {
			t.Fatal("render failure", format, err)
		}
		for _, secret := range []string{"PRIVATE", "git+ssh", fmt.Sprintf("%x", sha256.Sum256(input))} {
			if bytes.Contains(data, []byte(secret)) {
				t.Fatal("portable metadata leaked", format, secret)
			}
		}
		if format == "json" {
			var decoded BunRootResult
			if json.Unmarshal(data, &decoded) != nil || !reflect.DeepEqual(decoded, r) {
				t.Fatal("JSON differs from model")
			}
		} else if !bytes.Contains(data, []byte("manifest-only=1")) || !bytes.Contains(data, []byte("Textual comparison is not scan coverage.")) || !bytes.Contains(data, []byte("Exit: 3")) {
			t.Fatal("terminal lost count/scope/exit", string(data))
		}
	}
	if _, err := RenderBunRoot(r, "PRIVATE"); err == nil || err.Error() != "compare-bun-root: invalid-format" {
		t.Fatal("invalid format accepted or leaked", err)
	}
}
