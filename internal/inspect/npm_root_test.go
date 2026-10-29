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

func npmRootEnvelope(manifest, packages string, version int) []byte {
	return []byte(fmt.Sprintf(`{"manifest":%s,"lockfile":{"lockfileVersion":%d,"packages":%s}}`, manifest, version, packages))
}

func TestNPMRootOutcomesAndVersions(t *testing.T) {
	for _, version := range []int{2, 3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			input := npmRootEnvelope(`{"dependencies":{"same":"1","changed":"1.x","monly":"*","invalid":null}}`, `{"":{"dependencies":{"same":"1","changed":">=1 <2","lonly":"2","invalid":"1"}}}`, version)
			r, err := ReadNPMRoot(bytes.NewReader(input))
			if err != nil {
				t.Fatal(err)
			}
			if r.Schema != "packtrace.compare.npm-root.v1" || !r.Experimental || r.Scope != "supplied-root-metadata" || r.Privacy != "portable" || !r.RootPresent || r.ComparisonComplete || r.ExitCode != 3 || len(r.Groups) != 4 {
				t.Fatal("scope", r)
			}
			if r.Groups[0].Counts != (NPMRootCounts{Equal: 1, ManifestOnly: 1, LockOnly: 1, TextChanged: 1, Indeterminate: 1}) || r.Groups[0].ComparisonComplete {
				t.Fatal("five outcomes", r.Groups[0])
			}
			for i, name := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
				g := r.Groups[i]
				if g.Name != name {
					t.Fatal("group order", r.Groups)
				}
				if i > 0 && (g.ManifestState != "absent" || g.LockState != "absent" || !g.ComparisonComplete || g.Counts != (NPMRootCounts{})) {
					t.Fatal("absent group", g)
				}
			}
		})
	}
}

func TestNPMRootPresenceAndStates(t *testing.T) {
	for _, tc := range []struct {
		name, manifest, packages, ms, ls string
		present, complete                bool
		counts                           NPMRootCounts
	}{
		{"missing", `{"dependencies":{"p":"1"}}`, `{}`, "", "", false, false, NPMRootCounts{}},
		{"nonroot", `{"dependencies":{"p":"1"}}`, `{"node_modules/p":{"dependencies":{"p":"1"}}}`, "", "", false, false, NPMRootCounts{}},
		{"empty-root", `{"dependencies":{"p":"1"}}`, `{"":{}}`, "value", "absent", true, true, NPMRootCounts{ManifestOnly: 1}},
		{"decoded-equal", `{"dependencies":{"p":"\u005e1"}}`, `{"":{"dependencies":{"p":"^1"}}}`, "value", "value", true, true, NPMRootCounts{Equal: 1}},
		{"text-not-semantics", `{"dependencies":{"p":"1.x"}}`, `{"":{"dependencies":{"p":">=1 <2"}}}`, "value", "value", true, true, NPMRootCounts{TextChanged: 1}},
		{"null", `{"dependencies":null}`, `{"":{"dependencies":{"PRIVATE":"1"}}}`, "null", "value", true, false, NPMRootCounts{}},
		{"lock-null", `{"dependencies":{"PRIVATE":"1"}}`, `{"":{"dependencies":null}}`, "value", "null", true, false, NPMRootCounts{}},
		{"invalid", `{"dependencies":{"PRIVATE":"1"}}`, `{"":{"dependencies":[]}}`, "value", "invalid-type", true, false, NPMRootCounts{}},
		{"manifest-invalid", `{"dependencies":[]}`, `{"":{"dependencies":{"PRIVATE":"1"}}}`, "invalid-type", "value", true, false, NPMRootCounts{}},
		{"lock-entry-invalid", `{"dependencies":{"PRIVATE":"1"}}`, `{"":{"dependencies":{"PRIVATE":null}}}`, "value", "value", true, false, NPMRootCounts{Indeterminate: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := ReadNPMRoot(bytes.NewReader(npmRootEnvelope(tc.manifest, tc.packages, 3)))
			if err != nil {
				t.Fatal(err)
			}
			if r.RootPresent != tc.present || r.ComparisonComplete != tc.complete || r.ExitCode != 3 || r.Groups == nil {
				t.Fatal("presence", r)
			}
			if !tc.present {
				if len(r.Groups) != 0 {
					t.Fatal("nonroot fallback", r.Groups)
				}
				return
			}
			if len(r.Groups) != 4 || r.Groups[0].ManifestState != tc.ms || r.Groups[0].LockState != tc.ls || r.Groups[0].ComparisonComplete != tc.complete || r.Groups[0].Counts != tc.counts {
				t.Fatal("states", r.Groups)
			}
		})
	}
}

type npmRootFailReader struct{}

func (npmRootFailReader) Read([]byte) (int, error) { return 0, errors.New("PRIVATE-READ") }

func TestNPMRootPrivateFailures(t *testing.T) {
	for _, input := range [][]byte{
		nil, []byte(`[]`), []byte(`null`), []byte(`{"manifest":null,"lockfile":{}}`), []byte(`{"manifest":{},"lockfile":null}`), []byte(`{"manifest":{},"lockfile":[]}`),
		[]byte(`{"manifest":{},"manifest":{},"lockfile":{}}`), []byte(`{"manifest":{},"lockfile":{},"PRIVATE":1}`),
		[]byte(`{"manifest":{"dependencies":{"p":1,"p":2}},"lockfile":{}}`), []byte(`{"manifest":{},"lockfile":{"packages":{},"packages":{}}}`),
		[]byte(`{"manifest":{"name":"\ud800"},"lockfile":{}}`), []byte{0xff}, append(npmRootEnvelope(`{}`, `{}`, 3), []byte(`{}`)...),
	} {
		r, err := ReadNPMRoot(bytes.NewReader(input))
		if !reflect.DeepEqual(r, NPMRootResult{}) || err == nil || err.Error() != "compare-npm-root: invalid-input" {
			t.Fatal("invalid wire", r, err)
		}
	}
	for _, tc := range []struct {
		reader io.Reader
		code   string
	}{
		{npmRootFailReader{}, "read-failed"},
		{bytes.NewReader(npmRootEnvelope(`{}`, `{}`, 1)), "invalid-metadata"},
		{bytes.NewReader(npmRootEnvelope(`{}`, `{"":{},"":{}}`, 3)), "invalid-input"},
		{bytes.NewReader(npmRootEnvelope(`{}`, `{"":null}`, 3)), "invalid-metadata"},
		{strings.NewReader(strings.Repeat(`{"x":`, 129) + `0` + strings.Repeat(`}`, 129)), "limit-exceeded"},
	} {
		r, err := ReadNPMRoot(tc.reader)
		if !reflect.DeepEqual(r, NPMRootResult{}) || err == nil || err.Error() != "compare-npm-root: "+tc.code {
			t.Fatal("private error", r, err)
		}
	}
}

func TestNPMRootLimits(t *testing.T) {
	base := npmRootEnvelope(`{}`, `{"":{}}`, 3)
	exact := append(base, bytes.Repeat([]byte{' '}, (1<<20)-len(base))...)
	if _, err := ReadNPMRoot(bytes.NewReader(exact)); err != nil {
		t.Fatal("exact cap", err)
	}
	counter := &countingReader{reader: bytes.NewReader(append(exact, bytes.Repeat([]byte{' '}, 100)...))}
	if r, err := ReadNPMRoot(counter); err == nil || err.Error() != "compare-npm-root: limit-exceeded" || counter.n != (1<<20)+1 || !reflect.DeepEqual(r, NPMRootResult{}) {
		t.Fatal("bounded read", counter.n, r, err)
	}
	for _, n := range []int{20000, 20001} {
		declarations := make(map[string]string, n)
		for i := range n {
			declarations[fmt.Sprintf("p%05d", i)] = "1"
		}
		group, _ := json.Marshal(map[string]any{"dependencies": declarations})
		for _, side := range []string{"manifest", "root", "nonroot-records"} {
			manifest, packages := `{}`, `{"":{}}`
			switch side {
			case "manifest":
				manifest = string(group)
			case "root":
				packages = `{"":` + string(group) + `}`
			case "nonroot-records":
				records := make(map[string]any, n)
				records[""] = map[string]any{}
				for i := 0; i < n-1; i++ {
					records[fmt.Sprintf("node_modules/p%05d", i)] = map[string]any{}
				}
				raw, _ := json.Marshal(records)
				packages = string(raw)
			}
			input := npmRootEnvelope(manifest, packages, 3)
			if len(input) >= 1<<20 {
				t.Fatal("fixture too large", side, len(input))
			}
			r, err := ReadNPMRoot(bytes.NewReader(input))
			if n == 20001 {
				if err == nil || err.Error() != "compare-npm-root: limit-exceeded" || !reflect.DeepEqual(r, NPMRootResult{}) {
					t.Fatal("allowance bypass", side, err)
				}
				continue
			}
			want := NPMRootCounts{}
			if side == "manifest" {
				want.ManifestOnly = n
			}
			if side == "root" {
				want.LockOnly = n
			}
			if err != nil || !r.ComparisonComplete || len(r.Groups) != 4 || r.Groups[0].Counts != want {
				t.Fatal("allowance rejected", side, err, r.Groups)
			}
		}
	}
}

func TestNPMRootRenderPrivacyAndAgreement(t *testing.T) {
	input := npmRootEnvelope(`{"dependencies":{"PRIVATE-PACKAGE":"git+ssh://PRIVATE-PATH"}}`, `{"":{"resolved":"PRIVATE-URL","integrity":"PRIVATE-HASH"},"node_modules/PRIVATE-LOCATOR":{}}`, 3)
	r, err := ReadNPMRoot(bytes.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"terminal", "json"} {
		a, err := RenderNPMRoot(r, format)
		if err != nil || len(a) == 0 || a[len(a)-1] != '\n' {
			t.Fatal("render", err)
		}
		b, err := RenderNPMRoot(r, format)
		if err != nil || !bytes.Equal(a, b) {
			t.Fatal("nondeterministic")
		}
		for _, secret := range []string{"PRIVATE", "git+ssh", fmt.Sprintf("%x", sha256.Sum256(input))} {
			if bytes.Contains(a, []byte(secret)) {
				t.Fatal("leak", secret)
			}
		}
		if format == "json" {
			var decoded NPMRootResult
			if json.Unmarshal(a, &decoded) != nil || !reflect.DeepEqual(decoded, r) {
				t.Fatal("json mismatch")
			}
		}
		if format == "terminal" && (!bytes.Contains(a, []byte("manifest-only=1")) || !bytes.Contains(a, []byte("Textual comparison is not scan coverage.")) || !bytes.Contains(a, []byte("Exit: 3"))) {
			t.Fatal("terminal loss", string(a))
		}
	}
	if _, err := RenderNPMRoot(r, "PRIVATE"); err == nil || err.Error() != "compare-npm-root: invalid-format" {
		t.Fatal("format", err)
	}
}
