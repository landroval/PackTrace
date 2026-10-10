package demo

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const bunAd = `{"id":"PRIVATE-AD-ID","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"private-tuple-package"},"versions":["1.2.3"]}]}`

func bunText(t *testing.T, packages map[string]json.RawMessage, workspaces int) []byte {
	t.Helper()
	ws := map[string]any{}
	for i := 0; i < workspaces; i++ {
		ws[fmt.Sprint(i)] = map[string]any{}
	}
	b, e := json.Marshal(map[string]any{"lockfileVersion": 1, "workspaces": ws, "packages": packages})
	if e != nil {
		t.Fatal(e)
	}
	return append([]byte("// PRIVATE-ORIGINAL-TEXT\n"), b...)
}

// Catches key-based name inference, dropped duplicate/empty-key instances and
// converted-source digest/index bindings; expectations are source-literal.
func TestBunOriginalBindingsAndTupleIdentity(t *testing.T) {
	p := map[string]json.RawMessage{"": json.RawMessage(`["private-tuple-package@1.2.3","",{},"PRIVATE-INTEGRITY"]`), "a-root": json.RawMessage(`["@root:",{}]`), "z-other-key": json.RawMessage(`["private-tuple-package@1.2.3","PRIVATE-REGISTRY",{},"PRIVATE-INTEGRITY"]`)}
	b := bunText(t, p, 0)
	r, e := EvaluateBunMetadata(b, []byte(bunAd))
	if e != nil {
		t.Fatal(e)
	}
	if len(r.Inventory) != 2 || len(r.Candidates) != 2 || r.ExitCode != 3 || len(r.Findings) != 0 {
		t.Fatal("tuple claims/empty-key/root handling", r)
	}
	hash := sha256.Sum256(b)
	if r.Inputs.LockSHA256 != fmt.Sprintf("%x", hash) {
		t.Fatal("original Bun source binding lost")
	}
	for i, want := range []struct {
		loc   string
		index int
	}{{"", 0}, {"z-other-key", 2}} {
		o := r.Inventory[i]
		if o.Location != want.loc || o.SourceIndex != want.index || o.Name != "private-tuple-package" || o.SelectedName != o.Name || o.TupleKind != "npm" || o.IdentitySource != "bun-tuple" || o.IdentityQualification != "tuple-claim" || o.VersionQualification != "qualified" {
			t.Fatal("tuple/source state lost", o)
		}
		if r.Candidates[i].PackageIndex != i || r.Candidates[i].Kind != "bun-tuple-name-version-only" || r.Candidates[i].EnforcementEligible {
			t.Fatal("tuple promoted")
		}
	}
	p[""] = json.RawMessage(`[]`)
	if r.Inventory[0].Name != "private-tuple-package" {
		t.Fatal("result aliases source")
	}
}

// Catches treating a lexical version in an unsupported/broken tuple as npm.
func TestBunKindsRetainGapsAndValidSibling(t *testing.T) {
	for _, tc := range []struct{ name, tuple, kind string }{
		{"git", `["private-tuple-package@git+ssh://PRIVATE@host/repo",{},"tag"]`, "git"},
		{"github", `["private-tuple-package@github:PRIVATE/repo",{},"tag"]`, "github"},
		{"tarball", `["private-tuple-package@https://PRIVATE/file.tgz",{}]`, "tarball"},
		{"file", `["private-tuple-package@file:PRIVATE",{}]`, "folder"},
		{"link", `["private-tuple-package@link:PRIVATE",{}]`, "link"},
		{"workspace", `["private-tuple-package@workspace:PRIVATE"]`, "workspace"},
		{"missing-registry", `["private-tuple-package@1.2.3",{},"digest"]`, "unknown"},
		{"null-registry", `["private-tuple-package@1.2.3",null,{},"digest"]`, "unknown"},
		{"bad-info", `["private-tuple-package@1.2.3","",null,"digest"]`, "unknown"},
		{"missing-integrity", `["private-tuple-package@1.2.3","",{}]`, "unknown"},
		{"null-head", `[null]`, "unknown"}, {"numeric-head", `[42]`, "unknown"},
		{"empty-head", `[""]`, "unknown"}, {"empty-tuple", `[]`, "unknown"},
		{"bad-root", `["@root:",null]`, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := bunText(t, map[string]json.RawMessage{"a": json.RawMessage(tc.tuple), "z": json.RawMessage(`["private-tuple-package@1.2.3","",{},"digest"]`)}, 0)
			r, e := EvaluateBunMetadata(b, []byte(bunAd))
			if e != nil {
				t.Fatal(e)
			}
			if len(r.Inventory) != 2 || r.Inventory[0].TupleKind != tc.kind || r.Evaluations[0].VersionOutcome != "not-evaluated" || r.Evaluations[0].IdentityEqual || len(r.Candidates) != 1 || r.Candidates[0].PackageIndex != 1 {
				t.Fatal("unsupported tuple promoted/sibling lost", r)
			}
			for _, c := range r.Coverage {
				if c.Check == "version-conditions" && c.Outcome != "incomplete" {
					t.Fatal("gap hidden")
				}
			}
		})
	}
}

func TestBunSemantics(t *testing.T) {
	for _, tc := range []struct {
		name, head, ad, outcome string
		candidates              int
	}{
		{"scoped", "@scope/example@1.2.3", strings.ReplaceAll(bunAd, "private-tuple-package", "@scope/example"), "match", 1},
		{"invalid-semver", "private-tuple-package@latest", bunAd, "not-evaluated", 0},
		{"fixed-edge", "private-tuple-package@1.2.3", strings.Replace(bunAd, `"versions":["1.2.3"]`, `"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]`, 1), "no-match", 0},
		{"withdrawn", "private-tuple-package@1.2.3", strings.Replace(bunAd, `"modified":`, `"withdrawn":"2026-01-02T00:00:00Z","modified":`, 1), "match", 0},
		{"unknown-withdrawal", "private-tuple-package@1.2.3", strings.Replace(bunAd, `"modified":`, `"withdrawn":null,"modified":`, 1), "match", 0},
		{"cross-slot", "private-tuple-package@1.2.3", `{"id":"X","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"other"},"versions":["1.2.3"]},{"package":{"ecosystem":"npm","name":"private-tuple-package"},"versions":["9.9.9"]}]}`, "match", 0},
		{"unknown-range-sibling", "private-tuple-package@1.2.3", strings.Replace(bunAd, `"versions":["1.2.3"]`, `"versions":["1.2.3"],"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]`, 1), "match", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := json.Marshal(tc.head)
			tuple := append(append([]byte{'['}, h...), []byte(`,"",{},"digest"]`)...)
			r, e := EvaluateBunMetadata(bunText(t, map[string]json.RawMessage{"PRIVATE-KEY": tuple}, 0), []byte(tc.ad))
			if e != nil {
				t.Fatal(e)
			}
			if len(r.Candidates) != tc.candidates || r.Evaluations[0].VersionOutcome != tc.outcome {
				t.Fatal("same-slot/version/withdrawal contract", r)
			}
			if tc.name == "unknown-range-sibling" && r.Evaluations[0].VersionFullyEvaluated {
				t.Fatal("unknown sibling gap hidden")
			}
		})
	}
}

func TestBunNoVacuousCompletion(t *testing.T) {
	for _, p := range []map[string]json.RawMessage{{}, {"root": json.RawMessage(`["@root:",{}]`)}, {"unknown": json.RawMessage(`[]`)}} {
		r, e := EvaluateBunMetadata(bunText(t, p, 0), []byte(bunAd))
		if e != nil {
			t.Fatal(e)
		}
		if len(r.Candidates) != 0 || r.ExitCode != 3 {
			t.Fatal("empty scope cleared")
		}
		for _, c := range r.Coverage {
			if (c.Check == "version-conditions" || c.Check == "record-qualification") && c.Outcome != "incomplete" {
				t.Fatal("empty or unknown completed", c)
			}
		}
	}
}

func TestBunSourceBudgetsAndPrivateFailures(t *testing.T) {
	for _, tc := range []struct {
		name        string
		records, ws int
		fatal       bool
	}{{"records64", 64, 0, false}, {"records65", 65, 0, true}, {"workspaces64", 1, 64, false}, {"workspaces65", 1, 65, true}} {
		t.Run(tc.name, func(t *testing.T) {
			p := map[string]json.RawMessage{}
			for i := 0; i < tc.records; i++ {
				p[fmt.Sprint(i)] = json.RawMessage(`[]`)
			}
			r, e := EvaluateBunMetadata(bunText(t, p, tc.ws), []byte(bunAd))
			if (e != nil) != tc.fatal {
				t.Fatal("source budget evaded", e)
			}
			if tc.fatal && (r.Schema != "" || strings.Contains(e.Error(), "PRIVATE")) {
				t.Fatal("fatal partial/leak")
			}
		})
	}
	for _, b := range []string{`{"lockfileVersion":1,"workspaces":{},"packages":{"PRIVATE":42}}`, `{"lockfileVersion":1,"workspaces":{},"packages":{},"packages":{}}`, `{"lockfileVersion":1,"workspaces":{},"packages":{"x":["\ud800"]}}`} {
		r, e := EvaluateBunMetadata([]byte(b), []byte(bunAd))
		if e == nil || r.Schema != "" || strings.Contains(e.Error(), "PRIVATE") {
			t.Fatal("malformed inner input not private fatal")
		}
	}
}
