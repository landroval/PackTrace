package inventory

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestCompareRootOutcomes(t *testing.T) {
	cases := []struct {
		name, manifest, locked string
		ms, ls                 FieldState
		mv, lv                 string
		outcome                RequirementOutcome
	}{
		{"equal", `"^1"`, `"^1"`, FieldValue, FieldValue, "^1", "^1", RequirementEqual},
		{"decoded-equal", `"\u005e1"`, `"^1"`, FieldValue, FieldValue, "^1", "^1", RequirementEqual},
		{"empty-value", `""`, `""`, FieldValue, FieldValue, "", "", RequirementEqual},
		{"text-not-range", `"1.x"`, `">=1 <2"`, FieldValue, FieldValue, "1.x", ">=1 <2", RequirementTextChanged},
		{"whitespace", `" ^1 "`, `"^1"`, FieldValue, FieldValue, " ^1 ", "^1", RequirementTextChanged},
		{"alias", `"npm:real@^1"`, `"npm:other@^1"`, FieldValue, FieldValue, "npm:real@^1", "npm:other@^1", RequirementTextChanged},
		{"manifest-only", `""`, "", FieldValue, FieldAbsent, "", "", RequirementManifestOnly},
		{"lock-only", "", `"*"`, FieldAbsent, FieldValue, "", "*", RequirementLockOnly},
		{"null-both", `null`, `null`, FieldNull, FieldNull, "", "", RequirementIndeterminate},
		{"null-vs-absent", `null`, "", FieldNull, FieldAbsent, "", "", RequirementIndeterminate},
		{"absent-vs-invalid", "", `false`, FieldAbsent, FieldInvalidType, "", "", RequirementIndeterminate},
		{"invalid-vs-value", `{}`, `"1"`, FieldInvalidType, FieldValue, "", "1", RequirementIndeterminate},
		{"value-vs-null", `"1"`, `null`, FieldValue, FieldNull, "1", "", RequirementIndeterminate},
	}
	for _, version := range []int{2, 3} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("v%d/%s", version, tc.name), func(t *testing.T) {
				objects := [2]string{}
				for i, value := range []string{tc.manifest, tc.locked} {
					objects[i] = `{}`
					if value != "" {
						objects[i] = `{"dependencies":{"p":` + value + `}}`
					}
				}
				m, l := comparisonInputs(t, objects[0], fmt.Sprintf(`{"lockfileVersion":%d,"packages":{"":%s}}`, version, objects[1]))
				got, err := CompareRootRequirements(m, l)
				if err != nil || !got.RootPresent || len(got.Groups) != 4 {
					t.Fatal("comparison unavailable", err)
				}
				want := RequirementComparison{Name: "p", Manifest: LockField[string]{State: tc.ms, Value: tc.mv}, Locked: LockField[string]{State: tc.ls, Value: tc.lv}, Outcome: tc.outcome}
				if !reflect.DeepEqual(got.Groups[0].Entries, []RequirementComparison{want}) {
					t.Fatalf("rows: %#v", got.Groups[0].Entries)
				}
				complete := tc.outcome != RequirementIndeterminate
				if got.Complete != complete || got.Groups[0].Complete != complete {
					t.Fatal("incorrect completeness")
				}
				if got.ManifestSHA256 != m.SourceSHA256 || got.LockSHA256 != l.SourceSHA256 {
					t.Fatal("source digests lost")
				}
			})
		}
	}
}

func TestCompareRootGroupStates(t *testing.T) {
	states := []struct {
		raw   string
		state FieldState
	}{{"", FieldAbsent}, {`{}`, FieldValue}, {`null`, FieldNull}, {`[]`, FieldInvalidType}}
	for _, name := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
		for _, left := range states {
			for _, right := range states {
				t.Run(fmt.Sprintf("%s/%d/%d", name, left.state, right.state), func(t *testing.T) {
					objects := [2]string{}
					for i, raw := range []string{left.raw, right.raw} {
						objects[i] = `{}`
						if raw != "" {
							objects[i] = fmt.Sprintf(`{%q:%s}`, name, raw)
						}
					}
					m, l := comparisonInputs(t, objects[0], `{"lockfileVersion":3,"packages":{"":`+objects[1]+`}}`)
					got, err := CompareRootRequirements(m, l)
					if err != nil || !got.RootPresent || len(got.Groups) != 4 {
						t.Fatal("missing groups", err)
					}
					complete := (left.state == FieldAbsent || left.state == FieldValue) && (right.state == FieldAbsent || right.state == FieldValue)
					if got.Complete != complete {
						t.Fatal("wrong overall completeness")
					}
					for i, g := range got.Groups {
						want := RootGroupComparison{Name: m.Groups[i].Name, Complete: true, Entries: []RequirementComparison{}}
						if g.Name == name {
							want.ManifestState, want.LockState, want.Complete = left.state, right.state, complete
							if !complete {
								want.Entries = nil
							}
						}
						if !reflect.DeepEqual(g, want) {
							t.Fatalf("group: %#v; want %#v", g, want)
						}
					}
				})
			}
		}
	}
}

func TestCompareRootMissingAndEmpty(t *testing.T) {
	for _, packages := range []string{`{}`, `{"packages/ws":{"dependencies":{"p":"1"}},"node_modules/ws":{"link":true,"resolved":"packages/ws"}}`, `{"":{}}`} {
		t.Run(packages, func(t *testing.T) {
			m, l := comparisonInputs(t, `{"dependencies":{"p":"1"}}`, `{"lockfileVersion":3,"packages":`+packages+`}`)
			got, err := CompareRootRequirements(m, l)
			if err != nil {
				t.Fatal(err)
			}
			if packages == `{"":{}}` {
				if !got.RootPresent || !got.Complete || len(got.Groups) != 4 || len(got.Groups[0].Entries) != 1 || got.Groups[0].Entries[0].Outcome != RequirementManifestOnly {
					t.Fatal("empty root not compared")
				}
			} else {
				want := RootComparison{ManifestSHA256: m.SourceSHA256, LockSHA256: l.SourceSHA256}
				if !reflect.DeepEqual(got, want) {
					t.Fatal("missing root replaced or manufactured differences")
				}
			}
		})
	}
}

func TestCompareRootMixedAndOwnership(t *testing.T) {
	m, l := comparisonInputs(t, `{"dependencies":{"z":"last","p":null,"Case":"1","":""},"devDependencies":{"p":"1"},"optionalDependencies":null,"peerDependencies":{"p":"1"}}`, `{"lockfileVersion":3,"dependencies":{"legacy":{"version":"9"}},"packages":{"":{"dependencies":{"p":"2","case":"1","":""},"devDependencies":{"p":"2"},"optionalDependencies":{"unknown":"1"},"peerDependencies":{"p":"1"}},"node_modules/unrelated":{"dependencies":{"z":"not-root"}}}}`)
	before := comparisonJSON(t, []any{m, l})
	got, err := CompareRootRequirements(m, l)
	if err != nil || got.Complete || !got.RootPresent || len(got.Groups) != 4 {
		t.Fatal("lost partial comparison", err)
	}
	wantNames := []string{"", "Case", "case", "p", "z"}
	wantOutcomes := []RequirementOutcome{RequirementEqual, RequirementManifestOnly, RequirementLockOnly, RequirementIndeterminate, RequirementManifestOnly}
	if len(got.Groups[0].Entries) != len(wantNames) {
		t.Fatal("lost union members")
	}
	for i, row := range got.Groups[0].Entries {
		if row.Name != wantNames[i] || row.Outcome != wantOutcomes[i] {
			t.Fatal("name/order/outcome changed", row)
		}
	}
	if got.Groups[0].Complete || !got.Groups[1].Complete || got.Groups[1].Entries[0].Outcome != RequirementTextChanged || got.Groups[2].Complete || got.Groups[2].Entries != nil || !got.Groups[3].Complete || got.Groups[3].Entries[0].Outcome != RequirementEqual {
		t.Fatal("partial results collapsed or groups merged")
	}
	if comparisonJSON(t, []any{m, l}) != before {
		t.Fatal("inputs mutated")
	}
	resultBefore := comparisonJSON(t, got)
	m.Groups[0].Entries[0].Requirement = "changed"
	l.Records[0].Requirements[0].Entries[0].Requirement = "changed"
	m.Groups[1].Name = "changed"
	m.SourceSHA256[0] ^= 255
	l.SourceSHA256[0] ^= 255
	if comparisonJSON(t, got) != resultBefore {
		t.Fatal("output aliases inputs")
	}
	got.Groups[1].Entries[0].Manifest.Value = "changed"
	if got.Groups[3].Entries[0].Manifest.Value != "1" {
		t.Fatal("output groups alias each other")
	}
}

func TestCompareRootLayoutGuards(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*ManifestProjection, *NPMLockProjection)
	}{
		{"nil-manifest", func(m *ManifestProjection, l *NPMLockProjection) { m.Groups = nil }},
		{"nil-records", func(m *ManifestProjection, l *NPMLockProjection) { l.Records = nil }},
		{"short-root-groups", func(m *ManifestProjection, l *NPMLockProjection) {
			l.Records[0].Requirements = l.Records[0].Requirements[:3]
		}},
		{"long-manifest-groups", func(m *ManifestProjection, l *NPMLockProjection) { m.Groups = append(m.Groups, m.Groups[0]) }},
		{"wrong-manifest-name", func(m *ManifestProjection, l *NPMLockProjection) { m.Groups[0].Name = "secret-marker" }},
		{"wrong-root-name", func(m *ManifestProjection, l *NPMLockProjection) { l.Records[0].Requirements[0].Name = "secret-marker" }},
		{"wrong-root-order", func(m *ManifestProjection, l *NPMLockProjection) {
			g := l.Records[0].Requirements
			g[0], g[1] = g[1], g[0]
		}},
		{"invalid-manifest-without-root", func(m *ManifestProjection, l *NPMLockProjection) { m.Groups = nil; l.Records = []LockedRecord{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, l := comparisonInputs(t, `{}`, `{"lockfileVersion":3,"packages":{"":{}}}`)
			tc.mutate(&m, &l)
			assertComparisonError(t, m, l, "invalid-shape")
		})
	}
}

func TestCompareRootMembershipLimits(t *testing.T) {
	// Valid producer outputs: disjoint names and repeated names across two groups.
	left, right := map[string]any{}, map[string]any{}
	for _, group := range []string{"dependencies", "peerDependencies"} {
		a, b := map[string]string{}, map[string]string{}
		for i := 0; i < 10_000; i++ {
			a[fmt.Sprintf("a%05d", i)] = "1"
			b[fmt.Sprintf("b%05d", i)] = "2"
		}
		left[group], right[group] = a, b
	}
	m, l := comparisonInputs(t, comparisonJSON(t, left), `{"lockfileVersion":3,"packages":{"":`+comparisonJSON(t, right)+`}}`)
	t.Run("40000-union", func(t *testing.T) {
		got, err := CompareRootRequirements(m, l)
		if err != nil || !got.Complete || len(got.Groups) != 4 {
			t.Fatal("bounded maximum rejected", err)
		}
		total := 0
		for _, g := range got.Groups {
			total += len(g.Entries)
			for i, row := range g.Entries {
				prefix, index, outcome := "a", i, RequirementManifestOnly
				if i >= 10_000 {
					prefix, index, outcome = "b", i-10_000, RequirementLockOnly
				}
				if row.Name != fmt.Sprintf("%s%05d", prefix, index) || row.Outcome != outcome {
					t.Fatal("union reordered or truncated")
				}
			}
		}
		if total != 40_000 {
			t.Fatal("wrong union size", total)
		}
	})
	for _, side := range []string{"manifest", "lock"} {
		t.Run(side+"-20001", func(t *testing.T) {
			// Deliberately exceed successful producers' contracts to exercise guards.
			if side == "manifest" {
				copyM := m
				copyM.Groups = append([]DependencyGroup(nil), m.Groups...)
				copyM.Groups[2].Entries = []DeclaredDependency{{Name: "late", State: FieldNull}}
				copyM.Groups[2].State = FieldValue
				assertComparisonError(t, copyM, l, "limit-exceeded")
			} else {
				copyL := l
				copyL.Records = append([]LockedRecord(nil), l.Records...)
				copyL.Records[0].Requirements = append([]DependencyGroup(nil), l.Records[0].Requirements...)
				copyL.Records[0].Requirements[2].Entries = []DeclaredDependency{{Name: "late", State: FieldInvalidType}}
				copyL.Records[0].Requirements[2].State = FieldValue
				assertComparisonError(t, m, copyL, "limit-exceeded")
			}
		})
	}
}

func comparisonInputs(t *testing.T, manifest, lock string) (ManifestProjection, NPMLockProjection) {
	t.Helper()
	md, err := ParseManifest([]byte(manifest))
	if err != nil {
		t.Fatal(err)
	}
	m, err := ProjectManifest(md)
	if err != nil {
		t.Fatal(err)
	}
	ld, err := ParseNPMLock([]byte(lock))
	if err != nil {
		t.Fatal(err)
	}
	l, err := ProjectNPMLock(ld)
	if err != nil {
		t.Fatal(err)
	}
	return m, l
}

func comparisonJSON(t *testing.T, value any) string {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func assertComparisonError(t *testing.T, m ManifestProjection, l NPMLockProjection, code string) {
	t.Helper()
	got, err := CompareRootRequirements(m, l)
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Code != code || err.Error() != "inventory: "+code || !reflect.DeepEqual(got, RootComparison{}) {
		t.Fatalf("want zero result and %s, got %#v, %v", code, got, err)
	}
}
