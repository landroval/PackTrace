package inventory

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestCompareBunRootOutcomes(t *testing.T) {
	cases := []struct {
		name, manifest, locked string
		ms, ls                 FieldState
		mv, lv                 string
		outcome                RequirementOutcome
	}{
		{"equal", `"^1"`, `"^1"`, FieldValue, FieldValue, "^1", "^1", RequirementEqual},
		{"decoded-equal", `"^1"`, `"^1"`, FieldValue, FieldValue, "^1", "^1", RequirementEqual},
		{"text-not-range", `"1.x"`, `">=1 <2"`, FieldValue, FieldValue, "1.x", ">=1 <2", RequirementTextChanged},
		{"workspace-protocol", `"workspace:*"`, `"workspace:^"`, FieldValue, FieldValue, "workspace:*", "workspace:^", RequirementTextChanged},
		{"manifest-only", `""`, "", FieldValue, FieldAbsent, "", "", RequirementManifestOnly},
		{"lock-only", "", `"*"`, FieldAbsent, FieldValue, "", "*", RequirementLockOnly},
		{"null-vs-absent", `null`, "", FieldNull, FieldAbsent, "", "", RequirementIndeterminate},
		{"value-vs-invalid", `"1"`, `false`, FieldValue, FieldInvalidType, "1", "", RequirementIndeterminate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			objects := [2]string{}
			for i, value := range []string{tc.manifest, tc.locked} {
				objects[i] = `{}`
				if value != "" {
					objects[i] = `{"dependencies":{"p":` + value + `}}`
				}
			}
			m, l := bunComparisonInputs(t, objects[0], `{"":`+objects[1]+`}`)
			got, err := CompareBunRootRequirements(m, l)
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

func TestCompareBunRootMissingAndEmpty(t *testing.T) {
	for _, workspaces := range []string{`{}`, `{"packages/ws":{"name":"ws","dependencies":{"p":"1"}}}`, `{"":{}}`} {
		t.Run(workspaces, func(t *testing.T) {
			m, l := bunComparisonInputs(t, `{"dependencies":{"p":"1"}}`, workspaces)
			got, err := CompareBunRootRequirements(m, l)
			if err != nil {
				t.Fatal(err)
			}
			if workspaces == `{"":{}}` {
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

func TestCompareBunRootIgnoresOtherWorkspaces(t *testing.T) {
	m, l := bunComparisonInputs(t, `{"dependencies":{"p":"1"}}`, `{"":{"dependencies":{"p":"1"}},"packages/a":{"name":"a","dependencies":{"p":"2","q":"1"}}}`)
	got, err := CompareBunRootRequirements(m, l)
	if err != nil || !got.Complete {
		t.Fatal("comparison unavailable", err)
	}
	want := []RequirementComparison{{Name: "p", Manifest: LockField[string]{State: FieldValue, Value: "1"}, Locked: LockField[string]{State: FieldValue, Value: "1"}, Outcome: RequirementEqual}}
	if !reflect.DeepEqual(got.Groups[0].Entries, want) {
		t.Fatalf("non-root workspace leaked: %#v", got.Groups[0].Entries)
	}
}

func TestCompareBunRootMatchesNPM(t *testing.T) {
	manifest := `{"dependencies":{"z":"last","p":null,"Case":"1","":""},"devDependencies":{"p":"1"},"optionalDependencies":null,"peerDependencies":{"p":"1"}}`
	root := `{"dependencies":{"p":"2","case":"1","":""},"devDependencies":{"p":"2"},"optionalDependencies":{"unknown":"1"},"peerDependencies":{"p":"1"}}`
	m, npm := comparisonInputs(t, manifest, `{"lockfileVersion":3,"packages":{"":`+root+`}}`)
	_, bun := bunComparisonInputs(t, manifest, `{"":`+root+`}`)
	want, err := CompareRootRequirements(m, npm)
	if err != nil {
		t.Fatal(err)
	}
	got, err := CompareBunRootRequirements(m, bun)
	if err != nil {
		t.Fatal(err)
	}
	if got.LockSHA256 != bun.SourceSHA256 {
		t.Fatal("Bun digest lost")
	}
	want.LockSHA256 = got.LockSHA256
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Bun and npm comparisons diverge:\n%#v\n%#v", got, want)
	}
}

func TestCompareBunRootOwnership(t *testing.T) {
	m, l := bunComparisonInputs(t, `{"dependencies":{"p":"1"},"peerDependencies":{"p":"1"}}`, `{"":{"dependencies":{"p":"2"},"peerDependencies":{"p":"1"}}}`)
	before := comparisonJSON(t, []any{m, l})
	got, err := CompareBunRootRequirements(m, l)
	if err != nil {
		t.Fatal(err)
	}
	if comparisonJSON(t, []any{m, l}) != before {
		t.Fatal("inputs mutated")
	}
	resultBefore := comparisonJSON(t, got)
	m.Groups[0].Entries[0].Requirement = "changed"
	l.Records[0].Requirements[0].Entries[0].Requirement = "changed"
	l.SourceSHA256[0] ^= 255
	if comparisonJSON(t, got) != resultBefore {
		t.Fatal("output aliases inputs")
	}
}

func TestCompareBunRootLayoutGuards(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*ManifestProjection, *BunWorkspaceProjection)
	}{
		{"nil-manifest", func(m *ManifestProjection, l *BunWorkspaceProjection) { m.Groups = nil }},
		{"nil-records", func(m *ManifestProjection, l *BunWorkspaceProjection) { l.Records = nil }},
		{"short-root-groups", func(m *ManifestProjection, l *BunWorkspaceProjection) {
			l.Records[0].Requirements = l.Records[0].Requirements[:3]
		}},
		{"wrong-root-name", func(m *ManifestProjection, l *BunWorkspaceProjection) {
			l.Records[0].Requirements[0].Name = "secret-marker"
		}},
		{"invalid-manifest-without-root", func(m *ManifestProjection, l *BunWorkspaceProjection) {
			m.Groups = nil
			l.Records = []BunWorkspaceRecord{}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, l := bunComparisonInputs(t, `{}`, `{"":{}}`)
			tc.mutate(&m, &l)
			assertBunComparisonError(t, m, l, "invalid-shape")
		})
	}
}

func TestCompareBunRootMembershipLimits(t *testing.T) {
	left, right := map[string]any{}, map[string]any{}
	for _, group := range []string{"dependencies", "peerDependencies"} {
		a, b := map[string]string{}, map[string]string{}
		for i := 0; i < 10_000; i++ {
			a[fmt.Sprintf("a%05d", i)] = "1"
			b[fmt.Sprintf("b%05d", i)] = "2"
		}
		left[group], right[group] = a, b
	}
	m, l := bunComparisonInputs(t, comparisonJSON(t, left), `{"":`+comparisonJSON(t, right)+`}`)
	t.Run("40000-union", func(t *testing.T) {
		got, err := CompareBunRootRequirements(m, l)
		if err != nil || !got.Complete {
			t.Fatal("bounded maximum rejected", err)
		}
		total := 0
		for _, g := range got.Groups {
			total += len(g.Entries)
		}
		if total != 40_000 {
			t.Fatal("wrong union size", total)
		}
	})
	t.Run("lock-20001", func(t *testing.T) {
		// Deliberately exceed the producer's contract to exercise the guard.
		copyL := l
		copyL.Records = append([]BunWorkspaceRecord(nil), l.Records...)
		copyL.Records[0].Requirements = append([]DependencyGroup(nil), l.Records[0].Requirements...)
		copyL.Records[0].Requirements[2].Entries = []DeclaredDependency{{Name: "late", State: FieldInvalidType}}
		copyL.Records[0].Requirements[2].State = FieldValue
		assertBunComparisonError(t, m, copyL, "limit-exceeded")
	})
}

func bunComparisonInputs(t *testing.T, manifest, workspaces string) (ManifestProjection, BunWorkspaceProjection) {
	t.Helper()
	md, err := ParseManifest([]byte(manifest))
	if err != nil {
		t.Fatal(err)
	}
	m, err := ProjectManifest(md)
	if err != nil {
		t.Fatal(err)
	}
	ld, err := ParseBunLock([]byte(`{"lockfileVersion":1,"workspaces":` + workspaces + `,"packages":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	l, err := ProjectBunWorkspaces(ld)
	if err != nil {
		t.Fatal(err)
	}
	return m, l
}

func assertBunComparisonError(t *testing.T, m ManifestProjection, l BunWorkspaceProjection, code string) {
	t.Helper()
	got, err := CompareBunRootRequirements(m, l)
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Code != code || !reflect.DeepEqual(got, RootComparison{}) {
		t.Fatalf("want zero result and %s, got %#v, %v", code, got, err)
	}
}
