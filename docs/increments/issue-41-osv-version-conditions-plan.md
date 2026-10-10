# OSV Version Conditions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans for the proposed inline execution. Steps use checkbox syntax. Owner approval of this complete plan and explicit execution authorization are required first. Do not spawn agents or publish from this document.

**Goal:** Execute the 64 remaining OSV version-condition reference cases without converting unavailable evidence into a negative.

**Architecture:** One pure derived evaluator in `internal/intel` consumes the existing header/affected projections and opaque SemVer query. It reuses the structure checker and strict SemVer primitives, retains positional support/problems, and does not decide advisory applicability or scan coverage.

**Tech Stack:** Existing Go baseline, standard library only; no module/toolchain acquisition.

**Spec:** [Owner-approved specification](issue-41-osv-version-conditions.md). The [#15 reference contract](issue-15-osv-version-fixtures.md) travels with this plan.

## Status and global constraints

**Complete plan approved; local inline execution explicitly authorized.** The
owner approved this exact plan and authorized only its two Go files, synthetic
offline tests/vet, restored temporary mutations, evidence in these two documents
and scoped local jj commits. That initial execution authority did not include
agents, acquisition, probes, GitHub operations, CI or publication. The owner has
subsequently authorized publication under issue #41; see the handoff below.
Base is `2c1cad8653e801a1395c2e372a76979dd54c8067`; use only the `osv-version-conditions` jj workspace. Preserve the original checkout and all other workspaces/bookmarks.

- Exactly two new Go files; no existing Go/module/CLI/workflow changes.
- Existing limits: 20,000 affected slots, 20,000 version slots and combined 20,000 range/event/field units. New cumulative consumed text: inclusive 4 MiB; query/per-text strict SemVer allowance: inclusive 1 MiB.
- Fixed private errors, whole-zero fatal rejection, immutable input/source order, no inferred installed/origin/activity/coverage status.
- Unsupported ECOSYSTEM/GIT semantics remain indeterminate; no network, filesystem, clocks, real targets, package managers, external dependencies or probes.
- Publication/issue reservation, independent peer review and integration are separate. Local passing tests do not close a product capability.

## Review Focus

1. Last-affected before a later introduction must not invent affectedness at the earlier boundary: additional E01 test.
2. A transition tie beyond the query or a rejecting limit still blocks a negative: E02/E03.
3. A null optional list with a valid winning range preserves a positive but not full evaluation: E04.
4. A late per-text limit preserves an earlier list positive; cumulative failure instead returns whole-zero: Limits and Guards tests.
5. Diagnostics must retain source locators without raw unknown field names; output mutation must not change input or a fresh result: PrivacyOwnership test.

---

## Task 1: Pure version-condition evaluator

**Create:** `internal/intel/osv_version_conditions.go` and `internal/intel/osv_version_conditions_test.go`.

**Consumes:** `ParseOSVRecord`, `ProjectOSVHeader`, `ProjectOSVAffected`, `CheckOSVRangeStructure`, `ParseSemVer(string) (SemVer,error)`, `CompareSemVer(SemVer,SemVer) (int,error)`. Reuse unchanged `validateOSVRangeStructureInput`, `validOSVStructureList`, existing bounds and `ParseError` inside this package. Tests reuse existing `structureInput` and `semverTestValue` helpers.

**Produces:** `EvaluateOSVVersionConditions(OSVHeader, OSVAffectedProjection, SemVer) (OSVVersionConditions,error)` and exactly the concrete types in the specification. No operational consumer is added.

### Step 1 — Verify baseline and write tests first

- [ ] Inspect workspace parent/status; require only the two approved documents before Go changes.
- [ ] Under the offline environment below, run root tests/vet. The assessment observed 2,796 passing tests/subtests, not a minimum to fabricate if the actual tree differs.
- [ ] Create the complete test file below. No production evaluator exists yet.

```go
package intel

import (
    "encoding/json"
    "errors"
    "reflect"
    "strings"
    "testing"
)

func TestEvaluateOSVVersionConditionsReferences(t *testing.T) {
    // Rows are independently copied literal expectations from #15, not evaluator output.
    cases := []struct {
        id, fragment, query string
        want OSVVersionOutcome
        full bool
        support []OSVVersionSupport
    }{
        {"R01", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]}`, "0.9.9", OSVVersionNoMatch, true, nil},
        {"R02", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]}`, "1.0.0", OSVVersionMatch, true, []OSVVersionSupport{{-1,0}}},
        {"R03", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]}`, "2.0.0-rc.1", OSVVersionMatch, true, []OSVVersionSupport{{-1,0}}},
        {"R04", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]}`, "2.0.0", OSVVersionNoMatch, true, nil},
        {"R05", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]}`, "2.0.0+build", OSVVersionNoMatch, true, nil},
        {"R06", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"last_affected":"2.0.0"}]}]}`, "2.0.0", OSVVersionMatch, true, []OSVVersionSupport{{-1,0}}},
        {"R07", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"last_affected":"2.0.0"}]}]}`, "2.0.1-alpha", OSVVersionNoMatch, true, nil},
        {"R08", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}`, "0.0.0-0", OSVVersionMatch, true, []OSVVersionSupport{{-1,0}}},
        {"R09", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0.0.0"}]}]}`, "0.0.0-0", OSVVersionNoMatch, true, nil},
        {"R10", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}`, "999.0.0", OSVVersionMatch, true, []OSVVersionSupport{{-1,0}}},
        {"R11", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0-alpha"},{"fixed":"1.0.0"}]}]}`, "1.0.0-beta", OSVVersionMatch, true, []OSVVersionSupport{{-1,0}}},
        {"R12", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"}]}]}`, "1.0.0-rc.1", OSVVersionNoMatch, true, nil},
        {"R13", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"limit":"2.0.0"}]}]}`, "2.0.0", OSVVersionNoMatch, true, nil},
        {"R14", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"limit":"2.0.0"}]}]}`, "2.0.0-rc.1", OSVVersionMatch, true, []OSVVersionSupport{{-1,0}}},
        {"R15", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"limit":"1.0.0"},{"limit":"2.0.0"}]}]}`, "1.5.0", OSVVersionMatch, true, []OSVVersionSupport{{-1,0}}},
        {"R16", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"limit":"1.0.0"},{"limit":"2.0.0"}]}]}`, "2.0.0", OSVVersionNoMatch, true, nil},
        {"R17", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"limit":"1.0.0"},{"limit":"*"}]}]}`, "9.0.0", OSVVersionMatch, true, []OSVVersionSupport{{-1,0}}},
        {"R18", `{"ranges":[{"type":"SEMVER","events":[{"fixed":"2.0.0"},{"introduced":"1.0.0"}]}]}`, "1.5.0", OSVVersionMatch, true, []OSVVersionSupport{{-1,0}}},
        {"R19", `{"ranges":[{"type":"SEMVER","events":[{"fixed":"0.5.0"},{"introduced":"1.0.0"}]}]}`, "1.5.0", OSVVersionMatch, true, []OSVVersionSupport{{-1,0}}},
        {"R20", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"introduced":"1.5.0"},{"fixed":"2.0.0"}]}]}`, "1.7.0", OSVVersionMatch, true, []OSVVersionSupport{{-1,0}}},
        {"R21", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"},{"fixed":"2.0.0"}]}]}`, "2.0.0", OSVVersionNoMatch, true, nil},
        {"R22", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"},{"introduced":"3.0.0"},{"fixed":"4.0.0"}]}]}`, "2.5.0", OSVVersionNoMatch, true, nil},
        {"R23", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"},{"introduced":"3.0.0"},{"fixed":"4.0.0"}]}]}`, "3.0.0", OSVVersionMatch, true, []OSVVersionSupport{{-1,0}}},
        {"R24", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0+one"},{"fixed":"1.0.0+two"}]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
        {"R25", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"1.0.0"}]}]}`, "1.1.0", OSVVersionIndeterminate, false, nil},
        {"R26", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"limit":"*suffix"}]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
        {"R27", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0"}]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
        {"R28", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"limit":"0"}]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
        {"A01", `{"versions":["1.2.3"]}`, "1.2.3", OSVVersionMatch, true, []OSVVersionSupport{{0,-1}}},
        {"A02", `{"versions":["1.2.3"]}`, "1.2.4", OSVVersionNoMatch, true, nil},
        {"A03", `{"versions":["1.2.3+one"]}`, "1.2.3+two", OSVVersionNoMatch, true, nil},
        {"A04", `{"versions":["1.2.3+one"]}`, "1.2.3+one", OSVVersionMatch, true, []OSVVersionSupport{{0,-1}}},
        {"A05", `{"versions":["1.2.3","1.2.3"]}`, "1.2.3", OSVVersionMatch, true, []OSVVersionSupport{{0,-1},{1,-1}}},
        {"A06", `{"versions":["1.2.3",null]}`, "1.2.3", OSVVersionMatch, false, []OSVVersionSupport{{0,-1}}},
        {"A07", `{"versions":["1.2.3",null]}`, "1.2.4", OSVVersionIndeterminate, false, nil},
        {"A08", `{"versions":["1.2.3","v1.2.4"]}`, "1.2.4", OSVVersionIndeterminate, false, nil},
        {"A09", `{"versions":["1.2.3"],"ranges":[{"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"3.0.0"}]}]}`, "2.5.0", OSVVersionMatch, true, []OSVVersionSupport{{-1,0}}},
        {"A10", `{"versions":["1.2.3"],"ranges":[{"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"3.0.0"}]}]}`, "1.5.0", OSVVersionNoMatch, true, nil},
        {"A11", `{"versions":[],"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}`, "1.0.0", OSVVersionMatch, true, []OSVVersionSupport{{-1,0}}},
        {"A12", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}`, "2.0.0", OSVVersionNoMatch, true, nil},
        {"A13", `{"versions":["1.2.3"],"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}`, "1.2.3", OSVVersionMatch, false, []OSVVersionSupport{{0,-1}}},
        {"A14", `{"versions":["1.2.3"],"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}`, "1.2.4", OSVVersionIndeterminate, false, nil},
        {"A15", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"}]},{"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"3.0.0"}]}]}`, "2.0.0", OSVVersionMatch, true, []OSVVersionSupport{{-1,1}}},
        {"A16", `{"versions":[]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
        {"A17", `{}`, "1.0.0", OSVVersionIndeterminate, false, nil},
        {"A18", `{"versions":null}`, "1.0.0", OSVVersionIndeterminate, false, nil},
        {"A19", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"}]},{"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"3.0.0"}]}]}`, "1.5.0", OSVVersionNoMatch, true, nil},
        {"A20", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"3.0.0"}]},{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}`, "2.5.0", OSVVersionMatch, false, []OSVVersionSupport{{-1,0}}},
        {"U01", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
        {"U02", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}`, "^1.0.0", OSVVersionIndeterminate, false, nil},
        {"U03", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}`, "", OSVVersionIndeterminate, false, nil},
        {"U04", `{"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
        {"U05", `{"ranges":[{"type":"GIT","events":[{"introduced":"0"}]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
        {"U06", `{"ranges":[{"type":"OTHER","events":[{"introduced":"0"}]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
        {"U07", `{"ranges":[{"type":"SEMVER","events":null}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
        {"U08", `{"ranges":[{"type":"SEMVER","events":[]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
        {"U09", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"not-a-version"}]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
        {"U10", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0","fixed":"2.0.0"}]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
        {"U11", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"},{"last_affected":"1.5.0"}]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
        {"U12", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"future_bound":"2.0.0"}]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
        {"U13", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},null]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
        {"U14", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"limit":"not-a-version"}]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
        {"U15", `null`, "1.0.0", OSVVersionIndeterminate, false, nil},
        {"U16", `null`, "1.0.0", OSVVersionIndeterminate, false, nil},
        {"E01", `{"ranges":[{"type":"SEMVER","events":[{"last_affected":"1.0.0"},{"introduced":"2.0.0"}]}]}`, "1.0.0", OSVVersionNoMatch, true, nil},
        {"E02", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"2.0.0"}]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
        {"E03", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"2.0.0"},{"limit":"0.5.0"}]}]}`, "1.0.0", OSVVersionIndeterminate, false, nil},
        {"E04", `{"versions":null,"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}`, "1.0.0", OSVVersionMatch, false, []OSVVersionSupport{{-1,0}}},
    }
    for _, tc := range cases {
        t.Run(tc.id, func(t *testing.T) {
            rawAffected := `[` + tc.fragment + `]`
            if tc.id == "U15" { rawAffected = `null` }
            schema := `"1.9.1"`
            if tc.id == "U01" { schema = `"2.0.0"` }
            body := `{"id":"PACKTRACE-SYNTHETIC","modified":"2026-10-02T00:00:00Z","schema_version":` + schema + `,"affected":` + rawAffected + `}`
            h, a := structureInput(t, body)
            before, _ := json.Marshal(a)
            var q SemVer
            if tc.id != "U03" {
                var err error
                q, err = ParseSemVer(tc.query)
                if (err != nil) != (tc.id == "U02") { t.Fatal("unexpected query qualification") }
            }
            got, err := EvaluateOSVVersionConditions(h, a, q)
            if err != nil || got.SourceSHA256 != h.SourceSHA256 || got.HeaderSchema != h.Schema || got.Query != q || got.State != a.State { t.Fatal("lost source or fatal reference result", err) }
            after, _ := json.Marshal(a)
            if string(before) != string(after) { t.Fatal("mutated source evidence") }
            if tc.id == "U15" {
                if got.Entries != nil || len(got.Problems) != 1 || got.Problems[0].Kind != "affected-uninspectable" { t.Fatal("root absence invented a negative") }
                return
            }
            if len(got.Entries) != 1 { t.Fatal("lost affected slot") }
            d := got.Entries[0]
            if d.Index != 0 || d.State != a.Entries[0].State || d.Outcome != tc.want || d.FullyEvaluated != tc.full { t.Fatalf("want %v/%v, got %v/%v", tc.want, tc.full, d.Outcome, d.FullyEvaluated) }
            if len(d.Support) != len(tc.support) { t.Fatal("wrong positive support count") }
            blocked := tc.id == "U01" || tc.id == "U02" || tc.id == "U03" || tc.id == "U16"
            if blocked && d.Support != nil || !blocked && d.Support == nil || d.Problems == nil { t.Fatal("wrong nil/empty decision representation") }
            for i := range tc.support { if d.Support[i] != tc.support[i] { t.Fatal("wrong support locator/order") } }
            if !tc.full && len(d.Problems)+len(got.Problems) == 0 { t.Fatal("hidden evaluation gap") }
            if tc.full && len(d.Problems)+len(got.Problems) != 0 { t.Fatal("invented evaluation gap") }
            if tc.id == "U01" && got.Problems[0].Kind != "header-unsupported" { t.Fatal("lost header gate") }
            if (tc.id == "U02" || tc.id == "U03") && got.Problems[0].Kind != "query-unqualified" { t.Fatal("lost query gate") }
        })
    }
}

func versionConditionError(t *testing.T, h OSVHeader, a OSVAffectedProjection, code string) {
    t.Helper()
    got, err := EvaluateOSVVersionConditions(h, a, semverTestValue(t,"1.0.0"))
    var pe *ParseError
    if !errors.As(err,&pe) || pe.Code != code || err.Error() != "intel: "+code || !reflect.DeepEqual(got,OSVVersionConditions{}) { t.Fatal("expected whole-zero private error") }
}

func TestEvaluateOSVVersionConditionsGuards(t *testing.T) {
    for _, name := range []string{"digest","schema-enum","versions-nil","versions-state","member-state","member-residue","late-index","field-state","type-state","field-order","null-version-list","version-count","affected-count","range-count","text-limit","blocked-text-limit"} {
        t.Run(name,func(t *testing.T) {
            h,a := structureInput(t,`{"id":"private-marker","modified":"opaque","affected":[{"versions":["1.0.0"],"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`)
            code := "invalid-shape"
            switch name {
            case "digest": h.SourceSHA256[0] ^= 1
            case "schema-enum": h.Schema = 255
            case "versions-nil": a.Entries[0].Versions.Entries = nil
            case "versions-state": a.Entries[0].Versions.State = OSVFieldUnavailable
            case "member-state": a.Entries[0].Versions.Entries[0].State = OSVFieldAbsent
            case "member-residue": a.Entries[0].Versions.Entries[0] = OSVString{OSVFieldNull,"private-marker"}
            case "late-index": a.Entries[0].Ranges.Entries[0].Events.Entries[0].Index = 4
            case "field-state": a.Entries[0].Ranges.Entries[0].Events.Entries[0].Fields[0].Value.State = OSVFieldAbsent
            case "type-state": a.Entries[0].Ranges.Entries[0].Type.State = OSVFieldUnavailable
            case "field-order":
                f := a.Entries[0].Ranges.Entries[0].Events.Entries[0].Fields[0]
                a.Entries[0].Ranges.Entries[0].Events.Entries[0].Fields = []OSVEventField{f,f}
            case "null-version-list": a.Entries[0].Versions.State = OSVFieldNull
            case "version-count": a.Entries[0].Versions.Entries = make([]OSVString,20_001); code = "limit-exceeded"
            case "affected-count": a.Entries = make([]OSVAffectedEntry,20_001); code = "limit-exceeded"
            case "range-count": a.Entries[0].Ranges.Entries = make([]OSVRange,20_001); code = "limit-exceeded"
            case "text-limit", "blocked-text-limit":
                a.Entries[0].Versions.Entries = []OSVString{{OSVFieldValue,"1.0.0"},{OSVFieldValue,strings.Repeat("x",4<<20)}}
                code = "limit-exceeded"
                if name == "blocked-text-limit" { h.Schema = OSVHeaderSchemaUnknown }
            }
            versionConditionError(t,h,a,code)
        })
    }
}

func TestEvaluateOSVVersionConditionsLimits(t *testing.T) {
    t.Run("text-guard-boundary",func(t *testing.T) {
        // Fabricated layouts exercise the guard allowance, not authenticated source evidence.
        h,a := structureInput(t,`{"id":"TEST","modified":"opaque","affected":[{"versions":[]}]}`)
        a.Entries[0].Versions.Entries = []OSVString{{OSVFieldValue,strings.Repeat("x",(4<<20)-1)},{OSVFieldValue,"x"}}
        if err := validateOSVVersionConditionsInput(h,a); err != nil { t.Fatal("inclusive text guard rejected",err) }
        a.Entries[0].Versions.Entries[1].Value = "xx"
        versionConditionError(t,h,a,"limit-exceeded")
    })
    t.Run("per-text-limit-retains-positive",func(t *testing.T) {
        raw,_ := json.Marshal(map[string]any{"id":"TEST","modified":"opaque","affected":[]any{map[string]any{"versions":[]string{"1.0.0",strings.Repeat("x",(1<<20)+1)}}}})
        h,a := structureInput(t,string(raw))
        got,err := EvaluateOSVVersionConditions(h,a,semverTestValue(t,"1.0.0"))
        if err != nil || got.Entries[0].Outcome != OSVVersionMatch || got.Entries[0].FullyEvaluated || !reflect.DeepEqual(got.Entries[0].Support,[]OSVVersionSupport{{0,-1}}) || got.Entries[0].Problems[0] != (OSVVersionProblem{"version-limit",1,-1,-1}) { t.Fatal("per-text limit erased support or falsely completed") }
    })
    t.Run("bound-limit",func(t *testing.T) {
        raw,_ := json.Marshal(map[string]any{"id":"TEST","modified":"opaque","affected":[]any{map[string]any{"ranges":[]any{map[string]any{"type":"SEMVER","events":[]any{map[string]any{"introduced":"0"},map[string]any{"fixed":strings.Repeat("x",(1<<20)+1)}}}}}}})
        h,a := structureInput(t,string(raw))
        got,err := EvaluateOSVVersionConditions(h,a,semverTestValue(t,"1.0.0"))
        if err != nil || got.Entries[0].Outcome != OSVVersionIndeterminate || got.Entries[0].Problems[0] != (OSVVersionProblem{"bound-limit",-1,0,1}) { t.Fatal("bound limit hidden") }
    })
    for _, name := range []string{"affected","versions","range-units"} {
        t.Run(name+"-guard-boundary",func(t *testing.T) {
            h,a := structureInput(t,`{"id":"TEST","modified":"opaque","affected":[{"versions":[],"ranges":[]}]}`)
            switch name {
            case "affected":
                a.Entries = make([]OSVAffectedEntry,20_000)
                for i := range a.Entries { a.Entries[i] = OSVAffectedEntry{Index:i,State:OSVFieldNull} }
            case "versions":
                a.Entries[0].Versions.Entries = make([]OSVString,20_000)
                for i := range a.Entries[0].Versions.Entries { a.Entries[0].Versions.Entries[i] = OSVString{State:OSVFieldNull} }
            case "range-units":
                a.Entries[0].Ranges.Entries = make([]OSVRange,20_000)
                for i := range a.Entries[0].Ranges.Entries { a.Entries[0].Ranges.Entries[i] = OSVRange{Index:i,State:OSVFieldNull} }
            }
            if err := validateOSVVersionConditionsInput(h,a); err != nil { t.Fatal("inclusive structural guard rejected",err) }
        })
    }
}

func TestEvaluateOSVVersionConditionsPrivacyOwnership(t *testing.T) {
    h,a := structureInput(t,`{"id":"TEST","modified":"opaque","affected":[{"versions":["1.0.0","1.0.0"],"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"private-marker-field":"private-marker-value"}]}]}]}`)
    before,_ := json.Marshal(a)
    got,err := EvaluateOSVVersionConditions(h,a,semverTestValue(t,"1.0.0"))
    if err != nil || got.Entries[0].Outcome != OSVVersionMatch || got.Entries[0].FullyEvaluated { t.Fatal("wrong positive with unsupported range") }
    encoded,_ := json.Marshal(got.Entries[0].Problems)
    if strings.Contains(string(encoded),"private-marker") || !reflect.DeepEqual(got.Entries[0].Problems,[]OSVVersionProblem{{"range-structure",-1,0,-1}}) { t.Fatal("uncontrolled diagnostic or wrong locator") }
    got.Entries[0].Support[0].VersionIndex = 7
    got.Entries[0].Problems[0].Kind = "mutated-output"
    after,_ := json.Marshal(a)
    fresh,err := EvaluateOSVVersionConditions(h,a,semverTestValue(t,"1.0.0"))
    if err != nil || string(before) != string(after) || fresh.Entries[0].Support[0].VersionIndex != 0 || fresh.Entries[0].Problems[0].Kind != "range-structure" { t.Fatal("shared mutable output or source change") }
    // Tie diagnostics refer to all original events, not derived sort positions.
    h,a = structureInput(t,`{"id":"TEST","modified":"opaque","affected":[{"ranges":[{"type":"SEMVER","events":[{"fixed":"2.0.0"},{"introduced":"1.0.0"},{"introduced":"2.0.0"}]}]}]}`)
    tie,err := EvaluateOSVVersionConditions(h,a,semverTestValue(t,"1.5.0"))
    if err != nil || !reflect.DeepEqual(tie.Entries[0].Problems,[]OSVVersionProblem{{"precedence-tie",-1,0,0},{"precedence-tie",-1,0,2},{"no-usable-condition",-1,-1,-1}}) { t.Fatal("tie source locators lost") }
}
```

### Step 2 — Observe compilation RED, then behavioral RED

- [ ] Run the focused command below and retain the missing-API compilation failure separately. A compiler failure is not behavioral RED.
- [ ] Introduce the exact public type declarations from GREEN below, plus only this compiling stub:

```go
func EvaluateOSVVersionConditions(header OSVHeader, affected OSVAffectedProjection, query SemVer) (OSVVersionConditions,error) {
    return OSVVersionConditions{}, nil
}
func validateOSVVersionConditionsInput(header OSVHeader, affected OSVAffectedProjection) error {
    return nil
}
```

- [ ] Run focused tests again. Expect reference tests to fail because source/decisions are missing; guard tests must reject the fabricated empty success. Record actual counts, not predicted counts.

### Step 3 — Replace stub with complete minimal GREEN body

- [ ] Use this complete production file, without changing shared helpers or adding other files:

```go
package intel

import (
    "errors"
    "slices"
)

type OSVVersionOutcome uint8

const (
    OSVVersionIndeterminate OSVVersionOutcome = iota
    OSVVersionNoMatch
    OSVVersionMatch
)

type OSVVersionProblemKind string

type OSVVersionProblem struct {
    Kind OSVVersionProblemKind
    VersionIndex, RangeIndex, EventIndex int
}

type OSVVersionSupport struct { VersionIndex, RangeIndex int }

type OSVVersionEntryDecision struct {
    Index int
    State OSVFieldState
    Outcome OSVVersionOutcome
    FullyEvaluated bool
    Support []OSVVersionSupport
    Problems []OSVVersionProblem
}

type OSVVersionConditions struct {
    SourceSHA256 [32]byte
    HeaderSchema OSVHeaderSchemaState
    Query SemVer
    State OSVFieldState
    Entries []OSVVersionEntryDecision
    Problems []OSVVersionProblem
}

func versionConditionProblem(kind OSVVersionProblemKind, vi,ri,ei int) OSVVersionProblem {
    return OSVVersionProblem{kind,vi,ri,ei}
}

// EvaluateOSVVersionConditions derives version-only decisions from unchanged successful
// same-document projections. It does not qualify identity, origin, activity or coverage.
// Basic shape/digest guards do not authenticate fabricated evidence. Query values must
// come from ParseSemVer (or be unqualified zero); concurrent/unsafe mutation is excluded.
func EvaluateOSVVersionConditions(header OSVHeader, affected OSVAffectedProjection, query SemVer) (OSVVersionConditions,error) {
    if err := validateOSVVersionConditionsInput(header,affected); err != nil { return OSVVersionConditions{},err }
    structure,err := CheckOSVRangeStructure(header,affected)
    if err != nil { return OSVVersionConditions{},err }
    out := OSVVersionConditions{SourceSHA256:affected.SourceSHA256,HeaderSchema:header.Schema,Query:query,State:affected.State,Problems:make([]OSVVersionProblem,0)}
    if header.Schema != OSVHeaderSchemaV1Implicit && header.Schema != OSVHeaderSchemaV1Declared {
        out.Problems = append(out.Problems,versionConditionProblem("header-unsupported",-1,-1,-1))
    }
    if !query.qualified { out.Problems = append(out.Problems,versionConditionProblem("query-unqualified",-1,-1,-1)) }
    if affected.State != OSVFieldValue {
        out.Problems = append(out.Problems,versionConditionProblem("affected-uninspectable",-1,-1,-1))
        return out,nil
    }
    blocked := len(out.Problems) != 0
    out.Entries = make([]OSVVersionEntryDecision,0,len(affected.Entries))
    for i,entry := range affected.Entries {
        d := OSVVersionEntryDecision{Index:entry.Index,State:entry.State,Problems:make([]OSVVersionProblem,0)}
        if entry.State != OSVFieldValue {
            d.Problems = append(d.Problems,versionConditionProblem("affected-uninspectable",-1,-1,-1))
        } else if !blocked {
            evaluateOSVVersionEntry(&d,entry,structure.Entries[i],query)
        }
        out.Entries = append(out.Entries,d)
    }
    return out,nil
}

func validVersionConditionScalar(v OSVString, allowAbsent bool) bool {
    if v.State == OSVFieldValue { return true }
    return v.Value == "" && (v.State == OSVFieldNull || v.State == OSVFieldInvalidType || allowAbsent && v.State == OSVFieldAbsent)
}

// Validate all consumed shape/text before allocating decisions, including blocked
// headers and late slots. These bounds are work limits, not hard resident-memory caps.
func validateOSVVersionConditionsInput(h OSVHeader,a OSVAffectedProjection) error {
    bad := func() error { return &ParseError{Code:"invalid-shape"} }
    if h.Schema > OSVHeaderSchemaUnsupported { return bad() }
    if err := validateOSVRangeStructureInput(h,a); err != nil { return err }
    versions,text := maxAffectedVersions,4<<20
    consume := func(s string) error {
        if len(s) > text { return &ParseError{Code:"limit-exceeded"} }
        text -= len(s)
        return nil
    }
    for _,entry := range a.Entries {
        if entry.State != OSVFieldValue {
            if entry.Versions.State != OSVFieldUnavailable || entry.Versions.Entries != nil { return bad() }
            continue
        }
        if !validOSVStructureList(entry.Versions.State,entry.Versions.Entries == nil) { return bad() }
        if len(entry.Versions.Entries) > versions { return &ParseError{Code:"limit-exceeded"} }
        versions -= len(entry.Versions.Entries)
        for _,v := range entry.Versions.Entries {
            if !validVersionConditionScalar(v,false) { return bad() }
            if err := consume(v.Value); err != nil { return err }
        }
        for _,r := range entry.Ranges.Entries {
            if r.State != OSVFieldValue { continue }
            if !validVersionConditionScalar(r.Type,true) { return bad() }
            if err := consume(r.Type.Value); err != nil { return err }
            for _,event := range r.Events.Entries {
                if event.State != OSVFieldValue { continue }
                for i,field := range event.Fields {
                    if !validVersionConditionScalar(field.Value,false) { return bad() }
                    if err := consume(field.Name); err != nil { return err }
                    if err := consume(field.Value.Value); err != nil { return err }
                    if i > 0 && field.Name <= event.Fields[i-1].Name { return bad() }
                }
            }
        }
    }
    return nil
}

func versionConditionTextProblem(err error,prefix string) OSVVersionProblemKind {
    var pe *ParseError
    if errors.As(err,&pe) && pe.Code == "limit-exceeded" { return OSVVersionProblemKind(prefix+"-limit") }
    return OSVVersionProblemKind(prefix+"-outside-profile")
}

func evaluateOSVVersionEntry(d *OSVVersionEntryDecision,e OSVAffectedEntry,s OSVAffectedRangeStructure,q SemVer) {
    d.Support = make([]OSVVersionSupport,0)
    usable := false
    if e.Versions.State == OSVFieldValue {
        for i,v := range e.Versions.Entries {
            if v.State != OSVFieldValue {
                d.Problems = append(d.Problems,versionConditionProblem("version-outside-profile",i,-1,-1))
                continue
            }
            parsed,err := ParseSemVer(v.Value)
            if err != nil {
                d.Problems = append(d.Problems,versionConditionProblem(versionConditionTextProblem(err,"version"),i,-1,-1))
                continue
            }
            usable = true
            if parsed.Text() == q.Text() { d.Support = append(d.Support,OSVVersionSupport{i,-1}) }
        }
    } else if e.Versions.State != OSVFieldAbsent {
        d.Problems = append(d.Problems,versionConditionProblem("versions-uninspectable",-1,-1,-1))
    }
    if e.Ranges.State == OSVFieldValue {
        for i,r := range e.Ranges.Entries {
            match,known,problems := evaluateOSVVersionRange(r,s.Entries[i],q)
            usable = usable || known
            d.Problems = append(d.Problems,problems...)
            if match { d.Support = append(d.Support,OSVVersionSupport{-1,r.Index}) }
        }
    } else if e.Ranges.State != OSVFieldAbsent {
        d.Problems = append(d.Problems,versionConditionProblem("range-structure",-1,-1,-1))
    }
    if !usable { d.Problems = append(d.Problems,versionConditionProblem("no-usable-condition",-1,-1,-1)) }
    d.FullyEvaluated = usable && len(d.Problems) == 0
    if len(d.Support) != 0 { d.Outcome = OSVVersionMatch } else if d.FullyEvaluated { d.Outcome = OSVVersionNoMatch }
}

type osvVersionTransition struct {
    kind string
    value SemVer
    zero bool
    index int
}

func compareOSVVersionTransitions(a,b osvVersionTransition) int {
    if a.zero && b.zero { return 0 }
    if a.zero { return -1 }
    if b.zero { return 1 }
    // Both operands were successfully parsed; no zero/unqualified value reaches here.
    n,_ := CompareSemVer(a.value,b.value)
    return n
}

func evaluateOSVVersionRange(r OSVRange,s OSVRangeStructure,q SemVer) (bool,bool,[]OSVVersionProblem) {
    problem := func(kind OSVVersionProblemKind) (bool,bool,[]OSVVersionProblem) {
        return false,false,[]OSVVersionProblem{versionConditionProblem(kind,-1,r.Index,-1)}
    }
    if r.State != OSVFieldValue { return problem("range-structure") }
    if r.Type.State != OSVFieldValue || r.Type.Value != "SEMVER" { return problem("range-outside-profile") }
    if !s.Checked || !s.Satisfied { return problem("range-structure") }
    transitions := make([]osvVersionTransition,0,len(r.Events.Entries))
    problems := make([]OSVVersionProblem,0)
    hasLimit,allowed := false,false
    for _,event := range r.Events.Entries {
        // Satisfied structure guarantees exactly one known, nonempty string field.
        field := event.Fields[0]
        if field.Name == "limit" && field.Value.Value == "*" { hasLimit,allowed = true,true; continue }
        if field.Name == "introduced" && field.Value.Value == "0" {
            transitions = append(transitions,osvVersionTransition{kind:"introduced",zero:true,index:event.Index})
            continue
        }
        v,err := ParseSemVer(field.Value.Value)
        if err != nil {
            problems = append(problems,versionConditionProblem(versionConditionTextProblem(err,"bound"),-1,r.Index,event.Index))
            continue
        }
        if field.Name == "limit" {
            hasLimit = true
            // q and v are qualified upstream; error cannot become an equality fallback.
            n,_ := CompareSemVer(q,v)
            allowed = allowed || n < 0
        } else {
            transitions = append(transitions,osvVersionTransition{field.Name,v,false,event.Index})
        }
    }
    // Every bound must qualify before this range can contribute any decision.
    if len(problems) != 0 { return false,false,problems }
    slices.SortFunc(transitions,compareOSVVersionTransitions)
    for i := 0; i < len(transitions); {
        j,mixed := i+1,false
        for j < len(transitions) && compareOSVVersionTransitions(transitions[i],transitions[j]) == 0 {
            mixed = mixed || transitions[i].kind != transitions[j].kind
            j++
        }
        if mixed {
            for _,tr := range transitions[i:j] { problems = append(problems,versionConditionProblem("precedence-tie",-1,r.Index,tr.index)) }
        }
        i = j
    }
    if len(problems) != 0 {
        slices.SortFunc(problems,func(a,b OSVVersionProblem) int { if a.EventIndex < b.EventIndex { return -1 }; if a.EventIndex > b.EventIndex { return 1 }; return 0 })
        return false,false,problems
    }
    if hasLimit && !allowed { return false,true,nil }
    affected := false
    for _,tr := range transitions {
        n := 1
        if !tr.zero { n,_ = CompareSemVer(q,tr.value) }
        switch tr.kind {
        case "introduced": if n >= 0 { affected = true }
        case "fixed": if n >= 0 { affected = false }
        case "last_affected": if n > 0 { affected = false }
        }
    }
    return affected,true,nil
}
```

### Step 4 — GREEN, discrimination checks and author review

- [ ] Run gofmt on the two files; run focused tests. Require all 64 reference IDs and four E rows executed, not just package success.
- [ ] Run full root tests/vet with no acquisition. Retain one JSON stream and count only pass records with nonempty `Test`; report exact source/toolchain and new-suite count.
- [ ] Independently introduce and restore one mutation at a time: fixed `>=` to `>` (R04), last_affected `>` to `>=` (R06), alternative limits OR to AND (R15/R17), literal list equality to precedence equality (A03), ignore unknown siblings (A07/A14), omit tie rejection (R24/E02), omit source-order derivation (R18), weaken cumulative text comparison (Guards/text-limit), and return partial success on late fatal errors (Guards/text-limit).
- [ ] For each mutation, run the named focused reference/guard check and require its intended failure. Save/hash both pristine files before mutations in external temporary storage, restore exact bytes after every check, and verify digests before final commands. Never alter reference expectations to fit code.
- [ ] Review all five Review Focus classes, decoded evidence ownership, nil/empty representations, source-locator ordering, whole-zero failures, and the strict separation from confirmed advisory findings. Any discovered gap gets a literal regression in the owned test file; substantive contract changes return to owner review.

### Step 5 — Scoped local evidence and handoff

- [ ] If explicit execution authority includes local commits, use file-scoped `jj commit` for the two Go files and a separate documentation/evidence commit. Do not include other files or use Git commits.
- [ ] Update only these two documents with actual RED/GREEN/mutation/toolchain evidence and limits, retaining the original technical specification and plan body.
- [ ] Rerun tests/vet on the actual final workspace. Verify source/module/workflow files outside the two-file scope are unchanged.
- [ ] Report local implementation separately from independent peer approval/integration. Request permission for GitHub coordination/publication later; do not create/close issues, push, merge or modify protections automatically.

## Runnable command contract (Nushell)

Run from the new workspace. These commands are for later explicitly authorized
execution, not automatic downloads or native qualification:

```nu
let receipt = (mktemp -d | str trim | path join "root-tests.jsonl")
with-env { GOTOOLCHAIN: local, GOPROXY: off, GOWORK: off, CGO_ENABLED: "0" } {
    go version
    go test -count=1 -run '^TestEvaluateOSVVersionConditions' ./internal/intel
    if $env.LAST_EXIT_CODE != 0 { error make { msg: "Focused tests failed" } }
    go test -count=1 -json ./... | save $receipt
    if $env.LAST_EXIT_CODE != 0 { error make { msg: "Root tests failed" } }
    go vet ./...
    if $env.LAST_EXIT_CODE != 0 { error make { msg: "Vet failed" } }
}
```

The receipt above is stored in an external temporary directory, not the workspace;
record its location and never include it in commits. For mutations, select the exact named subtest
using Go `-run`; check its nonzero exit and actual failure records before restoring.
`GOPROXY=off` is acquisition policy, not OS-enforced networking denial.

## Plan self-review and execution gate

The plan covers the complete API, 64 literal reference rows, four added Review
Focus scenarios, support/uncertainty/source ownership, private errors and every
structural/text budget. Reused test helpers already exist in the integrated tree;
no imaginary API or dependency is required. Direct malformed/large projection
cases test defensive guards, not authentication or successful reader provenance.
No benchmark or native claims are inferred from these tests.

The owner reviewed this complete plan and selected inline execution with the exact
local authority recorded above. Independent human final-head review remains a
later gate; author review is not its substitute.

## Execution ledger

- Pre-flight: one task; no inter-task interfaces. Existing structure/strict SemVer
  helper contracts agree with the approved API and bounds.
- Ruling: use the authorized two-document scope as the progress ledger and external
  temporary receipts instead of Git-based SDD helper scripts or new repository
  scratch files. This preserves jj and scope; generic SDD scripts will not auto-read
  this ledger, so continuation must read this section explicitly.
- Ruling: no additional agents were authorized; final review will be author review
  with independent human review pending, never claimed as peer approval. The cost
  is the author's blind spots, to be resolved before reviewed integration.
- Task 1: API compilation RED observed (undefined new types/API, exit 1), then
  compiling-stub behavioral RED: 89 failed/0 passed tests/subtests, all 64 R/A/U
  reference IDs failed. Initial GREEN: 94 focused tests/subtests, exit 0.
- Ruling: the first file-scoped jj commit failed because `-R` changes the repository
  but not fileset path resolution relative to the shell cwd. Authorization had
  already been recorded in these documents before Go creation, but that attempted
  commit did not exist. Run scoped commits from the new workspace cwd, verify
  exact paths/parent afterward, and do not claim pre-code committed ancestry.
  The cost is that documentary commit timing follows initial RED/GREEN, not the
  stronger intended pre-code commit chronology; explicit owner authority remains.
- Documentary authority commit: `d41796034d0dcb6329062841a4b1a870fdc9193b`;
  code commit: `2ddf20cf5b1c9bfe84f65f3acba4246e0219db70`, verified to contain only
  the two Go files. Both descend from the exact planned integrated baseline.
- Mutation pass: all nine planned forms now fail their discriminating checks.
  The first unsorted-order check survived at R18 (its fixed bound was above the
  query), so E05 tests the same ordering at `2.0.0`; observed RED then restored
  GREEN. This changes neither R18 nor any of the 64 R/A/U reference expectations.
- Author review: multiple affected entries and affected root states lacked direct
  whole-result tests. Added two focused tests: isolated outcomes/source indices
  across four entries; absent/null/wrong-type/inspectable-empty root distinction.
  Observed RED against index collapse and empty-root-as-gap mutations, then GREEN
  after restoration. No production change was needed. One improvement pass only.
- Final tree checks: 2,897 root tests/subtests pass, including 101 new and all
  64 R/A/U IDs. `go vet ./...` exit 0; gofmt reports no changed file.
- Exact restored production SHA-256:
  `2d9be47662fc8b34e6b512ab26615c2fc9f5c12c2131af251b78f8661109cb69`.
  Final test SHA-256:
  `330fd9d8bb8b0630ea530365420968d3c368ec51711b2c0f0d67a6a2e06bc925`.
- Temporary receipts (not durable repository fixtures) include API/stub RED,
  initial GREEN, the surviving initial source-order check, E05 RED/GREEN, final
  mutation records, review-test RED/GREEN and the final root-test stream. The
  machine-specific temporary location is omitted from the public handoff; these
  files may disappear. The recorded observations are not invented durable fixtures.
- Task 1: local implementation/checks complete; independent human final-head review
  and integration remain pending. No acquisition, probes or CI was authorized.

### Publication handoff

The owner separately authorized issue creation under #6, scoped jj publication,
a PR against `development`, this issue's Project update and `landroval` ownership,
and selected `jsustt` as independent reviewer. The tracking issue is
[#41](https://github.com/landroval/PackTrace/issues/41); publication bookmark is
`issue-41-osv-version-conditions`. The specification/plan were renamed to the
issue-keyed filenames without changing the two verified Go files. This handoff
preserves the original authorization, code and evidence ancestors; it does not
rewrite published history or claim removal of text from historic commits.

A review request follows publication of the final head; neither the request nor
these local checks is independent approval. Parent #6, this issue's closure and
reviewed integration remain pending. No merge, force-push, security-setting change,
CI installation, acquisition, target execution or probe is authorized here.


### Author review disposition

Strengths: reused real reader/structure/SemVer paths, preflight shape/text bounds,
zero-on-fatal privacy, original locators and separation of positive evidence from
incomplete evaluation. Important test gaps above were addressed with literal
regressions and mutation discrimination. No remaining in-scope critical/important
issue or deferred minor was identified; author review cannot certify its own blind
spots. Verdict: retain locally, not ready for **reviewed integration**.

Declined to judge / executor rulings:

- Advisory identity/origin/activity and package matching: deferred deliberately by
  the approved API boundary. Version match alone is not advisory applicability;
  next separately approved increment must supply that authority.
- Full OSV/ECOSYSTEM/GIT semantics: deferred by strict supported profile. Unknown
  evidence remains indeterminate, never a clean negative.
- Authenticated producer/snapshot evidence: deferred because only owned projections
  are consumed here; digest/shape checks cannot authenticate fabricated evidence.
- CLI/report/coverage/policy decisions and target installation: deferred because
  none is wired or executed here. Consumers must preserve gaps before reporting.
- Official toolchain/native qualification and probes: deferred by current execution
  authority and platform gates. Modified local toolchain results do not close them.
- Hosted CI and independent human review: deferred, not silently passed; neither
  was authorized/executed. A separate reviewed final head is required for integration.
- Hard memory/sandbox guarantees: declined; cardinality/text checks are work bounds,
  not resident-memory or OS isolation evidence. No such guarantees are reported.
