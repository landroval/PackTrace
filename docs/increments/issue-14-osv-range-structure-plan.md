# Issue 14: OSV range structure implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: use `superpowers:executing-plans`
> for the project's inline workflow. This written plan is approved and the user
> explicitly authorized inline implementation, offline tests/vet, scoped docs/commits
> and publication in PR #27. No merge, dependencies, corpus/targets, CI or native work.

**Goal:** check the approved bounded SEMVER/ECOSYSTEM event structure profile.
**Architecture:** preflight the paired projections/layout/budgets before allocating
output; then build independent positional results with complete ordered diagnostics.
Header/type abstention is distinct from attempted structure checks. No intervals.
**Tech stack:** current Go module, standard library; existing intel types/errors.
**Spec:** [approved written contract](issue-14-osv-range-structure.md).

## Global constraints

- Only new internal/intel/osv_range_structure.go and osv_range_structure_test.go.
- Existing readers/projections/types, go.mod, inventory/Bun and probes unchanged.
- Reuse maxAffectedEntries, maxRangeUnits and consumeOSVRangeUnits unchanged.
- Inputs are unchanged successful paired projections from the same reader document;
  no concurrent mutation. Basic guards are not forged-input authentication.
- Only header V1Implicit/V1Declared and exact SEMVER/ECOSYSTEM permit event checks.
- Preserve order, indices, hierarchy states, nil/empty distinctions and raw siblings.
- Unknown/multiple/unusable claims remain diagnostics, not selected/dropped bounds.
- Introduced presence is separate from usability; partial non-object lists cannot
  generate false absent-introduced diagnostics.
- No sort/alternation/first-introduced/version/interval/identity/matching inference.
- No dependencies, acquisition, corpus/target/network/CI/native/worker/report work.
- Constant existing quotas: 20,000 affected slots and 20,000 combined range units.
  Count every slot/field even when header/type abstains. Zero whole result on errors.
- Inline review is not independent review; #15 stays blocked until reviewed integration.

## Review focus

1. Unsorted/non-alternating events and repeated limits remain structurally inspectable.
2. Unknown header/GIT/type abstention cannot return Satisfied=true or bypass budgets.
3. Null/multi-kind introduced is present, not absent; null event parents are unavailable.
4. All source problems survive in deterministic order, including mixed closing claims.
5. Large late errors return zero output, not prefixes or content-bearing diagnostics.

## Task 1: add the bounded checker

**Create:** internal/intel/osv_range_structure.go, osv_range_structure_test.go.
**Consumes:** OSVHeader, OSVAffectedProjection, existing OSVFieldState/OSVString,
OSVRange/OSVEvent and ParseError; unchanged constants/counter named above.
**Produces:** the exact five spec-defined types and 13 problem-kind constants,
`CheckOSVRangeStructure(header OSVHeader, affected OSVAffectedProjection) (OSVRangeStructureProjection, error)`.
No inter-task interfaces or unrelated shared Go changes.

- [ ] **Write tests first**, using the complete matrix/helper below. Add the guard,
  hierarchy, ownership and cumulative-boundary cases described afterward before
  implementing behavior. Expected reasons/flags are literals, not the checker logic.

```go
package intel

import (
    "crypto/sha256"
    "encoding/json"
    "errors"
    "fmt"
    "reflect"
    "strings"
    "testing"
)

func structureInput(t *testing.T, body string) (OSVHeader, OSVAffectedProjection) {
    t.Helper()
    doc, err := ParseOSVRecord([]byte(body))
    if err != nil { t.Fatal(err) }
    header, err := ProjectOSVHeader(doc)
    if err != nil { t.Fatal(err) }
    affected, err := ProjectOSVAffected(doc)
    if err != nil { t.Fatal(err) }
    return header, affected
}

func TestCheckOSVRangeStructureProfile(t *testing.T) {
    for _, tc := range []struct {
        name, raw string
        state, events OSVFieldState
        checked, satisfied bool
        problems []OSVRangeStructureProblem
    }{
        {"introduced-only", `{"type":"SEMVER","events":[{"introduced":"0"}]}`, OSVFieldValue, OSVFieldValue, true, true, []OSVRangeStructureProblem{}},
        {"fixed", `{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2"}]}`, OSVFieldValue, OSVFieldValue, true, true, []OSVRangeStructureProblem{}},
        {"last-affected", `{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"last_affected":"opaque"}]}`, OSVFieldValue, OSVFieldValue, true, true, []OSVRangeStructureProblem{}},
        {"limits", `{"type":"SEMVER","events":[{"introduced":"0"},{"limit":"*"},{"limit":"*"}]}`, OSVFieldValue, OSVFieldValue, true, true, []OSVRangeStructureProblem{}},
        {"unsorted-first-fixed", `{"type":"SEMVER","events":[{"fixed":"8"},{"introduced":"3"},{"introduced":"1"},{"limit":"2"}]}`, OSVFieldValue, OSVFieldValue, true, true, []OSVRangeStructureProblem{}},
        {"nonalternating", `{"type":"ECOSYSTEM","events":[{"introduced":"z"},{"introduced":"a"},{"fixed":"m"},{"fixed":"b"}]}`, OSVFieldValue, OSVFieldValue, true, true, []OSVRangeStructureProblem{}},
        {"opaque-text", `{"type":"SEMVER","repo":false,"events":[{"introduced":" "},{"fixed":"not-a-version"}]}`, OSVFieldValue, OSVFieldValue, true, true, []OSVRangeStructureProblem{}},
        {"range-null", `null`, OSVFieldNull, OSVFieldUnavailable, false, false, []OSVRangeStructureProblem{{OSVRangeProblemRangeNotObject,-1,""}}},
        {"range-number", `42`, OSVFieldInvalidType, OSVFieldUnavailable, false, false, []OSVRangeStructureProblem{{OSVRangeProblemRangeNotObject,-1,""}}},
        {"type-absent", `{}`, OSVFieldValue, OSVFieldAbsent, false, false, []OSVRangeStructureProblem{{OSVRangeProblemTypeUnusable,-1,"type"}}},
        {"type-null", `{"type":null,"events":[]}`, OSVFieldValue, OSVFieldValue, false, false, []OSVRangeStructureProblem{{OSVRangeProblemTypeUnusable,-1,"type"}}},
        {"git", `{"type":"GIT","repo":"not-fetched","events":[{"introduced":"X"}]}`, OSVFieldValue, OSVFieldValue, false, false, []OSVRangeStructureProblem{{OSVRangeProblemTypeOutsideProfile,-1,"type"}}},
        {"unknown-type", `{"type":"future","events":[]}`, OSVFieldValue, OSVFieldValue, false, false, []OSVRangeStructureProblem{{OSVRangeProblemTypeOutsideProfile,-1,"type"}}},
        {"events-absent", `{"type":"SEMVER"}`, OSVFieldValue, OSVFieldAbsent, true, false, []OSVRangeStructureProblem{{OSVRangeProblemEventsUnusable,-1,"events"}}},
        {"events-null", `{"type":"SEMVER","events":null}`, OSVFieldValue, OSVFieldNull, true, false, []OSVRangeStructureProblem{{OSVRangeProblemEventsUnusable,-1,"events"}}},
        {"events-wrong-type", `{"type":"SEMVER","events":false}`, OSVFieldValue, OSVFieldInvalidType, true, false, []OSVRangeStructureProblem{{OSVRangeProblemEventsUnusable,-1,"events"}}},
        {"events-empty", `{"type":"SEMVER","events":[]}`, OSVFieldValue, OSVFieldValue, true, false, []OSVRangeStructureProblem{{OSVRangeProblemEmptyEvents,-1,"events"},{OSVRangeProblemIntroducedNotRecorded,-1,"events"}}},
        {"event-null", `{"type":"SEMVER","events":[null]}`, OSVFieldValue, OSVFieldValue, true, false, []OSVRangeStructureProblem{{OSVRangeProblemEventNotObject,0,""}}},
        {"event-empty-object", `{"type":"SEMVER","events":[{}]}`, OSVFieldValue, OSVFieldValue, true, false, []OSVRangeStructureProblem{{OSVRangeProblemNoKnownEventKind,0,""},{OSVRangeProblemIntroducedNotRecorded,-1,"events"}}},
        {"only-fixed", `{"type":"SEMVER","events":[{"fixed":"2"}]}`, OSVFieldValue, OSVFieldValue, true, false, []OSVRangeStructureProblem{{OSVRangeProblemIntroducedNotRecorded,-1,"events"}}},
        {"unknown-only", `{"type":"SEMVER","events":[{"future":false}]}`, OSVFieldValue, OSVFieldValue, true, false, []OSVRangeStructureProblem{{OSVRangeProblemNoKnownEventKind,0,""},{OSVRangeProblemUnknownEventField,0,"future"},{OSVRangeProblemIntroducedNotRecorded,-1,"events"}}},
        {"unknown-sibling", `{"type":"SEMVER","events":[{"introduced":"0","future":null}]}`, OSVFieldValue, OSVFieldValue, true, false, []OSVRangeStructureProblem{{OSVRangeProblemUnknownEventField,0,"future"}}},
        {"unusable-introduced", `{"type":"SEMVER","events":[{"introduced":null}]}`, OSVFieldValue, OSVFieldValue, true, false, []OSVRangeStructureProblem{{OSVRangeProblemEventValueUnusable,0,"introduced"}}},
        {"empty-introduced", `{"type":"SEMVER","events":[{"introduced":""}]}`, OSVFieldValue, OSVFieldValue, true, false, []OSVRangeStructureProblem{{OSVRangeProblemEventValueUnusable,0,"introduced"}}},
        {"multi-kind", `{"type":"SEMVER","events":[{"introduced":"0","fixed":"1"}]}`, OSVFieldValue, OSVFieldValue, true, false, []OSVRangeStructureProblem{{OSVRangeProblemMultipleKnownEventKinds,0,""}}},
        {"multi-unusable", `{"type":"SEMVER","events":[{"introduced":null,"fixed":false}]}`, OSVFieldValue, OSVFieldValue, true, false, []OSVRangeStructureProblem{{OSVRangeProblemMultipleKnownEventKinds,0,""},{OSVRangeProblemEventValueUnusable,0,"fixed"},{OSVRangeProblemEventValueUnusable,0,"introduced"}}},
        {"mixed-closing", `{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1"},{"last_affected":"2"}]}`, OSVFieldValue, OSVFieldValue, true, false, []OSVRangeStructureProblem{{OSVRangeProblemMixedFixedLastAffected,-1,"events"}}},
        {"missing-and-mixed", `{"type":"SEMVER","events":[{"fixed":"1"},{"last_affected":"2"}]}`, OSVFieldValue, OSVFieldValue, true, false, []OSVRangeStructureProblem{{OSVRangeProblemIntroducedNotRecorded,-1,"events"},{OSVRangeProblemMixedFixedLastAffected,-1,"events"}}},
    } {
        t.Run(tc.name, func(t *testing.T) {
            body := `{"id":"TEST","modified":"opaque","affected":[{"package":null,"versions":false,"ranges":[`+tc.raw+`]}]}`
            header, affected := structureInput(t, body)
            got, err := CheckOSVRangeStructure(header, affected)
            want := OSVRangeStructureProjection{
                SourceSHA256: sha256.Sum256([]byte(body)), HeaderSchema: OSVHeaderSchemaV1Implicit, State: OSVFieldValue,
                Entries: []OSVAffectedRangeStructure{{Index:0, State:OSVFieldValue, RangesState:OSVFieldValue,
                    Entries:[]OSVRangeStructure{{Index:0, State:tc.state, EventsState:tc.events, Checked:tc.checked, Satisfied:tc.satisfied, Problems:tc.problems}},
                }},
            }
            if err != nil || !reflect.DeepEqual(got,want) { t.Fatalf("want %#v, got %#v, %v",want,got,err) }
        })
    }
}
```

  Continue the same test file with the following runnable guard/header/ownership/
  cumulative-budget checks. They use the imports in the first block, not extra production
  APIs. Additional table cases listed after them pin remaining source shapes/positions.

```go
func assertStructureError(t *testing.T, header OSVHeader, affected OSVAffectedProjection, code string) {
    t.Helper()
    got, err := CheckOSVRangeStructure(header,affected)
    var pe *ParseError
    if !errors.As(err,&pe) || pe.Code != code || err.Error() != "intel: "+code || !reflect.DeepEqual(got,OSVRangeStructureProjection{}) {
        t.Fatalf("want zero/%s, got %#v, %v",code,got,err)
    }
}

func TestCheckOSVRangeStructureHeaderGate(t *testing.T) {
    for _, tc := range []struct {raw string; schema OSVHeaderSchemaState; checked bool}{
        {"",OSVHeaderSchemaV1Implicit,true},
        {`"1.0.0"`,OSVHeaderSchemaV1Declared,true},
        {`null`,OSVHeaderSchemaUnknown,false},
        {`"future"`,OSVHeaderSchemaUnknown,false},
        {`"2.0.0"`,OSVHeaderSchemaUnsupported,false},
        {`"1.0.0+build"`,OSVHeaderSchemaUnknown,false},
    } {
        t.Run(tc.raw,func(t *testing.T) {
            body:=`{"id":"TEST","modified":"opaque","affected":[{"ranges":[{"type":"SEMVER","events":[{"introduced":"0","fixed":"1"}]}]}]`
            if tc.raw!="" {body+=`,"schema_version":`+tc.raw}
            header,affected:=structureInput(t,body+`}`)
            got,err:=CheckOSVRangeStructure(header,affected)
            if err!=nil || got.HeaderSchema!=tc.schema || len(got.Entries)!=1 || len(got.Entries[0].Entries)!=1 {t.Fatal("header/source hierarchy lost",err)}
            row:=got.Entries[0].Entries[0]
            var problems []OSVRangeStructureProblem
            if tc.checked {problems=[]OSVRangeStructureProblem{{OSVRangeProblemMultipleKnownEventKinds,0,""}}}
            want:=OSVRangeStructure{Index:0,State:OSVFieldValue,EventsState:OSVFieldValue,Checked:tc.checked,Problems:problems}
            if !reflect.DeepEqual(row,want) {t.Fatal("abstention interpreted as profile success/failure",row)}
        })
    }
}

func TestCheckOSVRangeStructureGuards(t *testing.T) {
    body:=`{"id":"private-marker","modified":"opaque","affected":[{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`
    for _, name:=range []string{"digest","top-unavailable","nil-affected","affected-index","nil-ranges","range-index","nil-events","event-index","nil-fields","nonvalue-children"} {
        t.Run(name,func(t *testing.T) {
            header,affected:=structureInput(t,body)
            switch name {
            case "digest": header.SourceSHA256[0]^=255
            case "top-unavailable": affected.State=OSVFieldUnavailable
            case "nil-affected": affected.Entries=nil
            case "affected-index": affected.Entries[0].Index=7
            case "nil-ranges": affected.Entries[0].Ranges.Entries=nil
            case "range-index": affected.Entries[0].Ranges.Entries[0].Index=7
            case "nil-events": affected.Entries[0].Ranges.Entries[0].Events.Entries=nil
            case "event-index": affected.Entries[0].Ranges.Entries[0].Events.Entries[0].Index=7
            case "nil-fields": affected.Entries[0].Ranges.Entries[0].Events.Entries[0].Fields=nil
            case "nonvalue-children": affected.Entries[0].State=OSVFieldNull
            }
            assertStructureError(t,header,affected,"invalid-shape")
        })
    }
}

func TestCheckOSVRangeStructureOwnership(t *testing.T) {
    field:=strings.Repeat("x",4096)
    rawField,err:=json.Marshal(field);if err!=nil {t.Fatal(err)}
    body:=`{"id":"TEST","modified":"opaque","affected":[{"ranges":[{"type":"SEMVER","events":[{"introduced":"0",`+string(rawField)+`:null}]}]}]}`
    header,affected:=structureInput(t,body)
    snapshot:=func(v any) []byte {t.Helper();b,err:=json.Marshal(v);if err!=nil {t.Fatal(err)};return b}
    before:=snapshot(struct{H OSVHeader;A OSVAffectedProjection}{header,affected})
    got,err:=CheckOSVRangeStructure(header,affected);if err!=nil {t.Fatal(err)}
    after:=snapshot(struct{H OSVHeader;A OSVAffectedProjection}{header,affected})
    if string(before)!=string(after) {t.Fatal("source changed")}
    problems:=got.Entries[0].Entries[0].Problems
    if !reflect.DeepEqual(problems,[]OSVRangeStructureProblem{{OSVRangeProblemUnknownEventField,0,field}}) {t.Fatal("exact field locator lost")}
    frozen:=snapshot(got)
    affected.Entries[0].Ranges.Entries[0].Events.Entries[0].Fields[1].Name="changed"
    affected.Entries[0].Ranges.Entries[0].Type.Value="GIT"
    affected.SourceSHA256[0]^=255
    header.SourceSHA256[0]^=255
    if string(frozen)!=string(snapshot(got)) {t.Fatal("output aliases nested input")}
    before=snapshot(struct{H OSVHeader;A OSVAffectedProjection}{header,affected})
    got.Entries[0].Entries[0].Problems[0].Field="output-change"
    got.Entries[0].Index=99
    after=snapshot(struct{H OSVHeader;A OSVAffectedProjection}{header,affected})
    if string(before)!=string(after) {t.Fatal("output mutation changed input")}
}

func TestCheckOSVRangeStructureCumulativeUnits(t *testing.T) {
    // Actual successful projections at exactly 20,000 units, with independent versions.
    events:=make(map[string]any,9998)
    for i:=0;i<9998;i++ {events[fmt.Sprintf("f%05d",i)]="opaque"}
    versions:=make([]string,20000)
    for i:=range versions {versions[i]="1"}
    entry:=func() map[string]any {return map[string]any{"ranges":[]any{map[string]any{"type":"SEMVER","events":[]any{events}}}}}
    first,second:=entry(),entry();first["versions"]=versions
    body,err:=json.Marshal(map[string]any{"id":"TEST","modified":"opaque","schema_version":"2.0.0","affected":[]any{first,second}})
    if err!=nil {t.Fatal(err)}
    header,affected:=structureInput(t,string(body))
    got,err:=CheckOSVRangeStructure(header,affected)
    if err!=nil || len(got.Entries)!=2 || got.Entries[1].Entries[0].Checked {t.Fatal("exact budget/header abstention",err)}
    // Explicitly forged late extra unit: old projector would reject this raw source.
    fields:=&affected.Entries[1].Ranges.Entries[0].Events.Entries[0].Fields
    *fields=append(*fields,OSVEventField{Name:"z",Value:OSVString{State:OSVFieldValue,Value:"opaque"}})
    assertStructureError(t,header,affected,"limit-exceeded")
}

func TestCheckOSVRangeStructureDerivedProblemBound(t *testing.T) {
    ranges:=make([]any,20000)
    for i:=range ranges {ranges[i]=map[string]any{"type":"SEMVER","events":[]any{}}}
    body,err:=json.Marshal(map[string]any{"id":"TEST","modified":"opaque","affected":[]any{map[string]any{"ranges":ranges}}})
    if err!=nil {t.Fatal(err)}
    header,affected:=structureInput(t,string(body))
    got,err:=CheckOSVRangeStructure(header,affected)
    if err!=nil || len(got.Entries)!=1 || len(got.Entries[0].Entries)!=20000 {t.Fatal("exact range-unit bound",err)}
    count:=0
    for i,row:=range got.Entries[0].Entries {
        want:=OSVRangeStructure{Index:i,State:OSVFieldValue,EventsState:OSVFieldValue,Checked:true,Problems:[]OSVRangeStructureProblem{{OSVRangeProblemEmptyEvents,-1,"events"},{OSVRangeProblemIntroducedNotRecorded,-1,"events"}}}
        if !reflect.DeepEqual(row,want) {t.Fatal("empty event diagnostics/prefix loss",i)}
        count+=len(row.Problems)
    }
    if count!=40000 {t.Fatal("derived problem bound",count)}
}
```

  Finish the same test file with hierarchy, cross-range and per-axis bound fixtures:

```go
func TestCheckOSVRangeStructureHierarchy(t *testing.T) {
    for _,tc:=range []struct{name,raw string;state OSVFieldState;entries []OSVAffectedRangeStructure}{
        {"absent","",OSVFieldAbsent,nil},
        {"null",`null`,OSVFieldNull,nil},
        {"wrong-type",`false`,OSVFieldInvalidType,nil},
        {"empty",`[]`,OSVFieldValue,[]OSVAffectedRangeStructure{}},
        {"mixed",`[null,false,{}, {"ranges":null}, {"ranges":false}, {"ranges":[]}]`,OSVFieldValue,[]OSVAffectedRangeStructure{
            {Index:0,State:OSVFieldNull,RangesState:OSVFieldUnavailable},
            {Index:1,State:OSVFieldInvalidType,RangesState:OSVFieldUnavailable},
            {Index:2,State:OSVFieldValue,RangesState:OSVFieldAbsent},
            {Index:3,State:OSVFieldValue,RangesState:OSVFieldNull},
            {Index:4,State:OSVFieldValue,RangesState:OSVFieldInvalidType},
            {Index:5,State:OSVFieldValue,RangesState:OSVFieldValue,Entries:[]OSVRangeStructure{}},
        }},
    } {
        t.Run(tc.name,func(t *testing.T) {
            body:=`{"id":"TEST","modified":"opaque"`
            if tc.raw!="" {body+=`,"affected":`+tc.raw}
            body+=`}`
            header,affected:=structureInput(t,body)
            got,err:=CheckOSVRangeStructure(header,affected)
            want:=OSVRangeStructureProjection{SourceSHA256:sha256.Sum256([]byte(body)),HeaderSchema:OSVHeaderSchemaV1Implicit,State:tc.state,Entries:tc.entries}
            if err!=nil || !reflect.DeepEqual(got,want) {t.Fatal("hierarchy/absence fabricated",got,err)}
        })
    }
}

func TestCheckOSVRangeStructureSeparation(t *testing.T) {
    body:=`{"id":"TEST","modified":"opaque","affected":[
      {"ranges":[
        {"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2"}]},
        {"type":"ECOSYSTEM","events":[{"introduced":"0"},{"last_affected":"2"}]}
      ]},
      {"ranges":[{"type":"SEMVER","events":[{"":false,"future":null,"introduced":"0"},{"fixed":"7","introduced":null}]}]}
    ]}`
    header,affected:=structureInput(t,body)
    got,err:=CheckOSVRangeStructure(header,affected)
    if err!=nil || len(got.Entries)!=2 || len(got.Entries[0].Entries)!=2 || len(got.Entries[1].Entries)!=1 {t.Fatal("positions lost",err)}
    for i,row:=range got.Entries[0].Entries {
        want:=OSVRangeStructure{Index:i,State:OSVFieldValue,EventsState:OSVFieldValue,Checked:true,Satisfied:true,Problems:[]OSVRangeStructureProblem{}}
        if !reflect.DeepEqual(row,want) {t.Fatal("cross-range closing mixture invented",row)}
    }
    want:=OSVRangeStructure{Index:0,State:OSVFieldValue,EventsState:OSVFieldValue,Checked:true,Problems:[]OSVRangeStructureProblem{
        {OSVRangeProblemUnknownEventField,0,""},
        {OSVRangeProblemUnknownEventField,0,"future"},
        {OSVRangeProblemMultipleKnownEventKinds,1,""},
        {OSVRangeProblemEventValueUnusable,1,"introduced"},
    }}
    if got.Entries[1].Index!=1 || !reflect.DeepEqual(got.Entries[1].Entries[0],want) {t.Fatal("complete ordered locators lost")}
}

func TestCheckOSVRangeStructureInputBounds(t *testing.T) {
    for _,axis:=range []string{"affected","ranges","events","fields"} {
        for _,mode:=range []string{"v1","unknown-header","git-type"} {
            t.Run(axis+"/"+mode,func(t *testing.T) {
                typ:="SEMVER";if mode=="git-type" {typ="GIT"}
                root:=map[string]any{"id":"TEST","modified":"opaque"}
                if mode=="unknown-header" {root["schema_version"]="2.0.0"}
                switch axis {
                case "affected": root["affected"]=make([]any,20000)
                case "ranges": root["affected"]=[]any{map[string]any{"ranges":make([]any,20000)}}
                case "events": root["affected"]=[]any{map[string]any{"ranges":[]any{map[string]any{"type":typ,"events":make([]any,19999)}}}}
                case "fields":
                    fields:=make(map[string]any,19998)
                    for i:=0;i<19998;i++ {fields[fmt.Sprintf("f%05d",i)]="opaque"}
                    root["affected"]=[]any{map[string]any{"ranges":[]any{map[string]any{"type":typ,"events":[]any{fields}}}}}
                }
                body,err:=json.Marshal(root);if err!=nil {t.Fatal(err)}
                header,affected:=structureInput(t,string(body))
                if _,err:=CheckOSVRangeStructure(header,affected);err!=nil {t.Fatal("exact source bound",err)}
                // Forged extra slot/field must fail before any returned prefix or abstention.
                switch axis {
                case "affected": affected.Entries=append(affected.Entries,OSVAffectedEntry{Index:20000,State:OSVFieldNull})
                case "ranges":
                    r:=&affected.Entries[0].Ranges.Entries
                    *r=append(*r,OSVRange{Index:20000,State:OSVFieldNull})
                case "events":
                    e:=&affected.Entries[0].Ranges.Entries[0].Events.Entries
                    *e=append(*e,OSVEvent{Index:19999,State:OSVFieldNull})
                case "fields":
                    f:=&affected.Entries[0].Ranges.Entries[0].Events.Entries[0].Fields
                    *f=append(*f,OSVEventField{Name:"z",Value:OSVString{State:OSVFieldValue,Value:"opaque"}})
                }
                assertStructureError(t,header,affected,"limit-exceeded")
            })
        }
    }
}
```

  Review the following explicit coverage checklist before behavior; extend the literal
  tables where a case is not yet represented (do not change expected contracts):
  - Header table: absent schema / `"1.0.0"` permits inspection; null, `"future"`,
    `"2.0.0"`, `"1.0.0+build"` abstain. Use ranges containing an unknown/multi-kind
    event and assert both source states remain but no profile problems/flags are
    invented on abstention. Compare exact expected HeaderSchema states.
  - Hierarchy table: no affected, affected:null, affected:false, affected:[],
    affected:[null,false,{}], and an object with ranges absent/null/false/[]. Assert
    explicit source states/indices and nil vs non-nil empty lists. No fake range rows.
  - Separation/diagnostics fixture: two affected entries with ranges in each; fixed
    and last_affected in different ranges must not emit MixedFixedLastAffected.
    Include an unknown empty key and valid introduced siblings. Assert all locators,
    problem order and separate entry/range positions, not only lengths.
  - Ownership fixture: reader-valid escaped header/type/event keys and field names,
    raw null/invalid/extensions. Marshal both source projections before checking,
    assert unchanged after checking; snapshot output, mutate input nested arrays,
    fields and digest and assert snapshot unchanged; mutate output Problems/Entries
    and assert fresh source snapshots unchanged. Never compare shallow copies.
  - Guard fixture from successful projections: mismatched digest, unavailable top,
    bad indices at all three levels, nil value lists/object fields and fabricated
    collections on non-value parents. Assert errors.As(*ParseError), exact category
    message and zero whole result; include a late bad slot after usable siblings.
  - Boundary fixtures: 20,000/20,001 affected slots; 20,000 range slots; 19,999 event
    slots plus one range; 19,998 fields plus one event/range. Use original successful
    projections for exact acceptance where possible, then an explicitly forged late
    extra slot/field for checker-limit RED without bypassing the old projector's cap.
    Repeat over-limit with unknown header and unsupported type to detect skipped guards.
  - Mixed cumulative fixture: two entries each consuming 10,000 units = one range,
    one event and 9,998 unknown fields; preserve an independently valid 20,000-version
    list. Then forge one late extra field. No budget reset or usable prefix may escape.
  - Derived output-bound fixture: 20,000 supported ranges with empty events; assert
    40,000 problems, all checked but unsatisfied. This is not a new source limit.

  Use literal spec limits in expectations, not production constants. Construct
  reader-valid fixtures in memory using json.Marshal/maps/slices; no target reads.
  Forged-guard tests are marked as such and do not establish authentication claims.

- [ ] **Observe compile RED**, then introduce only the exact spec types/constants
  and a zero-result stub. Rerun and observe behavioral failures on digest/shape,
  checked/satisfied flags, complete problems, hierarchy and controlled errors.
  Only then add behavior. Tests for unchanged old reader/projection contracts stay intact.
  The zero stub is `func CheckOSVRangeStructure(header OSVHeader, affected OSVAffectedProjection) (OSVRangeStructureProjection, error) { return OSVRangeStructureProjection{}, nil }`.
  Copy the exact types/constants from the approved spec into the new source during this
  compile-to-behavior RED step; they are the only definitions consumed by this task.

- [ ] **Implement preflight**, before output allocation. Use these private helpers;
  their repeated consumed-layout checks are local, not a new shared validation API:

```go
func validOSVStructureList(state OSVFieldState, nilItems bool) bool {
    switch state {
    case OSVFieldValue: return !nilItems
    case OSVFieldAbsent, OSVFieldNull, OSVFieldInvalidType: return nilItems
    default: return false
    }
}

func validOSVStructureMember(state OSVFieldState) bool {
    return state == OSVFieldValue || state == OSVFieldNull || state == OSVFieldInvalidType
}

func validateOSVRangeStructureInput(header OSVHeader, affected OSVAffectedProjection) error {
    badShape := func() error { return &ParseError{Code:"invalid-shape"} }
    if header.SourceSHA256 != affected.SourceSHA256 || !validOSVStructureList(affected.State, affected.Entries == nil) { return badShape() }
    if len(affected.Entries) > maxAffectedEntries { return &ParseError{Code:"limit-exceeded"} }
    remaining := maxRangeUnits
    for ai, entry := range affected.Entries {
        if entry.Index != ai || !validOSVStructureMember(entry.State) { return badShape() }
        if entry.State != OSVFieldValue {
            if entry.Ranges.State != OSVFieldUnavailable || entry.Ranges.Entries != nil { return badShape() }
            continue
        }
        if !validOSVStructureList(entry.Ranges.State, entry.Ranges.Entries == nil) { return badShape() }
        if err := consumeOSVRangeUnits(&remaining,len(entry.Ranges.Entries)); err != nil { return err }
        for ri, item := range entry.Ranges.Entries {
            if item.Index != ri || !validOSVStructureMember(item.State) { return badShape() }
            if item.State != OSVFieldValue {
                if item.Events.State != OSVFieldUnavailable || item.Events.Entries != nil { return badShape() }
                continue
            }
            if !validOSVStructureList(item.Events.State,item.Events.Entries == nil) { return badShape() }
            if err := consumeOSVRangeUnits(&remaining,len(item.Events.Entries)); err != nil { return err }
            for ei, event := range item.Events.Entries {
                if event.Index != ei || !validOSVStructureMember(event.State) { return badShape() }
                if event.State != OSVFieldValue {
                    if event.Fields != nil { return badShape() }
                    continue
                }
                if event.Fields == nil { return badShape() }
                if err := consumeOSVRangeUnits(&remaining,len(event.Fields)); err != nil { return err }
            }
        }
    }
    return nil
}
```

  The preflight reads only consumed layout/positions/counts; it does not verify ID,
  repo/versions/package, byte digests against raw inputs, or forged authenticity.

- [ ] **Implement independent results and profile checks** after behavioral RED.
  Retain the exact already-introduced spec types/constants; new source has no imports
  beyond what actual implementation needs. Complete behavior:

```go
func CheckOSVRangeStructure(header OSVHeader, affected OSVAffectedProjection) (OSVRangeStructureProjection,error) {
    if err := validateOSVRangeStructureInput(header,affected); err != nil { return OSVRangeStructureProjection{},err }
    result := OSVRangeStructureProjection{SourceSHA256:affected.SourceSHA256, HeaderSchema:header.Schema, State:affected.State}
    if affected.State != OSVFieldValue { return result,nil }
    result.Entries = make([]OSVAffectedRangeStructure,0,len(affected.Entries))
    inspectHeader := header.Schema == OSVHeaderSchemaV1Implicit || header.Schema == OSVHeaderSchemaV1Declared
    for _, entry := range affected.Entries {
        out := OSVAffectedRangeStructure{Index:entry.Index, State:entry.State, RangesState:entry.Ranges.State}
        if entry.Ranges.State == OSVFieldValue {
            out.Entries = make([]OSVRangeStructure,0,len(entry.Ranges.Entries))
            for _, item := range entry.Ranges.Entries {
                out.Entries = append(out.Entries,checkOSVRangeStructure(item,inspectHeader))
            }
        }
        result.Entries = append(result.Entries,out)
    }
    return result,nil
}

func checkOSVRangeStructure(item OSVRange, inspectHeader bool) OSVRangeStructure {
    result := OSVRangeStructure{Index:item.Index, State:item.State, EventsState:item.Events.State}
    if !inspectHeader { return result }
    add := func(kind OSVRangeProblemKind,index int,field string) {
        result.Problems = append(result.Problems,OSVRangeStructureProblem{Kind:kind,EventIndex:index,Field:field})
    }
    if item.State != OSVFieldValue { add(OSVRangeProblemRangeNotObject,-1,""); return result }
    if item.Type.State != OSVFieldValue { add(OSVRangeProblemTypeUnusable,-1,"type"); return result }
    if item.Type.Value != "SEMVER" && item.Type.Value != "ECOSYSTEM" { add(OSVRangeProblemTypeOutsideProfile,-1,"type"); return result }
    result.Checked = true
    result.Problems = make([]OSVRangeStructureProblem,0)
    if item.Events.State != OSVFieldValue { add(OSVRangeProblemEventsUnusable,-1,"events"); return result }
    if len(item.Events.Entries) == 0 { add(OSVRangeProblemEmptyEvents,-1,"events") }
    allObjects, introduced, fixed, lastAffected := true,false,false,false
    for _, event := range item.Events.Entries {
        if event.State != OSVFieldValue { allObjects=false; add(OSVRangeProblemEventNotObject,event.Index,""); continue }
        known := 0
        for _, field := range event.Fields {
            if isOSVRangeEventKind(field.Name) { known++ }
            switch field.Name {
            case "introduced": introduced=true
            case "fixed": fixed=true
            case "last_affected": lastAffected=true
            }
        }
        if known == 0 { add(OSVRangeProblemNoKnownEventKind,event.Index,"") }
        if known > 1 { add(OSVRangeProblemMultipleKnownEventKinds,event.Index,"") }
        for _, field := range event.Fields {
            if !isOSVRangeEventKind(field.Name) { add(OSVRangeProblemUnknownEventField,event.Index,field.Name)
            } else if field.Value.State != OSVFieldValue || field.Value.Value == "" { add(OSVRangeProblemEventValueUnusable,event.Index,field.Name) }
        }
    }
    if allObjects && !introduced { add(OSVRangeProblemIntroducedNotRecorded,-1,"events") }
    if fixed && lastAffected { add(OSVRangeProblemMixedFixedLastAffected,-1,"events") }
    result.Satisfied = len(result.Problems) == 0
    return result
}

func isOSVRangeEventKind(name string) bool {
    return name == "introduced" || name == "fixed" || name == "last_affected" || name == "limit"
}
```

  Add exported comments explaining bounded structure, exact source locators, caller
  preconditions and no version/interval/matching qualification. Private helpers remain
  private; do not move/change old helpers to support this module.

- [ ] **Format and verify focused/root offline.** All new cases and unchanged root
  suites pass, as does vet. Verify only the two new Go files changed, no go.sum,
  existing Go/module/probe bytes identical to approved base. Record actual counts.
- [ ] **Inline review and fresh verification.** Re-read the spec and inspect every
  abstention/diagnostic/guard branch. Check distinct order cases, all-record budgets,
  empty Problems vs nil, complete diagnostic order, snapshot ownership and derived
  40,000-problem bound. Re-run full tests/vet afterward. Do not call this independent review.
- [ ] **Commit only two Go files**, then separately record execution/limits/checks in
  spec/plan and a nested internal milestone. Publish only the authorized issue bookmark
  and first-person English updates to #14/PR #27. Keep Refs #14 and #15 blocked until
  second-person review and implementation integration; no automatic capability closure.

## Commands (Nushell)

Focused RED/GREEN, with failures inspected during RED:

```nu
with-env { GOTOOLCHAIN: local, GOPROXY: off, GOWORK: off, CGO_ENABLED: "0" } {
    go test -count=1 -run TestCheckOSVRangeStructure ./internal/intel
}
```

Full verification after implementation and again after inline review:

```nu
gofmt -w internal/intel/osv_range_structure.go internal/intel/osv_range_structure_test.go
with-env { GOTOOLCHAIN: local, GOPROXY: off, GOWORK: off, CGO_ENABLED: "0" } {
    go version
    go test -count=1 ./...
    if $env.LAST_EXIT_CODE != 0 { error make { msg: "Root tests failed" } }
    go vet ./...
    if $env.LAST_EXIT_CODE != 0 { error make { msg: "go vet failed" } }
}
jj commit -m "feat: check OSV range event structure" internal/intel/osv_range_structure.go internal/intel/osv_range_structure_test.go
```

Only commit after successful verification. The separate authorization covers this
bounded implementation/publication, not probes/downloads/targets or merging the PR. Official/native,
producer, matching, scanner and release qualification remain outside these synthetic tests.
