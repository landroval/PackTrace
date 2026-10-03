# Bounded Bun workspace declarations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. I preserve the owner's inline method and later GitHub peer review; no workflow/subagent execution is selected or authorized.

**Goal:** Implement the approved pure minimum typed Bun workspace-declaration projection with explicit states, owned positional evidence and two independent whole-document allowances.

**Architecture:** One new inventory module consumes unchanged successful BunLockDocument.Workspaces and reuses the existing object/scalar/group helpers. One owned synthetic test file pins literal claims, repeated memberships, nil/empty ownership, late whole-zero errors and non-authority. No reader/package-projection/shared-source changes or additional parser/consumer.

**Tech Stack:** Go, standard library only, existing inventory field/group/error helpers. No dependency/module or toolchain change.

**Spec:** [Approved workspace contract](issue-16-bun-workspaces.md), [draft PR #34](https://github.com/landroval/PackTrace/pull/34) at `4f74b970fc44c2cc327501bfaf9a3764e5f8ddf6`. The spec controls. Stop and resolve any discrepancy rather than infer new permissions from examples.

## Status and authority

I prepare this **local unapproved implementation-plan draft** after written-spec
approval and the owner's request to prepare the next plan. This authorizes the
plan document only: no plan push/PR update, Go source/test creation, compilation,
reader/fixture execution, mutation/root checks, acquisition or implementation.
The owner must review this written plan and explicitly authorize its execution
and any pre-code/implementation/evidence publication before the first Go file.
Approval of this plan without execution permission does not authorize those actions.

I retain the agreed isolated issue bookmark `issue-16-bun-workspaces-spec` and
direct integrated base `63b5873d747419e494432b2d1b80e10a611875d3`. I do not rebase,
merge siblings, change workspace or include the separate local-only unrelated
ledger-deletion checkpoint. PR #32/#33 are not dependencies. #16 remains OPEN/
Preparation, PR #34 draft. Ready/reviewer/merge/closure remain separate gates.

## Global Constraints

- Consume an unchanged successful ParseBunLock result, no concurrent input mutation. Existing64 MiB original input/depth128/integer versions0–3/strict JSONC behavior stays unchanged; no Bun producer/native compatibility claim.
- Exact proposed API below: Location, Name/Version LockField[string], Requirements []DependencyGroup and SourceSHA256/Records. No raw Fields copy, root flag, unavailable state, resolver or common inventory abstraction.
- One row per exact decoded workspace key, Go string order; exact `""` is the recorded root slot, absent root is not invented and `"."`/`"./"` remain distinct. All path/URL/control/private/Unicode text is inert evidence, not a qualified filesystem location.
- Name/version only explicit fields, missing/null/string/other => FieldAbsent/FieldNull/FieldValue/FieldInvalidType. Empty strings are values; unusable fields do not suppress siblings. No package/name/location/semantic fallback.
- Exactly four groups per row in dependencies/devDependencies/optionalDependencies/peerDependencies order. Missing/null/object/other => FieldAbsent/FieldNull/FieldValue/FieldInvalidType; non-value Entries nil, object Entries non-nil even empty. Object member requirements preserve exact keys/text and null/invalid states, no FieldAbsent invented entry.
- Independent bounds: at most20,000 workspace members checked before sorting/output allocation; at most20,000 cumulative object-group memberships across all workspaces/groups, including repeated names and null/invalid values. Pass one remaining allowance; no reset, deduplication or usable-only counting. Decoding allocations are not prevented by these work bounds.
- Nil Fields/Workspaces before count => whole-zero invalid-shape; count before per-row decode => limit-exceeded. Required object decode in sorted row order; later fatal returns whole-zero, never a prefix. No unused Packages guard or source SHA absence sentinel.
- Exact existing *ParseError and fixed texts inventory: invalid-shape/inventory: limit-exceeded; no raw/wrapped decoder/value/key/path/private content. Existing reader rejects duplicates/envelope/version errors before projection; do not rebuild its validator.
- Original-byte digest copied, document not mutated, returned strings/groups/entries independent of later raw mutation and sibling outputs. Records non-nil even empty. Unknown/unsupported raw evidence remains in the caller-retained document, not projected Fields.
- Successful sensitive evidence is not trusted policy or public-log/terminal/report/IPC-safe output. No path following/discovery/producer/package-manager/target/native execution, installed/effective inventory, config/overrides/catalogs/INFO semantics, resolution/matching/consumer/report/CLI/network/CI/fuzz/race/dependency/module work.
- Offline owned implementation checks only after explicit authorization: GOTOOLCHAIN=local/GOPROXY=off/GOWORK=off/CGO_ENABLED=0, no go.sum. Source purity and synthetic results do not qualify runtime platforms, memory limits, scanner coverage, pilots or shipping parents.
- [Development guidelines](../development-guidelines.md) and [collaboration gates](../github-collaboration.md) govern file-scoped jj commits/publication and independent review. CodeGraph unavailable; no retry/index. This plan is not instructions to inspect secrets or alter credentials/security.

## Review Focus

1. Root versus opaque location/name claims: missing root, dot variants, traversal/absolute/URL/control text and package tuple names must not cause invented root/identity/installed attribution.
2. Unusable scalar/group evidence beside usable siblings: null, empty and wrong types stay distinct, unsupported raw data stays in the document, no configuration/INFO fallback.
3. Whole-document allowances: repeated and unusable memberships spread across rows/groups consume the same remaining budget; workspace rows and memberships never combine/reset/deduplicate.
4. Mutable ownership boundaries: raw input, document maps, one output group and another repeated membership cannot alias; empty/nil and original-byte digest are preserved.
5. Private fatal versus sensitive success: late malformed/overlimit data discards all output and produces exact fixed errors; retained hostile claims confer no I/O, safety or coverage authority.

## Task 1 — projection, owned synthetic tests and scoped evidence

**Files:**
- Create `internal/inventory/bunlock_workspaces.go`: two exact structs and one public internal projection function.
- Create `internal/inventory/bunlock_workspaces_test.go`: named C01–C48 variants and focused states/locations/bounds/ownership/privacy tests.
- Only under separate evidence-publication authorization after checks: update this plan/the spec and one nested `docs/pre-1.0-features.md` milestone. No other existing source/module/probe/type/error/helper or top-level shipping change.

**Consumes (unchanged):**
- `ParseBunLock(data []byte) (BunLockDocument, error)` and its owned Workspaces/Fields/SHA256.
- `rawObjectMembers(raw json.RawMessage) (map[string]json.RawMessage, error)` from bunlock.go.
- `projectField[T string | bool](fields map[string]json.RawMessage, key string) LockField[T]` and `maxProjectedRecords = 20_000` from npmlock_projection.go.
- `projectDependencyGroups(fields map[string]json.RawMessage, allowance int) ([]DependencyGroup, int, error)` from manifest.go, plus `maxLockedRequirements = 20_000` from npmlock_projection.go.
- Exact `ParseError{Code string}`, `FieldState`, `LockField[string]`, `DependencyGroup` and `DeclaredDependency`, all unchanged.

**Produces (exact copied spec API):**

```go
type BunWorkspaceRecord struct {
    Location      string
    Name, Version LockField[string]
    Requirements  []DependencyGroup
}

type BunWorkspaceProjection struct {
    SourceSHA256 [32]byte
    Records      []BunWorkspaceRecord
}

func ProjectBunWorkspaces(doc BunLockDocument) (BunWorkspaceProjection, error)
```

### Authority and fresh baseline

- [ ] Obtain written-plan approval and **explicit inline source/test, owned offline checks/restored mutations, scoped code/evidence/pre-code publication authorization**. Record/commit/push/read back the pre-code approval before creating Go. If that push/read-back fails, stop source execution; do not change authentication or silently publish a different bookmark.
- [ ] Recheck exact approved spec bytes/PR/head/owner/comments/bookmark/base; existing two Go files absent, tree clean, unrelated checkpoint intact. Declare the two files/helper reuse/no shared changes in the issue under coordination authorization. No sibling base sync or new workspace.
- [ ] Capture exact toolchain and fresh offline root JSON tests/vet outside the repo. Count Action=pass records with nonempty Test, never package records or summed parallel runs. Historical2,219 is context, not this baseline. Save all preexisting tracked source/module/checklist fingerprints.

### Independently expected tests before declarations

- [ ] Create only the planned owned test file with these complete initial tests. Helpers construct inputs and assert invariants; expected rows/states/bounds are literal and never call production projectors to generate an oracle. Do not read Markdown at runtime or import probe/target/producer fixtures.

```go
package inventory

import (
    "bytes"
    "crypto/sha256"
    "encoding/json"
    "fmt"
    "go/ast"
    "go/parser"
    "go/token"
    "reflect"
    "strconv"
    "testing"
)

func bunWorkspaceTestDocument(t *testing.T, w map[string]any) (BunLockDocument, []byte) {
    t.Helper()
    data, err := json.Marshal(map[string]any{
        "lockfileVersion": 1, "workspaces": w, "packages": map[string]any{},
    })
    if err != nil { t.Fatal("invalid owned fixture") }
    doc, err := ParseBunLock(data)
    if err != nil { t.Fatal("reader rejected owned fixture") }
    return doc, data
}

func bunWorkspaceTestMembers(n int, value any) map[string]any {
    m := make(map[string]any, n)
    for i := 0; i < n; i++ { m[fmt.Sprintf("x%05d", i)] = value }
    return m
}

func bunWorkspaceTestFatal(t *testing.T, doc BunLockDocument, code string) {
    t.Helper()
    got, err := ProjectBunWorkspaces(doc)
    pe, ok := err.(*ParseError)
    if !ok || pe == nil || pe.Code != code || err.Error() != "inventory: "+code ||
        !reflect.DeepEqual(got, BunWorkspaceProjection{}) {
        t.Fatal("missing exact controlled whole-zero fatal")
    }
}

func TestProjectBunWorkspacesEmpty(t *testing.T) {
    doc, data := bunWorkspaceTestDocument(t, map[string]any{})
    got, err := ProjectBunWorkspaces(doc)
    if err != nil || got.Records == nil || len(got.Records) != 0 ||
        got.SourceSHA256 != sha256.Sum256(data) { t.Fatal("empty owned result missing") }
}

func TestProjectBunWorkspacesLocationsGroups(t *testing.T) {
    doc, data := bunWorkspaceTestDocument(t, map[string]any{
        "z": map[string]any{"name": "same"},
        "a": map[string]any{"name": "same"},
        "": map[string]any{
            "name": "same", "version": "", "dependencies": map[string]any{"x": "1"},
            "optionalDependencies": map[string]any{"x": "2"},
        },
    })
    before := append([]byte(nil), data...)
    got, err := ProjectBunWorkspaces(doc)
    if err != nil || len(got.Records) != 3 || got.SourceSHA256 != sha256.Sum256(before) {
        t.Fatal("source/rows missing")
    }
    for i, location := range []string{"", "a", "z"} {
        if got.Records[i].Location != location || got.Records[i].Name !=
            (LockField[string]{State: FieldValue, Value: "same"}) {
            t.Fatal("location sorted/repeated claim lost")
        }
    }
    want := []DependencyGroup{
        {Name: "dependencies", State: FieldValue, Entries: []DeclaredDependency{{Name: "x", Requirement: "1", State: FieldValue}}},
        {Name: "devDependencies"},
        {Name: "optionalDependencies", State: FieldValue, Entries: []DeclaredDependency{{Name: "x", Requirement: "2", State: FieldValue}}},
        {Name: "peerDependencies"},
    }
    if !reflect.DeepEqual(got.Records[0].Requirements, want) || got.Records[0].Version !=
        (LockField[string]{State: FieldValue}) { t.Fatal("groups/empty value conflated") }
    if !bytes.Equal(data, before) { t.Fatal("input bytes modified") }
}

func TestProjectBunWorkspacesFieldStates(t *testing.T) {
    doc, _ := bunWorkspaceTestDocument(t, map[string]any{
        "": map[string]any{
            "name": nil, "version": false, "dependencies": false,
            "devDependencies": map[string]any{}, "optionalDependencies": nil,
            "peerDependencies": map[string]any{"a": nil, "b": false, "c": ""},
        },
    })
    got, err := ProjectBunWorkspaces(doc)
    if err != nil || len(got.Records) != 1 { t.Fatal("usable row missing") }
    r := got.Records[0]
    want := []DependencyGroup{
        {Name: "dependencies", State: FieldInvalidType},
        {Name: "devDependencies", State: FieldValue, Entries: []DeclaredDependency{}},
        {Name: "optionalDependencies", State: FieldNull},
        {Name: "peerDependencies", State: FieldValue, Entries: []DeclaredDependency{
            {Name: "a", State: FieldNull}, {Name: "b", State: FieldInvalidType},
            {Name: "c", State: FieldValue},
        }},
    }
    if r.Name != (LockField[string]{State: FieldNull}) || r.Version !=
        (LockField[string]{State: FieldInvalidType}) || !reflect.DeepEqual(r.Requirements, want) {
        t.Fatal("states/usable sibling/nil-empty evidence lost")
    }
}

func TestProjectBunWorkspacesBoundsPrecedence(t *testing.T) {
    for _, n := range []int{10_000, 10_001} {
        t.Run(fmt.Sprint(n), func(t *testing.T) {
            doc, _ := bunWorkspaceTestDocument(t, map[string]any{
                "a": map[string]any{"dependencies": bunWorkspaceTestMembers(10_000, nil)},
                "z": map[string]any{"peerDependencies": bunWorkspaceTestMembers(n, false)},
            })
            if n == 10_001 { bunWorkspaceTestFatal(t, doc, "limit-exceeded"); return }
            got, err := ProjectBunWorkspaces(doc)
            if err != nil || len(got.Records) != 2 ||
                len(got.Records[0].Requirements) != 4 || len(got.Records[1].Requirements) != 4 ||
                len(got.Records[0].Requirements[0].Entries) != 10_000 ||
                len(got.Records[1].Requirements[3].Entries) != 10_000 {
                t.Fatal("unusable memberships not retained/count-bounded")
            }
        })
    }
    t.Run("late-private-shape", func(t *testing.T) {
        doc, _ := bunWorkspaceTestDocument(t, map[string]any{
            "a-private": map[string]any{"name": "synthetic-secret"}, "z-private": map[string]any{},
        })
        doc.Workspaces["z-private"] = json.RawMessage(`null`)
        bunWorkspaceTestFatal(t, doc, "invalid-shape")
    })
}

func TestProjectBunWorkspacesOwnership(t *testing.T) {
    doc, data := bunWorkspaceTestDocument(t, map[string]any{
        "a": map[string]any{"name": "private", "dependencies": map[string]any{"x": "1"}},
        "z": map[string]any{"name": "private", "dependencies": map[string]any{"x": "1"}},
    })
    got, err := ProjectBunWorkspaces(doc)
    if err != nil || len(got.Records) != 2 || len(got.Records[0].Requirements) != 4 ||
        len(got.Records[1].Requirements) != 4 || len(got.Records[0].Requirements[0].Entries) != 1 ||
        len(got.Records[1].Requirements[0].Entries) != 1 { t.Fatal("owned evidence missing") }
    wantDigest := sha256.Sum256(data)
    clear(data)
    clear(doc.Workspaces["a"])
    clear(doc.Fields["workspaces"])
    delete(doc.Workspaces, "z")
    if got.SourceSHA256 != wantDigest || got.Records[0].Name.Value != "private" ||
        got.Records[1].Name.Value != "private" { t.Fatal("raw input aliases typed result") }
    got.Records[0].Requirements[0].Entries[0].Requirement = "changed"
    if got.Records[1].Requirements[0].Entries[0].Requirement != "1" {
        t.Fatal("output memberships alias")
    }
}

func TestProjectBunWorkspacesGuards(t *testing.T) {
    for _, mode := range []string{"fields", "workspaces"} {
        t.Run(mode, func(t *testing.T) {
            doc, _ := bunWorkspaceTestDocument(t, map[string]any{})
            if mode == "fields" { doc.Fields = nil } else { doc.Workspaces = nil }
            bunWorkspaceTestFatal(t, doc, "invalid-shape")
        })
    }
    t.Run("unused-packages-zero-digest-basic-guard", func(t *testing.T) {
        doc, _ := bunWorkspaceTestDocument(t, map[string]any{})
        doc.Packages, doc.SHA256 = nil, [32]byte{}
        got, err := ProjectBunWorkspaces(doc)
        if err != nil || got.Records == nil || len(got.Records) != 0 ||
            got.SourceSHA256 != ([32]byte{}) { t.Fatal("invented package/digest absence guard") }
        // A defensive mutated document is not reader-qualified/authenticated evidence.
    })
}

func TestProjectBunWorkspacesPrivacySeparation(t *testing.T) {
    t.Run("sensitive-inert-success", func(t *testing.T) {
        doc, _ := bunWorkspaceTestDocument(t, map[string]any{
            "file:///private\x00\n": map[string]any{
                "name": "synthetic-secret\x00\n", "version": "not-semver",
                "dependencies": map[string]any{"x": "https://synthetic-user:synthetic-secret@private.invalid/path"},
            },
        })
        got, err := ProjectBunWorkspaces(doc)
        if err != nil || len(got.Records) != 1 || len(got.Records[0].Requirements) != 4 ||
            len(got.Records[0].Requirements[0].Entries) != 1 { t.Fatal("inert row missing") }
        r := got.Records[0]
        if r.Location != "file:///private\x00\n" || r.Name !=
            (LockField[string]{State: FieldValue, Value: "synthetic-secret\x00\n"}) ||
            r.Version != (LockField[string]{State: FieldValue, Value: "not-semver"}) ||
            r.Requirements[0].Entries[0] != (DeclaredDependency{Name: "x", State: FieldValue,
                Requirement: "https://synthetic-user:synthetic-secret@private.invalid/path"}) {
            t.Fatal("sensitive internal evidence interpreted or lost")
        }
    })
    t.Run("owned-source-purity", func(t *testing.T) {
        file, err := parser.ParseFile(token.NewFileSet(), "bunlock_workspaces.go", nil, 0)
        if err != nil { t.Fatal("cannot inspect owned source") }
        for _, imp := range file.Imports {
            path, err := strconv.Unquote(imp.Path.Value)
            if err != nil || (path != "maps" && path != "slices") { t.Fatal("out-of-scope import") }
        }
        for _, decl := range file.Decls {
            if d, ok := decl.(*ast.GenDecl); ok && d.Tok == token.VAR { t.Fatal("mutable singleton") }
        }
        ast.Inspect(file, func(n ast.Node) bool {
            if call, ok := n.(*ast.CallExpr); ok {
                if id, ok := call.Fun.(*ast.Ident); ok &&
                    (id.Name == "print" || id.Name == "println" || id.Name == "panic") {
                    t.Fatal("owned production side effect")
                }
            }
            return true
        })
    })
}
```

- [ ] Add `TestProjectBunWorkspacesReference` with named C01–C48 cases from the exact approved table. Transcribe literal inputs/expected states directly, not generated runtime Markdown. Use the helper above for qualified documents; construct the deliberately nil/malformed defensive variants only after parsing, and mark them as such. C29 is an existing-reader duplicate-key regression: check its typed `duplicate-key`/fixed text/zero document and never call projection; it can pass during projection RED. C01–C28/C30–C48 are projection examples. A documentary row is not a test/subtest count.
- [ ] Extend `LocationsGroups`/Reference for C02–C07/C12/C17/C21–C28 and focus1/2: literal locations with independently expected order `["", ".", "../private", "./", "/abs", "C:\\private", "file:///x", "nul\x00\n"]`, missing root, exact Unicode/case/whitespace scalars, entries A/a/z, repeated same names/text conflicts, opaque aliases/ranges/catalog/file/git/private URL strings. Pin no Packages tuple fallback and unchanged unknown/precise raw evidence. Run the same claims through four separate version0–3 literals and JSONC/whitespace variants; expected digests are independently sha256.Sum256(originalData), not doc reconstruction.
- [ ] Extend `FieldStates` for C08–C20 and focus2: each name/version independently absent/null/empty/string/number/bool/array/object; each group independently absent/null/empty-object/array/bool/number/string, with usable siblings. Each requirement independently null/false/array/object/number/empty/string. Retain explicit literal expected structs as above. Unknown raw config/peer/INFO must not become entries or repair missing fields; do not add raw Fields to the new API.
- [ ] Extend `BoundsPrecedence` for C33–C48/focus3/5 with the exact table constructions below. Use literal20_000/20_001 expectations, never production constants. Repeated/null/invalid members count even when identity scalars are unusable. Before each error check snapshot intended prior valid rows and use the whole-zero assertion, not only nonnil error.

| IDs | Concrete owned construction and assertion |
| --- | --- |
| C33 | Build20,001 workspace object members, then set doc.Fields=nil. Expect invalid-shape before limit; snapshot result must be the entire zero value. |
| C34–C36 | For each raw nil, null, [], string, number, bool and malformed JSON substitute one parsed workspace raw. Place a bad z after a valid a; expect whole-zero invalid-shape with fixed private text. |
| C37–C38 | Build map with root `""` plus rows w00001–w19999;20,000 success with four absent groups each. Add one z object to reach20,001, parse, then replace only doc.Workspaces["z"] with raw null; limit precedes per-row shape. |
| C39–C40 | One dependencies object from bunWorkspaceTestMembers(20_000,"1") or20_001; boundary success versus whole-zero limit. Verify nonnil Records/Entries and exact count. |
| C41–C42 | Root dependencies10,000 plus optionalDependencies10,000/10,001 using the same x names. Two memberships per repeated name are counted, never merged. |
| C43–C44 | a and z each10,000 requirements or z10,001; root need not exist. Do not reset remaining allowance per row. |
| C45–C46 | a.dependencies10,000 null and z.peerDependencies10,000/10,001 false, as the complete test above. All unusable entries count; no usable-only consumption. |
| C47 | root plus19,999 other empty workspace objects, with root.dependencies20,000 entries. Assert both independent counts succeed, not a shared combined20k cap. |
| C48 | a-private has sensitive name/version plus10,000 requirements whose string values are synthetic-secret; z has10,001 false requirements. Total20,001. Exact private limit and whole-zero, no disclosure of any earlier prefix or late JSON. |

- [ ] Extend `Ownership` for C25/C28/C30–C32/focus4 in separate calls. Snapshot original input/doc bytes before projection, verify no mutation, then clear caller bytes, raw workspace bytes, top-level raw Fields, replace/delete maps, or mutate one output group/entry. Untouched typed/sibling results and a second fresh projection stay equal to literal originals. Verify nonnil empty Records/object Entries and nil non-value Entries explicitly. Raw data is retained only if the caller keeps the original document; never claim a projected raw bundle.
- [ ] Add `TestProjectBunWorkspacesPrivacySeparation` for focus1/5: sensitive/control/URL-looking successful strings remain exact data, no inferred registration/safety/freshness/installed/coverage status; private failures use the assertion above. Inspect new production AST with `go/parser`/`go/ast`: imports limited to maps/slices, no mutable VAR singleton or print/println/panic call. Also review the unchanged consumed helpers manually. This owned-source guard is not native/no-write proof. No target files or fake storage consumers.

### Compilation and behavioral RED

- [ ] Run all new focused tests before API declarations. Inspect missing ProjectBunWorkspaces/BunWorkspaceProjection compilation RED; the compiler need not print every missing name. Save status/output externally.
- [ ] Add the exact two structs above and the following temporary zero/nil stub to the new production file. Rerun focused JSON tests: successful projection rows fail structure/digest/non-nil assertions; fatal rows fail typed errors. Record actual pass/fail records and names. Do **not** claim C29 or AST purity necessarily fail or that all48 reference rows are projection tests.

```go
func ProjectBunWorkspaces(doc BunLockDocument) (BunWorkspaceProjection, error) {
    return BunWorkspaceProjection{}, nil
}
```

### Minimum implementation and GREEN

- [ ] Replace the stub with this complete planned module. Reuse maxProjectedRecords/maxLockedRequirements and existing helpers unchanged; no new constants, private parser/registry/deep-copy framework or shared extraction. Comments qualify source class, input precondition, controlled errors and non-authority.

```go
package inventory

import (
    "maps"
    "slices"
)

// BunWorkspaceRecord retains declarations recorded in a lockfile workspace.
// Location and scalar claims are opaque, not safe paths or installed attribution.
type BunWorkspaceRecord struct {
    Location      string
    Name, Version LockField[string]
    Requirements  []DependencyGroup
}

// BunWorkspaceProjection links owned typed claims to original Bun input bytes.
// Unknown/unsupported raw evidence remains in the caller-retained document.
type BunWorkspaceProjection struct {
    SourceSHA256 [32]byte
    Records      []BunWorkspaceRecord
}

// ProjectBunWorkspaces requires an unchanged successful ParseBunLock result and no
// concurrent mutation. Basic guards do not authenticate a forged document. The
// two allowances bound metadata work, not RSS, paths, producer support or coverage.
// Successful sensitive evidence is internal data, not public-log/report/IPC output.
func ProjectBunWorkspaces(doc BunLockDocument) (BunWorkspaceProjection, error) {
    if doc.Fields == nil || doc.Workspaces == nil {
        return BunWorkspaceProjection{}, &ParseError{Code: "invalid-shape"}
    }
    if len(doc.Workspaces) > maxProjectedRecords {
        return BunWorkspaceProjection{}, &ParseError{Code: "limit-exceeded"}
    }
    records := make([]BunWorkspaceRecord, 0, len(doc.Workspaces))
    remaining := maxLockedRequirements
    for _, location := range slices.Sorted(maps.Keys(doc.Workspaces)) {
        fields, err := rawObjectMembers(doc.Workspaces[location])
        if err != nil { return BunWorkspaceProjection{}, err }
        groups, used, err := projectDependencyGroups(fields, remaining)
        if err != nil { return BunWorkspaceProjection{}, err }
        remaining -= used
        records = append(records, BunWorkspaceRecord{
            Location: location,
            Name: projectField[string](fields, "name"),
            Version: projectField[string](fields, "version"),
            Requirements: groups,
        })
    }
    return BunWorkspaceProjection{SourceSHA256: doc.SHA256, Records: records}, nil
}
```

- [ ] Run focused GREEN and inspect every literal ID/variant. Diagnose unexpected failure before changing code; do not weaken states, ownership, both budgets or controlled whole-zero errors. The shared decoders already own typed strings/groups; do not clone whole raw workspace objects or add a second raw evidence API.

### Restored mutations and final author review

- [ ] Save new production source SHA externally. Temporarily reset remaining=maxLockedRequirements inside each row iteration: C44 and late/global/privacy budget tests must fail. Restore original source and verify SHA before the next mutation.
- [ ] Temporarily combine counts by setting initial remaining=maxLockedRequirements-len(doc.Workspaces): C47 must fail. Restore/check SHA. This is distinct from the global-reset failure.
- [ ] Temporarily overwrite used with the count of FieldValue entries after group projection, changing only this new module: C46 spread over two rows must fail because null/invalid memberships cease to consume remaining allowance. Do not mutate the shared helper; restore/check SHA.
- [ ] Temporarily force Name to the Location-derived FieldValue, then separately reverse the sorted key slice with slices.Reverse before iteration: C26 and explicit literal location ordering/repeated-row tests respectively must detect the changes. Never rely on randomized Go map order as the ordering mutation or oracle. Restore/check SHA each time.
- [ ] Temporarily return a populated partial projection on a late malformed raw object or append its key as a marker to the error: C36/C48/private-fatal tests must fail. Test partial/disclosure separately; use a coherent fixture whose other guards do not mask the defect. Restore/check SHA before final checks. Never commit temporary code or report an unchecked restoration.
- [ ] Format only the two new Go files. Freshly run focused and full root JSON tests/vet under the offline flags below; capture actual toolchain/stdout/stderr/status. Count one actual root stream's nonempty Test pass records and new TestProjectBunWorkspaces records; C29 is a reader example, not extra producer evidence. Check original Go/module/probe/shipping bytes and no go.sum; source restored SHA must match.
- [ ] Self-review all five focus classes against complete source/tests. Decline native/producer/consumer coverage because explicitly excluded, not silently dropped. Record author review as such; no workflow/subagent/GitHub approval is inferred. Commit only the two Go files under approved execution authority.
- [ ] Only under separately approved evidence publication, update spec/plan and a single nested pre-1.0 inventory milestone with exact measured RED/GREEN/mutations/counts/toolchain/limits. Commit those docs separately, push only issue16 bookmark, and read back exact head/body/file scope. Never push the unrelated local checkpoint. Keep #16 OPEN and PR34 draft; ready/reviewer/merge/closure require separate authority.

## Future offline commands and commits

These commands are examples for explicitly authorized execution, not preparation
observations. Save JSON streams/stdout/stderr/status outside the repository. Do not
run product tests or mutation commands while this plan is unapproved.

```nu
with-env {GOTOOLCHAIN: "local", GOPROXY: "off", GOWORK: "off", CGO_ENABLED: "0"} {
    go test -count=1 -run '^TestProjectBunWorkspaces' ./internal/inventory
}
```

```nu
with-env {GOTOOLCHAIN: "local", GOPROXY: "off", GOWORK: "off", CGO_ENABLED: "0"} {
    go version
    go test -count=1 -json ./...
    go vet ./...
}
```

```nu
gofmt -w internal/inventory/bunlock_workspaces.go internal/inventory/bunlock_workspaces_test.go
jj diff --name-only
jj commit internal/inventory/bunlock_workspaces.go internal/inventory/bunlock_workspaces_test.go -m "feat: project Bun workspace claims (#16)"
```

Use slash-separated -run components for selected subtests, and verify at least one
intended test executed; a zero selection is not RED/GREEN evidence. If a temporary
receipt/fingerprint disappears, do not invent it: distinguish historical observed
results from fresh checks, verify the restored functions against the approved GREEN
listing and document the recovery before committing/publishing.

## Self-review and handoff

The single task implements each spec section with unchanged interfaces/helpers and
maps C01–C48 to Reference/Empty/LocationsGroups/FieldStates/BoundsPrecedence/Ownership/
Guards/PrivacySeparation. The five Review Focus classes have explicit owning test
steps. Expected states/order/limits come from the written spec, not a production
oracle. Complete initial tests and the minimum module are planned source, not
compiled declarations or executed fixtures.

I self-reviewed every spec section against the single task, all48 reference mappings,
exact API/helper/constant names, fixed error codes, both budget roles, whole-zero and
ownership/privacy invariants, and the five owning focus steps. I corrected the late
20,001-row fixture construction and made the ordering mutation explicitly reversed,
not randomized map iteration. I found no remaining in-scope requirement gap.

During preparation I syntax/formatted four Go fragments and syntax-checked three
Nushell examples with nu-check (0.116.0), and verified four links/anchors. I copied
the approved API exactly; all previous tracked bytes/module/checklist and the separate
local deletion checkpoint remain unchanged. Legal Go variadic and CLI ./... tokens
are not placeholders. These checks neither compile the API/tests nor execute a reader,
fixture, root test/vet, mutation, native probe or qualification job; no new test count.

I preserve inline execution as the previously selected method; no new agent workflow
is recommended or dispatched. After syntax/link/type/coverage self-review, the next
gate is **owner review of this written plan**, with a separate explicit execution/
pre-code/evidence-publication choice. Plan preparation/approval alone does not grant
those permissions. I do not push this plan, change Project state or start Go work
without that authorization.
