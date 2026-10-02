# Bounded OSV npm identities implementation plan (#13)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans
> for the selected inline workflow. Track steps below; an author self-review is
> not independent GitHub review. No execution starts without explicit approval.

**Goal:** Qualify bounded lexical npm identity candidates from paired OSV evidence,
retaining exact source claims, profile uncertainty and usable-name conflicts.

**Architecture:** One pure intel helper consumes existing OSVHeader and
OSVAffectedProjection from the same unchanged successful OSVDocument. Validate
consumed layout/budgets before output allocation; retain every positional entry;
interpret only v1 inspectable package objects. No common inventory/intel model.

**Tech Stack:** Existing development Go toolchain and standard library only,
including strings, net/url and test-only reflect/errors/encoding/json.

**Spec:** [approved specification](issue-13-osv-npm-identity.md).

Status: plan approved; inline execution explicitly authorized, including two new
Go files, offline RED/GREEN/root tests/vet, scoped commits and publication in draft
PR #28. No new dependencies/targets/corpus, CI/native work, ready/reviewer request
or merge is authorized.
Published in [draft PR #28](https://github.com/landroval/PackTrace/pull/28).
Completed code: `95f4504c`; compile/behavioral RED observed (198 new failing cases
against zero stub), post-review focused/root tests 1,143 total/198 new and offline
vet pass. Case-folding mutation failed both conflict fixtures and was removed.
Gofmt/old Go/module/probe bytes/no go.sum verified. Toolchain:
go1.27.1-X:nodwarf5 linux/amd64; no native/producer/product qualification.
Author self-review, not independent review; PR remains draft, no merge.

Workspace ruling: use the selected jj feature workspace and external execution ledger
rather than git-script/root workspace scaffolding. This matches the approved workspace
preference; the cost is manual bookkeeping/base/scope verification.

## Global constraints

- Only new production/test files: internal/intel/osv_npm_identity.go and
  internal/intel/osv_npm_identity_test.go. Do not change old Go files or go.mod;
  no dependencies/go.sum, probe work, corpus/targets or runtime/network operation.
- Keep SourceSHA256, affected indices/order/duplicates, states and all source strings
  exactly; own output collections. Unavailable parents are not absent children.
- Pair successful unchanged projections, no concurrent input mutation. Basic guards
  do not authenticate forged inputs or revalidate unrelated ranges/versions.
- Reader precondition: 4 MiB, depth 128. Existing maxAffectedEntries=20,000 counts
  every slot. Preflight even when header/identity interpretation abstains.
- Lexical name subset: ASCII A-Z/a-z/0-9/-/./_/~, total 1..214 bytes including @/slash.
  Unscoped leading dot/underscore excluded; scoped nonempty components allow them.
  No trim, case folding, package.name decoding, Unicode/alias/registry inference.
- Optional PURL: exact pkg:npm/, unversioned, at most 650 raw bytes; encoded scope;
  split before one-time path decoding. No query/subpath/version or fallback stripping.
- Unknown is abstention; Candidate is unconfirmed lexical identity; Unqualified is
  unsupported/unusable; Conflict is two usable npm name claims differing exactly.
  None is a match/no-match, origin confirmation, coverage completion or enforcement.
- Fatal invalid-shape/limit-exceeded: existing ParseError, exact intel: CODE and zero
  whole result. Profile problems are owned diagnostics, nil error; never truncation.
- Publication, ready/reviewer requests, merge and queue cleanup retain separate gates.
  Plan preparation is not new Go execution or CI/native/producer qualification.

## Review focus

1. Legacy case and encoded case remain exact; Foo vs foo is a conflict, not equality.
2. Usable PURL cannot rescue absent/null/invalid ecosystem/name; inspect all siblings.
3. Split before decode; encoded slash, double-encoded @ and query plus semantics cannot
   synthesize another supported identity. No qualifier/version-stripping fallback.
4. Header abstention cannot bypass invalid consumed layout or 20,001-slot guard.
5. Independent owned output and unavailable-vs-absent/nil-vs-empty hierarchy survive
   retained duplicates, source mutation and late malformed positions.

---

### Task 1: one bounded helper and its independent literal checks

**Files:**
- Create: internal/intel/osv_npm_identity.go.
- Create/test: internal/intel/osv_npm_identity_test.go.
- Read unchanged: osv.go, osv_header.go, osv_affected.go and existing tests.
- Documentation after GREEN: this plan, its spec and one nested milestone in
  ../pre-1.0-features.md; no top-level capability/shipping closure.

**Interfaces:**
- Consumes: OSVHeader and OSVAffectedProjection as defined in the approved spec;
  existing ParseOSVRecord, ProjectOSVHeader, ProjectOSVAffected for real fixtures.
- Produces: QualifyOSVNPMIdentities(header OSVHeader, affected OSVAffectedProjection)
  (OSVNPMIdentityProjection, error), with the five exact types and constants in spec.
- Private only: validateOSVNPMIdentityInput(header, affected) error;
  validOSVNPMName(name string) bool; parseOSVNPMIdentityPURL(text string)
  (name string, usable bool); qualifyOSVNPMIdentityEntry(entry OSVAffectedEntry)
  OSVNPMIdentityEntry. No exported parser/validator or shared-type change.

- [x] **Step 1: recheck authority, live ownership and independent base.**

Read both documents, docs/development-guidelines.md and docs/github-collaboration.md.
Confirm explicit plan+execution approval before code. Inspect #13/PR #28 comments,
assignment, head/base and concurrent teammate changes. Check clean selected jj
workspace/bookmark issue-13-osv-npm-identity-spec descending directly from integrated
development c5337ea8; do not stack unreviewed #14. If development moved, assess/rebase
only with appropriate approval, then verify the actual changed baseline. Keep a
temporary external execution ledger rather than a competing .pi queue.

Use the existing selected workspace; do not create a generic git branch/worktree,
new root task file or subagent/workflow dispatch. Current preference is inline; the
user must confirm method/authority at the handoff before implementation starts.

- [x] **Step 2: fresh offline baseline and record exact toolchain.**

Commands below are Nushell; run only after execution authorization:

```nu
with-env {GOTOOLCHAIN: local, GOPROXY: off, GOWORK: off, CGO_ENABLED: '0'} {
    go version
    go test -count=1 ./...
    go vet ./...
}
```

Inspect each exit status/output before proceeding; a failed baseline is not RED
for this feature. Stop for missing toolchain/dependency; never enable auto-download.
Record actual branch tests/toolchain, not sums of sibling branches.

- [x] **Step 3: write fixtures and literal behavioral assertions first.**

Use real envelopes, a local fixture helper and deep independent expected values:

```go
func npmIdentityInput(t *testing.T, packageJSON string) (OSVDocument, OSVHeader, OSVAffectedProjection) {
    t.Helper()
    source := `{"id":"fixture","modified":"opaque","affected":[{"package":` + packageJSON + `}]}`
    doc, err := ParseOSVRecord([]byte(source))
    if err != nil { t.Fatal(err) }
    header, err := ProjectOSVHeader(doc)
    if err != nil { t.Fatal(err) }
    affected, err := ProjectOSVAffected(doc)
    if err != nil { t.Fatal(err) }
    return doc, header, affected
}

func TestQualifyOSVNPMIdentitiesCaseConflict(t *testing.T) {
    _, header, affected := npmIdentityInput(t, `{"ecosystem":"npm","name":"Foo","purl":"pkg:npm/foo"}`)
    got, err := QualifyOSVNPMIdentities(header, affected)
    want := OSVNPMIdentityProjection{
        SourceSHA256: affected.SourceSHA256, HeaderSchema: OSVHeaderSchemaV1Implicit,
        State: OSVFieldValue,
        Entries: []OSVNPMIdentityEntry{{
            Index: 0, State: OSVFieldValue, PackageState: OSVFieldValue,
            Ecosystem: OSVString{State: OSVFieldValue, Value: "npm"},
            Name: OSVString{State: OSVFieldValue, Value: "Foo"},
            PURL: OSVString{State: OSVFieldValue, Value: "pkg:npm/foo"},
            Qualification: OSVNPMIdentityConflict, PURLUsable: true, PURLName: "foo",
            Problems: []OSVNPMIdentityProblem{{Kind: OSVNPMIdentityProblemPURLNameConflict, Field: "purl"}},
        }},
    }
    if err != nil || !reflect.DeepEqual(got, want) { t.Fatal("case conflict lost", got, err) }
}
```

Import test dependencies explicitly. The fixture source ID is synthetic, not a
source-derived path or active advisory. Add these named suites with literal expected
qualifications/fields/problems, not production helper results as the oracle:

**TestQualifyOSVNPMIdentitiesProfile:** use the package tuple npm/Foo as baseline.

| Changed claim | Literal result |
|---|---|
| PURL absent | Candidate, false/empty derived PURL, non-nil empty Problems |
| PURL pkg:npm/Foo or pkg:npm/%46oo | Candidate, PURLUsable true, PURLName Foo |
| PURL pkg:npm/foo | Conflict, PURLNameConflict/purl |
| name @Scope/_Name; PURL pkg:npm/%40Scope/_Name | Candidate, exact case/scoped text |
| name @scope/.name or @.scope/name; matching bounded PURL | Candidate (lexical only, not registration) |
| name .name or _name unscoped | Unqualified, NameOutsideProfile/name |
| name empty, *, a/b, @scope/, @/name, @@scope/name | Unqualified, NameOutsideProfile/name |
| name a:b, a+b, a%20b, space/control/non-ASCII | Unqualified, NameOutsideProfile/name |
| ecosystem npm with whitespace, NPM, PyPI or empty | Unqualified, EcosystemOutsideProfile/ecosystem |
| ecosystem/name absent, null or non-string | Unqualified, corresponding Unusable problem |
| PURL null or non-string | Unqualified, PURLUnusable/purl (no fallback) |
| PURL empty, pkg:NPM/Foo, PKG:npm/Foo or wrong type | Unqualified, PURLOutsideProfile/purl |
| PURL pkg:npm/Foo@1, ?key=value or #path | Unqualified, PURLOutsideProfile/purl |
| PURL pkg:npm/@scope/name | Unqualified, PURLOutsideProfile/purl |
| PURL pkg:npm//Foo, /Foo, Foo/ or scope/a/b | Unqualified, PURLOutsideProfile/purl |
| PURL encoded slash, @ in name, control/non-ASCII or malformed % escape | Unqualified, PURLOutsideProfile/purl |
| PURL pkg:npm/%2540scope/name | Unqualified, PURLOutsideProfile/purl; decode once only |
| missing ecosystem/name with usable PURL | Unqualified; parsed PURL retained, no inference |
| PyPI/Foo with usable npm PURL | Unqualified, ecosystem problem, not a parsed cross-domain conflict |
| absent ecosystem, invalid name and invalid PURL | Three problems in ecosystem/name/purl order |

Cover every JSON primitive/unusable type, rather than only one representative. Empty
name and whitespace PURL are typed strings outside profile, not InvalidType.

**TestQualifyOSVNPMIdentitiesHierarchy:** build full envelopes for absent/null/non-array/
empty affected; null/non-object/object affected slots; absent/null/non-object/empty
package. Verify every copied state/string, nil/non-nil collections and source indices;
wrong-level name/ecosystem/purl must not fill missing package fields. Retain duplicates
and nonmonotonic Foo/Bar source order beside unusable/unsupported entries.

**TestQualifyOSVNPMIdentitiesHeaderGate:** implicit/declared v1 vs null/bad/unsupported
schema, preserving source text in unknown results with Problems=nil and no derived PURL.
Both v1 modes inspect; unknown/unsupported modes do not generate profile diagnostics.

A concrete preflight/whole-zero assertion, in addition to the table cases:

```go
func TestQualifyOSVNPMIdentitiesLateGuardDuringAbstention(t *testing.T) {
    _, header, affected := npmIdentityInput(t, `{"ecosystem":"npm","name":"Foo"}`)
    header.Schema = OSVHeaderSchemaUnknown
    second := affected.Entries[0]
    second.Index = 4 // forged late locator, not reader-produced evidence
    affected.Entries = append(affected.Entries, second)
    got, err := QualifyOSVNPMIdentities(header, affected)
    var parseErr *ParseError
    if !errors.As(err, &parseErr) || parseErr.Code != "invalid-shape" || err.Error() != "intel: invalid-shape" || !reflect.DeepEqual(got, OSVNPMIdentityProjection{}) {
        t.Fatal("abstention bypassed preflight or leaked partial output", got, err)
    }
}
```

**TestQualifyOSVNPMIdentitiesLimits:** test literal 214/215 lengths, including full
scope @slash length; exact 650 raw unscoped PURL (`pkg:npm/` + 214 `%41` escapes) paired
with 214 A name, and 651 outside profile without fatal error. Use 20,000/20,001 slots
counting unusable/repeated identities, no prefix. The over-limit forged projection
extends a successful parsed input expressly for the guard; do not call it producer
or reader acceptance. Test unknown/unsupported header cannot bypass this limit.

**TestQualifyOSVNPMIdentitiesGuards:** forged paired digest, top unavailable/value nil/
non-value children, missing/noncontiguous/reordered indices, invalid member/package
state and fabricated unavailable child values. Assert exact existing error and zero
**whole** result with nonzero digest; a late bad entry must not return earlier results.

**TestQualifyOSVNPMIdentitiesOwnership:** copy doc raw maps/slices and complete input
projections into independent snapshots before call; compare after. Then mutate output
entries/Problems/strings and input entries/strings independently; no aliases, ordering
changes or duplicated-slot sharing. Unrelated versions/ranges remain unchanged, not
copied into this output or reinterpreted as identity.

**TestQualifyOSVNPMIdentitiesSeparation:** raw package.name percent text is never decoded;
valid lexical candidates do not parse versions, URLs, registry origin, withdrawal or
installed claims. Preserve unrelated raw siblings. Reader 4 MiB/depth-128 success and
rejections remain existing reader behavior, not a new full-schema acceptance claim.

- [x] **Step 4: observe API compile RED, then behavioral RED.**

Run only the new suite first. Observe undefined QualifyOSVNPMIdentities/types, record
compiler error outside repo. Add exact five types/constants from approved spec and
zero-return signature, nothing else. Re-run: literal output cases must fail behaviorally;
inspect actual case names/reasons so fixture errors cannot masquerade as RED. Count
actual fails/passes; do not assert every guard test must fail against a zero stub.

```nu
with-env {GOTOOLCHAIN: local, GOPROXY: off, GOWORK: off, CGO_ENABLED: '0'} {
    go test -count=1 ./internal/intel -run '^TestQualifyOSVNPMIdentities' -v
}
```

- [x] **Step 5: implement the smallest helpers, no generalized parser.**

Private name and PURL algorithms are fixed by these plan snippets:

```go
func validOSVNPMName(name string) bool {
    if len(name) == 0 || len(name) > 214 { return false }
    component := func(s string) bool {
        if s == "" { return false }
        for i := 0; i < len(s); i++ {
            c := s[i]
            if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~') { return false }
        }
        return true
    }
    if strings.HasPrefix(name, "@") {
        parts := strings.Split(name[1:], "/")
        return len(parts) == 2 && component(parts[0]) && component(parts[1])
    }
    return name[0] != '.' && name[0] != '_' && component(name)
}

func parseOSVNPMIdentityPURL(text string) (string, bool) {
    if len(text) > 650 || !strings.HasPrefix(text, "pkg:npm/") { return "", false }
    tail := strings.TrimPrefix(text, "pkg:npm/")
    if strings.ContainsAny(tail, "@?#") { return "", false }
    parts := strings.Split(tail, "/")
    if len(parts) != 1 && len(parts) != 2 { return "", false }
    name, err := url.PathUnescape(parts[len(parts)-1])
    if err != nil || strings.ContainsAny(name, "@/") { return "", false }
    if len(parts) == 2 {
        scope, err := url.PathUnescape(parts[0])
        if err != nil || !strings.HasPrefix(scope, "@") { return "", false }
        name = scope + "/" + name
    }
    if !validOSVNPMName(name) { return "", false }
    return name, true
}
```

Before allocations, validate pairing, 20,000 entry bound, top/member/package layouts,
indices and immediate OSVString states: object package strings can be absent/null/
invalid-type/value but never unavailable; non-value string states have empty Value.
Unusable parent package children must equal zero OSVString, and non-object affected
members require PackageState Unavailable. Top non-value states may only be absent/
null/invalid-type with nil entries; value lists require non-nil entries. Package in
an object entry can be absent/null/invalid-type/value, not Unavailable. Array members
can only be null/invalid-type/value. Return &ParseError{Code: "invalid-shape"} or
&ParseError{Code: "limit-exceeded"}, never allocated partial output. Budget tests with
otherwise successful shapes separate categories; do not rely on unspecified category
priority when several guards fail simultaneously.

The entry qualification has no fallback; use the literal field order below:

```go
func qualifyOSVNPMIdentityEntry(entry OSVAffectedEntry) OSVNPMIdentityEntry {
    out := OSVNPMIdentityEntry{Index: entry.Index, State: entry.State, PackageState: entry.PackageState,
        Ecosystem: entry.Ecosystem, Name: entry.Name, PURL: entry.PURL,
        Qualification: OSVNPMIdentityUnqualified, Problems: []OSVNPMIdentityProblem{}}
    problem := func(kind OSVNPMIdentityProblemKind, field string) {
        out.Problems = append(out.Problems, OSVNPMIdentityProblem{Kind: kind, Field: field})
    }
    ecoOK := entry.Ecosystem.State == OSVFieldValue && entry.Ecosystem.Value == "npm"
    if entry.Ecosystem.State != OSVFieldValue {
        problem(OSVNPMIdentityProblemEcosystemUnusable, "ecosystem")
    } else if !ecoOK {
        problem(OSVNPMIdentityProblemEcosystemOutsideProfile, "ecosystem")
    }
    nameOK := entry.Name.State == OSVFieldValue && validOSVNPMName(entry.Name.Value)
    if entry.Name.State != OSVFieldValue {
        problem(OSVNPMIdentityProblemNameUnusable, "name")
    } else if !nameOK {
        problem(OSVNPMIdentityProblemNameOutsideProfile, "name")
    }
    switch entry.PURL.State {
    case OSVFieldAbsent:
        // Optional source absence, not a fabricated PURL identity.
    case OSVFieldValue:
        out.PURLName, out.PURLUsable = parseOSVNPMIdentityPURL(entry.PURL.Value)
        if !out.PURLUsable { problem(OSVNPMIdentityProblemPURLOutsideProfile, "purl") }
    default:
        problem(OSVNPMIdentityProblemPURLUnusable, "purl")
    }
    if ecoOK && nameOK && out.PURLUsable && entry.Name.Value != out.PURLName {
        problem(OSVNPMIdentityProblemPURLNameConflict, "purl")
        out.Qualification = OSVNPMIdentityConflict
    } else if len(out.Problems) == 0 {
        out.Qualification = OSVNPMIdentityCandidate
    }
    return out
}
```

Concrete consumed-layout and top-level flow:

```go
func validateOSVNPMIdentityInput(header OSVHeader, affected OSVAffectedProjection) error {
    bad := func() error { return &ParseError{Code: "invalid-shape"} }
    if header.SourceSHA256 != affected.SourceSHA256 { return bad() }
    if len(affected.Entries) > maxAffectedEntries { return &ParseError{Code: "limit-exceeded"} }
    switch affected.State {
    case OSVFieldValue:
        if affected.Entries == nil { return bad() }
    case OSVFieldAbsent, OSVFieldNull, OSVFieldInvalidType:
        if affected.Entries != nil { return bad() }
        return nil
    default:
        return bad()
    }
    for index, entry := range affected.Entries {
        if entry.Index != index { return bad() }
        switch entry.State {
        case OSVFieldValue:
            if entry.PackageState < OSVFieldAbsent || entry.PackageState > OSVFieldValue { return bad() }
        case OSVFieldNull, OSVFieldInvalidType:
            if entry.PackageState != OSVFieldUnavailable { return bad() }
        default:
            return bad()
        }
        for _, claim := range []OSVString{entry.Ecosystem, entry.Name, entry.PURL} {
            if entry.PackageState != OSVFieldValue {
                if claim != (OSVString{}) { return bad() }
            } else if claim.State < OSVFieldAbsent || claim.State > OSVFieldValue || claim.State != OSVFieldValue && claim.Value != "" {
                return bad()
            }
        }
    }
    return nil
}

func QualifyOSVNPMIdentities(header OSVHeader, affected OSVAffectedProjection) (OSVNPMIdentityProjection, error) {
    if err := validateOSVNPMIdentityInput(header, affected); err != nil {
        return OSVNPMIdentityProjection{}, err
    }
    result := OSVNPMIdentityProjection{SourceSHA256: affected.SourceSHA256, HeaderSchema: header.Schema, State: affected.State}
    if affected.State != OSVFieldValue { return result, nil }
    result.Entries = make([]OSVNPMIdentityEntry, 0, len(affected.Entries))
    inspect := header.Schema == OSVHeaderSchemaV1Implicit || header.Schema == OSVHeaderSchemaV1Declared
    for _, entry := range affected.Entries {
        out := OSVNPMIdentityEntry{Index: entry.Index, State: entry.State, PackageState: entry.PackageState,
            Ecosystem: entry.Ecosystem, Name: entry.Name, PURL: entry.PURL}
        if inspect && entry.State == OSVFieldValue && entry.PackageState == OSVFieldValue {
            out = qualifyOSVNPMIdentityEntry(entry)
        }
        result.Entries = append(result.Entries, out)
    }
    return result, nil
}
```

The default zero qualification is Unknown: header abstention and uninspectable
parents do not allocate Problems or derive PURL. The result has no raw JSON, copied
versions/ranges or generic-parser dependency. Preflight allocation of tiny local
claim tuples is not output allocation or a hard-RSS claim.

- [x] **Step 6: GREEN, self-review and one focused mutation check.**

Run focused tests, then full fresh root tests and vet under offline environment.
Review every guard/abstention path, problem ordering, case handling and source ownership.
Temporarily make the conflict comparison case-insensitive; the Foo vs foo literal
case must fail. Restore the original code immediately and verify diff contains no
mutation. This is author verification, not independent review or product qualification.

- [x] **Step 7: final verification and code-only commit.**

Gofmt only the two new Go files; git diff --check (jj diff --check is unsupported).
Re-run focused/root tests and vet after restored mutation/review edits. Verify old
tracked Go files/module/probes match the actual baseline and no go.sum exists. Count
passed tests/subtests from actual branch JSON output, keep receipts outside repo.
Stop on unexpected scope, failures or unavailable tooling; no acquisition fallback.

Commit only the two Go files with jj using subject feat: qualify OSV npm identity
candidates. Inspect exact paths/hash and clean workspace before evidence docs.

- [x] **Step 8: completion evidence and authorized publication, without integration.**

Record observed RED/GREEN, toolchain, actual counts, code hash, bounds and unqualified
work in separate scoped spec/plan documentation commit; add one nested milestone,
never close its parent shipping gate. Check local links/anchors and shell examples
without pretending parsing is test execution. Move/push only issue-specific bookmark
and read back PR head/base/path list/body. Update #13 body/comment/Project to Review
only within approved publication scope; English first-person GitHub text. Keep PR
draft until separately authorized ready/requested second-person review; no merge,
parent/dependency/shipping closure or assumption that author review is independent.

Implementation/publication scope at execution handoff must explicitly cover these
steps; approval of this prepared plan alone is not permission to execute them.
