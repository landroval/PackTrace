# Pure npm root-input selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. I preserve the agreed inline method; author review does not replace the independent GitHub reviewer.

**Goal:** Implement the approved pure two-record npm selection decision without filesystem access, producer inference or silent fallback.

**Architecture:** One new inventory module preflights both scalar state pairs, qualifies the exact caller-selected profile and records the precedence-governing candidate and usability independently. One new test file pins literal outcomes, coherent layouts, profile abstention and immutable evidence. Existing parsers, projections and shared errors remain unchanged.

**Tech Stack:** Go, standard library only; production needs no imports or new dependency. Existing `inventory.ParseError` supplies fatal errors.

**Spec:** [Approved issue17 contract](issue-17-npm-input-selection.md), published in draft [PR #31](https://github.com/landroval/PackTrace/pull/31) at `4254a873c4fe80c6491a8b35ea77b105e6e75a7e`. The spec remains authoritative if an illustrative plan snippet disagrees; resolve the discrepancy before execution.

## Status and authority

This is a **local written-plan draft, not approved/published or execution authority**. The user authorized plan preparation after approving/publishing the specification. I have not created source/test files or run selector/root tests for this preparation.

I use the existing `issue-17-npm-input-selection-spec` bookmark/workspace from development `235347cc0be03e3cc5019db40a1e3b710920be9b`, not pending PR #29/#30. A previously recorded integrated tree had1,231 tests/subtests; PR #30's1,543 results belong to that different tree and must not be added/imported here. Execution must run a fresh actual-tree baseline/final count rather than treating either historical count as current evidence.

## Global constraints

- Exact qualifying profiles: `npm@8.19.4`, `npm@10.9.4`, `npm@11.6.2`; others are retained/unqualified, not normalized or universally invalid npm syntax.
- Presence values0..2; usability values0..5. Unknown permits0/2/3, Absent permits0 only, Present permits0..5; both slots preflight before every gate.
- Unknown presence and present unqualified/unusable shrinkwrap never permit fallback. Only qualified shrinkwrap absence permits considering package-lock.
- `Candidate` is the governing slot, not a usable tree/access authority. Success has nonzero State/Diagnostic; fatal is whole-zero with exact `*ParseError{Code:"invalid-shape"}` / `inventory: invalid-shape`.
- Profile and both pairs are copied exactly. No containers, raw paths, byte/hash fabrication, mutation, general candidate registry or shared FieldState changes.
- Manifest/hidden/installed/raw/other-manager evidence stays independently retained by the caller; hidden-lock is auxiliary, never fallback. No global coverage/findings/exit result.
- No target reads, parser calls, cwd/environment/state/output access, manager execution, acquisition, native/CI/race/fuzz work or sibling integration. Source/producer/native/pilot/release qualification remains open.
- Offline owned checks use GOTOOLCHAIN=local, GOPROXY=off, GOWORK=off, CGO_ENABLED=0. Standard-library-only root module; no go.sum.
- [Development guidelines](../development-guidelines.md) and [collaboration gates](../github-collaboration.md) govern scoped jj commits and independent review. CodeGraph was unavailable; do not retry/index automatically.

## Review Focus

1. Unknown+Unreadable/Unsafe is not confirmed presence or absence: it blocks fallback without fabricating a candidate; compare Present+same cause explicitly.
2. A usable higher-priority record must not suppress invalid layout in the lower-priority record; unsupported profile must not suppress either slot's preflight.
3. Candidate is retained even with unusable/unknown usability; usable shrinkwrap with invalid/unknown package-lock preserves the lower states without a global-complete conclusion.
4. Exact profile authority: whitespace/case/family/next-patch/npm12 and hostile opaque profile text abstain, not profile-normalize or implicitly prove a producer.
5. Whole-zero error privacy and scalar ownership: malformed states with private-marker profiles cannot leak/wrap raw text, and changing inputs/results after calls must not change the other value.

## Task 1 — bounded selector, tests and scoped evidence

**Files:**
- Create `internal/inventory/npm_input_selection.go` — exact contract types, `SelectNPMInput`, one private coherent-pair guard.
- Create `internal/inventory/npm_input_selection_test.go` — literal references and focused invariant/ownership/privacy tests.
- Documentary completion only after separate execution/evidence authority: this plan, `issue-17-npm-input-selection.md`, one nested milestone in `docs/pre-1.0-features.md`.
- Do not modify any preexisting Go/module/probe/shared parser/error/CLI file or top-level shipping checkbox.

**Interfaces:** consumes `SelectNPMInput(profile string, shrinkwrap, packageLock NPMInputState)` as defined below; produces `(NPMInputSelection, error)` with all exact fields/constants from the spec. Reuses `*ParseError`; no new error protocol or dependency on pending CLI types.

### Approval and baseline

- [ ] Obtain written-plan approval **and explicit inline source/test/offline verification/evidence publication authorization**. If approved, record and push authorization before any Go creation; failed push stops source work. Preparation/assignment/board state is not permission.
- [ ] Recheck issue owner/live comments, exact selected branch/base/clean tree, intended two source files absent and unchanged spec. Keep the existing workspace; no rebase/merge of sibling work without separate authority.
- [ ] Run a fresh offline root baseline and vet; retain JSON result stream/toolchain outside the repo and count actual `Action=="pass"` records with nonempty Test. Do not count package-pass records or sum parallel branches.

### Independent tests and RED

- [ ] Write `TestSelectNPMInputReference` first. Transcribe all31 success and10 guard rows C01–C31/G01–G10 from the spec as Go literals; do not load Markdown at runtime, derive expected outcomes from production guards/switches or generate expectations by running the candidate implementation. Each named subtest compares the full result, exact error type/code/text, nil-error classification and unchanged inputs.

The following complete initial test pins a reference outcome and an otherwise non-governing malformed state. Extend its file with the other literal rows and the specific tests listed immediately below; the source types are defined in the API block, not invented by fixtures.

```go
package inventory

import "testing"

func TestSelectNPMInputReference(t *testing.T) {
    t.Run("C13", func(t *testing.T) {
        shrinkwrap := NPMInputState{Presence: 2, Usability: 5}
        packageLock := NPMInputState{Presence: 2, Usability: 1}
        beforeS, beforeP := shrinkwrap, packageLock
        want := NPMInputSelection{
            Profile: "npm@11.6.2", ProfileQualified: true,
            Shrinkwrap: shrinkwrap, PackageLock: packageLock,
            Candidate: 1, State: 2, Diagnostic: 6,
        }
        got, err := SelectNPMInput("npm@11.6.2", shrinkwrap, packageLock)
        if err != nil || got != want {
            t.Fatalf("unexpected reference result: got=%#v err=%v", got, err)
        }
        if shrinkwrap != beforeS || packageLock != beforeP {
            t.Fatal("caller states changed")
        }
    })
    t.Run("G08", func(t *testing.T) {
        got, err := SelectNPMInput("npm@11.6.2",
            NPMInputState{Presence: 2, Usability: 1},
            NPMInputState{Presence: 1, Usability: 5})
        pe, ok := err.(*ParseError)
        if !ok || pe.Code != "invalid-shape" || pe.Error() != "inventory: invalid-shape" {
            t.Fatal("missing fixed ParseError")
        }
        if got != (NPMInputSelection{}) {
            t.Fatal("fatal result was not whole-zero")
        }
    })
}
```

- [ ] Add `TestSelectNPMInputLayouts`: literal18-pair validity table (Unknown: true,false,true,true,false,false; Absent: true,false,false,false,false,false; Present: alltrue). Test every pair in both slots, keeping the other present-usable, across the three anchors, empty and npm12 profiles. Add first outside-domain values (presence3, usability6) and enum255 in both domains/slots. Invalid cases always exact fatal/zero; valid cases retain exact scalar input/profile and nonzero successful State/Diagnostic. Do not call the production guard for expected validity.
- [ ] Add `TestSelectNPMInputPrecedence`: for each anchor, use a usable package-lock against shrinkwrap Unknown+0/2/3 and Present+0/2/3/4/5; pin no fallback, exact governing candidate/diagnostic and the difference between unknown presence and known presence. Pin Absent+usable package-lock, both absent, unknown package-lock and usable shrinkwrap with lower Unknown+Unreadable or Present+Invalid. Keep every case in its own subtest so an early fatal cannot suppress later cases.
- [ ] Add `TestSelectNPMInputProfiles`: empty/auto/npm/npm12/next-patch/case/leading and trailing whitespace, newline, NUL, private-marker URL-like and Unicode profile strings. All coherent inputs retain exact profile/pairs and abstain; malformed either slot remains fatal even for outside profiles. Pin all three anchors, not an npm-prefix heuristic.
- [ ] Add `TestSelectNPMInputOwnership`: copy input snapshots before calls; alter original scalar variables after success and check saved result unchanged; alter a returned result and check originals/second fresh call unchanged. Preserve a lower-priority Unknown+Unreadable source rather than converting it to absent. No unsafe/concurrency test is needed for immutable-string/value ownership.
- [ ] Add `TestSelectNPMInputSeparation`: inspect only the two new source files for no production imports/IO/printing/global state; exercise arbitrary opaque profiles with malformed states and assert exact private error/zero result, no `%w`/raw text. Native/source safety and caller-owned manifest/hidden preservation cannot be established by a synthetic file read: no temp-directory scaffold or false physical-absence claim.
- [ ] Run focused tests before declarations; inspect expected missing-API compilation RED. Then add exactly the API declarations and temporary zero/nil stub below; rerun to observe behavioral failures of all41 reference rows (every success has nonzero State/Diagnostic; every guard needs a typed error). Keep compile RED separate from behavioral pass/fail counts. A compilation failure alone does not pin precedence.

### Exact API for the temporary RED stub

```go
package inventory

type NPMInputPresence uint8
const (
    NPMInputPresenceUnknown NPMInputPresence = iota
    NPMInputPresenceAbsent
    NPMInputPresencePresent
)
type NPMInputUsability uint8
const (
    NPMInputUsabilityUnqualified NPMInputUsability = iota
    NPMInputUsabilityUsable
    NPMInputUsabilityUnreadable
    NPMInputUsabilityUnsafe
    NPMInputUsabilityUnsupported
    NPMInputUsabilityInvalid
)
type NPMInputState struct {
    Presence NPMInputPresence
    Usability NPMInputUsability
}
type NPMInputCandidate uint8
const (
    NPMInputCandidateNone NPMInputCandidate = iota
    NPMInputCandidateShrinkwrap
    NPMInputCandidatePackageLock
)
type NPMInputSelectionState uint8
const (
    NPMInputSelectionUnknown NPMInputSelectionState = iota
    NPMInputSelectionUsable
    NPMInputSelectionUnusable
    NPMInputSelectionIndeterminate
    NPMInputSelectionAbsent
)
type NPMInputDiagnostic uint8
const (
    NPMInputDiagnosticUnknown NPMInputDiagnostic = iota
    NPMInputDiagnosticNone
    NPMInputDiagnosticProfileUnqualified
    NPMInputDiagnosticShrinkwrapPresenceUnknown
    NPMInputDiagnosticPackageLockPresenceUnknown
    NPMInputDiagnosticUsabilityUnqualified
    NPMInputDiagnosticCandidateUnusable
    NPMInputDiagnosticNoRootLock
)
type NPMInputSelection struct {
    Profile string
    ProfileQualified bool
    Shrinkwrap, PackageLock NPMInputState
    Candidate NPMInputCandidate
    State NPMInputSelectionState
    Diagnostic NPMInputDiagnostic
}
func SelectNPMInput(profile string, shrinkwrap, packageLock NPMInputState) (NPMInputSelection, error) {
    return NPMInputSelection{}, nil
}
```

### Minimum GREEN

- [ ] Replace the zero stub with a preflight and the fixed two-slot decision below. Keep declarations unchanged; add comments on caller-qualified states, governing-candidate/non-authority and whole-zero fatal errors. No generic registry/list or extra copy helper.

```go
func validNPMInputState(input NPMInputState) bool {
    if input.Usability > NPMInputUsabilityInvalid {
        return false
    }
    switch input.Presence {
    case NPMInputPresenceUnknown:
        return input.Usability == NPMInputUsabilityUnqualified ||
            input.Usability == NPMInputUsabilityUnreadable ||
            input.Usability == NPMInputUsabilityUnsafe
    case NPMInputPresenceAbsent:
        return input.Usability == NPMInputUsabilityUnqualified
    case NPMInputPresencePresent:
        return true
    default:
        return false
    }
}

func SelectNPMInput(profile string, shrinkwrap, packageLock NPMInputState) (NPMInputSelection, error) {
    if !validNPMInputState(shrinkwrap) || !validNPMInputState(packageLock) {
        return NPMInputSelection{}, &ParseError{Code: "invalid-shape"}
    }
    result := NPMInputSelection{
        Profile: profile, Shrinkwrap: shrinkwrap, PackageLock: packageLock,
        State: NPMInputSelectionIndeterminate,
        Diagnostic: NPMInputDiagnosticProfileUnqualified,
    }
    switch profile {
    case "npm@8.19.4", "npm@10.9.4", "npm@11.6.2":
        result.ProfileQualified = true
    default:
        return result, nil
    }
    usability := shrinkwrap.Usability
    switch shrinkwrap.Presence {
    case NPMInputPresenceUnknown:
        result.Diagnostic = NPMInputDiagnosticShrinkwrapPresenceUnknown
        return result, nil
    case NPMInputPresencePresent:
        result.Candidate = NPMInputCandidateShrinkwrap
    case NPMInputPresenceAbsent:
        switch packageLock.Presence {
        case NPMInputPresenceUnknown:
            result.Diagnostic = NPMInputDiagnosticPackageLockPresenceUnknown
            return result, nil
        case NPMInputPresenceAbsent:
            result.State = NPMInputSelectionAbsent
            result.Diagnostic = NPMInputDiagnosticNoRootLock
            return result, nil
        case NPMInputPresencePresent:
            result.Candidate = NPMInputCandidatePackageLock
            usability = packageLock.Usability
        }
    }
    switch usability {
    case NPMInputUsabilityUnqualified:
        result.Diagnostic = NPMInputDiagnosticUsabilityUnqualified
    case NPMInputUsabilityUsable:
        result.State = NPMInputSelectionUsable
        result.Diagnostic = NPMInputDiagnosticNone
    default:
        result.State = NPMInputSelectionUnusable
        result.Diagnostic = NPMInputDiagnosticCandidateUnusable
    }
    return result, nil
}
```

- [ ] Run focused GREEN and inspect results, including all reference rows, both-slot guards and the five review focus classes. Unexpected failures require diagnosis before changing expectations; do not weaken the approved tuple/profile/no-fallback contract to pass.

### Targeted mutations and final review

- [ ] Snapshot source SHA, temporarily treat Unknown/Unusable shrinkwrap as absent or fall through to package-lock; run the focused precedence/reference tests and inspect an expected failure such as C07/C13. Restore and verify original SHA before continuing.
- [ ] Temporarily skip package-lock preflight when shrinkwrap is usable or move preflight below profile abstention; run guard/layout tests and inspect G08/G09/G10 failure. Restore and verify SHA.
- [ ] Temporarily qualify family/npm12 or strip profile whitespace; run profile/reference tests and inspect C25/C27/C30 failure. Restore and verify SHA. No mutation remains in a commit.
- [ ] Format only the two new Go files; run fresh offline root JSON tests/vet, count the actual final tree plus its new selector tests, and report exact toolchain/method. Verify preexisting Go/module/probe bytes, absent go.sum and unchanged top-level gates.
- [ ] Self-review the five focus classes against implementation and tests. A source purity guard is not native safety qualification. Record no critical/important issue only if actually reviewed; never label author review independent.
- [ ] Make a scoped jj code commit for only the two new Go files after observed checks. Then, only within authorized evidence/publication scope, update the spec/plan and nested milestone with observed counts/RED/mutations/limits, commit those documents and push only the issue bookmark. Exact PR head/body/file-scope read-back must reflect the actual tree, not planned counts.
- [ ] Independent review handoff, ready/requested reviewer, integration and queue closure remain pending separate authority. Keep PR #31 draft unless the user authorizes otherwise; keep capability/shipping gates open. No auto-close keyword replaces its acceptance.

## Future Nushell commands — not executed for preparation

Focused RED/GREEN/mutation checks use:

```nu
with-env {GOTOOLCHAIN: "local", GOPROXY: "off", GOWORK: "off", CGO_ENABLED: "0"} {
    go test -count=1 -run '^TestSelectNPMInput' ./internal/inventory
}
```

Fresh baseline/final owned checks use:

```nu
with-env {GOTOOLCHAIN: "local", GOPROXY: "off", GOWORK: "off", CGO_ENABLED: "0"} {
    go version
    go test -count=1 -json ./...
    go vet ./...
}
```

Capture outputs/status outside the repo, stop on unexpected failure and never infer vet from the previous command. Format with `gofmt -w internal/inventory/npm_input_selection.go internal/inventory/npm_input_selection_test.go` only after authorized creation. Commands in this document are planned, not run, and do not approve a download/target/native runner.

## Plan coverage and handoff

The single task owns the complete fixed API and test cycle. Reference/layout/precedence/profile/ownership/separation tests map to all spec sections and all five focus classes; no shared-reader change or new subsystem is needed. I self-reviewed spec coverage, exact type/constant/signature consistency, tuple/profile/fallback/ownership focus mapping and placeholders; I found no missing contract item or critical/important documentary issue. I checked three local links, three Go snippets with gofmt (syntax only, not compilation) and two Nushell snippets with nu-check (syntax only), plus unchanged prior tracked bytes. This file is documentary preparation only:41 fixture rows remain unexecuted and all quoted RED/GREEN outcomes are expected, not observed.

The user must approve this written plan and separately authorize source/test/offline execution/evidence publication before Task1 begins. I preserve inline execution plus GitHub second-person review, with no workflow/subagent dispatch or implied native qualification. Publication alone can add this plan to the draft PR, but cannot create the Go files or move the issue into execution.
