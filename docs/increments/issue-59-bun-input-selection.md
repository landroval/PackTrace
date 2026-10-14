# Issue #59 — conservative Bun root-input selection

**Execution authority:** I authorize this exact reviewed contract/plan under my current autonomous-development instruction, including the existing local Go/owned fixtures and six mutation controls, a new issue workspace, issue-specific publication, the unchanged PR-only approval bypass, and accepted-child closure. Primary owner: landroval. At most three initial existing root CI jobs, 15 minutes each; no rerun/manual dispatch. Preparation-time pending/no-execution statements below are preserved historical records, not the current delivery status. Native/producer/provisioning/S64/security/credential/release work remains excluded.


## Status and authority

I approved the conservative design and creating [#59](https://github.com/landroval/PackTrace/issues/59), a child of [#5](https://github.com/landroval/PackTrace/issues/5), in Preparation. I selected exact Bun 1.3.2/1.4.2 policy anchors, no inferred text/binary precedence, a pure caller-supplied decision and a small implementation/test boundary.

**This exact written contract is a draft for review and approval.** Preparation is not code, test execution, publication or integration authority. No implementation plan or Go implementation has been approved. S64 stays paused; #5 and native qualification gates stay open.

Source baseline: development commit `880ece81d263d04d38c200c42467bd857242cbf7`. This extends the effective-input responsibility in `docs/design-decisions.md` §19. It follows, but does not modify, the supplied-state pattern in `internal/inventory/npm_input_selection.go`. Existing Bun readers/projections and their successful-document preconditions remain unchanged.

## Purpose and exclusions

Make one deterministic internal decision from the two root-slot classifications supplied by a caller: text `bun.lock` and binary `bun.lockb`. Retain uncertainty and both observations even when only one slot is a candidate.

This function does not discover/open paths, inspect bytes, run Bun, convert formats, evaluate a lockfile version/configuration/layout, read packageManager metadata, authenticate a producer, parse manifests, project inventory or calculate global coverage/findings. No caller-supplied claim authorizes any of those operations. A binary input remains unsupported even if the caller labels its usability Usable.

Automatic selection requires one coherent interpretation. Since no text/binary precedence has been qualified for these anchors, simultaneous presence must not become an implicit preference or fallback. An explicit selection mechanism is outside this increment; this function accepts none.

## Exact internal surface

Package `internal/inventory` adds:

```go
func SelectBunInput(
    profile string,
    text, binary BunInputState,
) (BunInputSelection, error)
```

Concrete types use the existing npm naming pattern, but remain a separate Bun domain; do not rename/refactor existing npm types or add a generic manager framework. Enums below have underlying `uint8`, start at zero with `iota`, and have exactly the stated ordering.

| Type | Constants in order |
| --- | --- |
| `BunInputPresence` | `BunInputPresenceUnknown`, `BunInputPresenceAbsent`, `BunInputPresencePresent` |
| `BunInputUsability` | `BunInputUsabilityUnqualified`, `BunInputUsabilityUsable`, `BunInputUsabilityUnreadable`, `BunInputUsabilityUnsafe`, `BunInputUsabilityUnsupported`, `BunInputUsabilityInvalid` |
| `BunInputCandidate` | `BunInputCandidateNone`, `BunInputCandidateText`, `BunInputCandidateBinary` |
| `BunInputSelectionState` | `BunInputSelectionUnknown`, `BunInputSelectionUsable`, `BunInputSelectionUnusable`, `BunInputSelectionIndeterminate`, `BunInputSelectionAbsent` |
| `BunInputDiagnostic` | `BunInputDiagnosticUnknown`, `BunInputDiagnosticNone`, `BunInputDiagnosticProfileUnqualified`, `BunInputDiagnosticTextPresenceUnknown`, `BunInputDiagnosticBinaryPresenceUnknown`, `BunInputDiagnosticConflictingInputs`, `BunInputDiagnosticUsabilityUnqualified`, `BunInputDiagnosticCandidateUnusable`, `BunInputDiagnosticLegacyBinaryUnsupported`, `BunInputDiagnosticNoRootLock` |

`BunInputState` has exactly `Presence BunInputPresence` and `Usability BunInputUsability`.

`BunInputSelection` has exactly these fields, in order:

| Field | Type and meaning |
| --- | --- |
| `Profile` | `string`; exact private caller text, not public diagnostic material |
| `ProfileQualified` | `bool`; recognizes a policy anchor only; not producer/source authentication or executed compatibility |
| `Text`, `Binary` | `BunInputState`; exact scalar records supplied by the caller |
| `Candidate` | `BunInputCandidate`; a sole observed slot, not a supported/usable dependency tree |
| `State` | `BunInputSelectionState`; decision conditional on the supplied classifications |
| `Diagnostic` | `BunInputDiagnostic`; one fixed primary reason, not a list of all input problems |

A sole binary candidate is still Unusable/LegacyBinaryUnsupported. Zero values are sentinels, not successful absence or an empty inventory. Every nonfatal result sets State and Diagnostic explicitly and preserves Profile, Text and Binary. No raw path/document/bytes are accepted or returned. No serializer/public report is added.

## Input-layout validation — before every decision

Validate both scalar records, even if the profile is unknown or one slot could not govern. Any unknown presence enum or usability enum outside the closed vocabulary is invalid.

| Presence | Allowed usability |
| --- | --- |
| Unknown | Unqualified, Unreadable, Unsafe |
| Absent | Unqualified only |
| Present | All six declared usability values |

The two slots follow the same shape rule. This represents caller classifications, not an assertion that every format is supported. Thus Present/Usable binary is a valid supplied shape whose decision remains unsupported; the selector never trusts that claim to expand support.

Any invalid layout returns the whole-zero `BunInputSelection{}` and the existing `*ParseError{Code: "invalid-shape"}`. No input value appears in the error. There is no partial result on fatal error. Do not panic or fall back.

## Profile qualification

Only the exact, case-sensitive strings `bun@1.3.2` and `bun@1.4.2` set ProfileQualified true. No trim, normalization, SemVer range, latest alias or target hint may manufacture a recognized anchor.

Any other profile, including empty, Unicode, controls, invalid UTF-8 bytes or oversized text, is kept verbatim in the private Profile field and yields CandidateNone, SelectionIndeterminate and DiagnosticProfileUnqualified, with nil error, after both layouts have been checked. This is not a public-text interface. It performs no profile parsing, length-dependent processing, copying/formatting, or serialization; fixed exact comparisons and a string-header retention do not add an unbounded work buffer. A later public consumer must separately bound/redact its inputs/output.

## Decision order and complete presence table

After shape validation and profile qualification, apply the following table for a recognized profile. The first matching diagnostic is canonical when both presence values are unknown: TextPresenceUnknown precedes BinaryPresenceUnknown.

| Text presence | Binary presence | Candidate | State | Primary diagnostic |
| --- | --- | --- | --- | --- |
| Unknown | Unknown/Absent/Present | None | Indeterminate | TextPresenceUnknown |
| Absent/Present | Unknown | None | Indeterminate | BinaryPresenceUnknown |
| Absent | Absent | None | Absent | NoRootLock |
| Present | Present | None | Indeterminate | ConflictingInputs |
| Present | Absent | Text | See text usability table | See text usability table |
| Absent | Present | Binary | Unusable | LegacyBinaryUnsupported |

The binary-only row applies to every valid Present usability classification. Preserve the classification without implying it was independently verified. Both-present remains indeterminate regardless of either usability: an unusable input does not prove absence and does not authorize choosing the sibling.

For Text/Absent:

| Text usability | Candidate | State | Diagnostic |
| --- | --- | --- | --- |
| Unqualified | Text | Indeterminate | UsabilityUnqualified |
| Usable | Text | Usable | None |
| Unreadable/Unsafe/Unsupported/Invalid | Text | Unusable | CandidateUnusable |

SelectionAbsent is conditional absence of the two supplied slots, not a complete discovery scope, empty installed inventory or successful coverage. SelectionUsable is conditional usability of the text slot only; it does not validate format/configuration versions, tuple/workspace layouts or producer compatibility. Preserve other evidence outside this selector.

## Truthfulness, privacy and runtime properties

- Consume neither raw files nor target configuration; take no opener, reader, callback or context. Finite scalar decision work requires no cancellation machinery.
- No I/O, network, goroutine, subprocess, mutation, cache, global mutable state, dependency or native branch.
- Preserve profile and both state records exactly; never reclassify unknown/unreadable/unsafe into absence, or unsupported binary into supported text.
- Fixed enum diagnostics and `invalid-shape` are the only reason vocabulary. Keep caller text out of errors/comments/logs/public diagnostics.
- Repeated calls with identical arguments yield identical values; no implicit enum-number conversion to npm states or indirect coupling to npm validator evolution.
- No public profile/support claim, CLI schema or exit behavior changes. No safe/clean/installed/finding/coverage assertion follows from this result.

## Scope and acceptance, pending a separately approved plan

Product files: only new `internal/inventory/bun_input_selection.go` and `internal/inventory/bun_input_selection_test.go`. Documentation files: this issue-keyed specification and its subsequent issue-keyed plan under `docs/increments/`. Existing parsers/projections, npm selection, CLI, demo/snapshots/S64, dependencies, CI and security settings remain byte-identical.

After written-contract approval, prepare the concrete plan covering:

1. Frozen interface and complete independent expected state matrix, exact profile variants, inactive-slot invalid shapes, candidate retention and private/control text.
2. Distinct missing-API/compiler evidence and behavioral assertion RED, then minimum production code and GREEN; no implementation before intended tests fail.
3. Deterministic targeted negative/mutation checks for unknown-to-absent, guessed coexistence precedence, binary usability trust, validation/profile ordering and profile broadening; record actual failures and exact source restoration.
4. Parallel builder/adversarial analyst with disjoint write ownership; the builder alone owns both Go files and the analyst supplies private independent counterexamples. A fresh independent final reviewer checks the complete exact head after integration, not a moving partial file.
5. Fresh authorized focused/root tests, vet/build/format and exact-scope checks, unchanged existing npm/Bun/CLI behavior, followed by separately authorized PR/integration/hosted evidence and read-back.

None of those executions has occurred for #59. Counts, AST/static inspection, prior tests and prior CI success do not qualify this new helper. Passing scalar synthetic tests will not qualify real Bun producers or macOS/Windows/native/scanner support. The issue closes only after its own full accepted implementation delivery; #5 remains open and S64 remains paused.

## Executed local evidence and remaining delivery gates

The sole builder implemented only the two new Go paths. Missing-API compiler RED
was recorded separately from a compiling wrong stub with **485 named assertion
failures**, then **486 new named tests/subtests passed**. All six specified controls
compiled, produced their intended named runtime failures, restored source/test
bytes exactly, and replayed the complete focused GREEN. The independent private
adversarial lane found no missing scalar discriminator.

A fresh exact `880ece81d263d04d38c200c42467bd857242cbf7` base archive passed
**3,185** named tests/subtests; the restored candidate passed **3,671**, with no
test/package/build failures. Vet, all-package build, separate CLI build and scoped
gofmt checks passed. Local compiler: `go1.27.1-X:nodwarf5 linux/amd64`, explicitly
modified and not official/native/producer qualification. Whole exact-candidate
archive, independent task/whole-branch reviews, final PR prospective parents/tree,
official PR event and actual merged-development push acceptance remain separate
delivery gates; completion comments record their eventual outcome.

Private-helper qualification retained the original signal/cleanup and evidence
review NO findings. Inert runtime evidence then showed Python 3.14's selector
consuming the old `InterruptedError` signal handler until the command deadline.
The reviewed one-line correction raises `KeyboardInterrupt`; eleven owned
cleanup/reservation/capture/client-shadow controls passed. Eleven controlled
offline decoder checks cover framing, offsets, digests, EOF and endpoint/run
binding. These are helper fixtures, not real hosted evidence or a sandbox claim.

The earlier source checks ran after the documentation checkpoint: their initial
whole-base tree binding was corrected with a fresh exact-base archive receipt,
not by rewriting historical output. Unrelated task-ledger deletions stay outside
all published heads. No discovery, Bun producer, native prototype, S64 continuation,
new dependency/toolchain installation, workflow or security change is delivered.
