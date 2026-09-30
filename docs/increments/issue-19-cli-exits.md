# Issue 19: pure scan exit selection

Status: the written specification is approved, including four explicit Boolean
conditions and interruption precedence. The [implementation plan](issue-19-cli-exits-plan.md)
was approved and bounded inline execution explicitly authorized. Implementation
passes synthetic verification; second-person PR review and integration remain pending.
Tracking: [issue #19](https://github.com/landroval/PackTrace/issues/19).
Authority: [scan defaults and exits](../design-decisions.md#5-scan-defaults-and-exit-codes)
and [evidence and coverage](../design-decisions.md#3-evidence-and-coverage-model).

## Goal and boundary

Select the approved scan exit code from four explicit caller-supplied conditions.
This is a small internal, in-memory decision function, not an operational CLI,
coverage evaluator or report schema. It does not require the OSV header work in
#12 and must not be stacked on its unreviewed PR.

The caller is responsible for determining the conditions from qualified outcomes.
The selector neither obtains evidence nor verifies that those conditions truthfully
represent a scan. Successful local calculation is not successful scan completion.

## Proposed internal interface

New package `internal/cli`, with only these two new Go files:
`internal/cli/exits.go` and `internal/cli/exits_test.go`.

```go
type ScanExitConditions struct {
    Interrupted bool
    ReportPreventingError bool
    RequiredCoverageIncomplete bool
    EnforcedUnacceptedFindings bool
}

func SelectScanExit(conditions ScanExitConditions) int
```

This is an internal control input, not a public report/IPC model. All 16 Boolean
combinations are representable; no enum, numeric input, extra validation interface
or returned error is necessary. The function returns a code; it must not call
`os.Exit`, inspect signals, print, read files, assemble reports or alter its input.

## Meaning of each condition

- **Interrupted:** the caller established user interruption. Unexpected worker
  death, parser failure or unavailable evidence is not automatically interruption.
- **ReportPreventingError:** an invalid invocation/policy or operational failure
  prevents producing the requested report. A check failure that can be represented
  in that report is a coverage gap, not automatically this condition.
- **RequiredCoverageIncomplete:** the caller established that required coverage
  cannot be claimed complete. Required incomplete/not-run/unknown/excluded work
  cannot silently count as completion. Evidence-based non-applicability and policy
  requirements are evaluated outside this slice, not inferred by the selector.
- **EnforcedUnacceptedFindings:** unaccepted findings exist in an enforced category.
  Findings alone, enforcement-disabled findings or accepted findings do not set
  this condition. Policy/exception evaluation is outside this slice.

A false coverage flag is an explicitly supplied qualified condition, not a default
inference that missing evidence means completion. The zero Go struct calculates
`0` under the truth table, but does not authorize constructing a real scan result
from defaults. Future callers must establish every applicable condition before
using this selector; that integration needs its own contract and tests.

## Exit semantics and coexistence

The selected design makes user interruption the separate highest-priority outcome:
if `Interrupted` is true, return **130**, including when other conditions coexist.
This pins an internal precedence for the approved "interruption has its own outcome"
direction; it does not define signal handling or report preservation mechanisms.

Otherwise apply the existing ordinary precedence **2 > 3 > 1 > 0**:

1. A report-preventing error yields **2**.
2. Required incompleteness yields **3**, even with enforced findings.
3. Enforced, unaccepted findings yield **1**.
4. With none of these conditions, yield **0**.

All source conditions remain available to the caller independently of the chosen
code. The single returned integer must not erase report findings, coverage gaps or
errors. Report retention and partial-report preservation are future integration
obligations, not behaviors implemented by this helper. No code means "safe".

## Complete acceptance matrix

`I` = Interrupted, `E` = ReportPreventingError,
`C` = RequiredCoverageIncomplete, `F` = EnforcedUnacceptedFindings.
`0`/`1` below mean false/true input flags, not scan exits.

| I | E | C | F | Returned code |
| --- | --- | --- | --- | --- |
| 0 | 0 | 0 | 0 | 0 |
| 0 | 0 | 0 | 1 | 1 |
| 0 | 0 | 1 | 0 | 3 |
| 0 | 0 | 1 | 1 | 3 |
| 0 | 1 | 0 | 0 | 2 |
| 0 | 1 | 0 | 1 | 2 |
| 0 | 1 | 1 | 0 | 2 |
| 0 | 1 | 1 | 1 | 2 |
| 1 | 0 | 0 | 0 | 130 |
| 1 | 0 | 0 | 1 | 130 |
| 1 | 0 | 1 | 0 | 130 |
| 1 | 0 | 1 | 1 | 130 |
| 1 | 1 | 0 | 0 | 130 |
| 1 | 1 | 0 | 1 | 130 |
| 1 | 1 | 1 | 0 | 130 |
| 1 | 1 | 1 | 1 | 130 |

Tests must use these independently specified expectations, not compute expected
codes with the selector or duplicate its decision algorithm. Observe behavioral
RED before implementation and fresh offline root tests/vet after inline review.
Record actual toolchain/counts and synthetic-only limitations; the execution evidence
below records performed verification without qualifying a real scan.

## Scope, work bounds and coordination

Fixed four conditions and a returned integer: constant work, no unbounded inputs,
collections, parser, allocation quota, clock, environment or process-global state.
Use the current Go module and standard library without acquiring dependencies.
Existing inventory/intel/shared JSON Go files, go.mod and probes remain unchanged.

#19 moved from **Preparation** to **In progress** after written-specification and
implementation-plan approval plus explicit execution authorization. It is now ready
for **Review**, with the issue open pending second-person review and integration. Work from `development` on the
issue-specific bookmark `issue-19-cli-exits-spec`; no OSV header types or code are
consumed. GitHub is the live ownership/status queue. A later draft PR uses
`Refs #19`; documentation alone cannot close this issue or its capability parent.
An agreed second-person review and reviewed integration remain required.

## Execution evidence

- Code commit `9cecc77b`: only `internal/cli/exits.go` and
  `internal/cli/exits_test.go` added. Existing Go files, module and probes unchanged;
  no dependencies or go.sum. The branch is independent of unmerged PR #25.
- Missing API compile RED, then 15 of 16 matrix rows failed against a zero stub
  before decision logic; the all-clear row passed. Including the failed parent,
  behavioral RED reported 16 failing tests/subtests and one passing subtest.
- After inline review, fresh offline root verification: **894 passing tests/subtests,
  including 17 selector tests/subtests (16 rows plus parent)**, and `go vet ./...`.
  These counts belong to this branch's development baseline, not a cumulative suite
  including the 51 header cases from separate PR #25.
- Toolchain: `go1.27.1-X:nodwarf5 linux/amd64`. Synthetic development evidence is
  not official/native release qualification. No real scanner, caller outcome
  classification, policy/report integration or process-exit behavior was executed.
- Inline review checked all coexistence priorities, literal expectations, caller
  qualification responsibility, pure return values and unchanged existing sources.
  It is not independent review; second-person review and integration remain pending.

## Exclusions

No working scan command or entry point, argument parsing, policy/exception reads,
check lifecycle aggregation, coverage classification, findings matching, report
assembly/write/retention, filesystem/network/target access, state initialization,
IPC interpretation, signal handling, native probes, producer qualification,
dependencies/toolchains, CI activation or release acceptance. This helper cannot
qualify the complete CLI exit contract without future caller/runtime evidence.
