# Issue 19: pure scan exit selection implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: use `superpowers:executing-plans`
> for the explicitly approved inline workflow. The user approved this plan and
> authorized two new Go files, offline tests/vet, scoped documentation/commits and
> publication in PR #26. Integration still requires a second-person review.

**Goal:** return the approved scan exit code from four explicit caller conditions.
**Architecture:** one pure function in new `internal/cli`; no integrations or helpers.
Interruption precedes the ordinary 2 > 3 > 1 > 0 decisions. Caller qualification and
report preservation remain outside this slice.
**Tech stack:** current Go module, standard library, existing root verification.
**Spec:** [approved written contract](issue-19-cli-exits.md).

## Global constraints

- Only new `internal/cli/exits.go` and `internal/cli/exits_test.go` for production/test code.
- Preserve all existing Go files, go.mod and probes; no dependencies or go.sum.
- Work from the approved issue branch based on development, not PR #25.
- Four explicit Boolean facts are trusted caller conditions, not observed evidence.
- Unknown/excluded/not-run required coverage cannot be silently supplied as complete.
- Interruption returns 130 for all eight coexistence cases. Ordinary precedence is
  exactly 2 > 3 > 1 > 0. All 16 input combinations are legitimate.
- Returning 0 does not establish safety or prove a completed scan; no default flags
  may substitute for future qualified caller outcomes.
- No scanner/entry point, policy/coverage/exception evaluation, report schema or I/O,
  state/network/target access, signals/IPC/native work, acquisitions or CI activation.
- Inline review is not independent review. Keep #19 open until reviewed integration;
  this internal milestone does not close its CLI capability parent or release gates.

## Review focus

1. Enforced findings with incomplete required coverage yield 3, not 1.
2. Report-preventing error beats incompleteness/findings; reportable check failures
   must not be reclassified here as report-preventing errors.
3. Interruption with any other condition yields 130, not an ordinary code.
4. False enforcement flag yields 0 when other flags are clear; this is not evidence
   of no findings. Unknown source coverage is a caller obligation, not inspected here.
5. Do not introduce process exit/printing/I/O, a global result cache or shared-schema
   changes into this pure return-value function.

## Task 1: implement the pure selector

**Create:** `internal/cli/exits.go`, `internal/cli/exits_test.go`.
**Consumes:** only the four Boolean fields of ScanExitConditions defined below.
**Produces:** `SelectScanExit(conditions ScanExitConditions) int` in package `cli`.
There are no inter-task interfaces or dependencies on unmerged OSV work.

- [x] **Write the test first**, using a synthetic mask only to encode four explicit
  flags: I=bit3, E=bit2, C=bit1, F=bit0. Expected codes are literals copied from the
  independently approved 16-row matrix, never calculated with production logic.
  Complete `internal/cli/exits_test.go` content:

```go
package cli

import (
    "fmt"
    "testing"
)

func TestSelectScanExit(t *testing.T) {
    for _, tc := range []struct {
        mask uint8
        want int
    }{
        {0b0000, 0}, {0b0001, 1}, {0b0010, 3}, {0b0011, 3},
        {0b0100, 2}, {0b0101, 2}, {0b0110, 2}, {0b0111, 2},
        {0b1000, 130}, {0b1001, 130}, {0b1010, 130}, {0b1011, 130},
        {0b1100, 130}, {0b1101, 130}, {0b1110, 130}, {0b1111, 130},
    } {
        t.Run(fmt.Sprintf("%04b", tc.mask), func(t *testing.T) {
            conditions := ScanExitConditions{
                Interrupted: tc.mask&8 != 0,
                ReportPreventingError: tc.mask&4 != 0,
                RequiredCoverageIncomplete: tc.mask&2 != 0,
                EnforcedUnacceptedFindings: tc.mask&1 != 0,
            }
            if got := SelectScanExit(conditions); got != tc.want {
                t.Fatalf("conditions=%+v: want %d, got %d", conditions, tc.want, got)
            }
        })
    }
}
```

- [x] **Observe compile RED**, expecting missing ScanExitConditions/SelectScanExit.
  Introduce exactly the spec's four-field type and a stub returning 0; rerun focused
  tests and observe behavioral RED: only 0000 passes, every other row fails before
  adding decision logic. Do not use compilation failure alone as the behavioral gate.
- [x] **Implement minimal logic after RED.** Complete source (types introduced during
  the stub step are retained, not redefined):

```go
package cli

// ScanExitConditions are qualified caller conditions, not evidence collected here.
// Default flags do not establish complete coverage, no findings or safety.
type ScanExitConditions struct {
    Interrupted bool
    ReportPreventingError bool
    RequiredCoverageIncomplete bool
    EnforcedUnacceptedFindings bool
}

// SelectScanExit selects a code without terminating the process or erasing facts.
// User interruption precedes ordinary error > required gap > enforcement > success.
func SelectScanExit(conditions ScanExitConditions) int {
    if conditions.Interrupted { return 130 }
    if conditions.ReportPreventingError { return 2 }
    if conditions.RequiredCoverageIncomplete { return 3 }
    if conditions.EnforcedUnacceptedFindings { return 1 }
    return 0
}
```

- [x] **Format, run focused/root tests and vet offline.** Every row and the unchanged
  root suites must pass. Verify that only the two new Go files changed; no existing
  types/readers/Bun/probes/module changes or go.sum. Record actual counts/toolchain.
- [x] **Review and reverify.** Inline spec/diff review maps every matrix row to its
  condition priorities, checks the caller-evidence boundary and no side-effect imports.
  Rerun fresh full root tests/vet after review. Human review remains a separate gate.
- [x] **Commit scoped code** (`9cecc77b`), then record approved execution and verification separately
  in the spec/plan and a nested internal milestone. Publish only if explicitly authorized;
  keep Refs #19, an agreed second-person reviewer and review/integration before Done.
  Do not change #12/#13/#14 or claim a full runtime CLI exit implementation.

## Execution record

The user approved this plan and explicitly authorized inline implementation,
scoped documentation/commits, offline tests/vet and updates to PR #26. The current
jj workspace was retained; GitHub #19 is the live queue and local execution
receipts stay outside the repository. The branch starts from development
`c921da54`; no unmerged OSV header source or interface is consumed.

Observed missing-API compile RED, then **15 failing matrix rows/one passing row**
with the zero stub (16 failures including parent). Minimal implementation passed
focused/root checks. Inline review confirmed the complete literal matrix and
priority order, pure return behavior, caller obligations and unchanged existing
source/module/probes. Fresh post-review root verification: **894 tests/subtests
passed, including 17 new selector tests/subtests**, and `go vet ./...`, using
`go1.27.1-X:nodwarf5 linux/amd64`. No dependencies or go.sum. The code commit
`9cecc77b` contains only the two new Go files.

These are synthetic development checks on this independent branch, not combined
counts from PR #25 or runtime/native/producer/pilot/release acceptance. No independent
review occurred inline; second-person review and integration remain required.

## Commands (Nushell)

Focused RED/GREEN (RED failure is expected and must be inspected):

```nu
with-env { GOTOOLCHAIN: local, GOPROXY: off, GOWORK: off, CGO_ENABLED: "0" } {
    go test -count=1 -run TestSelectScanExit ./internal/cli
}
```

After implementation and again after inline review:

```nu
gofmt -w internal/cli/exits.go internal/cli/exits_test.go
with-env { GOTOOLCHAIN: local, GOPROXY: off, GOWORK: off, CGO_ENABLED: "0" } {
    go version
    go test -count=1 ./...
    if $env.LAST_EXIT_CODE != 0 { error make { msg: "Root tests failed" } }
    go vet ./...
    if $env.LAST_EXIT_CODE != 0 { error make { msg: "go vet failed" } }
}
jj commit -m "feat: select scan exit from explicit outcomes" internal/cli/exits.go internal/cli/exits_test.go
```

Only commit after successful verification. This plan itself does not authorize
implementation, publication beyond the approved specification, external acquisition
or independent-review claims.
