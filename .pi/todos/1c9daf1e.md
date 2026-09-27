{
  "id": "1c9daf1e",
  "title": "Increment 3: typed npm records implemented",
  "tags": [],
  "status": "closed",
  "created_at": "2026-09-26T20:42:47.982Z"
}

# Execution ledger — [increment 3 plan](../../docs/increments/03-npm-locked-records-plan.md)

Task 1: complete.

User selected typed npm records, approved written spec including 20,000-record projection bound, then approved the plan and explicitly authorized inline execution, local synthetic tests/vet and scoped code/docs commits. No downloads, native/probe changes or changes to the existing reader.

Spec bc765026; plan/base 223f955c; code 8ef999fe; completion docs 0ad9d97b. Files: internal/inventory/npmlock_projection.go (87 lines) and npmlock_projection_test.go (218 lines).

Pre-flight: Document/ParseError reused unchanged; no competing interface changes.

RED: tests first failed to compile for the missing API. Specified types plus a zero-result stub then compiled; all 36 projection tests/subtests failed at runtime on missing data or expected errors. This was behavioral RED, not merely compile failure.

GREEN: 139 passing root tests/subtests; root go vet passed. Both rerun after inline review. go list -m all reports only packtrace. Environment: go1.27.1-X:nodwarf5 linux/amd64 with GOTOOLCHAIN=local GOPROXY=off GOWORK=off CGO_ENABLED=0. No release/native qualification claimed.

Coverage: v2/v3 ordering/root/workspace/link/aliases/odd locations; exact explicit fields without inferred names or semantic validation; all four string/bool states, empty/false and mixed invalid/usable fields; original digest, raw legacy/unknown evidence unchanged, independence from later source mutation; empty vs nil; late nil record returns zero; full 20,000 records vs zero-result rejection at 20,001 including root. Existing npmlock.go, npmlock_test.go and go.mod unchanged. No I/O imports added.

Documentation verification: 53 local Markdown links; 85 shipping parents retained, still only two documentary parents checked; projection milestone nested only.

Review inline, not independent. Further increments still require their own approvals.
