{
  "id": "f34ac7cd",
  "title": "Increment 1: implement and verify npm v3 reader",
  "tags": [],
  "status": "closed",
  "created_at": "2026-09-26T20:02:48.745Z"
}

# Execution ledger — [increment 1 plan](../../docs/increments/01-npm-v3-reader-plan.md)

Task 1: complete.

User approved the specification, plan, and inline execution in the current jj workspace: create go.mod/reader/tests, run local synthetic tests/vet and scoped commit. No downloads, real investigated inputs, native runners/probes, or old probe changes authorized or performed.

Base: bfd10800. Production commit: 0fe821ad. Module packtrace; reader internal/inventory/npmlock.go; tests alongside it.

RED: go test ./... failed at compilation with undefined ParseNPMLockV3 and ParseError before implementation existed, matching the plan's expected absent-reader failure.
GREEN: 38 tests passed. go test -count=1 ./... and go vet ./... re-run successfully after review; go list ./... reports only packtrace/internal/inventory. No go.sum/external dependencies. Existing nested SCALIBR probe not run or changed; historical graph build blocker remains separate.

Development environment: go1.27.1-X:nodwarf5 linux/amd64; GOTOOLCHAIN=local GOPROXY=off GOWORK=off CGO_ENABLED=0. Not official-toolchain or native release qualification.

Ruling: fused token validation establishes syntax, duplicate-key and nesting rules before raw projection; no preliminary json.Valid pass, which has a larger internal depth limit. Surrogate validation follows syntactically valid token traversal. This preserves the approved contract with fewer redundant passes.

Inline diff/spec review complete; no independent reviewer claimed. Cases cover raw field retention, exact digests, caller-input independence, aliases/link/duplicate-name locations as uninterpreted evidence, huge/precise values, Unicode/escaped duplicates, errors without content, malformed/shapes/versions, 64 MiB and depth-128 boundaries. Reader performs no filesystem/network I/O and is not a CLI or installation/effectiveness/provenance determination.

Remaining increments require their own approvals; global design completion no longer blocks unrelated work.
