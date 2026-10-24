# Bun advisory batch implementation plan

Status: proposed for review, not approved. Execution requires the owner's explicit
approval of the [specification](issue-67-bun-batch.md) and this plan.

**Goal:** evaluate one supplied text `bun.lock` against 1–16 supplied advisories.
**Architecture:** validate the whole wire and the Bun lockfile once, share the
advisory preflight with `ReadBatchProfile`, then call `ReadBun` once per usable
advisory and assemble the existing `BatchResult`.
**Tech stack:** current Go module and standard library only.

## Global constraints

- Existing commands, schemas and demos keep their exact bytes and exit codes; only
  root help gains one line.
- Fatal bounds are checked before any per-advisory evaluation.
- Reuse `BatchResult`, `BatchAdvisory`, `RenderBatch`, `ReadBun` and the existing
  inventory/intel APIs; no new public types beyond `ReadBunBatch`.
- No identity profile, disk access, dependencies, network or native probes.

## Review focus

- The extracted advisory preflight returns the same usable flags, slot count and
  `limit-exceeded` decisions for npm as before.
- Per-advisory packets reuse the original `lockfile_text` JSON string bytes.
- Output privacy: no raw strings from the lockfile or advisories.

## Task 1: shared preflight and ReadBunBatch

Files:
- Modify `internal/inspect/batch.go`: move the advisory slot/OSV preflight into an
  unexported helper used by `ReadBatchProfile`.
- Create `internal/inspect/bun_batch.go` and `bun_batch_test.go`: `ReadBunBatch`.

Steps:
1. Write tests for the contract cases through `ReadBunBatch` and `RenderBatch`.
2. Observe RED (missing `ReadBunBatch`).
3. Extract the helper, implement `ReadBunBatch`, observe GREEN; existing batch tests
   pass unchanged.
4. Mutations, each restored: drop valid siblings after an invalid record; skip the
   aggregate slot budget; reuse one reference for every advisory.

## Task 2: CLI command

Files:
- Modify `cmd/packtrace/main.go` and `main_test.go`: dispatch `inspect-bun-batch`,
  its help text, `--identity-profile` rejection, and the root help line.

Steps:
1. Add CLI tests (help, invalid arguments without reading stdin, both formats, exit
   codes, diagnostics) and observe RED.
2. Implement and observe GREEN.
3. Differential check: build the base commit and the change into a `mktemp -d`
   directory and compare stdout, stderr and exit code of `inspect`, `inspect-bun`,
   `inspect-batch` (both profiles) and the demos on the same owned inputs.

## Verification

```text
GOPROXY=off GOWORK=off CGO_ENABLED=0 go test -count=1 ./internal/inspect ./cmd/packtrace
GOPROXY=off GOWORK=off CGO_ENABLED=0 go test -count=1 ./...
GOPROXY=off GOWORK=off CGO_ENABLED=0 go vet ./...
```

## Delivery

Issue branch `issue-67-bun-batch` from `development`; scoped commits for
specification/plan, implementation with tests, and evidence; draft PR with `Refs #67`
until acceptance, then second-person review before integration.

## Execution evidence (draft, pending review)

Executed locally at the issue author's request before owner approval; these results
do not replace the pending specification/plan approval or second-person review.

- RED: build failure (`undefined: ReadBunBatch`), then CLI assertion failures for the
  missing `inspect-bun-batch` command.
- GREEN: 26 new tests/subtests in `internal/inspect` and `cmd/packtrace`; existing
  batch tests pass unchanged after extracting `preflightAdvisories`,
  `newBatchResult` and `appendBatchAdvisory`.
- Mutations, each restored: breaking after an invalid record, skipping the aggregate
  slot budget, and reusing one reference were each detected.
- Differential check (base `fc7080d` vs change, built in a `mktemp -d` copy): identical
  stdout/stderr/exit for `inspect` and `inspect-batch` (both profiles, both formats),
  `inspect-bun`, all 12 demo runs, subcommand help, `--version`, `scan --help` and
  malformed input. Only root `--help` (one new line) and the new command differ.
- `go test -count=1 ./...` (3,697 tests/subtests) and `go vet ./...` pass offline with
  go1.27.1 darwin/arm64.
