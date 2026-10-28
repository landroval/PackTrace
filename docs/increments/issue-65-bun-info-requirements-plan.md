# Bun package INFO requirements implementation plan

Status: the original implementation is integrated through
[PR #66](https://github.com/landroval/PackTrace/pull/66), following the owner's
current acceptance. The original plan and author execution evidence below are
historical; the final section records the separately accepted CLI compatibility
clarification and its regression tests. See the
[current contract](issue-65-bun-info-requirements.md).

**Goal:** type the dependency groups recorded in each Bun tuple's INFO object.
**Architecture:** after `projectBunTuple` copies a recognized INFO object, decode its
members and call the existing `projectDependencyGroups` with the remaining
whole-projection allowance, exactly as `ProjectNPMLock` does per record.
**Tech stack:** current Go module and standard library only.

## Global constraints

- Four groups in fixed order when INFO is present; `nil` when the record has no INFO.
- One 20,000-membership allowance for the whole projection; overflow returns
  `limit-exceeded` with a zero projection.
- For admitted inputs, existing `BunLockedRecord` fields, kinds, raw `Info` and
  ordering stay unchanged. INFO overflow is a newly rejected input, including
  through existing CLI consumers; their output is not claimed unchanged there.
- No changes to `projectDependencyGroups`, the reader, the workspace projection,
  the npm projection or the demo.
- No range semantics, I/O, dependencies, native probes, CLI or public schema.

## Review focus

- `classifyBunTuple` already guarantees a recognized INFO is a JSON object; the new
  decode must not change kinds or turn a recognized record into an error.
- The allowance is threaded through records, not reset per record.
- Tests exercise `ProjectBunLock`, not the helper.

## Task 1: project INFO groups in ProjectBunLock

Files:
- Modify `internal/inventory/bunlock_projection.go`: add `Requirements` to
  `BunLockedRecord`; in `ProjectBunLock`, keep a `remaining` allowance starting at
  `maxLockedRequirements`, and for records with `Info != nil` decode the object
  members and project the groups, returning `limit-exceeded` on overflow.
- Modify `internal/inventory/bunlock_projection_test.go`.

Steps:
1. Add table tests per kind with INFO, the four group states, nil requirements for
   unknown records and workspaces without INFO, empty INFO, repeated names,
   ownership and the 20,000/20,001 bound across several records.
2. Run them and observe RED (missing `Requirements` field).
3. Implement and observe GREEN; update existing exact-record expectations only to
   add the new field.
4. Run one restored mutation (reset the allowance per record) and confirm the
   cross-record bound test fails.
5. Run the full root suite and vet.

## Verification

```text
GOPROXY=off GOWORK=off CGO_ENABLED=0 go test -count=1 -run 'Bun' ./internal/inventory ./internal/demo
GOPROXY=off GOWORK=off CGO_ENABLED=0 go test -count=1 ./...
GOPROXY=off GOWORK=off CGO_ENABLED=0 go vet ./...
```

## Delivery

Issue branch `issue-65-bun-info-requirements` from `development`; scoped commits for
specification/plan, implementation with tests, and evidence; draft PR with `Refs #65`
until acceptance, then second-person review before integration. After approval and
execution, record RED/GREEN, toolchain and counts here and in the pre-1.0 checklist.

## Execution evidence (historical author record, pending review at the time)

Executed locally at the issue author's request before owner approval; these results
do not replace the pending specification/plan approval or second-person review.

- RED: build failure, `BunLockedRecord has no field or method Requirements`.
- GREEN: Bun inventory, demo and inspect tests pass; 9 new tests/subtests.
- Mutation: resetting the allowance per record failed `TestProjectBunLockRequirementBound`; restored.
- `go test -count=1 ./...` (3,680 tests/subtests) and `go vet ./...` pass offline with go1.27.1 darwin/arm64.

## Accepted compatibility clarification and CLI regression

During review the owner explicitly accepted keeping the new 20,000-membership
allowance, including its stricter CLI admission. A 64-package cap does not prevent
one tuple from carrying 20,001 INFO requirements; such a wire input can remain
below 1 MiB. No allowance or production validation was weakened.

The follow-up `cmd/packtrace/bun_info_limit_test.go` exercises both `inspect-bun`
and `inspect-bun-batch`, in terminal and JSON, at 20,000 and 20,001 memberships in
one tuple. The exact cap retains a portable partial report and exit 3. Overflow
returns exit 2, no stdout and the existing fixed private diagnostic. The test also
checks that the fixture stays below the wire cap and that admitted output does not
expose its synthetic metadata.

The test was first run through an external overlay against pre-increment
`development`: its four overflow subtests failed for the intended reason (exit 3
instead of 2), while the exact-cap controls passed. All eight subtests passed with
the proposed INFO implementation. This is current regression verification, not a
claim that the reviewer observed the author's historical TDD sequence.
