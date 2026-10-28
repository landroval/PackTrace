# Bun package INFO requirements implementation plan

Status: proposed for review, not approved. Execution requires the owner's explicit
approval of the [specification](issue-65-bun-info-requirements.md) and this plan.

**Goal:** type the dependency groups recorded in each Bun tuple's INFO object.
**Architecture:** after `projectBunTuple` copies a recognized INFO object, decode its
members and call the existing `projectDependencyGroups` with the remaining
whole-projection allowance, exactly as `ProjectNPMLock` does per record.
**Tech stack:** current Go module and standard library only.

## Global constraints

- Four groups in fixed order when INFO is present; `nil` when the record has no INFO.
- One 20,000-membership allowance for the whole projection; overflow returns
  `limit-exceeded` with a zero projection.
- Existing `BunLockedRecord` fields, kinds, raw `Info`, ordering and errors unchanged.
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

## Execution evidence (draft, pending review)

Executed locally at the issue author's request before owner approval; these results
do not replace the pending specification/plan approval or second-person review.

- RED: build failure, `BunLockedRecord has no field or method Requirements`.
- GREEN: Bun inventory, demo and inspect tests pass; 9 new tests/subtests.
- Mutation: resetting the allowance per record failed `TestProjectBunLockRequirementBound`; restored.
- `go test -count=1 ./...` (3,680 tests/subtests) and `go vet ./...` pass offline with go1.27.1 darwin/arm64.
