# Bun root requirement comparison implementation plan

Status: proposed for review, not approved. Execution requires the owner's explicit
approval of the [specification](issue-63-bun-root-comparison.md) and this plan.

**Goal:** compare the Bun root workspace requirements with manifest declarations
without claiming semantic, installed or coverage results.
**Architecture:** reuse the increment 6 comparator. Move its per-group comparison
into one unexported helper and call it from a Bun entry point that only selects the
root workspace record. Result types, rules and bounds stay unchanged.
**Tech stack:** current Go module and standard library only.

## Global constraints

- Root location is exactly `""`; other workspaces are never substitutes; a missing
  root is indeterminate, not an empty root.
- Four groups stay separate and in their existing order; exact decoded names/text.
- Side limits remain 20,000 memberships each; output has at most 40,000 union rows.
- `CompareRootRequirements` keeps its signature, guards, error order and results;
  its existing tests are not edited.
- No parser/projection changes, range semantics, I/O, dependencies, native probes,
  CLI or public schema.

## Review focus

- The npm refactor is behavior-preserving: guard order and zero results on error.
- The Bun entry point validates the manifest layout before inspecting records and
  rejects nil `Records`, mirroring the npm guards.
- Tests exercise the public entry point, not the helper.

## Task 1: shared helper and Bun comparator

Files:
- Modify `internal/inventory/root_comparison.go`: extract
  `compareRootGroups(declared, locked []DependencyGroup, result RootComparison) (RootComparison, error)`
  holding the lock-group guard and the per-group merge.
- Create `internal/inventory/bun_root_comparison.go` with
  `CompareBunRootRequirements(manifest ManifestProjection, lock BunWorkspaceProjection) (RootComparison, error)`.
- Create `internal/inventory/bun_root_comparison_test.go`.

Steps:
1. Write table tests for the Bun entry point: all outcomes, decoded equality,
   missing versus empty root, non-root workspace non-substitution, digest retention,
   input/output independence, layout guards, the lock-side 20,001 bound, the 40,000
   union and parity with `CompareRootRequirements` for identical declarations.
2. Run them and observe RED for the missing entry point.
3. Extract the helper, add the Bun entry point, and observe GREEN.
4. Run one restored mutation (drop the `Location != ""` check) and confirm a test fails.
5. Run the full root suite and vet.

## Verification

```text
GOPROXY=off GOWORK=off CGO_ENABLED=0 go test -count=1 -run 'CompareBunRoot|CompareRoot' ./internal/inventory
GOPROXY=off GOWORK=off CGO_ENABLED=0 go test -count=1 ./...
GOPROXY=off GOWORK=off CGO_ENABLED=0 go vet ./...
```

## Delivery

Issue branch `issue-63-bun-root-comparison` from `development`; scoped commits for
specification/plan, implementation with tests, and evidence; draft PR with `Refs #63`
until acceptance, then second-person review before integration. After approval and
execution, record RED/GREEN, toolchain and counts here and in the pre-1.0 checklist.
