# GitHub collaboration

## Source of truth

- [GitHub Issues](https://github.com/landroval/PackTrace/issues) track live scope,
  ownership, dependencies and approval links.
- [PackTrace development](https://github.com/users/landroval/projects/1) shows delivery
  status and the `Blocked` reason. A label or board movement is not execution permission.
- [Design decisions](design-decisions.md) remain authoritative. Approved specifications
  and plans live in [increments/](increments/); [pre-1.0 acceptance](pre-1.0-features.md)
  defines shipping qualification.
- [.pi records](../.pi/README.md) retain historical decisions and evidence. Do not
  duplicate the live GitHub queue or assume local claims lock teammates' clones.

## Capability parents and first slices

| Parent | Capability | Initial children |
| --- | --- | --- |
| [#5](https://github.com/landroval/PackTrace/issues/5) | Inventory and producer compatibility | #16 Bun workspaces; #17 npm input selection |
| [#6](https://github.com/landroval/PackTrace/issues/6) | Advisory qualification and matching | #12 header; #13 identity; #14 event structure; #15 version fixture contract |
| [#7](https://github.com/landroval/PackTrace/issues/7) | Native safety and lifecycle | #22 macOS qualification plan |
| [#8](https://github.com/landroval/PackTrace/issues/8) | CLI, coverage and policy | #18 arguments; #19 exits; #20 coverage contract |
| [#9](https://github.com/landroval/PackTrace/issues/9) | Offline storage and preparation | #21 snapshot manifest |
| [#10](https://github.com/landroval/PackTrace/issues/10) | Trusted references and integrity | Future slices after contracts/dependencies are understood |
| [#11](https://github.com/landroval/PackTrace/issues/11) | Reports, privacy and qualification | #23 CI/fuzzing qualification plan |

The initial parents are Backlog and all twelve children start in Preparation,
unassigned. Existing Bun reader [#1](https://github.com/landroval/PackTrace/issues/1)
and package projection [#3](https://github.com/landroval/PackTrace/issues/3) are
already integrated, not recreated. This tracking setup does not authorize feature
implementation or mark any product gate complete.

Dependency chain: #12 blocks #13 and #14; #14 blocks #15. #22 has an external
runner/mechanism qualification gap. `blocked` labels and Project `Blocked` text
expose these conditions; the native issue relationships are authoritative for
issue-to-issue dependencies. Clear/update labels and text when blockers change.

## Delivery states

| Status | Entry/exit condition |
| --- | --- |
| Backlog | Capability or future slice not sufficiently prepared |
| Preparation | Resolve scope, specification, plan, approvals and dependencies |
| Ready | Relevant written specification and plan approved; explicit execution authorization recorded; dependencies satisfied |
| In progress | One agreed primary owner executes the approved scope |
| Review | Draft completed, fresh checks and limits recorded, second-person review requested |
| Done | Task-specific acceptance met and PR integrated; closure reason/evidence retained |

Documentation-only tasks require reviewed artifacts, not fabricated Go execution.
A parent capability stays open until its own shipping criterion has executed
acceptance evidence; completing its initial children is not enough. Superseded or
not-applicable issues must say why they closed, not imply delivered functionality.

The Project has a `Delivery board` view using the native Status field. If GitHub
initially displays an ungrouped board, select **Group by -> Status** in the view
settings; CLI/API support for view grouping is separate from field creation.

## Avoiding collisions

1. Agree on one primary owner in the issue before starting. Assigning yourself is
   not an atomic lock; inspect existing assignees, comments and PRs and coordinate.
2. Use one clone/workspace and one issue-specific branch/bookmark per implementation
   task. Do not share a working directory or push to another contributor's branch.
3. Declare intended files and interfaces in the issue and open a draft PR early.
   Shared readers, states or consumer interfaces require an agreed contract and
   integration order, even when people edit different files.
4. Separate independent new modules/tests where appropriate; do not invent generic
   abstractions merely to divide ownership. Changes outside approved scope need review.
5. Keep a dependent issue in Preparation until its prerequisites and own approvals
   are satisfied. If work must stack, explicitly agree on the base branch and
   integration order; dependency closure alone does not authorize implementation.
6. Use issue-keyed specification filenames such as `issue-18-scan-arguments.md`
   and `issue-18-scan-arguments-plan.md` under `docs/increments/`. Do not independently
   reserve the same next sequential increment number. Existing numbered contracts
   remain unchanged.
7. Request a second-person review and resolve shared-contract concerns before
   integration. Recheck after changes; preserve the existing protected branch rules.

## CLI examples (Nushell)

`gh` API authentication and Git SSH authentication are separate. Project commands
need the `project` scope; grant it explicitly only when necessary. Never include
private keys, tokens, passwords or investigated project content in issues/PRs.

Inspect current work before claiming an issue:

```nu
gh issue list --repo landroval/PackTrace --state open
gh issue list --repo landroval/PackTrace --assignee "@me"
gh pr list --repo landroval/PackTrace --state open
gh issue view 18 --repo landroval/PackTrace
gh project item-list 1 --owner landroval --format json
```

The following commands change GitHub or publish a branch. Use them only after
agreeing ownership and the relevant scope/authorization; numbers are examples,
not instructions to start those tasks now:

```nu
gh issue edit 18 --repo landroval/PackTrace --add-assignee "@me"
gh issue comment 18 --repo landroval/PackTrace --body "Ownership agreed; planned files/interfaces and approvals are linked in this issue."
gh project item-edit 1 --owner landroval --url https://github.com/landroval/PackTrace/issues/18 --field Status --value "In progress"
```

Start from current integration history in your own workspace:

```nu
jj git fetch --remote origin
jj new development@origin -m "feat: parse scan arguments"
```

After approved changes, tests and scoped commits, select the intended commit (not
an empty working-copy change) and publish only the issue bookmark. In this
single-commit example the completed commit is `@-`; inspect `jj log` first:

```nu
jj log -r '@ | @-'
jj bookmark create issue-18-scan-args -r @-
jj git push --remote origin --bookmark issue-18-scan-args
gh pr create --repo landroval/PackTrace --base development --head issue-18-scan-args --draft --title "CLI: parse scan arguments" --body "Refs #18. Scope, approvals, tests and intended interfaces are linked in the issue."
```

Use `Refs #N` for preparation/partial PRs. Use `Closes #N` only when the PR fulfills
that issue's complete acceptance. GitHub closing keywords automatically close an
issue on merge into the default branch; they do not evaluate approval or evidence.
Use `--head` explicitly so `gh` does not unexpectedly push or offer a fork.

After review evidence is ready:

```nu
gh pr ready PR_NUMBER --repo landroval/PackTrace
gh project item-edit 1 --owner landroval --url ISSUE_URL --field Status --value Review
```

Replace `PR_NUMBER` and `ISSUE_URL` with actual values. Request the agreed reviewer;
review availability and workload are team decisions, not automatic assignment.

## Verification and integration

For approved root-module implementation, use the offline commands in the
[README](../README.md#local-development), record behavioral RED/GREEN, and run full
root tests/vet again after review. Dependency acquisition, target inputs, native
probes/runners and publication retain their separate gates.

At setup, `development` requires a reviewed PR under an existing ruleset; no Actions
workflows or required status checks were observed. This change does not alter
repository permissions/protections or install CI. #23 prepares CI/toolchain/fuzzing
qualification before a separately authorized implementation. Never claim enforced
CI or native qualification solely because a PR merged.

After integration, update the task's evidence/closure and Project status/blockers.
Status synchronization is manual; no auto-Ready or auto-Done workflow was installed.
