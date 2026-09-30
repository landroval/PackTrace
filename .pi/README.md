# Shared development ledger

The Markdown files in `todos/` are versioned task records for contributors, whether
or not they use Pi. They supplement, rather than replace, the project documentation:

- [Design decisions](../docs/design-decisions.md): authoritative decisions and approval boundaries.
- [Increment specifications and plans](../docs/increments/): approved scopes and verification evidence.
- [Pre-1.0 checklist](../docs/pre-1.0-features.md): shipping requirements, not inferred from task closure.

## Active backlog

[GitHub collaboration](../docs/github-collaboration.md) defines the live issue queue,
ownership and Project states. These files remain historical evidence/backlog pointers,
not a second live assignment system.

[Remaining product design contracts](todos/42e46cd7.md) points to unresolved work.
It is not an instruction to finish global design before another bounded increment.
A new increment still requires its own specification, plan and execution approvals.

## Completed increment records

These are historical records at their cited commits. Test counts, API names and
limitations describe that increment, not necessarily the current tree. Consult the
linked plans and current design decisions before relying on an old contract.

| Increment | Ledger |
| --- | --- |
| 1 | [npm v3 reader](todos/f34ac7cd.md) |
| 2 | [npm v2/v3 extension](todos/a9556cff.md) |
| 3 | [Typed locked records](todos/1c9daf1e.md) |
| 4 | [Manifest declarations](todos/85fc142b.md) |
| 5 | [Locked requirements](todos/6989c695.md) |
| 6 | [Root requirement comparison](todos/376c49b0.md) |
| 7 | [OSV record reader](todos/02fa889c.md) |
| 8 | [OSV temporal projection](todos/f5d2ffe1.md) |
| 9 | [OSV affected identities](todos/58147a3a.md) |
| 10 | [Explicit OSV versions](todos/e4ff360d.md) |
| 11 | [OSV ranges and events](todos/0fc26843.md) |
| 12 | [Bun text lockfile reader](todos/08cbf8ea.md) |
| 13 | [Typed Bun locked records](todos/b7e3c214.md) |

## Other historical design records

- Completed preparation: [evidence review](todos/d330dad8.md) and
  [adapter adoption decision](todos/41fdd98c.md).
- Superseded global workflow: [requirements interview](todos/0da13e3b.md),
  [single specification](todos/1da3dc30.md), [review](todos/b280ad8c.md),
  [approval](todos/d3777fee.md), and [implementation planning](todos/9d00549b.md).
  These were replaced by per-increment work, not completed as full-product gates.
- [Visual companion](todos/2ad316d4.md): closed as not applicable.

## Maintenance and collaboration

- Each task file starts with JSON metadata followed by Markdown. Preserve its ID,
  filename and creation timestamp; use the body for scope, evidence and closure reason.
- `closed` means no further work under that task. It can mean completed, superseded
  or not applicable; read the reason/tags. It never implies production qualification.
- Record agreed ownership before parallel work. Local session claims are not a
  distributed lock across teammates' clones; coordinate scope and branches separately.
- Keep approved scope, meaningful decisions, blockers, verification and commit links.
  Do not commit session IDs/claims, machine-specific paths, credentials, raw investigated
  inputs or transient working-copy notes. Retain relevant historical toolchain details
  when they explain verification limits.
- Review task changes explicitly and commit them with `jj`, separately from unrelated
  code. This directory's versioning does not authorize committing all other Pi state.
- Historical authorization notes are evidence of past scope, not standing permission
  for new implementation, downloads, target access, probes or publication.
