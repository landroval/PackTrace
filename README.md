# PackTrace

A Go project building a **read-only, offline-first CLI for investigating JavaScript
project dependencies**: known malicious-package advisories, vulnerabilities, and
installed-file integrity drift.

> **Development status:** PackTrace contains experimental CLI commands, internal
> readers and evidence projections, including a native integrity-scan candidate.
> There is no installable release or production-qualified platform support yet.

## What exists today

The production module uses only the Go standard library. Its internal packages
preserve evidence and uncertainty without executing the investigated project's code.

| Area | Implemented | Not established by this work |
| --- | --- | --- |
| npm lockfiles | Bounded v2/v3 JSON reading; positional locked records and dependency requirements | Full npm producer/layout compatibility or installed-package inventory |
| Bun text lockfiles | Bounded JSONC reading and typed package-tuple evidence (increments 12–13) | Workspace semantics, installed-layout attribution or producer/native compatibility |
| Package manifests | Bounded JSON reading and separate dependency declaration groups | Dependency resolution or package-manager execution |
| Root comparison | Exact textual comparison of explicitly paired manifest and lockfile root requirements | Semantic range equivalence, installation drift, or findings |
| OSV records | Bounded JSON reading, temporal claims, affected identities, explicit versions, ranges and events | Full schema/identity qualification, interval evaluation, advisory applicability, or matching |
| Shared validation | Strict JSON object validation, duplicate-key/Unicode checks and bounded nesting | Native filesystem containment or a hard process-memory cap |

The readers retain raw fields and source digests. Projections distinguish missing,
null, invalid and usable evidence; nested OSV projections also distinguish children
that could not be inspected. Array positions, duplicates and unfamiliar event fields
are retained rather than silently normalized away.

These are internal APIs, not a supported public Go SDK. See the
[increment specifications and verification records](docs/increments/) for exact
contracts, limits and tests.

## Intended investigation flow

The planned product will keep three evidence classes separate: **declared**, **locked**,
and **observed installed**. It will report findings separately from investigation
coverage, with terminal, JSON and SARIF output.

The pilot targets npm and modern text `bun.lock`, single projects and workspaces,
and native Linux, macOS and Windows qualification. Those are targets, not current
compatibility claims. Bun reading and package-tuple projection now exist, while
workspace semantics, installed observations, matching, intelligence synchronization,
integrity investigation and reporting remain future work.

## Windows desktop target

The intended desktop target is **Windows 11 x64**, not Windows Server-only.
Server 2022 is a CI regression baseline; passing there does not establish Windows
11 desktop qualification. The Windows candidate uses the same x64 implementation
with local NTFS and conservative supported-path boundaries.

Windows 11 on ARM can run this x64 code under emulation, but that is not native
x64-hardware validation. See [PR #96](https://github.com/landroval/PackTrace/pull/96)
for source-bound corpus results, failed attempts, observer/cleanup checks and
limitations. The initial #7 delivery uses the explicitly accepted combined evidence
in [design decisions, section 2](docs/design-decisions.md#2-native-targets-and-initial-delivery-acceptance);
that is not whole-product release or native Windows 11 x64-hardware qualification.
macOS is deferred, not completed. No safety gate is waived by choosing a target.

## Safety and interpretation

- Scanning is designed to be offline. Intelligence synchronization and public-artifact
  preparation require separate, explicit authorization; package identities must not
  be silently submitted to remote services.
- Never execute target code or package managers, install target dependencies, or
  modify the investigated tree to make it scannable.
- Missing, inaccessible, malformed or unsupported evidence must remain visible as
  uncertainty or a coverage gap, not a negative finding.
- Package presence does not prove execution. Matching reference bytes does not prove
  safety. A successful parse or complete textual comparison is not a security verdict.
- Native safeguards and producer compatibility require their own evidence. Passing
  synthetic tests is not proof that an untrusted project can be safely scanned.

The current in-memory components are building blocks for these requirements, not an
implementation of all of them. Consult the [design decisions](docs/design-decisions.md)
for the authoritative boundaries.

## Local development

### Requirements

- An already-installed Go toolchain compatible with the `go 1.27.1` directive in
  [go.mod](go.mod).
- Nushell for the commands below.
- [Jujutsu (`jj`)](https://www.jj-vcs.dev/) for the project's scoped commit workflow.
  It is not required merely to run Go tests.

Recorded development verification used `go1.27.1-X:nodwarf5 linux/amd64`; this is
not official-toolchain or native release qualification. Toolchain acquisition is a
separate setup step, not something the commands below perform automatically.

### Run the root module's checks

From the repository root, in Nushell:

```nu
with-env { GOTOOLCHAIN: local, GOPROXY: off, GOWORK: off, CGO_ENABLED: "0" } {
    go version
    go test -count=1 ./...
    if $env.LAST_EXIT_CODE != 0 { error make { msg: "Go tests failed" } }
    go vet ./...
    if $env.LAST_EXIT_CODE != 0 { error make { msg: "go vet failed" } }
}
```

These checks use synthetic inputs and the local toolchain. The root module has no
external dependencies. The environment settings are not a network sandbox, and these
commands do **not** run or qualify the separate modules under `probes/`.

There is intentionally no `packtrace scan` quick-start yet. Do not treat a successful
`go test` or library build as a working scanner.

## Experimental supplied reference digest

Pipe exact raw bytes to `packtrace check-reference-digest --integrity SRI` (terminal
by default; `--format json` for portable JSON). For example, in Nushell:

```nu
^printf '%s' abc | packtrace check-reference-digest --integrity 'sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=' --format json
```

The command reads stdin only, never a path. `--max-bytes N` accepts decimal
0–536870912, default 536870912 (512 MiB). Canonical single-token SHA-256/384/512
claims can match or mismatch; unsupported or multiple tokens report unknown without
reading. All usable reports exit `3`; invalid arguments, check and output failures
exit `2`. Equality is not publisher assurance, archive validity, coverage or security.

## Experimental npm root comparison

Pipe supplied JSON metadata to `packtrace compare-npm-root --format json` (or omit
`--format` for terminal output):

```nu
'{"manifest":{"dependencies":{"example":"^1"}},"lockfile":{"lockfileVersion":3,"packages":{"":{"dependencies":{"example":"1.x"}}}}}' | packtrace compare-npm-root --format json
```

The report counts textual declaration differences, not semantic equivalence,
installed state, security or a target scan. It never opens a project. npm lock
versions 2 and 3 are supported; a missing root remains incomplete. Usable
metadata exits `3`; invalid input, arguments or output failures exit `2`.

## Experimental Bun root comparison

With a locally built binary, `packtrace compare-bun-root --format json` compares
supplied root declarations without opening a project (terminal output is the
default). Send exactly a
manifest object and the original text `bun.lock` string on stdin, for example:

```json
{"manifest":{"dependencies":{"example":"^1"}},"lockfile_text":"{\"lockfileVersion\":1,\"workspaces\":{\"\":{\"dependencies\":{\"example\":\"1.x\"}}},\"packages\":{}}"}
```

The portable report contains fixed group/state labels and counts of equal,
manifest-only, lock-only, text-changed and indeterminate requirements. This example
has one textual change; it does not evaluate whether the two ranges are equivalent.
Names, requirement strings, paths and hashes are not exported. A missing root or
uninspectable group remains incomplete; zero counts do not establish safety.

Input is bounded to 1 MiB, with the existing manifest/workspace projection limits.
`--help` does not read stdin. Usable metadata summaries exit `3`, even when their
textual comparison is complete; argument, read, parse, limit and output failures
exit `2`. This is not a scanner or a producer/native compatibility qualification.

## Repository map

```text
internal/inventory/  npm lockfile and manifest evidence; root requirement comparison
internal/intel/      OSV record reading and evidence projections
internal/jsoninput/  Shared strict JSON validation
probes/              Isolated evaluation work, separate from production dependencies
docs/               Design, compatibility evidence and increment contracts
.pi/                 Shared task ledger and contributor guide
```

## Contributing

Use the [GitHub collaboration guide](docs/github-collaboration.md) for the live
issue queue, shared Project, ownership rules and `gh`/`jj` examples. Task creation
and assignment do not replace implementation approvals.

1. Read the [current design decisions](docs/design-decisions.md) and
   [development guidelines](docs/development-guidelines.md).
2. Use the [shared ledger guide](.pi/README.md) to find historical work and the active
   backlog. Coordinate scope before parallel work; a closed task is not automatically
   a completed product capability.
3. Choose a small, useful increment. Review its written specification, then its plan
   and execution authorization. Unrelated global design questions need not block it.
4. Add focused tests, observe the relevant failure, implement the approved scope, and
   rerun root tests and vet. Record what was and was not verified.
5. Use small scoped `jj` commits. Review task-ledger updates separately from unrelated
   code; do not commit credentials, private SSH keys, session state or investigated data.

Downloads, new dependencies, real target inputs, native probes/runners and publication
retain separate approval boundaries. No probe or network workflow is authorized merely
because its code or documentation is present in the repository.

## Further reading

- [Design decisions](docs/design-decisions.md) — current authority; supersedes earlier
  global-design gates and selective SCALIBR-reuse proposals.
- [Pre-1.0 checklist](docs/pre-1.0-features.md) — capabilities and qualification still required.
- [Development roadmap](docs/development-roadmap.md) — broader delivery context; read
  alongside the superseding design decisions.
- [Inventory compatibility](docs/inventory-compatibility.md) and
  [evaluation results](docs/inventory-evaluation-results.md) — targets, limitations and evidence.
- [Native safety probe plan](docs/native-safety-probe.md) — separate feasibility and safety gates.
