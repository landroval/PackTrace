# PackTrace

A Go project building a **read-only, offline-first CLI for investigating JavaScript
project dependencies**: known malicious-package advisories, vulnerabilities, and
installed-file integrity drift.

> **Development status:** PackTrace currently contains internal readers and evidence
> projections, not a runnable scanner. There is no scan command, matching engine,
> installable release, or production-qualified platform support yet.

## What exists today

The production module uses only the Go standard library. Its internal packages
preserve evidence and uncertainty without executing the investigated project's code.

| Area | Implemented | Not established by this work |
| --- | --- | --- |
| npm lockfiles | Bounded v2/v3 JSON reading; positional locked records and dependency requirements | Full npm producer/layout compatibility or installed-package inventory |
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
compatibility claims. Bun parsing, installed observations, matching, intelligence
synchronization, integrity investigation and reporting remain future work.

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
