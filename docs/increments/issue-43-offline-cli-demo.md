# Runnable offline CLI demo — compact delivery brief

## Status and goal

The owner explicitly approved this written brief as the specification and compact
execution plan, authorized inline TDD/implementation, six owned scenario runs,
scoped jj commits and the new issue/draft code PR, and selected stacked execution
on the exact PR #42 head below. This accepted lighter process replaces separate
spec/plan documents for this increment; the brief ships with the code, not as a
documentation-only PR. Independent review and integration remain separate gates.

Deliver an actual `cmd/packtrace` executable that connects the existing npm lock
reader/projection, OSV header/affected/npm-identity/time projections, strict SemVer,
version-condition evaluator and exit selector. Success is demonstrating the real
pipeline from owned inert data to a visible result, not another isolated helper.

Recommended: an experimental `demo` command with incorporated fixtures. Reading
arbitrary local projects/advisory files instead would require native opening,
effective-input selection, snapshot/provenance and privacy contracts; that is not
silently included. No new dependencies, downloads, target execution or probes.

## Command and behavior

- `packtrace --help`, `packtrace --version`, `packtrace scan --help`: fixed,
  truthful control output, exit 0 unless output fails.
- `packtrace demo [--scenario NAME] [--format terminal|json]`: default scenario
  `candidate`, default terminal. Reject duplicates, unknown options/values, extra
  arguments and malformed invocations privately, with exit 2.
- Other production grammar delegates to existing `cli.ParseArgs`. A valid `scan`
  request returns fixed `cli: scan-unavailable`, exit 2, without opening its root
  or producing a pretend scan. Existing parser/defaults/exit logic stay unchanged.
- No arbitrary input paths, stdin data, target settings, feeds or output files.
  Fixtures are ordinary inert strings in Go, parsed on every invocation. Selection
  changes the input, never selects a precomputed candidate/result.

For each explicit-name, concrete-version dependency record (excluding the project
root record), correlate qualified npm advisory identity and version decisions by
that same affected index. Do not derive names from locations or combine one slot's
identity with another slot's version result. Preserve byte digests, indices,
version support/problems, full-evaluation flag and source withdrawal disposition.
A candidate requires exact explicit name equality, candidate identity profile,
version `match`, and withdrawal **not declared**. Reported withdrawal suppresses
new candidates while retaining the version evaluation; unknown withdrawal blocks
candidate promotion and remains a gap. No result establishes current activity.
All identities in these owned fixtures are explicit, fixed and within the agreed
npm subset; this is not a general inventory-name normalization algorithm.

Use one `demo.Result` for both renderers, with experimental schema marker
`packtrace.demo.v1`, synthetic scope, source digests, locked observations,
per-record/per-affected evaluations, identity/version-only candidates, empty
confirmed findings, coverage and exit code. Candidates are never enforcement
eligible. JSON is a provisional demo envelope, not the production report schema.
Terminal output quotes data and prominently labels synthetic/demo limitations.

Coverage distinguishes completed fixture parsing/projection, completed or
incomplete version evaluation, incomplete advisory applicability (origin,
freshness and category not qualified), and not-run installation/integrity.
Every usable demo report therefore returns `cli.SelectScanExit` with required
coverage incomplete: **3**, even with zero candidates. Parse/argument/output
failure returns **2**, with no successful empty report. No "safe/clean" claim.

## Literal acceptance scenarios

| Scenario | Required visible result | Exit |
| --- | --- | --- |
| candidate | One explicit locked package; same-slot npm identity + SemVer range match; one limited candidate, zero confirmed findings | 3 |
| no-version-match | Same identity, fixed-boundary version no-match; zero candidates; gaps remain | 3 |
| unsupported | ECOSYSTEM range indeterminate; zero candidates; version gap visible | 3 |
| withdrawn | Source reports withdrawal; version match retained, zero new candidates | 3 |
| different-identity | Other-name slot matches version, same-name slot does not; zero candidates, no cross-slot correlation | 3 |
| malformed | Strict reader rejects inert malformed advisory; private diagnostic, no successful report | 2 |

Also verify help/version, invalid/duplicate arguments without echoing private
markers, JSON/terminal agreement, deterministic results/digests and failed output.
Tests use literal expectations, not expectations computed by the evaluator.

## Files and execution checklist

Only create `cmd/packtrace/main.go`, `cmd/packtrace/main_test.go`,
`internal/demo/demo.go`, `internal/demo/demo_test.go`, and this issue-keyed brief.
Do not change existing Go, module, workflow, production report or task-ledger files.

1. Record approval; isolate with jj, preserving all unrelated changes.
2. Write scenario and command acceptance tests; observe intended API/behavior RED.
3. Implement the smallest pipeline and entrypoint; no generic orchestration framework.
4. Run focused tests, root `go test -count=1 ./...`, vet and gofmt with the existing
   local toolchain and acquisition disabled. Build/run the actual executable on
   all six owned scenarios, including JSON; record actual process exit codes.
   Check a targeted cross-slot/withdrawal mutation where it discriminates behavior,
   restore exact bytes, and rerun checks. This is synthetic Linux demo evidence,
   not official-toolchain, native target-safety or producer qualification.
5. Perform author review, update this brief with concise evidence, make scoped jj
   commits, publish one code PR and request the agreed independent reviewer.

## Dependency, GitHub and authority boundary

The evaluator is PR #42 / issue #41, head
`c14129d2e5685536d28dbd477d2617634218c114`, not integrated development yet.
The preparation workspace starts at verified development `2c1cad8653e801a1395c2e372a76979dd54c8067`.

The owner approved stacked execution. Preserve this brief and base its isolated
change on that exact dependency head, without changing #42 or its bookmark.
Create a new issue under #8, owned by `landroval`, with native dependency on #41;
use its allocated number for this filename/bookmark. Publish only that bookmark
and a **draft** code PR whose temporary base is `issue-41-osv-version-conditions`.
Explain that it must not merge into the dependency branch. Request `jsustt` when
it is eligible for independent final-head review, not fictitiously while draft.

Parent #8 remains open. Integration is blocked until #42 has independent approval
and reviewed integration. Retargeting/synchronization, making the dependent PR
ready, merge, closure/Done, security changes, CI, credential changes, arbitrary
input access, acquisition and native probes need their own relevant authority.
Tracked by issue #43 under #8, with #41 as a native integration dependency.

## Delivery ledger

- Pre-flight: entrypoint -> demo model -> unchanged inventory/intel/exit APIs agree;
  issue #43 ownership and explicit stacked authority recorded before code.
- Execution uses this brief as its ledger and external temporary receipts, not
  Git-oriented SDD helper scripts; original checkout and dependency PR stay intact.
- Task: implemented and locally verified. API compilation RED and compiling-stub
  behavioral RED were observed before GREEN. The new packages pass 45 tests/subtests;
  the actual stacked root passes 2,942 (2,897 prerequisite + 45 new), with vet and
  gofmt clean. No agents or cleanup/merge were authorized.
- The built executable ran all six scenarios in both terminal and JSON: ten usable
  reports exit 3 and the two malformed-input runs exit 2. Candidate case yields one
  limited candidate; the other cases yield none. All confirmed findings stay empty.
- Cross-slot and ignored-withdrawal mutations both caused behavioral failures and
  were restored byte-for-byte. The first cross-slot attempt failed compilation due
  to an unused index; only the corrected compiling mutant counts as discrimination.
- Author review checked real input derivation, same-slot correlation, withdrawal,
  gaps/exits, quoted terminal/private diagnostics, output failures and file scope.
  No remaining in-scope important/critical issue was identified; independent review
  remains pending. Arbitrary-input/native/producer/report qualification was not judged
  as delivered, because it is explicitly excluded and visible in demo coverage.
- Validation used owned synthetic data and modified local
  `go1.27.1-X:nodwarf5 linux/amd64`, with acquisition disabled. This is not official
  toolchain qualification, a network-denial sandbox test or native target-safety proof.

## Try the executable (Nushell, from this workspace)

```nu
let bin = (mktemp -d | str trim | path join "packtrace")
with-env {GOTOOLCHAIN: "local", GOPROXY: "off", GOWORK: "off", CGO_ENABLED: "0"} {
    go build -o $bin ./cmd/packtrace
}
^$bin demo --scenario candidate
^$bin demo --scenario unsupported --format json
```

Exit 3 is intentional: usable synthetic report, incomplete required applicability.
This actually executes the pipeline; it does not scan a real project.
