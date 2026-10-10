# Issue #50 — bounded supplied advisory batches

## Approved in-chat design and execution

The owner approved **Execute and publish** after the bounded design was presented:
inline TDD, local owned-input checks, issue creation and a PR ready for review
against development. This one brief records scope, execution steps and evidence;
no separate specification/plan PR. Base: `d4c95f90b9b485a7d3dcc0a6c50e4c70795a2ffc`.

## Contract

- Add `inspect-batch [--format terminal|json] [--identity-profile explicit-only|npm-lock-v2-v3]`.
  Default terminal/explicit-only; reuse the existing argument grammar. Help and
  invalid flags do not read stdin. Existing inspect and demo reports stay unchanged.
- Stdin has exactly `lockfile` and `advisories` (1–16 records). Strict whole-wire
  JSON, duplicate/depth/UTF-8/surrogate checks; raw record fragments retained.
- Bounds: 1 MiB wire, read at most 1 MiB + 1, 64 lock records including root,
  64 aggregate source affected slots including malformed records/members,
  at most 4,096 package-slot pairs. Reject overflow before repeated evaluation.
  Existing upstream limits apply; no truncation, hard stdin deadline or RSS cap.
- Reuse single-record inspection/evaluation. Each advisory stays in input order
  with its own opaque reference and portable report; duplicates remain distinct.
  Invalid advisory metadata produces an explicit per-record gap without dropping
  valid siblings. Whole-wire/lock/budget failures return whole-zero/private errors.
- JSON schema `packtrace.inspect.batch.v1`: locked-entry count, positional advisory
  entries (`reference`, `state`, optional existing portable `report`), candidate
  comparison count, findings, coverage and exit. The nested report's advisory
  reference is rebound to its position, never its raw ID. Count comparisons,
  not unique authenticated findings. All-unusable input stays visibly incomplete.
- Terminal/JSON come from this same model. Portable only; no raw names, versions,
  locations, requirements, IDs, URLs, hashes or caller-supplied diagnostics.
- Existing profile, same-slot and withdrawal gates retained. Derived positives
  remain installation-name hypotheses. Findings empty, candidates never enforcement
  eligible, applicability incomplete, installed/integrity not run. Usable exit 3;
  fatal private exit 2. Input/profile grants no source/canonical/freshness authority.

## Files and execution

Only new `internal/inspect/batch.go` and test, existing cmd main/test and this brief.
No existing reader/intel/inventory API, single-advisory schema, module, workflow,
shared ledger, target/producer/dependency execution, dependency/agent, CI, merge,
new bypass, release, issue closure or Project Done changes.

1. Observe missing-API RED and compiling-stub behavioral RED for literal outcomes.
2. Implement the minimal bounded adapter; retain all valid siblings and raw slots.
3. Run focused/root tests, vet/gofmt and compiled owned cases in both formats.
4. Discriminate sibling-discard/reference mixing/aggregate-budget bypass mutations;
   restore exact bytes and repeat checks. Compare legacy executable outputs.
5. Author-review privacy, coverage, source order, boundary and profile behavior;
   commit/push only the scoped issue bookmark; publish a normal development PR and
   request independent final-head review. Publication is not integration permission.

## Evidence ledger

- Baseline in isolated jj workspace: 3,013 tests/subtests pass, no acquisitions.
- Modified local `go1.27.1-X:nodwarf5 linux/amd64`; checks use
  `GOTOOLCHAIN=local GOPROXY=off GOWORK=off CGO_ENABLED=0`. This is synthetic/local
  development evidence, not native safety, named-producer/platform or hosted CI.
- API compilation RED observed, followed by compiling-stub behavioral RED:
  18 failing tests/subtests and no compiler stderr. Focused GREEN: 90;
  root GREEN: **3,031** (3,013 prerequisite + 18 new); vet/gofmt clean.
- Thirteen owned executable cases ran in terminal/JSON, including partial/all-invalid
  records, independent comparisons, profiles, unknown withdrawal, empty inventory,
  exact 4,096 pairs, malformed wire, invalid lock and advisory/global-slot overflow.
  Usable reports exit 3, fatal reports exit 2; no confirmed findings or enforcement.
- Seventy-two inspect invocations (18 inputs, two profiles, two formats) and twelve
  original demo invocations preserve stdout/stderr/exits byte-for-byte against the
  integrated prerequisite executable. Only top-level help advertises the new command.
- Three compiling mutants (sibling discard, advisory-reference mixing, aggregate
  budget reset) caused intended behavioral failures; exact source bytes restored
  and root/vet/build checks repeated.
- Author review covered wire/record/global-slot guards before repeated evaluation,
  raw evidence/projection boundaries, sibling isolation/order, private failure/view,
  unknown/empty scopes and unchanged single-record/profile semantics. No known
  in-scope important/critical issue remains; this is not independent approval.
- Execution ruling: an initial documentation commit accidentally used the original
  cwd and produced an empty, unpublished local commit (no paths committed). The
  original 21 ledger deletions remain intact; the actual brief commit used the
  isolated workspace, before tests/code. That local marker is not in this PR.
- Independent final-head review and integration remain pending; no renewed bypass.

## Owned example (Bash)

```bash
bin="$(mktemp -d)/packtrace"
GOTOOLCHAIN=local GOPROXY=off GOWORK=off CGO_ENABLED=0 go build -o "$bin" ./cmd/packtrace
cat <<'JSON' | "$bin" inspect-batch --format json
{"lockfile":{"lockfileVersion":3,"packages":{"node_modules/example-package":{"name":"example-package","version":"1.2.3"}}},"advisories":[{"id":"EXAMPLE-OSV-001","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"example-package"},"versions":["1.2.3"]}]},42]}
JSON
# Expected exit 3: one limited candidate comparison, one invalid-advisory gap.
```

This is not an installed-package scan, canonical/source authentication, feed
completeness, supported-producer declaration, security clearance or release.
