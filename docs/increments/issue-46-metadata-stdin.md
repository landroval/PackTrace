# Experimental inspection of supplied npm/OSV metadata

## Purpose and authority

The next usable slice consumes operator-supplied metadata instead of requiring
incorporated demo scenarios. It is an offline metadata inspector, not a project
scanner, installed inventory, authenticated feed or complete threat assessment.

The owner authorized preparing this compact brief after the demo promotion.
**Approved:** the owner selected “Ejecutar y publicar apilado (recomendado)”,
explicitly approving this written specification/plan, inline TDD, owned stdin
checks, scoped jj commits, issue #46 and dependent draft publication.
No dependency acquisition or target access is authorized. Use one brief with
the code, not a separate docs PR.

Preparation workspace: `metadata-stdin`, parent
`05b4f99748f4e4af323d026fd4d934166311c935`; promotion PR #45 targets `development`.
Do not modify existing workspaces, bookmarks, reviews or the unrelated task deletions.

## Command and input

- `packtrace inspect --help`: truthful usage, exit 0; never consume stdin.
- `packtrace inspect [--format terminal|json]`: defaults to terminal; accepts one
  optional format, separated or attached. Repeated/unknown options, other values,
  positional arguments or help mixed with options return a fixed private error, 2,
  before reading stdin. No paths, output files, privacy-weakening flags or feeds.
- Consume stdin once as a JSON object with exactly `lockfile` and `advisory` keys,
  each an object. The lockfile is npm v2/v3; the advisory is one OSV record. Unknown
  envelope keys, null/missing/wrong-type members, duplicates at any depth, invalid
  UTF-8/surrogates, trailing data and unsupported lock versions fail privately.
- Reuse `jsoninput.Object` and actual inventory/intel parsers/projections; preserve
  the owned raw JSON fragments, not reserialized substitutes or forged projections.
- Total wire limit: **1,048,576 bytes**. Read no more than limit + 1; read errors or
  overflow produce no usable report. After projection, cap total package records
  (including a root if present) at **64**, affected slots at **64**, and pair output
  at **4,096**. Existing nested intel/inventory guards remain effective. Reject
  excess before repeated version evaluation; do not truncate and claim completion.
- These are application limits, not an RSS cap, source authenticity, network-denial
  sandbox or hard wall-clock bound. An unfinished input stream can wait for EOF;
  this slice adds no asynchronous worker/deadline subsystem.

## Evaluation and uncertainty

Reuse/extract the existing demo evaluation flow within `internal/demo`; two real
callers justify a narrow internal byte-input entry point, not a configurable engine.
Update its owned-input-only package comment accurately. Preserve the six existing
demo outcomes, schema and observable output; do not give caller bytes a synthetic
scope label. The separate `internal/inspect` adapter owns input bounds and its
portable output view, not a second version/identity matcher.

- Exclude only the decoded empty-key project root. Other locations remain opaque
  metadata, never filesystem paths. Preserve every remaining locked observation.
- Missing/null/wrong-type names or versions, empty names, non-SemVer versions and
  link/unqualified-link records remain visible as typed qualification states and
  gaps. Do not discard the document or infer canonical names from location keys.
  This deliberately cannot match many normal npm records lacking explicit names.
- A usable concrete version can be evaluated independently of missing identity;
  an unusable query is explicitly not evaluated, never silently a no-match.
- Correlate declared explicit name and version outcome within the **same affected
  index**. Candidates require exact explicit name, qualified OSV npm candidate,
  concrete version match, no reported/unknown withdrawal and no link/unqualified
  link. Absence of a link declaration is not proof of registry origin.
- Preserve support/problem indices, uncertainty and withdrawal state. A reported
  withdrawal suppresses new candidates without erasing version evidence; unknown
  withdrawal also blocks promotion. Positive support does not erase sibling gaps.
- Empty inventory or absent/empty/unqualified affected evidence has explicit
  not-run/incomplete coverage, not a vacuous completed investigation.
- Origin, producer, freshness, category and applicability remain unqualified.
  Installation/integrity are not run; confirmed findings stay empty; every candidate
  is identity/version-only and not enforcement eligible.
- Usable partial inspection returns **3**, even with zero candidates, via the
  existing exit selector. Argument/read/parse/limit/output failure returns **2**
  without an empty successful report. Existing help/version/scan behavior stays.

## Portable-only result

Schema `packtrace.inspect.v1`, explicitly experimental, supplied-metadata scope and
`portable` presentation. JSON and terminal derive from the same allowlisted view.
Expose opaque report-local package/advisory references, typed qualification states,
locked observation kinds, pair/support/problem indices, decisions, gaps and exit.

All caller metadata is unknown-origin. Never emit raw package names, versions,
advisory IDs, locations, URLs, payload text, credentials or evidence digests/hashes
in either output or diagnostics. Omit hashes even if retained privately during
projection: portable fingerprints can enable dictionary attacks. Do not promise
anonymity or correlation across runs. Do not mutate matching evidence to redact it.
Local investigative detail, public/private classification, SARIF, trusted policy,
exceptions and production schema/producer qualification are **out of scope**.
This implements only this experimental command's conservative portable view.

## Implementation and acceptance ledger

Permitted files: existing `cmd/packtrace/main.go`, `main_test.go`,
`internal/demo/demo.go`, `demo_test.go`; new `internal/inspect/inspect.go`,
`inspect_test.go`; this brief, renamed with a real issue number when authorized.
No existing intel/inventory/CLI parser, module, workflow or task-ledger changes.

1. Record approval here; create the owner-assigned child issue under #8, dependent
   on #43, only with publication authority. Keep historical integration distinct
   from an independently reviewed merge into `development`.
2. Write literal tests and observe RED before implementation. Preserve source
   bytes and existing callers while extracting shared evaluation; no copied matcher.
3. Implement bounds, conservative qualification, portable-only view and command.
4. Run focused/root tests, vet and gofmt, then compile and exercise terminal/JSON
   using owned inert stdin bytes. No real third-party project/feed or network probe.
5. Demonstrate behavioral RED for a compiling cross-slot mutant and a portable
   leakage mutant; restore exact bytes, repeat checks and document author review.
6. Scoped jj commits and a dependent draft PR only if authorized; no merge, cleanup,
   issue closure/Done or claim of independent approval. Request final-head review
   only when eligible. No new agents or dependencies.

Literal checks: positive (1 limited candidate, 0 findings, 3); fixed boundary
(0 candidates, 3); unsupported range and withdrawal (gaps, 0 candidates, 3);
cross-slot separation (0, 3); absent name with valid version (inventory retained,
identity gap, 0, 3); unusable version and link (retained, no candidate, 3); empty
inventory/affected (honest gaps, 3); malformed/duplicate envelope or nested JSON,
read failure and bounds (2, no report); exactly/over byte/record/slot limits;
private markers and their digests absent from both formats/diagnostics;
reference relationships, deterministic decisions, format agreement, failed/short
output, no stdin reads on bad args/help, and all original demo regressions.

## Bash example after implementation (not executed during preparation)

The shell explicitly supplies metadata; PackTrace does not open the input path.
These commands are published in Bash; local instructions can use Nushell.

```bash
bin="$(mktemp -d)/packtrace"
GOTOOLCHAIN=local GOPROXY=off GOWORK=off CGO_ENABLED=0 go build -o "$bin" ./cmd/packtrace
cat <<'JSON' | "$bin" inspect --format json
{"lockfile":{"lockfileVersion":3,"packages":{"":{},"node_modules/example-package":{"name":"example-package","version":"1.2.3"}}},"advisory":{"id":"EXAMPLE-OSV-001","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"example-package"},"versions":["1.2.3"]}]}}
JSON
# Expected exit 3: usable partial metadata inspection, not complete applicability.
```

Local verification uses the existing modified Go toolchain with acquisition off.
Those environment controls are not OS sandbox evidence or official qualification.

## Execution ledger

- Issue #46 created/read back: owner landroval, parent #8, native blocked-by #43.
- Approval recorded before new Go; dependency head remains exact and unchanged.
- Execution checks and publication are pending; no independent approval claimed.
