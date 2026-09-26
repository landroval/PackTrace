# Inventory evaluation: probe A results

**Status:** bounded Linux evaluation completed with recorded gaps and a blocked
optional component. This is not a product implementation or compatibility release.
**Date:** 2026-09-26 (UTC).

Approved scope: [inventory compatibility proposal](inventory-compatibility.md).
Probe: [README and reproduction instructions](../probes/scalibr-inventory/README.md).

## 1. Executive decision

SCALIBR v0.5.3 is **not sufficient as PackTrace's inventory model**. The three
extractors can supply useful identity observations, but lose source/digest/layout
information and require caller-owned validation, scope selection, limits, and
coverage accounting. Three malformed-input crashes were reproduced in isolated
children. The optional dependency-graph command could not compile on this host.

Proceed next to a reviewed production design using this evidence. Do not promote
this probe into the product, treat its normalized output as complete inventory,
or implement fallback parsers before design/plan approval.

## 2. What actually ran

Environment:

- Linux x86_64, kernel `7.2.7-1-cachyos`.
- Go `go1.27.1-X:nodwarf5 linux/amd64`; `GOTOOLCHAIN=local`.
- SCALIBR `v0.5.3`, previously resolved to
  `c421bee3c558c457b7b3c891d3200d1f910d93c4`; module checksums in the isolated
  [go.sum](../probes/scalibr-inventory/go.sum). `go mod verify` succeeded.
- `CGO_ENABLED=0`, no legacy build tags or dependency patches.
- Unprivileged bubblewrap, no host home mount, read-only code/fixture mounts,
  and separate transient systemd user-service cgroups.
- Each case: no network namespace route, 5-second deadline, 512 MiB memory maximum,
  zero swap, one worker, and no capabilities. No target JavaScript was executed.

The final network/isolation control confirmed an external connection fails with
`ENETUNREACH` and both `/target` and its source-path alias reject writes with
`EROFS`. This verifies the particular probe boundary, not a production scanner.

### Executed checks

| Check | Result |
| --- | --- |
| Initial evidence-capture tests against an unimplemented function | Four failures for the intended missing behavior; raw output retained |
| Final extractor evidence-capture Go tests | Four passed |
| Independent fixture-path/budget Python tests | Two passed; path test first reproduced five input-construction mistakes |
| `go vet . ./cmd/extractors` | Passed |
| Full `go test ./...` | **Failed:** optional graph command compilation; not reported as a passing suite |
| Extractor binary build | Passed |
| Optional graph binary build | **Blocked:** pinned dependency/toolchain incompatibility; two graph cases not run |
| Final synthetic case corpus | 75 records: 73 executed children and two blocked-build cases |
| Final expectation deviations | Zero after correcting the fixture construction bug; this is not a product acceptance rate |
| Native Linux root/link, permission, and controlled-changing-file cases | Executed with the limitations below |
| macOS / Windows / actual npm or Bun execution | **Not run** |

Executed-child outcomes: 58 returned inventory/empty output without an extraction
error, 12 returned explicit errors, and three panicked. Errors and panics remain
visible even though the harness itself completed. A returned empty inventory or
zero child exit status alone does not count as successful inspection.

The four Go tests cover evidence capture, a 2 MiB boundary rejection, preservation
of partial Bun output with an error, and disabling manifest version inference.
They are probe checks, not a security test suite for PackTrace.

## 3. Confirmed observations

Case IDs identify entries in the committed
[observations](../probes/scalibr-inventory/evidence/observations.json).
Raw logs are preserved by filename within
[raw-runs.json](../probes/scalibr-inventory/evidence/raw-runs.json).

| Area / cases | Observed behavior | Design implication |
| --- | --- | --- |
| npm formats: A01 | Synthetic v1 nested dependencies and v2/v3 package maps yielded identities | Useful extraction candidates, not producer-version certification |
| Shrinkwrap: A02 | Existing shrinkwrap caused package-lock extraction to return no packages; direct shrinkwrap yielded identity | Select and record effective files explicitly; do not conflate skipped and empty |
| Unreadable shrinkwrap: `a02-unreadable-shrinkwrap` | Injected Open permission failure did not prevent package-lock identities being returned | Caller must distinguish not-found from access failure before applying precedence |
| Selection failures: A03 | FileRequired returned false after injected Stat denial; direct extraction still worked | A boolean selector cannot replace coverage diagnostics |
| npm duplicates: A04 | Three locked entries became two identity records; two same-version physical positions collapsed | Preserve per-entry and physical instances outside this projection |
| Registry classification: `a05-private-npm` | `https://private.invalid/npm/a.tgz` produced `PUBLIC_REGISTRY` | Do not use upstream classification as public-fetch authorization |
| Workspaces: A06 | Lock identities and root manifest identity were available, but structured ownership/link/declaration information was incomplete | Preserve workspace and dependency-group evidence separately |
| Optional/bundled groups: A07 | Some dependency flags survive; platform/peer context and actual installation are not established | Keep expected absence and incomplete evidence separate from threats |
| Digests/source conflicts: A08 | Raw reference digests and resolved URLs were absent from emitted records; repeated identity conflicts collapsed | Mandatory supplementary raw-field provenance for integrity/reference work |
| Bun versions/configuration: A09 | All six authored combinations parsed identities | This does not establish grammar, configVersion, workspace, catalog, or override semantics |
| Bun identity/source variants: A10 | Tuple identities were projected; URL/file versions could be empty and workspace tokens could survive as version text | Do not treat all output versions as valid registry versions |
| Unsupported versions: A11 | Bun -1/999 and npm 999 yielded identities | Explicit version allowlisting is needed before these extractors |
| Partial extraction: `a11-partial` | One valid package was returned together with an empty-tuple error | Retain both partial findings/inventory and incomplete coverage |
| Missing/filtered manifests: A12 | Missing name/version, literal null, VSCode/Unity-shaped manifests could produce empty output without an error | A separately observed manifest cannot silently disappear from coverage |
| Version inference: A13 | With include-dependencies enabled, `^1.0.0` yielded synthetic version `1.0.0` despite no installed package | Disable the mode for installed/locked inventory |
| Installed-shaped trees: A14 | Explicitly enumerated manifests retained separate observed paths, including duplicate identities and unreferenced store-shaped content | Shows manifest projection only; discovery and active dependency resolution are untested |
| Native containment: A15 | In-root links opened; absolute/relative escapes were denied; cycle/dangling links errored; Linux case-distinct names remained distinct | Useful os.Root evidence on this host, not Windows junction or mount/device containment proof |
| Cancellation: A16 | All three extractors returned identities with an already-canceled context | Calling Extract with a context alone is not a cancellation guarantee |
| Size budgets: A16 | npm FileRequired rejected the oversized reported size, but direct Extract still ran; Bun accepted it | Enforce real reader/byte budgets before invocation |
| Live-file instability: `a16-changing-file` | Controlled external mutation produced versions 1.0.0 and 2.0.0 and an explicit unstable result | Before/after evidence can disclose this change; it is not an immutable snapshot or race-proof design |
| Native permission: `a03-native-permission` | Mode-000 synthetic manifest could not be opened; explicit error returned without elevation | Preserve access failure; do not substitute empty inventory |
| Filename selection: A18 | Corrected unsupported filenames, hidden npm lockfile and nested lockfile were rejected by FileRequired | Product discovery must explain unsupported/skipped inputs; direct Extract was intentionally exercised separately |

### Reproduced upstream panics

These are local evaluation observations, not published advisories or claims of
remote exploitability. No disclosure or upstream issue was published.

1. `a05-bad-alias`: npm v1 dependency version `npm:bad` caused a slice-bounds panic
   in alias handling.
2. `a11-null`: literal `null` Bun lockfile caused a nil-pointer panic.
3. `a12-null-person`: a named/versioned manifest with `maintainers: [null]` caused
   a nil-pointer panic in person filtering.

The containing child exited with status 2 in each case. The runner retained stack
traces and continued with other isolated cases; it did not call a recovered crash
successful validation.

## 4. Optional graph component: blocked, not validated

The default graph build failed at:

```text
google.golang.org/grpc@v1.81.0/internal/transport/handler_server.go:271:18:
undefined: http2.TrailerPrefix
```

Source inspection explained the local combination: x/net v0.54.0's legacy
`http2/server.go` defines that constant but excludes the file under Go 1.27
without the `http2legacy` tag. The pinned gRPC code still references it.

No source patch, dependency upgrade, legacy tag, or alternate toolchain was used.
This blocks graph evaluation on the observed toolchain; it does not establish
failure on Go 1.26.3 or another supported toolchain. A later explicit decision is
needed before changing the evaluation pin or toolchain.

The source-review concern remains: a constraint solver can emit all matching
versions rather than observed physical resolution edges. The proposed ambiguous
and missing-dependency graph cases are **NOT RUN**, not experimentally confirmed.

## 5. Measured footprint and costs

Machine-readable values:
[summary.json](../probes/scalibr-inventory/evidence/summary.json).

| Measurement | Result | Interpretation |
| --- | --- | --- |
| Selected module graph entries | 244 including the probe module | Not 244 linked modules |
| Extractor import graph | 419 packages across 42 non-main modules | Includes standard packages and probe support code; not a production binary estimate |
| Graph import graph | 525 packages across 49 non-main modules | Import discovery succeeded, but compilation failed |
| Extractor binary | 17,970,494 bytes (about 17.14 MiB) | Unstripped, trimpath probe with its synthetic-input support |
| Graph binary | Not produced | No size/performance claim |
| Isolated module-cache file bytes | 1,021,598,412 (about 974.27 MiB) | Both probe surfaces and preparation data; not measured network-transfer bytes |
| Final 73 case wrapper times, summed | 22.338 seconds | Includes service startup and polling; not project scan runtime |
| Reported service runtimes, summed | About 1.454 seconds | Rounded service telemetry for tiny synthetic cases, not a benchmark guarantee |
| Largest case cgroup MemoryPeak | About 21.6 MiB | Includes the sandbox/cgroup; not isolated-process peak RSS |

This footprint is materially larger than the three parser source files suggest.
The actual extractor import graph includes filesystem/image and Git-related
packages through shared SCALIBR infrastructure. Review this cost before making
SCALIBR a production dependency; do not equate advertised modularity with a small
linked surface. The module cache remains local; it was not committed or deleted.

No pilot runtime/memory target or production binary-size promise is established
by these small fixtures. No throughput benchmark against real projects was run.

### Licensing

SCALIBR's root license is Apache-2.0. Root license/notice files were found and
hashed for all 42 modules in the extractor import graph; see
[dependency-license-inventory.json](../probes/scalibr-inventory/evidence/dependency-license-inventory.json).

That is a file inventory, not full license classification, per-file notice review,
legal clearance, or a redistribution audit. Binary symbol retention and applicable
notice obligations still require review before a production release. No upstream
fixture packages were copied; inputs are authored synthetic data.

## 6. Harness corrections and retained failure evidence

The evaluation deliberately retained failures rather than converting them into
successful checks:

- **CA bundle mount:** initial preparation failed TLS certificate verification
  because the mounted certificate directory contained links to an unmounted
  distribution CA bundle. Mounted the existing bundle read-only; TLS verification
  stayed enabled. The initial error is retained.
- **Offline module metadata:** `go mod tidy` did not populate every module `.info`
  needed for offline `go list -m all`. Added metadata acquisition to the explicitly
  online preparation stage, then reran the listing offline successfully. No
  scanner network fallback was added.
- **Optional graph compilation:** retained the default full-suite/build failure
  and recorded the affected cases as blocked; no compatibility workaround applied.
- **Filename fixture construction:** five A18 cases initially forgot to pass the
  intended path to the fixture builder. A failing regression check exposed the
  incorrect paths, the builder was corrected, and all 73 executable cases were
  rerun. Initial observations/input records remain in raw evidence. Expectations
  were not rewritten to accept the wrong paths.

Repeat runs use distinct native target/control paths and preserve earlier logs.
A run refusing to overwrite an existing fixture is not a scanner failure. Hard
safety limits and errors remain distinct from source-behavior expectations.

## 7. Adoption recommendation by component

| Component | Recommendation | Required before production use |
| --- | --- | --- |
| npm lockfile extractor | **Conditional reuse with supplementation**, not authoritative inventory | Preserve entry keys, links, digests, URLs, workspace/group evidence; explicit effective-file/version selection; malformed-input protection and bounded reads |
| Manifest extractor | **Conditional reuse for identity observations only** | Disable inferred dependencies; preserve filtered/missing manifests and all declarations separately; avoid unnecessary person metadata; protect malformed arrays |
| Bun extractor | **Do not adopt its output as the normalized model; prefer an upstream field-preserving extension or narrowly owned JSONC projection** | Retain tuple/source/digest/workspace/config semantics and version validation; compare maintenance/footprint against double parsing in the approved design |
| Offline nodemodules enricher | **Exclude from the initial production design** | First resolve its toolchain compatibility in an approved evaluation; separately prove physical-edge semantics rather than range candidates |
| SCALIBR complete scanner / plugin registries | **Not evaluated or selected** | Do not enable unrelated plugins or capabilities by importing a broad registry |

The Bun recommendation is now based on demonstrated information loss and input
behavior, not an assumption that custom parsing is better. No custom Bun parser
has been implemented. The final dependency decision belongs in the design review:
these conditional recommendations are not automatic adoption authorization.

## 8. Coverage still missing

- Actual npm/Bun-generated fixtures and exact producer-version compatibility.
- macOS and Windows execution, Windows junctions/case behavior, and runner support.
- A production discovery/walker implementation and safe reconciliation of declared,
  locked, and observed-installed package instances.
- Real workspace glob semantics, full peer resolution, external-store scope rules,
  and npm 12 semantics (still deferred by the approved baseline).
- Optional graph runtime behavior, blocked by the compile failure.
- General race resistance, mount/special-file defenses, hardlink/file-identity
  policy, or safety on a compromised host.
- Advisory matching, full offline/private-data tests for a product, trusted artifact
  validation, integrity comparison, policy, JSON/SARIF contracts, and release checks.
- Full fuzzing, large-scale resource testing, production dependency security review,
  and license clearance.

The wrapper's `usable/gap/blocked` labels are conservative evaluation notes, not
production coverage metrics. Many cases intentionally combine a useful identity
projection with missing required fields. A matching expected panic is still a gap.

## 9. Next approval boundary

Review these recommendations and use them to write the technical design for:

1. The observation/evidence/coverage model and effective-input selection.
2. The minimal SCALIBR adapter or alternative field-preserving handling per format.
3. Filesystem, parser, and worker/resource trust boundaries.
4. The first offline inventory-to-report slice and its runnable acceptance checks.

Then review the detailed implementation plan and explicitly authorize production
implementation. Separate authorization is needed for package-manager-generated
fixtures, additional native runners, or changes to the graph evaluation baseline.
The probe has stopped at this report; it has not become product code.
