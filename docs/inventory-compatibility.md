# Inventory compatibility and SCALIBR evaluation

**Status:** package-manager evaluation baseline and probe A approved, including
pinned public Go dependency downloads and isolated local Linux execution.
Production implementation and later qualification remain unapproved.
**Research date:** 2026-09-26 (UTC).
**Extractor runtime evidence:** probe A now has a
[results report](inventory-evaluation-results.md): 73 synthetic Linux cases
executed, three upstream panics reproduced, and two optional graph cases blocked
by compilation. Four extractor-harness Go tests and two fixture tests passed;
the whole-module Go suite did not pass because the graph command does not build.
No actual npm/Bun producer compatibility or macOS/Windows support is validated.
The proposal below is preserved as the approved scope, not as an execution log.

Related: [roadmap](development-roadmap.md),
[guidelines](development-guidelines.md),
[pre-1.0 checklist](pre-1.0-features.md).

## 1. Recommendation

Evaluate individual SCALIBR extractors, not its complete scanner, behind a small
PackTrace-owned observation boundary. Its npm, Bun, and manifest extractors are
useful candidates, but their source shows they cannot alone supply the required
inventory, provenance, and relationship model.

First run an explicitly approved, isolated synthetic-fixture probe. Use the result
to choose which extractors to retain and the smallest supplementary handling.
Do not build production adapters or custom lockfile parsers during this probe.

Alternatives:

1. **Selective reuse plus narrow supplements — recommended.** Reuse demonstrated
   extraction behavior; retain raw evidence needed for physical instances,
   source URLs, digests, workspaces, and truthful coverage. Costs include adapter
   maintenance and potentially parsing selected fields twice.
2. **Upstream improvements first.** Propose missing fields/diagnostics upstream
   after confirming gaps. Reduces long-term duplication but makes delivery depend
   on upstream acceptance and release timing. Do not block the pilot indefinitely.
3. **Owned parsing for an unsuitable extractor.** Use only when the measured
   gaps or footprint make reuse more complex or less trustworthy than a narrow
   maintained implementation. This is not a license to replace all extractors.

The design must permit mixed outcomes: npm reuse may be worthwhile even if Bun
requires different handling. Public Go APIs and plugin frameworks are unnecessary.

## 2. Source baseline and important compatibility changes

### Evaluation pin

Evaluate `github.com/google/osv-scalibr v0.5.3`, whose tag resolved during this
review to commit `c421bee3c558c457b7b3c891d3200d1f910d93c4` [S1]. Its `go.mod`
declares `go 1.26.3` [S8]. That is a candidate dependency/toolchain constraint,
not an approved PackTrace toolchain selection or an installed local toolchain.

Record the module checksum and resolved commit during an approved download.
A tag/commit pin and checksum aid reproducibility; neither authenticates the
benignness of the code. Do not substitute `main` or `latest` during evaluation.

### Version-dependent npm semantics

The npm 11.6.2 documentation says `npm-shrinkwrap.json` takes precedence over
`package-lock.json` [N1]. The npm 12.1.0 documentation says npm no longer reads or
writes shrinkwrap files [N2]. Its Arborist implementation defaults to lockfile v3
but writes v4 for patch/manifest-extension state [N3].

Therefore, unconditional shrinkwrap precedence is not correct for all current
npm versions. The original requirement is retained for the proposed npm 8–11
baseline. npm 12 is a separate compatibility decision, not silently treated as
npm 11. A lockfile v3 alone cannot identify which npm major produced/used it.

A declared `packageManager` version is target-supplied evidence, not independent
proof. If conflicting lockfiles and unknown manager semantics make selection
ambiguous, report the ambiguity and require explicit manager selection in the
future design; do not invent an effective dependency tree.

### Bun format and layout changes

Text `bun.lock` became the default in Bun 1.2 [B1]. Bun's current docs distinguish
`configVersion` from `lockfileVersion`: configuration defaults can change the
installed layout without changing the package identities [B2].

The Bun 1.4.2 source enumerates text lockfile versions 0–3. Version 2 tightens
integrity/path checks; version 3 represents scoped/nested override forms [B3].
Do not infer supported grammar merely because SCALIBR can deserialize the outer
JSON. No Bun parser or installed-layout case has been executed here.

Bun isolated installs use an in-project `.bun` store with links and peer-context
variants. Current documentation also describes an opt-in external global virtual
store and leftover unreferenced store entries [B2]. Outside-root stores and
unreferenced content need explicit classification, not blind traversal or proof
that a dependency is active.

## 3. Approved evaluation baseline and proposed qualification

The user approved the npm 8/10/11 and Bun 1.3.2/1.4.2 evaluation baseline, with
npm 12 deferred. Native qualification targets remain proposed. All rows below
are **planned or explicitly limited**, not validated. Exact
producer versions are test anchors, not a blanket promise for every release in a
major family. Production support claims require fixtures generated by the named
producer and actual scanner execution on each supported platform.

### Package managers and lockfiles

| Test anchor / input | Lockfile | Workspace / installed-layout target | Proposed disposition |
| --- | --- | --- | --- |
| npm 8.19.4 | v2; package-lock or shrinkwrap | Single project; workspaces; hoisted tree with nested version conflicts | Baseline candidate; shrinkwrap precedence |
| npm 10.9.4 | v3; package-lock or shrinkwrap | Same, including workspace links | Baseline candidate; shrinkwrap precedence |
| npm 11.6.2 | v3; package-lock or shrinkwrap | Same, including workspace links | Baseline candidate; shrinkwrap precedence |
| npm 5/6-shaped synthetic input | v1 | Nested dependency records; no workspace support claim | Evaluate extractor behavior; defer full pilot support unless needed |
| npm 12.1.0 | v3/v4 | Changed shrinkwrap and patch/extension semantics | Detect and report unsupported semantics initially; add only after an explicit scope decision |
| Bun 1.3.2 | Text versions 0/1 as encountered; config absent/0/1 | Single project and workspaces; hoisted and in-project isolated layout | Baseline candidate; verify actual generated version rather than assume it |
| Bun 1.4.2 | Text versions 0/1/2/3 as encountered | Same; catalog/override metadata and peer-context variants | Baseline candidate; test each claimed format explicitly |
| Any known manager with only manifests/installed content | No effective lockfile | Bounded installed discovery | Preserve observed inventory; lock-based checks incomplete, not installation reconstruction |
| npm nested/shallow strategies or linked store | Any | Beyond baseline layout | Detect; no complete relationship/layout claim until qualified |
| Bun opt-in external global store | Text | Links leaving selected project root | Record link and boundary gap; do not follow outside-root targets by default |
| pnpm, Yarn, binary bun.lockb, unknown versions | Any | Any | Explicitly unsupported; no conversion or install |

Selecting these anchors does not require installing or running them in probe A.
Their generated-fixture qualification is a later, separately approved activity.

### Workspace structures and observation rules

- Baseline targets: one root project, explicit relative workspace paths, and
  `packages/*` / `apps/*` patterns; workspace-to-workspace links within the root.
- Treat nested independent projects as separate project scopes, not implicit
  members of the root workspace. Mixed npm/Bun roots require explicit selection
  or separately reported scopes; never merge incompatible resolutions.
- Unsupported glob forms, overlapping/nested workspace ownership, and escaping
  workspace paths must remain explicit coverage/attribution gaps until tested.
- Inspect nested package locations rather than relying only on top-level
  `node_modules`. The hidden npm `.package-lock.json` is mutable layout evidence,
  not proof of installed contents or a replacement for observation.
- Include extra physically observed packages even if absent from the effective
  lockfile. Distinguish linked instances, materialized package content, and
  unreferenced store content. Presence does not establish runtime use.
- Observe bundled packages where present, retain their parent artifact context,
  and do not invent a separate registry artifact for them.
- Represent local directories, local tarballs, Git references, arbitrary URL
  sources, and workspace links without fetching or executing them. Unknown
  version/source fields remain unknown.

### Native execution targets

Proposed pilot qualification targets: Linux Ubuntu 24.04 amd64, macOS 15 arm64,
and Windows Server 2022 amd64. Record actual runner image, filesystem, toolchain,
and architecture per run. These are proposed test environments, not asserted
minimum OS requirements or promised support for untested architectures.

Probe A initially runs only on the current Linux host if authorized. macOS and
Windows remain not run until native runners are explicitly available/authorized.
Windows link-creation restrictions must be recorded; a skipped symlink test is
not evidence of Windows link support. Do not elevate privileges to make it pass.

## 4. Required observation contract

This is a conceptual boundary, not production Go type definitions.

| Observation | Required information | Rules |
| --- | --- | --- |
| Declaration | Manifest path, workspace, dependency key/alias, original spec, dependency group | A range is not an installed or resolved version |
| Locked resolution | Effective lockfile and entry locator, name/version/source, digest and algorithm, groups, links, available edges | A lockfile is project-supplied evidence, not installation proof |
| Installed instance | Observed manifest and content location, link target within scope, claimed name/version, observation method | Preserve duplicate physical instances and manifest uncertainty |
| Relationship | From/to observation IDs, relationship kind, supporting entry/path, ambiguity | Candidate range matches are not actual resolution edges |
| Evidence | Source file locator, bounded-byte digest, extractor/version, observation time, errors/conflicts | Keep original evidence provenance; do not leak unrelated metadata |
| Coverage | Attempted/completed/unsupported/incomplete/excluded outcome, reason, affected scope | Empty output does not imply a successful empty inventory |

Reconciliation links observations without replacing conflicting values. Missing
optional packages can be expected absences; missing evidence must not become a
malware conclusion. Advisory matching and integrity checks consume these distinct
observations later; they are outside the first probe.

## 5. Verified source observations and gaps

“Verified” here means inspected source at the pinned revision, not runtime tests.

| Area | Source observation | PackTrace consequence |
| --- | --- | --- |
| Extractor API | `New(*config_go_proto.PluginConfig)` returns `(filesystem.Extractor, error)`; `FileRequired(FileAPI) bool`; `Extract(context.Context, *ScanInput) (inventory.Inventory, error)` [S2–S5] | Individual extractors can be called without the full scanner; preserve output and error independently |
| File input | `ScanInput` has rooted `FS`, relative `Path`, `Root`, `Info`, and `Reader`; SCALIBR FS includes Open/ReadDir/Stat and documents ReaderAt for opened files [S5, S9] | Own scope selection, bounded readers, handle lifetime, and filesystem containment |
| npm precedence | `extractPkgLock` skips package-lock if opening sibling shrinkwrap succeeds; other open errors do not establish why it failed [S2] | Preflight effective-file selection and permission failures; do not turn unreadable shrinkwrap into fallback success |
| npm instances | `npmPackageDetailsMap` merges by name/version or commit; root and `link` records are skipped [S2] | Output alone loses repeated locked instances and workspace/link structure |
| npm source/digest | Output keeps coarse source category and Git information, but not raw resolved URLs/integrity; internal lockfile structs omit integrity [S2, S6] | Supplementary field preservation is a demonstrated gap; internal structs are not importable public APIs |
| npm authorization | `DeterminePackageSource` classifies HTTP URLs containing `npm` as public registry [S2] | Never use this value to authorize networking or disclose package names |
| Bun grammar | Uses JSONC conversion plus an unexported struct with version and package tuples; the version is not validated by the extractor [S3] | Explicit supported-version/shape validation is necessary |
| Bun information loss | Reads identity chiefly from tuple element 0; omits workspaces, configVersion, artifact digests, most source/layout data and dependency edges [S3] | Successful identity extraction cannot establish complete Bun inventory |
| Bun failure behavior | Returns joined tuple errors with partial inventory; dereferences the decoded lockfile without a null check [S3] | Test partial results and literal `null`; possible panic is source-indicated, not reproduced |
| Manifest observations | Requires name and version, and filters VSCode/Unity-shaped manifests; extracts regular dependency declarations but not all dependency groups/workspace fields [S4] | Missing/filtered identity must remain visible; root declarations need separate preservation |
| Manifest version inference | Optional include-dependencies mode computes minimum versions from constraints [S4] | Keep this mode disabled for inventory; never use inferred minima as locked or installed versions |
| Graph enrichment | Offline nodemodules enricher uses declaration constraints; solver returns all matching versions/instances and path filtering falls back to all candidates [S10] | Evaluate separately; do not accept ParentIDs as observed Node/Bun resolution paths without evidence |
| Diagnostics/limits | Size checks occur in selected FileRequired implementations; Extract uses ReadAll; Bun constructor ignores supplied config; selected parsing paths do not consult cancellation [S2–S4] | Bound inputs outside the extractors; capture selection skips; cancellation needs a tested boundary |
| Containment | SCALIBR DirFS wraps os.DirFS, which Go documents as not preventing symlink escape [S9, G1] | Do not expose arbitrary targets through it; evaluate os.Root with read-only access and separate special-file/budget safeguards |

Other source-indicated regression cases include malformed npm aliases and null
entries in manifest person arrays. Probe them as inert data; do not present static
inspection as an executed crash reproduction or a published vulnerability claim.

### API stability, footprint, and licensing

- SCALIBR remains a v0 module. Go's version guidance does not give v0 the same
  compatibility expectations as stable v1 APIs [G2]. Keep the revision pinned and
  rerun adapter checks on upgrades; extractor `Version() == 0` is not the module
  release identity.
- The top-level module declares container, database, cloud, protobuf, and many
  other dependencies [S8]. This is not proof they all enter a selective binary.
  Measure resolved module downloads, the selected packages' import graph, build
  time, binary size, and peak memory separately.
- Use separate probe commands for extractors and optional graph enrichment so
  its incremental footprint can be measured. Do not import blanket plugin lists.
- SCALIBR uses Apache-2.0 [S11]. Preserve notices for any copied source/fixtures;
  inspect licenses for the actual transitive graph before adoption. This source
  review is not a completed license audit or a choice of PackTrace's license.
- Its README describes macOS/Windows support as experimental [S12]. None of the
  selected extractors' empty capability requirements proves platform support.

## 6. Probe A proposal — isolated extractor evaluation

### Question and scope

Can the three pinned extractors and optional offline graph enricher contribute
accurate observations with bounded inputs, explicit gaps, and acceptable cost?

Create only an isolated Go module under `probes/scalibr-inventory/` after approval.
No root `go.mod`, production `cmd/` or `internal/` scaffolding, scanner CLI, custom
lockfile implementation, advisory integration, artifact downloads, or CI publishing.

Proposed artifacts inside that module:

- `README.md`, `go.mod`, `go.sum`: scope, pinned dependencies, commands, licensing.
- `probe_test.go` and `testdata/`: explicitly enumerated synthetic cases and
  expected field/diagnostic observations.
- `cmd/extractors/` and `cmd/graph/`: small measurement/observation entry points,
  never product entry points.
- `results/`: fixture hashes, raw observations, errors, gap classification,
  toolchain/OS metadata, build/import measurements, and captured command output.

Place generated synthetic scan trees under a dedicated probe temporary directory.
Caches, output, and logs must be siblings outside those trees. Never point the
probe at an existing user JavaScript project. Do not create an external repository.

### Exact fixture groups

Author minimal inert manifests/lockfiles using names such as
`@packtrace-fixture/a`; never resolve them online. Each case has a checked-in
expected-observation record independent of extractor output. No JavaScript is run.

| Group | Inputs | Required observation / question |
| --- | --- | --- |
| A01 | npm v1 nested dependency map; npm v2 and v3 package maps | Recover identities; record groups, locators, and missing fields separately |
| A02 | package-lock and shrinkwrap with deliberately different names/versions; shrinkwrap-only | Demonstrate selection behavior and provenance for npm <=11 semantics |
| A03 | Synthetic permission error opening shrinkwrap; denied Stat; denied Reader | Record selection/read errors, including silent upstream skips |
| A04 | Same package/version at two nested locations, plus a different version | Quantify upstream deduplication without inventing physical instances |
| A05 | Alias, scoped alias, malformed npm alias, registry URL, private URL containing `npm`, local path/tarball, full and abbreviated Git ref | Retain source uncertainty; expose identity/source classification limitations |
| A06 | Root plus two workspace manifests, workspace link entries, packages/* pattern, shared dependency and nested conflict | Distinguish observed declarations, link records, and missing ownership/edge output |
| A07 | Dev, optional, devOptional, bundled, peer and optional-peer metadata; absent platform-specific package | Distinguish flags and absence; no malware inference |
| A08 | SHA-512/SHA-1 integrity fields, conflicting source/digest for repeated identity, missing integrity | Show exactly which provenance fields are lost; no integrity verification attempted |
| A09 | Bun tuple maps for text versions 0, 1, 2, 3; config absent/0/1; workspace and override/catalog records | Separate deserialization success from complete semantic support |
| A10 | Bun aliases, scoped identities, URL/Git/local/workspace tuples, same identity under different keys | Assess identities, lost resolution/context, duplicate handling |
| A11 | Invalid JSON/JSONC, literal null, wrong field types, empty/non-string Bun tuples, duplicate keys; versions -1/999 | Capture errors, panic or permissive acceptance without claiming validation |
| A12 | Valid manifest, missing name/version, null, VSCode/Unity-shaped manifests, null contributor/maintainer element; all dependency groups | Characterize filtered/partial identity and declaration behavior |
| A13 | Range ^1.0.0 with no installed dependency; include-dependencies off and on | Demonstrate inferred-minimum behavior; ensure result labels never call it installed |
| A14 | Known hoisted and .bun-shaped synthetic installed trees; two same-version locations, peer variants, extra unreferenced store entry | Observe manifests at explicit enumerated locations; no claim of full scanner discovery |
| A15 | In-root link, escaping link to a synthetic sentinel sibling, cycle, dangling link, case-collision and Windows-shaped paths | Evaluate root/reader boundary; never read the sentinel through an escaping link |
| A16 | Reader returning an error mid-read; bounded over-limit input; already-canceled context; synthetic before/after file change | Record incomplete work and cancellation limitations, not false success |
| A17 | Graph input with a parent range matching two installed versions and a missing declared dependency | Determine whether enricher edges are candidates rather than physical resolution |
| A18 | pnpm/Yarn/bun.lockb filenames plus hidden npm lockfile and mixed npm/Bun root | Record individual FileRequired decisions; do not pretend the probe implements product discovery |

The sentinel contains only a synthetic marker; no private file is used. Native
permission/link cases supplement fault-injected FS cases where feasible. Record
unsupported/skipped native cases rather than quietly substituting a simulation.

### API exercise and evidence

For each extractor, call its constructor, FileRequired, and Extract with controlled
inputs. Exercise direct Extract independently so a FileRequired rejection cannot
hide behavior. Keep include-dependencies disabled except the explicit A13 case.

Use an in-memory/fault-injected FS for parser cases. For native link cases,
evaluate `os.OpenRoot`/`Root.FS` via a read-only view satisfying SCALIBR's FS
contract [G1]. Root containment is not a mount/device or whole-host sandbox;
reject special files, use only controlled synthetic trees, and retain a hard
process timeout. This does not validate production filesystem safety.

Run each malformed/cancellation case in a child process. The harness may execute
only its own built Go probe binary, never target scripts or package managers.
Capture panic, timeout, stderr, partial inventory and errors as observations.
A caught panic is a gap, not successful validation.

Output per case: case ID, input hashes, extractor/module version, selection,
observed identities/locations/groups/edges, absent required fields, diagnostics,
process outcome, elapsed time, and an explicit classification of usable / gap /
blocked. Sort output for comparison, retaining raw results separately.

A successful harness run means the evaluation finished; it does not mean every
extractor met PackTrace's requirements. Promote no compatibility row based only
on synthetic deserialization.

### Safety and cost limits

Proposed limits for this probe, not product defaults:

- At most 80 concrete cases across A01–A18; one case worker at a time.
- Normally <=2 MiB per input, <=64 MiB total fixture bytes, <=256 files per tree,
  and <=32 path components. The over-limit case uses a generated bounded reader,
  not a large on-disk allocation.
- 5-second hard child-process deadline per case; 10-minute total test deadline.
- 512 MiB hard child memory cap where the approved environment supports it.
  `GOMEMLIMIT` is supplementary, not a hard RSS cap. Do not run adversarial cases
  where hard isolation is unavailable; report them blocked.
- Preparation/build: 15-minute wall deadline and 2 GiB maximum new module-cache
  storage; stop and request revised approval if exceeded. Record build peak
  memory separately rather than conflating it with scanner runtime.
- Dependency downloads only during an explicitly authorized preparation step,
  using the public Go module proxy/checksum service and required approved backing
  storage. No direct VCS fallback, private modules, or arbitrary target URLs.
- Set `GOTOOLCHAIN=local`; if Go >=1.26.3 is unavailable, stop. No automatic Go,
  npm, Bun, sandbox, or other tooling installation is included.
- No global Go configuration or credentials changes. Use process-local settings,
  isolated module/build caches, and separate writable temporary directories.
- After preparation, run build/tests with networking denied at the OS/sandbox
  boundary. `GOPROXY=off` alone does not prove network denial. If a suitable
  unprivileged boundary is unavailable, stop for a revised execution plan; do not
  change host firewall/security settings or request elevation automatically.
- Fixture directories are read-only during inspection; record before/after hashes.
  Read-only fixtures and synthetic-only access do not prove product read-onlyness.
- No installation of target dependencies, no npm/Bun execution, no external
  project scans, no advisory/artifact fetching, and no publication.

### Proposed command contract

These commands describe the future isolated module. It does not exist yet;
none of these commands has been run. Syntax below is Nushell. Before execution,
set absolute GOMODCACHE/GOCACHE/GOTMPDIR paths to the dedicated probe directories,
verify the local toolchain, and apply the approved sandbox/limits.

Inside `probes/scalibr-inventory`, authorized preparation would use:

```nu
with-env {GOTOOLCHAIN: local, GOWORK: off, GOFLAGS: '', GOPROXY: 'https://proxy.golang.org', GOSUMDB: 'sum.golang.org', GOPRIVATE: '', GONOPROXY: '', GONOSUMDB: '', GOVCS: '*:off'} {
    go mod tidy
    go mod verify
}
```

The module must pin SCALIBR v0.5.3 before this step. Review the resulting module
and checksum graph; do not run dependency tests, generators, or installation hooks.

Under OS-enforced network denial, the evaluation commands would be:

```nu
with-env {GOTOOLCHAIN: local, GOWORK: off, GOPROXY: off, CGO_ENABLED: '0', GOFLAGS: '-mod=readonly'} {
    go list -m -json all
    go list -deps -json ./cmd/extractors
    go list -deps -json ./cmd/graph
    go test -count=1 -timeout=10m -run '^TestProbe' -json .
    go build -trimpath -o results/extractors-probe ./cmd/extractors
    go build -trimpath -o results/graph-probe ./cmd/graph
}
```

Capture outputs and exit statuses separately; stop on command failure. Run
`go version -m` on each built artifact and record binary/cache sizes. Measure
runtime and memory with native runner/sandbox facilities and disclose unavailable
measurements. Do not treat Go heap statistics as peak RSS. These commands are
for local Linux probe A only; native cross-platform qualification needs its own
reviewed runner instructions.

### Probe completion criterion

Produce `docs/inventory-evaluation-results.md` with raw evidence locations,
usable behavior, confirmed gaps, blocked checks, footprint/license observations,
and a retain/supplement/replace recommendation per extractor. Do not silently
patch SCALIBR or write production fallback parsers during the evaluation.

Stop after reporting results. Resolve matrix and trust-boundary decisions and
obtain design/implementation-plan approval before production code.

## 7. Later qualification — not authorized by probe A

Synthetic fixtures cannot establish actual npm/Bun producer compatibility.
A subsequent proposal must specify exact pinned manager/runtime downloads,
reviewed benign fixture manifests, any local registry setup, flags, and isolation
before generating installed trees. No real malicious dependencies are permitted.

Run the final selected fixtures on native Linux, macOS, and Windows, exercising
actual links/junctions, permissions, case handling, hoisted/isolated layouts,
optional platform packages, and workspace ownership. Verify fixtures were not
modified by inspection. Cache/target code must not be executed by the scanner.

Do not publish workflows, spend hosted-runner resources, or install package
managers under the assumption that approving probe A also approves this stage.

## 8. Approval record and remaining gates

- **Approved:** the npm 8/10/11 and Bun 1.3.2/1.4.2 package-manager evaluation
  baseline. npm 12 remains explicitly deferred; do not apply npm <=11 shrinkwrap
  precedence to it as though it were supported.
- **Approved subsequently:** the user lifted the earlier "Do not run yet" hold
  by selecting "Approve with downloads": create and run only probe A with
  pinned public Go dependencies, prerequisite verification, and documented limits.
- **Not authorized:** automatic tooling installation, additional native runners,
  production implementation, package-manager execution, or publication.
- **Development practice:** commit approved changes progressively using `jj`.

Approval covers the documented synthetic inputs, paths, child-process execution,
limits, measurements, and local Linux evaluation. Unavailable toolchain/sandbox
prerequisites remain blockers, not authorization to install tools, elevate
privileges, or claim support.

Probe approval is not approval of production code or later qualification.

## 9. Primary sources

Source/API facts above are distinguished from proposed behavior and unrun checks.
The SCALIBR source links are pinned to the inspected release commit. npm/Bun
release-tag links were read as source; no package-manager code was executed.

- [S1: SCALIBR v0.5.3 commit](https://github.com/google/osv-scalibr/commit/c421bee3c558c457b7b3c891d3200d1f910d93c4)
- [S2: npm extractor](https://github.com/google/osv-scalibr/blob/c421bee3c558c457b7b3c891d3200d1f910d93c4/extractor/filesystem/language/javascript/packagelockjson/packagelockjson.go)
- [S3: Bun extractor](https://github.com/google/osv-scalibr/blob/c421bee3c558c457b7b3c891d3200d1f910d93c4/extractor/filesystem/language/javascript/bunlock/bunlock.go)
- [S4: package.json extractor](https://github.com/google/osv-scalibr/blob/c421bee3c558c457b7b3c891d3200d1f910d93c4/extractor/filesystem/language/javascript/packagejson/packagejson.go)
- [S5: filesystem extractor API](https://github.com/google/osv-scalibr/blob/c421bee3c558c457b7b3c891d3200d1f910d93c4/extractor/filesystem/filesystem.go)
- [S6: internal npm lockfile structures](https://github.com/google/osv-scalibr/blob/c421bee3c558c457b7b3c891d3200d1f910d93c4/internal/dependencyfile/packagelockjson/packagelockjson.go)
- [S7: extracted package/location types](https://github.com/google/osv-scalibr/blob/c421bee3c558c457b7b3c891d3200d1f910d93c4/extractor/extractor.go)
- [S8: SCALIBR go.mod](https://github.com/google/osv-scalibr/blob/c421bee3c558c457b7b3c891d3200d1f910d93c4/go.mod)
- [S9: filesystem implementation](https://github.com/google/osv-scalibr/blob/c421bee3c558c457b7b3c891d3200d1f910d93c4/fs/fs.go)
- [S10: nodemodules enricher](https://github.com/google/osv-scalibr/blob/c421bee3c558c457b7b3c891d3200d1f910d93c4/enricher/transitivedependency/nodemodules/nodemodules.go), [offline solver](https://github.com/google/osv-scalibr/blob/c421bee3c558c457b7b3c891d3200d1f910d93c4/enricher/transitivedependency/internal/offline_solver.go), [edge filtering](https://github.com/google/osv-scalibr/blob/c421bee3c558c457b7b3c891d3200d1f910d93c4/enricher/transitivedependency/internal/offline_enricher.go)
- [S11: SCALIBR license](https://github.com/google/osv-scalibr/blob/c421bee3c558c457b7b3c891d3200d1f910d93c4/LICENSE)
- [S12: SCALIBR platform notes](https://github.com/google/osv-scalibr/blob/c421bee3c558c457b7b3c891d3200d1f910d93c4/README.md)
- [N1: npm 11.6.2 lockfile documentation](https://github.com/npm/cli/blob/v11.6.2/docs/lib/content/configuring-npm/package-lock-json.md)
- [N2: npm 12.1.0 lockfile documentation](https://github.com/npm/cli/blob/v12.1.0/docs/lib/content/configuring-npm/package-lock-json.md)
- [N3: npm 12.1.0 Arborist lockfile implementation](https://github.com/npm/cli/blob/v12.1.0/workspaces/arborist/lib/shrinkwrap.js)
- [B1: Bun lockfile documentation](https://bun.com/docs/pm/lockfile)
- [B2: Bun isolated installs and global store](https://bun.com/docs/pm/isolated-installs)
- [B3: Bun 1.4.2 text-lockfile implementation](https://github.com/oven-sh/bun/blob/bun-v1.4.2/src/install/lockfile/bun.lock.rs)
- [G1: Go os.Root and os.DirFS documentation](https://pkg.go.dev/os#Root)
- [G2: Go module version compatibility](https://go.dev/doc/modules/version-numbers)
