# SCALIBR inventory probe A

Isolated, disposable evaluation code. **Not a PackTrace implementation or a
scanner for arbitrary projects.** Approved scope and safety limits:
[docs/inventory-compatibility.md](../../docs/inventory-compatibility.md).

## Scope

- SCALIBR v0.5.3, pinned in this module and `go.sum`.
- Synthetic data only, authored by `make_fixtures.py`; no npm/Bun execution,
  installed target dependencies, downloaded package artifacts, or real projects.
- Three individual extractors; graph enrichment compiled separately.
- Linux-only runner using bubblewrap and transient systemd user services.
- Each case runs in its own child with no network route, no host home mount,
  a 5-second service deadline, MemoryMax=512 MiB, MemorySwapMax=0, and no capabilities.
- Fixture trees are mounted read-only. The changing-file case deliberately uses
  an outside fixture controller to mutate its own synthetic target, with a
  before/after handshake. It is not a claim of race resistance.
- The module/build caches and generated logs/binaries stay local and are ignored
  by version control. Native trees are never silently deleted or overwritten.

## How to reproduce (Nushell)

Requires an already installed Go toolchain >=1.26.3, Python 3, bubblewrap, and a
working systemd user manager with memory-controller delegation. No automatic
installation or global configuration changes. Do not run as root.

```nu
cd probes/scalibr-inventory
python3 make_fixtures.py
python3 run.py prepare
python3 run.py build
python3 run.py cases
python3 run.py verify
python3 collect_evidence.py
```

`prepare` is the **only online stage**. It downloads pinned public Go modules and
module metadata through the Go proxy/checksum infrastructure, with direct VCS
fallback disabled. It mounts the existing system CA bundle read-only; TLS checks
are never disabled. It does not run dependency tests or generators.

`build` and `verify` run under OS-enforced network isolation. `cases` executes only
the built probe against the authored corpus. Inputs rejected by FileRequired are
still deliberately passed to Extract, with the distinction recorded.

The initial `red` mode was run against an unimplemented observation function to
verify that the four evidence-capture tests failed for the intended reason. It
is an initial development check, not part of subsequent reproduction.

### Known blocked surface

The pinned optional graph command fails to compile with the observed Go 1.27.1
host: gRPC v1.81.0 references `http2.TrailerPrefix`, which is excluded by the
Go-1.27-selected x/net v0.54.0 sources. The original whole-module test failure is
retained. No dependency upgrades, source patches, legacy build tags, or toolchain
downloads are applied to hide it.

The runner verifies the independent extractor package and command, and records
the graph build failure. Graph cases are marked `blocked-build` / NOT RUN. An
extractor-only test pass is not a passing `go test ./...` result.

### Results and interpretation

- `testdata/cases.json`: independent input and source-review expectation table.
- `results/*.stdout`, `*.stderr`, `*.process.json`: raw outputs, failures,
  deadlines, return codes, measured service runtime/memory, and command details.
- `results/observations.json`: case outcomes, deviations from initial hypotheses,
  known limitations, and before/after native tree hashes.
- `results/graph-build-blocker.json`: exact command and logs for the optional build.

Expected outcomes describe hypotheses about upstream behavior, **not** acceptable
product behavior. A reproduced panic or unsupported-version acceptance is a gap
rather than a pass. Expectation deviations require review; do not rewrite the
expectations merely to make them agree. Random map iteration can choose which
collapsed npm entry supplies a location; do not infer deterministic attribution.

The harness labels predeclared source-review limitations conservatively. Manual
review must distinguish executed observations from untested claims in those
labels. The case harness finishing is not evidence of production compatibility,
correct package-manager discovery, all-platform support, or safety of a project.

Changing evidence, blocked checks, and all-package compile failures remain
visible in the [evaluation report](../../docs/inventory-evaluation-results.md).
`collect_evidence.py` writes the bounded committed `evidence/` bundle: final
observations, exact raw logs keyed by their original filenames, initial failure
history, selected imports/modules, root-license file hashes, and measurements.
`SHA256SUMS.json` detects changes to those files; it is not independent authentication.

All executable cases were rerun after a fixture-builder filename bug was fixed.
The source-review expectations were retained, and `test_fixtures.py` now checks
those paths and corpus budgets. `cases --group A18` can repeat only that group;
full native reruns allocate new synthetic target/control paths, without deletion.

## Footprint and licenses

The module graph/download cache is not the linked binary dependency set. Measure
these separately using captured `go list`, `go version -m`, binary sizes, and
systemd memory reports. Service MemoryPeak includes the transient cgroup and is
not an exact isolated-process RSS statistic.

SCALIBR's license is Apache-2.0. Fixtures are authored synthetic data, not copied
upstream packages. Selected dependency-license files must be inventoried before
production adoption; this probe does not certify redistribution compliance.

## Limitations

No actual package-manager-generated installed tree, macOS/Windows execution,
production discovery walk, advisory matching, reference authentication, or
integrity comparison is implemented here. Do not promote this code into production
without an approved design and implementation plan.
