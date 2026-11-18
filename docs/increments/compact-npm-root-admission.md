# Compact npm root admission

Implemented on base `e8c96045`, without increasing existing allowances.

`npm-root-original` transports original raw inputs, native receipt primitives
(source ID, physical location, native method, receipt SHA-256), and selection.
Each input, receipt and selection consumes a private row; serialized bytes consume
the existing shared private byte budget. Integrity witnesses consume those same
budgets. No semantic model is bundled into a free row, no public field grants
private authority, and no compressed model is transported.

Both endpoints reparse with the existing strict manifest/lock parsers and collector
projections. The worker selects this profile only after exact legacy private-model
round-trip equality. The parent independently reconstructs, validates receipt-bound
originals, and joins the unchanged bounded public inventory using
`PortableMatching`/`ValidateOriginalClaims`. Scope/record/catalog validation remains
unchanged. Receipt consistency still has the existing native child-acquisition
boundary, not filesystem or publisher authentication.

The profile is deliberately limited to successful root-only flat registry npm
acquisitions: at most 1,024 installed instances, 512 KiB original bytes, 4,096
cumulative projected requirements, 4,096 observations, and 8,192 reconstructed
graph rows. Existing parser, public-row, frame, traffic and private budgets still
apply independently; these lower reconstruction bounds do not promise admission
of every 1,024-instance acquisition plus its witnesses. Unsupported acquisitions
use the unchanged bounded legacy path.

## Measured production milestones

Evidence directory:
`/home/justcharles/.local/state/packtrace/advisory-completeness-RIKjKdJf/scale-fix/compact-npm-production-TQXxevih`

* Same frozen 1,000-package metadata target: actual supervised parent admission
  of 1,002 original inputs, 360,229 raw bytes, 3,006 private rows, 898,063 private
  bytes, and 7,004 reconstructed graph rows. No payload comparison claimed by
  this metadata-only test. The legacy 6,006-row envelope remains refused.
* Normal tests exercise actual supervised one-package compact comparisons in
  portable/local CLI modes (equality and drift), as well as legacy fallback.
  Missing originals/scope receipts withhold completion; missing/swapped native
  receipts fail parent admission. Shared private row/byte ceilings are tested.
* Exact 1,000 **tiny-payload** CLI: 1,000 comparisons, zero findings, completed
  inventory, whole-installed integrity, reference authority and reference
  comparison. Exit remains 3 for independent native/lifecycle qualification.
  This is not the 1-GiB workload, a native campaign or performance qualification.
* The first CLI replay of the older frozen archives retained 1,000
  `reference-unusable` gaps (10-KiB tar padding). The successful tiny-payload run
  uses newly authored fixtures from the existing strict-USTAR fixture generator,
  with newly bound original lock SRI and policy pin; it does not relabel those old
  archives as valid. Both results are retained.

`targeted.log`, `root-tests.log`, `vet.log`, `affected-race.log` and their `.exit`
files retain actual checks. `final-supervised-race.log` additionally preserves
failed 1,000-package race-instrumented metadata/CLI replays: the unchanged 100 ms
resident-sampling guard reported stale observations. Small compact-path race
cases passed; the scale success is a non-race production claim, not a passing
race-scale or global/native qualification claim. The initial capacity invocation's exclusive-create
fixture collision is retained in `legacy-and-policy-capacity.log`; the fresh
fixture replay passed in `legacy-and-policy-capacity-recheck.log`.
`freeze.txt` identifies the immutable commit and final recheck artifacts.

Opt-in tests: `PACKTRACE_COMPACT_NPM_FIXTURE` points to the frozen metadata corpus;
`PACKTRACE_COMPACT_NPM_CLI` points to the fresh tiny corpus containing
`checked-1000/prepared/compact-policy.json`. Run through the authorized offline
`scale-fix/go.sh` wrapper. Regular tests require neither corpus.
