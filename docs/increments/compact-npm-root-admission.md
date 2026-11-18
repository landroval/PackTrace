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

## Review follow-up on `08f1c8f9`

External, separately checksummed evidence:
`/home/justcharles/.local/state/packtrace/advisory-completeness-RIKjKdJf/scale-fix/compact-review-iCJGJbdt`

This follow-up changes diagnostics and tests, **not admission**. The 100 ms
samplers, 350 ms freshness checks, source/physical/private bindings, reconstruction
validation, and all existing limits remain unchanged. No hostile-child or
publisher-authentication claim is added. Independent parent-owned acquisition or
attestation would be separate work, not an inference from matching receipts.

### First stale transition: qualified blocker, not a passing race run

Caller-owned `ScanFault` now retains the first guard label, observed sample gap,
and bounded current protocol-operation label/duration. `ScanReceipt` additionally
retains maximum lifecycle sampling mutex wait and native-query time. No raw child
labels, paths, payloads or errors enter these diagnostics or public reports.
Deterministic tests retain first-fault identity and verify that stale samples still
fail. The existing private-lifetime stage vocabulary includes the new fixed labels.

The authorized exact scale replay with `-race -p 1` still fails closed. In
`final-serial-scale-race.log`, metadata first fails in `scanMonitor.own`'s
`time.Since(m.last) > 350*time.Millisecond` branch (`protocol-own-gap`, approximately
402 ms, operation `receive`), while lifecycle maximum gap is approximately 100 ms,
maximum mutex wait 2.4 microseconds, and maximum query time 4.5 ms. CLI first fails
in `scanMonitor.sample`'s same freshness branch (`protocol-sample-gap`, approximately
385 ms), while lifecycle maximum gap is approximately 101 ms. Earlier diagnostic
replays also caught the CLI while processing `policy`. These are fresh runs, not
retroactive proof of which check fired in the old log.

Serializing package test execution did not remove the failure. The protocol
monitor measures receipt of worker self-samples, whereas the lifecycle samples
retained processes independently. Worker samples and semantic messages share one
serialized pipe (`scanSender.send`); `channel.receive`, typed decoding, and parent
validation precede the next sample's admission. A `receive` interval alone does
not distinguish child work, pipe blocking and envelope parsing. There is no
measured lifecycle lock contention that justifies a scheduling patch here.
Bounded message fragmentation/validation scheduling would need a separate
protocol change with equivalent reconstruction and accounting. Merely refreshing
`m.last` on semantic traffic, accepting late samples, or enlarging the threshold
would hide the evidence gap and was not done. Race-scale qualification is open.

### Actual multi-file production scope and boundaries

`replay.py` authored **new synthetic** strict-USTAR archives, preserved registry
source identities, bound the actual compressed SRI into each lock and policy,
and pinned each policy. `verify.py`, a separate Python stdlib reader, replayed
all archive members against installed bytes, verified SRI/lock joins and policy
pins, and asserted saved comparison outcomes. Old frozen padded archives and
new tiny archives remain separate; neither is relabeled by these results.

| Owned supervised CLI case | Measured outcome (all exit 3) |
| --- | --- |
| 1,000 packages, eight files/package | 8,000 equal entries, zero findings; inventory, whole-installed integrity and reference comparison completed |
| Same corpus, one changed JS file | 7,999 equal entries and exactly one modified entry/finding |
| 1,022 packages plus witnesses | Whole-installed integrity completed; 8,176 equal entries |
| 1,023 packages plus witnesses | Comparisons completed but whole-installed integrity **incomplete** |
| 1,000 packages, 4,174-byte manifests | Comparisons completed but whole-installed integrity **incomplete** |
| 1,000 root packages plus nested install | Whole-installed integrity/reference comparison **incomplete**; `ownership-ambiguous` gap retained |
| 1,000 root packages plus linked workspace | Inventory and whole-installed integrity **incomplete** |

The 1,000-package multi-file corpus has 426,212 raw original bytes, 12,627,000
installed payload bytes and 20,480,000 expanded archive bytes. Contents include
manifest, JS entry point, nested JS module, type declarations, README, license,
binary data and executable script. These are representative file *kinds*, not a
representative registry sample or general npm-shape support.

The witness row boundary is unchanged: compact primitives cost `3*N+6` rows;
adding one witness per instance costs `4*N+6`. Thus 1,022 needs 4,094 rows, while
1,023 needs 4,098, exceeding 4,096. `retainIntegrityScope` abstains rather than
exempting witnesses from the budget. The larger-manifest corpus has 4,490,212 raw
original bytes, beyond the 512-KiB compact profile; the unchanged bounded legacy
fallback cannot grant original admission. Nested/workspace shapes also retain
fallback and their incomplete outcomes. Completed payload comparisons alone do
not imply successful private original/scope admission. The reports expose
incomplete coverage, not a new public capacity-reason classification.

`TestOfflineCompactNPMBoundaryCLI`, opt-in with
`PACKTRACE_COMPACT_NPM_BOUNDARIES=<evidence>/fixtures`, asserts these six bounded
coverage outcomes against real supervised CLI children and checks target
immutability. The independent drift run is retained externally. The initial
boundary test attempt hit its existing **test helper's** 20-second timeout; the
measured standalone cases took about 31 seconds. Only this opt-in test's process
timeout is now 90 seconds; product deadlines/guards are unchanged. Initial
failures and successful retry logs are retained. The metadata fixture must use
the old frozen metadata corpus, not the fresh payload corpus: an initial wrong
corpus/toolchain replay and a non-executable wrapper invocation also remain in
the evidence, not silently discarded.

Root tests, vet, small affected races, opt-in supervised boundaries, and the
non-race exact metadata/tiny replays were rerun. Consult `.exit` files, including
failing race-scale replays, rather than inferring success from this document.
No 1-GiB/performance/native campaign was run. Independent native qualification,
resident qualification and applicable malicious/vulnerability checks remain
uncompleted; successful reports still say so and exit 3. This is improved
bounded production evidence, **not full transport qualification**. `freeze.txt`
in the external evidence identifies the final detached head and clean child.
