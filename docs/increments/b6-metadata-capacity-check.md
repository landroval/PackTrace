# Frozen B6 metadata/reference capacity check

## Result

**The projected 1,000 distinct npm instances cannot carry the required evidence
under the existing limits at production base `f3270bb8`.** No production change
or limit increase is proposed. This is an offline, bounded feasibility check,
not B6 qualification or a performance/native campaign.

Evidence directory:
`/home/justcharles/.local/state/packtrace/advisory-completeness-RIKjKdJf/scale-fix/metadata-capacity-K80mKcG4`.
`freeze.txt` there records the full final local check revision. `release-fixtures`
and `race-fixtures` contain the successful regular/race checks, source originals,
archives, exact authored manifest, product original receipts, capacity JSON,
small accepted records and reports. Later verification logs name their own
fresh fixture directory. Failed exploratory runs are retained, not overwritten.

The check uses `prepare_corpus.metadata()` unchanged for the original B6 target.
The reference-equipped variant preserves **all** 1,000 distinct names, root
dependencies, locked instances, installed manifests and physical paths. Each gets
its own actual inert USTAR/gzip archive containing its original installed
`package.json`; the real SHA-512 SRI and canonical npm URL are added to the lock
and exact policy reference. Every archive is checked with product
`CheckReferenceDigestSet`, including `DigestMatch` and actual byte count; every
reference is checked against the source lock tuple. No producer, download,
publisher authenticity, intelligence, key, or synthetic trust receipt is used.
The small policy pin is computed from the actual external source and supplied
to product native policy acquisition, not treated as proof by itself.

Only metadata files are materialized: 1,002 target files per 1,000-instance case;
no 48,998 payloads, 1 GiB target, native qualification or timing campaign. The
miniature **does not substitute for the full B6 corpus**. It establishes a
necessary metadata/evidence bound before any full payload could be relevant.

## Actual product results

| Resource | Original B6, 1,000 | Checked references, 2 | Checked references, 1,000 |
| --- | ---: | ---: | ---: |
| Collected inventory complete | yes | yes | yes |
| Raw original bytes | 168,229 | 949 | 360,229 |
| Original input rows | 1,002 | 4 | 1,002 |
| Semantic observations | 3,001 | 7 | 3,001 |
| Evidence rows | 2,003 | 7 | 2,003 |
| Original private rows | **6,006** | 18 | **6,006** |
| Compact private original JSON bytes | 2,435,032 | 7,486 | 2,848,028 |
| Actual policy file bytes (with LF) | 347 | 1,130 | **392,346** |
| Product source policy admitted | yes, no refs | yes | **no** |
| `emitOriginal` sends a frame | no | yes | no |
| Whole integrity result | incomplete | **completed, zero findings** | not reached |

The original B6 lock is 99,149 bytes and has **no** resolved/SRI/reference data.
Its empty reference policy is merely a local diagnostic wrapper. Product
acquisition emits no comparison records and cannot complete whole integrity.
Raw-byte admission is not evidence of reference feasibility or original-frame
admission. The corrected lock is 291,149 bytes; its retained source originals
still fit the 524,288-byte / 4,096-input capture limits and pass
`ValidateOriginalBytes`. Those isolated successes do not override later limits.

### First actual full-flow blocker: policy source admission

`AcquirePolicy` reads at most `MaxPolicyBytes` = **262,144**, and `ParsePolicy`
enforces that limit. The checked 1,000-reference policy is **392,346 bytes**;
`ValidatePolicy` passes semantically, but both real source acquisition and parser
reject it. No rejected policy is used to acquire a plan.

A decisive serialization lower bound for these exact reference tuples is the
compact product-marshaled `references` **array alone: 392,001 bytes**. It already
exceeds 262,144 by **129,857 bytes**, before any policy wrapper. Thus removing
whitespace, shortening prose or removing optional wrapper fields cannot rescue
this fixture without changing required reference evidence or its scope.

The product parser admits the first **667** references in compact Go policy
serialization at **261,809 bytes**, rejects the first **668** at **262,201**.
The authored Python policy has an additional final LF. Prefixes are diagnostics
only: they do **not** qualify a reduced scope, and none replaces the full fixture.
This is an exact bound for these paths/names/URLs/SHA-512 references, not a
universal minimum across other package naming schemes or altered SRI algorithms.

### First original-evidence branch if policy admission were repaired

`scanPolicyMaterialBuffer.emitOriginal` first checks shared private row capacity,
**before** private projection, `addOriginal`, semantic validation, or marshaling.
Both full metadata fixtures need:

- 1,001 locked + 1,000 declared + 1,000 installed observations = 3,001;
- 1,002 input leases + 1,000 metadata leases + 1 root metadata row = 2,003;
- 1,002 original input rows;
- total **6,006**, exceeding `MaxPolicyMaterials` = **4,096** by **1,910**,
  with **zero** other private material already charged.

The actual call returns `(false, nil)` and sends zero bytes. This is not a raw
capture overflow, reference comparison failure, or observed frame rejection.
For this unchanged collector shape the row demand is `6*n+6`; its isolated
row-only bound is 681 instances (4,092 rows), with 682 needing 4,098. That is
**not** a demonstrated supported scale: byte/frame limits may fail sooner.
Even dropping every declaration observation would leave 5,006 rows; this check
does not drop them or otherwise weaken the required evidence.

### Additional measured but later counterfactual frame blocker

Calling the actual product channel directly, bypassing only original admission
for diagnosis, rejects both full originals at the **1,048,576-byte** message
ceiling. The real envelope plus LF would need **2,435,092** or **2,848,088** bytes,
respectively. `addOriginal` also has a **1,044,480-byte** payload guard
(`maxMessage-4096`). These are independently measured necessary failures, not
the first branch actually reached by `emitOriginal`. The 8,388,608 private-byte
ceiling alone would not block either original.

## Positive small-scale receipt

The two-instance fixture follows the same names/path/manifest/archive/SRI/reference
recipe. It admits an actual **7,546-byte** original frame, replays it with product
channel receive/decode and `ValidateOriginalBytes`, and admits it into a separate
parent material buffer. Product `AcquireWithInventory` rereads the external
pinned policy and actual lock/manifests/archives; two real comparison records
carry non-nil `IntegrityScopeWitness` receipts. Each is serialized and decoded
through the product channel, checked with `ValidateRecord` and
`ValidateIntegrityScopeReceipt`, and separately charged by the parent buffer.
The callback uses the same finite-array normalization as `scan.go`.
`ValidateOriginalClaims` joins the replayed original to the collected public
inventory. Parent and sender account identically: **20 rows / 10,802 bytes**.
Product `BuildReportWithPolicy` completes integrity with zero findings.
Native qualification remains incomplete; this is not a globally qualified run
or a full supervisor lifecycle/protocol campaign.

## Frozen inputs and review

Successful `release-fixtures/manifest.json` SHA-256:
`149d9bcfe02314e581a3391f79ac273e1607a283bc28b736d8eeba46dc9f378e`.
The manifest enumerates every authored source file and archive (not derived
reports). The independently regenerated race fixture has the same manifest.

Checked-1,000 lock SHA-256:
`9a54b1009716ff85d90260470acb4e4d862a2faabc82bae9642846b61b170ac1`.
Checked-1,000 policy SHA-256:
`8509fff83cf3be9e69c975e2985957c54c2a9933f4e060c307c2a8444035f975`.
Original-1,000 lock SHA-256:
`13d54f826c79ff6798fe0513cab3e23e3bb32f79237b48b6c11d7d92c8362f48`.

Only two local check files and this report are added. No production sources,
limits, native implementation, producers, keys, publication, host configuration
or network are changed. CodeGraph reported this specific workspace uninitialized;
no index was created. Relevant production code and callers were inspected
instead. The fixture author exclusively creates a new trusted owned destination;
the opt-in test exclusively creates result files and skips without its explicit
environment variable. Archives have exactly two terminal USTAR zero blocks:
Python tarfile's optional record padding is not accepted by the existing strict
product profile. All original manifest bytes/entries remain present. Exploratory
failures (missing test plan fail-on, optional tar padding, and omitted wire-array
normalization) were corrected only in the local check and retained in evidence.

## Reproduction and remaining scope

From this workspace, Nushell-compatible:

```nu
let base = '/home/justcharles/.local/state/packtrace/advisory-completeness-RIKjKdJf/scale-fix'
let run = (mktemp -d ($base | path join 'metadata-repeat-XXXXXXXX') | str trim)
let fixtures = ($run | path join 'fixtures')
python3 -B probes/offline-integrity/check_metadata_capacity.py $fixtures
with-env {PACKTRACE_METADATA_CAPACITY: $fixtures} {
    timeout 180s bash ($base | path join 'go.sh') test -race ./internal/execution -run '^TestOfflineMetadataCapacity$' -count=1 -v
}
```

Every rerun requires a fresh fixture directory; results are intentionally not
overwritten. Run races **serially**. The evidence directory also retains a Bash
`reproduce.sh` that creates a unique directory and saves stdout/stderr.

Regular and race checks passed; focused existing original-capture/admission,
policy binding and whole-integrity negative/join regressions also passed under
race detection. This establishes the bounded conclusion only. The full 1,000
archive catalog/installed comparison path, full 50,000-file witness accounting,
aggregate comparison reads, 64-MiB cumulative IPC, 8-MiB combined private
material, intelligence/advisory selected-original/work bounds, output sizes,
resource lifetimes, performance and native qualifications remain **untested at
full B6 scale**. They cannot be inferred to pass after repairing an earlier
blocker. No full campaign should be claimed or implicitly authorized here.
