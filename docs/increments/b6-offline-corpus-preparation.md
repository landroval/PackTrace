# B6 offline corpus preparation (not qualification)

This small stdlib authoring helper at `probes/offline-integrity/prepare_corpus.py`
prepares an inert **target**, not a benchmark, campaign, package-manager output,
intelligence generation, authenticated reference set or B6 acceptance result.
It follows the authored JSON/owned-directory conventions in
`probes/scalibr-inventory/make_fixtures.py` and the stdlib fixture checks. No
producer, target code, network, scanner, native measurement or timing is invoked.
Import and `project()` do no filesystem I/O. The default CLI only prints a compact
projection; it does not enumerate a real project or allocate/write 1 GiB.

Scope is the [B6 preparation obligation](public-beta-readiness-plan.md#9-b6--mandatory-fixed-performance-and-recovery-qualification)
and [design section 18](../design-decisions.md#performance-qualification-target).
It changes no production limit. Existing small native-probe budgets do **not**
authorize this full corpus. No five-run or runtime/memory qualification is claimed.

## Counting and byte convention

The exact reference dimensions are **1,000 distinct installed instances, 50,000
regular target files, 1,073,741,824 logical target-content bytes**. Here “content”
includes every regular target file's bytes, including manifests and lockfile;
metadata is a subset, not an extra 1 GiB. This convention must be accepted/frozen
before a later B6 campaign; interpreting the target as 1 GiB of payload *plus*
metadata would be a different corpus, not a reason to silently pad this one.

- One root `package.json`, one root `package-lock.json` (npm lock v3), 1,000
  installed `package.json` files, and 48,998 inert `.txt` payload files.
- Root project is not an installed instance. There are 1,000 locked package
  instances, 1,000 installed identities, and **1,001 lock `packages` entries**
  including the empty-key root row. Locked and installed evidence remain distinct.
- Paths are `node_modules/fixture-NNNNNN/{package.json,file-NNNNNN.txt}`.
  Package indices start at zero. Each instance gets 48 payloads, with one extra
  for the first 998 instances. File indices restart per instance.
- 1,002 directories **including the target root** are excluded from file/byte
  counts. No links, hardlink sharing, special files, executable content, hidden
  lock, archive, policy, receipt or expected-output file is inside the target.
- Logical bytes are not filesystem allocation, resident memory or scan-read work.
  Reports, references, intelligence, scratch, and corpus copies are external and
  have separate, as-yet-unapproved storage/read budgets. Timestamps/modes/inodes
  are not a reproducibility promise.

Exact default projection (UTF-8/ASCII, compact sorted-key JSON with final LF):

| Item | Files/entries | Bytes |
| --- | ---: | ---: |
| Root manifest | 1 | 25,080 |
| Installed manifests | 1,000 | 44,000 (44 each) |
| Root lockfile | 1 / 1,001 package entries | 99,149 |
| All metadata / raw manifest+lock data | 1,002 | 168,229 |
| Payload | 48,998 | 1,073,573,595 |
| All target files | 50,000 | 1,073,741,824 |
| Independently base64-encoded manifest+lock data only | 1,002 values | 225,640 |

Payload is the repeated ASCII line `PackTrace owned inert B6 fixture; never
execute.\n`, truncated per file. In numeric instance/file order the first 27,415
payloads have 21,911 bytes, the rest 21,910. Projection hashes just the two distinct
payload sizes and reuses their hashes; it does not hash a virtual GiB byte by byte.
These repetitive, uncompressed text bytes are not representative entropy,
compression or filesystem performance evidence. No gap is removed by lowering
counts, shrinking names, dropping declarations, sharing instances or claiming
that missing references mean successful work.

## Compact expected-work/digest contract

`records()` yields one `{bytes,kind,path,sha256}` record per regular file:
metadata paths in sorted order, then payloads in numeric instance/file order.
Each record uses ASCII sorted-key compact JSON plus LF. SHA-256 of their
concatenation (no header) for the reference projection is:

```text
fe63530a278af53fc2f78ffac2d056522d585d95bbde4cabdbe0c7370b51b3a8
```

The compact projection includes the dimensions, all counts, bytes, deterministic
recipe and record digest; it does not dump 50,000 records. A consumer can stream
`records()` if needed. The digest binds paths, kinds, sizes and contents, not
publisher authenticity or admitted product receipts.

Expected authored inventory is 1,000 locked plus 1,000 installed observations;
these are not measured scanner output. If authenticated identical package
references were later prepared, candidate regular-file integrity work is 49,998
files / 1,073,617,595 bytes (installed manifests plus payloads, excluding root
manifest/lock). These are unique logical comparison bytes, **not** total reads,
archive bytes, rereads, protocol frames or public product-record counts.
Advisory decisions and reference archive count are explicitly `null`, not zero:
no intelligence/reference generation exists in this preparation step.

## Feasibility remains unresolved

Whole-scope completion is **not demonstrable** with this target alone:

- The authored lock has names/versions but no `resolved` origins or archive SRI.
  No fake digest/authentication is supplied. Origin classification, concrete
  references and user-designated trust policy remain unprepared. Missing source
  authority/reference evidence must remain a gap, not a qualified no-match.
- `internal/projectinventory/private_original_bytes.go` retains at most 524,288
  raw bytes / 4,096 inputs. The projected 168,229 raw bytes and 1,002 input files
  are below these isolated ceilings, not proof of successful collector admission.
  Base64 data alone is 225,640 bytes; that excludes JSON receipt fields, semantic
  inventory/evidence witnesses, escaping and the frame envelope. The actual
  private encoded receipt has **not** been constructed or admitted. The single
  1,048,576-byte frame and shared 67,108,864-byte IPC traffic bounds in
  `internal/execution/protocol.go` still apply.
- `internal/integrityscan/policy.go` permits at most 262,144 policy bytes and
  20,000 references. A count of 1,000 does not prove the fully specified policy
  fits its byte bound. Reference archive sizes, trust/digest checks, per-file and
  aggregate read limits and actual integrity witness sizes remain unmeasured.
  Private policy material shares 4,096 rows / 8,388,608 encoded bytes
  (`policy_material.go`, `scan_policy_material.go`); target-file count is not a
  policy row estimate.
- [Selected-generation advisory completeness](advisory-selected-generation-completeness.md)
  still needs actual admitted original-bound receipts, origins, prepared local
  intelligence, freshness/source predicates, selected-original/binding/work
  accounting and parent replay. Its 512-MiB / 4,096-unit comparison limits and
  1,024 selected-original bound are unchanged. No empty lookup is invented as a
  decision; no intelligence identity/state/trust receipt is frozen here.
- Full preparation storage (including references/state/receipts), read/capture
  budgets, native role lifetime peaks, final source-close/reap boundaries, cache
  protocol and five-run authority remain separate B6 work. This helper neither
  renews budgets nor establishes that the fixed target is feasible under them.

## Usage and miniature validation

From the repository root, Nushell-compatible commands:

```nu
# Exact reference projection only; stdout may be saved outside the target.
python3 -B probes/offline-integrity/prepare_corpus.py
python3 -B -m unittest discover -s probes/offline-integrity -p test_prepare_corpus.py -v

# Only in a new trusted owned parent, never a real project:
let owned = (mktemp -d | str trim)
python3 -B probes/offline-integrity/prepare_corpus.py --instances 2 --files 12 --target-bytes 8192 --write-owned ($owned | path join target)
```

`write_owned()` uses exclusive new-directory/new-file creation, never merges or
cleans up, and leaves partial failures for inspection. The parent must be trusted,
owned and stable: this is not an untrusted-path containment/sandbox interface.
CLI writes are deliberately miniature-only (32 MiB); default/full-size write
attempts are refused before creating a destination. The reusable writer can
stream a larger authorized preparation later; it is not invoked at reference size
by tests or these instructions.

Tests independently walk two separately authored temporary 2-instance / 12-file /
8,192-byte trees, check types, links, metadata identities, physical logical byte
counts, every payload byte, and reconstruct the digest without `records()`.
They check reproduction, frozen reference projection values, no-I/O projection,
invalid-dimension refusal and no overwrite. No test runs a native scan or records
timings. This evidence validates the **recipe and miniature authoring only**.
