# Experimental intelligence lifecycle

The #9 candidate implements owned filesystem snapshots, explicit preparation,
offline transport and scan observations. It is not a release qualification,
advisory matching engine, publisher signature verifier or security verdict.
Issue #9 remains open until its source/native evidence, protected review and
integration gates are accepted. Matching belongs to #6; general policy belongs
to #8. macOS remains paused.

## Commands and side effects

```text
packtrace intel sync [--full] [--state-dir DIR] [--format terminal|json]
packtrace intel import [--state-dir DIR] [--trusted-snapshot-digest SRI] [--format terminal|json] FILE
packtrace intel export [--state-dir DIR] --output FILE [--format terminal|json]
packtrace intel status [--state-dir DIR] [--format terminal|json]
packtrace intel pin [--state-dir DIR] GENERATION_SHA256_HEX
packtrace intel unpin [--state-dir DIR] GENERATION_SHA256_HEX
packtrace cache prune [--state-dir DIR] [--apply PREVIEW_SHA256_HEX] [--format terminal|json]
```

- **Sync** is the only online command. It takes no target project or package
  selection. Only its admitted public OSV source destinations/IDs are queried;
  target names are never turned into remote lookups. `--full` explicitly chooses
  full reconciliation within the same one-operation limits, not a fresh retry
  allowance. Failed incremental work does not reset its budget and start full.
- **Import** admits a bounded complete offline bundle and can initialize a fresh
  store. Existing unmarked directories are never adopted. **Export** streams one
  pinned snapshot to an explicit new file, without overwriting a destination or
  writing under the store. An ancestor output directory is permitted only with
  native original-parent/leaf checks; incomplete private output may remain.
- **Status** and export open existing state readonly. Missing state is not
  initialized or repaired. **Pin/unpin** change explicit retention only; they
  do not change source freshness or remove active/previous/reader protection.
- **Prune** without `--apply` only previews. Applying requires the independently
  supplied exact preview digest plus a fresh complete ownership/protection
  revalidation. A matching copied preview file is not deletion authority.
  Quarantine and unlink use retained original native objects. Uncertainty
  preserves/charges data and reports a partial result, not a rollback.

The default is `os.UserCacheDir()/packtrace` (design section29). Relative explicit
selectors are resolved against the invocation directory. A missing/relative
platform default requires an explicit selector; it must not silently select
state under the current project. Lexical normalization is not a safety proof.
No command elevates privileges, changes host settings, executes target code,
installs dependencies, or adopts third-party caches.

Linux durable owned-state binding v3 uses the original filesystem's full UUID
and its exported inode/subvolume/generation handle, with owner checks. Runtime
device/mount/ancestry checks still apply, but boot-assigned `st_dev` and mount IDs
are not persisted. Old v2 bindings are rejected, never silently converted or
rewritten. Only supported ext4/XFS/Btrfs native UUID/handle shapes are admitted;
volatile tmpfs/overlay and unavailable native queries cannot claim durable owned
storage. Readonly investigation-root admission is unchanged. Btrfs has local
native evidence; ext4/XFS ABI checks and cross-compilation are not runtime
qualification. No actual host reboot/remount campaign is implied.

## Offline scan and portable output

`scan --state-dir DIR` selects an already prepared external store. The independent
`scan --trusted-snapshot-digest SRI` designation accepts a single canonical
SHA-256 SRI for the expected snapshot descriptor, not an input checksum echoed
by the same bundle. It does not authorize network traffic.

The controller retains original target metadata, the physically separate store
and its exact generation lease through comparison, rendering, public output and
confirmed child reap. The worker independently verifies those bindings and reads
that generation, not a later activation selector. A scan never downloads,
initializes, repairs, prunes, or renews acquisition timestamps. Corruption and
unavailable/expired/future evidence remain gaps; fallback is explicit.

Selected intelligence adds scan JSON schema **1.2** and corresponding terminal
and SARIF observations. Unselected inventory output keeps its existing **1.1**
contract; historical supplied-input schemas remain unchanged. The report exposes
snapshot identity, closed source/freshness labels, counts and gaps—not private
paths, targets, raw advisories, source credentials or local HMAC material.
Readonly storage-occupation observations are `null`/unknown, not fabricated zero.
There is still no advisory applicability or matching result.

Intel command output uses its separate schema **1.0**. Successful bounded
maintenance/preparation is not successful complete project security coverage.
Operational/output failure is `2`, incomplete usable evidence is `3`, interruption
is `130`; scan retains its global coverage/qualification rules. Output failure
or missing confirmed cleanup cannot become success.

## Source, trust, licensing and freshness

The source profile captures generation-bound OSV npm ZIP/global change CSV,
checks transport checksums and EOF, validates records and produces typed catalog
and256 identity-index blocks. Modified/new records are reprojected; unchanged
verified metadata can be merged without reopening every advisory semantically.
Sealing still verifies **all** mandatory referenced original bytes/objects.
An imported bundle always rebuilds projections from actual originals before
activation; rehashed forged derived indexes are insufficient.

HTTPS authenticates the admitted transport endpoint, not advisory authorship.
Local hashes prove byte relationships, not benignness or publisher endorsement.
A private root/instance-bound HMAC records this installation's controlled local
acquisition. Its key/MAC are not exported; copying markers or changing files does
not transfer this authority. An independently expected descriptor can designate
an import, but import/copy/mtime never refreshes upstream acquisition claims.

Known publisher profiles are GitHub advisories (CC-BY-4.0), OpenSSF Malicious
Packages (Apache-2.0), EEF's own OSV records (CC-BY-4.0) and GSD (CC0-1.0).
Full license texts, provenance and attribution notices are shipped under
[`internal/intelstore/licenses/`](../internal/intelstore/licenses/README.md).
EEF's grant is not a grant over other publishers' CVE ADP containers. Unknown
required publishers block the whole candidate; OSV software's license is not a
blanket dataset license. These notices establish the supported profiles, not
that every possible future record is redistributable.

Source check age is24 hours; independent successful full-reconciliation age is
seven days. The exact boundary is current, later is expired; future/rollback or
unqualified claims are unknown. Incremental checks never renew the independent
full age. A404 for a known ID retains unresolved evidence; it does not prove
withdrawal or erase the record. Replay/one-minute overlap plus periodic full
reconciliation are not a guarantee of upstream listing completeness.

## Resource and recovery boundaries

| Profile | Ceiling |
| --- | --- |
| Managed logical lengths + conservative reservations |32GiB |
| Staging reservation per operation |16GiB |
| Preparation/import/export/prune operation |900s |
| Sync responses / requests |2GiB /10000 |
| Source ZIP / global CSV / one advisory |1GiB /256MiB /4MiB |
| Semantic advisory processing / candidate records |8GiB /2000000 |
| Offline USTAR / members |16GiB /2001024 |
| Logical catalog retention / entries |256MiB /2100000 |
| Index runs / merge heads |64MiB /32 |
| Pending original files / directories / concurrent flushes |64 /272 /16 |
| Private IPC frame / total |1MiB /64MiB |

These are not promises of physical disk usage or portable hard RSS containment.
The source read cache retains only1MiB across two windows; actual native fills
remain guarded/charged and final original stability is mandatory. Blocking
flushes retain original handles and positive file-before-directory fences;
ordinary synchronous filesystem APIs retain immediate durability.

Failed or uncertain writes, deduplicated staging and quarantine remain charged.
There is no automatic eviction, omitted-record activation, global `syncfs`,
ceiling increase, or background preparation fallback. Current/previous snapshots,
actual readers and durable pins constrain pruning. Zero-byte lock/tombstone stubs
and empty retired directories remain intentionally; namespace ceilings are finite.
External OS/cache deletion is not preventable; choose persistent state explicitly
when retention matters. Process-kill tests do not prove survival of power loss,
controller failure, arbitrary hardware or filesystem faults.

## Evidence status

Local root race tests (4641 passes, no failures,7 skips) and local/Windows-targeted
vet passed with the independently pinned official Go1.27.1 Linux amd64 SDK.
Earlier development measurements used a modified SDK and remain separately
scoped. Local official-toolchain tests do not replace exact-source public CI or
native acceptance campaigns. Windows cross-checks are static, not runtime or
native x64-hardware acceptance.
Controlled TLS fixtures, cached real ZIP replays and authored large global CSV
fixtures do not qualify a live public OSV acquisition. Failed operations consume
their authorized attempt. The first public bootstrap exhausted900s without activation; the second attempt
failed admission because its old Btrfs binding used a boot-dependent device ID.
Both consume their authorized attempts. The v3 correction preserves the rejected
state and requires fresh qualification; it does not turn controlled performance
evidence into a successful public sync. Exact-source official CI, newly
authorized native execution and owner-controlled review/integration remain gates.
No live advisory dataset, downloaded binaries or caches are embedded in this repo;
the small transport fixture is explicitly authored inert test data.
