# Experimental intelligence lifecycle

The #9 lifecycle, integrated by PR#102, implements owned filesystem snapshots,
explicit preparation, offline transport and scan observations. It is not a
release qualification, publisher signature verifier or security verdict. The
usable matching increment belongs to [#6](increments/issue-6-usable-advisory-scan.md);
general policy belongs to #8. Native qualification limits remain explicit and
macOS remains paused.

For current daily use see the [user manual](user-guide.md) / [manual en español](user-guide.es.md).
Current operational scan output is schema **1.7**; the 1.1/1.2/1.6 descriptions and
per-increment test counts below retain historical scope, not the current top-level
schema. With no saved setup, privacy remains portable. Explicit per-user `setup`
can save local output; scan flags/policy still control it. Local output now includes
bounded summaries/conditions from the same already-read advisory originals, never
additional live lookups or publisher authentication. Saved scan defaults do not
apply to the maintenance commands below: pass the intended `--state-dir` explicitly.

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
and its exported inode/subvolume/generation handle, with owner checks. The positive
native proof belongs only to its retained original root, not a pathname cache;
every use still checks the original owner/device/mount/ancestry. Boot-assigned
`st_dev` and mount IDs
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
Selecting advisory checks adds schema **1.6** with grouped bounded npm matching,
explicit pinned exact `npmOrigins` or optional public `npmRegistry` correspondence,
and documented OSV-delivered OpenSSF/GitHub category profiles. Installed decisions
require their own native manifest evidence and qualified selected-lock agreement.
The new registry grant must explicitly authorize installed association; old exact
rules remain locked-only. At this historical increment, optional local detail required an explicit scan flag;
the later per-user setup behavior is described above.
Advisory counts remain observation-level matches separate from drift findings;
unknown categories, corrections and correspondence keep coverage incomplete. See
the [usable matching contract](increments/issue-6-usable-advisory-scan.md) and
[first-version-blocker increment](increments/issue-6-explain-version-conditions.md).
The latter retains one fixed evaluator reason with numeric source positions,
without changing version verdicts or treating diagnostics as coverage. The
OpenSSF profile additionally accepts the bounded descriptive CWE shape; CWE
metadata remains informational, never category authority. An independently pinned
`advisoryCandidates` policy option can authorize local investigation of stable
recorded npm identities with private/unknown origins. It is off by default;
[origin candidates](increments/issue-6-offline-origin-candidates.md) remain final
indeterminate, never enforcement eligible, with a separate observation-row count.
Portable retains opaque references and SARIF does not turn candidates into alerts.

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
| Pending original files / directories / concurrent flushes |128 /272 /16 |
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

Local root race tests (4648 passes, no failures,7 skips) and local/Windows/Linux-arm64-targeted
vet passed with the independently pinned official Go1.27.1 Linux amd64 SDK.
Earlier development measurements used a modified SDK and remain separately
scoped. Local official-toolchain tests do not replace exact-source public CI or
native acceptance campaigns. Windows cross-checks are static, not runtime or
native x64-hardware acceptance.
Controlled TLS fixtures, cached real ZIP replays and authored large global CSV
fixtures do not qualify a live public OSV acquisition. The controlled full corpus
with128 pending originals activated231048 records in833s within the unchanged900s
limit. Actual retained-handle rollover tests enforce the128/129 boundary.

The separately authorized public campaign on candidate `5a4f0602` completed a
bootstrap in657s, an incremental revalidation in55s and a full reconciliation
in305s. Separate readonly status processes confirmed each selected generation
and local-acquisition authority. All retained231211 records and233350 memberships;
859 identity gaps remained explicit, with no temporal or disposition gaps in
these observations. Each command returned3 for incomplete identity coverage,
not operational failure. The incremental renewed only the source-check time;
the full operation renewed the independent reconciliation time. The listing
body did not change during these follow-ups: real changed/withdrawn events were
**unobserved**, not passed by absence; their causal fixtures remain separate.
Local acquisition is not publisher authentication or advisory matching.

Three earlier public operations failed and remain charged/preserved: a900s
bootstrap deadline, an old boot-dependent Btrfs binding, and an overly strict
ID grammar applied to an unrelated ecosystem in the global CSV. The corrected
parser retains interior spaces in listing-only IDs without granting npm/HTTP
request authority; it replayed all2771470 captured rows without skipping older
rows. No old marker was rewritten. Explicit owner extensions capped the complete
campaign at6 operations; all6 are consumed, with no further acquisition authority.
Wire totals were unavailable, so full admitted envelopes were conservatively
reserved rather than reporting zero. Exact-source official CI, newly authorized
native execution and owner-controlled review/integration remain gates.
No live advisory dataset, downloaded binaries or caches are embedded in this repo;
the small transport fixture is explicitly authored inert test data.
