# Issue 6: usable offline advisory scan

## Functional contract and authority

This increment extends the [first bounded matching slice](issue-6-offline-matching.md).
The operator explicitly approved an optional pinned public-npm registry grant,
64 active identities rather than64 total observations, and4096 aggregate work
units/decisions under the existing byte/time/IPC/retention limits. The existing
[privacy design](../design-decisions.md#14-report-privacy-profiles) already permits
explicit local detail; portable stays the default.

The goal is an actual CLI investigation of a representative500-package project:
malicious and vulnerability matches, independent locked and observed-installed
evidence, supported negatives, corrections/withdrawals and visible unknowns.
It is not a new online scan, dependency framework, general enforcement engine,
full-source/platform qualification or permission to merge or finish the epic.

## Explicit namespace and installed correspondence

Policy version1 adds optional fields:

```json
{
  "npmRegistry": "https://registry.npmjs.org",
  "requirePortable": false
}
```

These are additions to the ordinary policy, not a complete policy. Nonempty
`npmRegistry` requires the operator's independent `--trusted-policy-digest` and a
supported npm manager. Only the exact public registry spelling is accepted.
Each selected lock resolution must still be the canonical tarball URL for its
qualified name and concrete version, through complete selected native evidence.
No implicit default, URL substring, private/mirror, Git/file/workspace or Bun
equivalence is granted. This authorizes namespace correspondence only—not
registry, publisher or installed-content authentication, and never networking.

Existing exact `npmOrigins` entries keep their64-rule bound and priority at their
locations. A mismatch cannot fall back to the registry-wide grant. Their previous
locked-only authority is not silently upgraded: installed association additionally
requires the new explicit registry grant.

An installed assessment evaluates its **own** physically observed manifest and
concrete version. Qualification requires complete native directory metadata and
manifest evidence, one unambiguous selected-lock claim-agreement relation,
matching location/name/version/scope and the qualified lock grant. Conflict,
missing/unstable/unreadable evidence, unsupported aliases/links and ambiguous
Bun correspondence remain indeterminate. A lock entry is never installation
proof; even supported installed correspondence does not authenticate contents
or prove execution. The matching-only portable inventory carries a typed numeric
`metadataEvidence` reference per installed observation. Parent admission checks
that specific native-metadata lease, not any complete directory in the same
workspace. Historical inventory-only projections keep their previous shape.

## Source profiles, conditions and changes

Supported new profiles use OSV-delivered affected `database_specific.source`
attribution with exact canonical repository/type/package/record-ID paths:

| Profile | Category |
| --- | --- |
| `osv-openssf-malicious-v1` | malicious |
| `osv-github-reviewed-v1` | vulnerability |
| `osv-github-malware-v1` | malicious |

The original narrow `openssf-malicious-v1` profile remains supported. Neither
GHSA/MAL prefixes, CWE, severity, summary text nor license counts alone classify
an advisory. Unknown paths/providers, spoofed/credential-bearing/encoded URLs,
conflicting type claims and unqualified acquisition remain unsupported. Source
links are inspected as metadata, **never followed** by scan. The selected OSV
source provenance is required independently; this is not publisher authentication.

OSV's [model conversion](https://github.com/google/osv.dev/blob/master/osv/models.py)
overwrites per-affected `database_specific.source` from configured repository
attribution when source details are included. GitHub's [advisory documentation](https://docs.github.com/en/code-security/concepts/vulnerability-reporting-and-management/github-advisory-database)
distinguishes reviewed/unreviewed vulnerabilities from malware and confirms GHSA
IDs cover all types. GitHub's internal review/severity/CWE metadata is
informational, not a substitute for the qualified source/type path. Unsupported
additional layouts remain unknown.

Match only the verified original's same affected slot. The new npm-specific
condition entry point qualifies `ECOSYSTEM` ranges only for npm with strict
canonical SemVer boundaries/order, using the existing introduced/fixed/
last_affected/limit semantics. Loose versions, dependency selectors, other
ecosystems and unsupported conditions remain unknown where relevant. The legacy
evaluator and supplied-input tools are unchanged; projections are not rewritten
to pretend one range type is another.

A newly selected generation evaluates the changed original's conditions again.
Whole-record withdrawals suppress new active findings; published is optional,
while present timestamps and modification/withdrawal chronology must be valid.
Unknown correction/exclusion fields that could invalidate a positive are not
ignored. No alias-range/provenance merge is inferred. Historical pinned evidence
is preserved. Staleness affects coverage independently of retained valid matches.
Other provider profiles and unknown corrections keep required coverage incomplete.

## Scale without a cache or relaxed guards

Group qualified names by the existing identity hash block, at most64 distinct
active names per window. Read and verify the complete original block once, bind
its rows to the same verified catalog, then hydrate one identity at a time from
mandatory originals. Group repeated versions/physical copies without merging
observations. Callback raw evidence is not retained across identities and the
snapshot is not reentered from its callback.

- Shared scan bound:4096 actual condition-evaluation plus emitted-row work units,
  and at most4096 decisions/processed observations, not a renewed per-window cap.
- Shared actual identity reads:512MiB, including failures and cancellation;
  catalog acquisition keeps its separate existing bound.
- Window retention does not multiply existing4096 selected bindings,1024 originals,
 16MiB raw,256MiB logical or metadata limits.
- Existing original-handle/EOF/digest/length/stability/lease checks, five-minute
  scan,1MiB frame,64MiB shared traffic and resident-observation guards remain.
- Resource exhaustion is an explicit gap, never empty success or quiet truncation.
  Exhausted work stops hydration inside the current window; actual close,
  context and lease failures still abort rather than certify partial findings.

The parent still retains its original target/store/generation through output and
confirmed cleanup/reap; matching uses the already selected generation, not a new
`current` selection. Scan never downloads, initializes, repairs or renews data.

## Actionable local view, default portable view

`--privacy local` exposes bounded canonical identities, concrete versions,
relative investigation paths, safe advisory IDs (at most256 bytes) and original hashes.
Overlong/unsupported IDs stay opaque instead of expanding or aborting local IPC. It omits
origin URLs, credentials, raw contents, absolute host paths and authority pins.
Unqualified or invalid data stays unknown rather than echoing arbitrary tokens.
Terminal text is escaped; SARIF locations are relative and only represent actual
observed-installed evidence, never invented locations for locked-only matches.

Portable retains opaque inventory/advisory/support relationships and no local
sidecar. It does not expose private/unknown identities or dictionary-sensitive
hashes. Parent IPC refuses unsolicited local frames, invalid IDs/paths, missing
or inconsistent local closure and mismatched presentation context. A policy's
`requirePortable: true` refuses local before content investigation. Local output
is sensitive and choosing it does not authorize uploading it. Both modes have
identical matching decisions, findings and investigation coverage.

Advisory-selected output advances additively to schema1.4. Existing summary
`observations`/`totalObservations` retain their **locked** meaning; new
`installedObservations`/`totalInstalledObservations` and `work` report the distinct
scope. Decisions link installed observation IDs to supporting locked IDs without
mixing evidence/observation namespaces. Eligible counts are observation-level
matches, not deduplicated incidents or proof of compromise. Integrity drift
counts remain separate. Historical1.0/1.1/1.2 builders remain unchanged.

## Verification boundary

Authored inert fixtures contain503 source records for500 package identities,
including both categories, standard/unknown corrections and withdrawals. They
are prepared, sealed, exported and imported by the real source/store pipeline,
not hand-forged descriptors. A second immutable snapshot changes conditions and
withdraws an initially matching record; selecting the original generation after
activation retains its original decisions.

Actual CLI checks cover the500-package project, own-manifest conflicts, private
origin and missing-install cases, both formats of evidence and both privacy
modes. Rendering checks cover terminal/JSON/SARIF, relative installed locations,
secret/portable leakage and policy-enforced privacy. Reader controls measure real
byte savings, mandatory originals, corruption/cancellation/EOF/resource behavior;
parent controls reject forged relation/count/privacy/closure claims. Whole offline
root race/vet and independent criticism are required before publication.

These authored observations do not measure every real project, source record or
platform and do not imply global index completeness, unrestricted provider
coverage, publisher authentication, a safety verdict, merge authority or epic
completion. General required-check/enforcement completion remains separate.
