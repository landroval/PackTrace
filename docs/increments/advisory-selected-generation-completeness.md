# Selected-generation advisory completeness (unreleased schema 1.8)

## Operational meaning

The operational policy report can complete **both malicious and vulnerability
checks for the selected inventory within the admitted selected generation**.
This is not upstream/feed completeness, a statement about unacquired records,
threat absence, current safety, publisher authentication, or proof of execution.
Other source authority, freshness, native qualification, integrity, resource and
final process obligations remain independent. The public report still freezes a
comparison before output and finalization; `130 > 2 > 3 > 1 > 0` is unchanged.

The new optional `advisories.selectedScope` has contract
`selected-generation-originals-v1` and category booleans. These are public
explanations, not portable authority. Only an independently admitted private
receipt can enable completion. `scopeAttempt.bytesRead` and `.work` report
additional actual admission work, including failed attempts, separately from the
historical matching summary's work. Repeated source observation descriptor,
manifest and provenance/preparation object reads are charged too; seal/pin/native
metadata keep their existing separate caps. Their sum with the original summary must fit
the unchanged 512-MiB/4096-unit comparison ceilings. A failed attempt cannot be
retried on the same report with a renewed allowance.

## Positive predicates

After worker EOF and exchange join, the parent:

1. Retains its own snapshot reader under the already admitted selected generation
   pin, through output/finalization. Additional descriptor/manifest/catalog and
   repeated source-observation object reads consume the original matching allowance.
   It independently observes and compares generation, source authority, original
   acquisition freshness and selection. Expired/unknown age does not prevent a
   finite selected-snapshot comparison: `source-stale` remains in the summary and
   required intelligence-freshness remains incomplete. A digest pin does not renew
   age. No source is acquired, resealed or reapproved.
2. Reparses retained original inventory bytes against stable input receipts and
   joins their entire selected observation/evidence projection. Existing inventory
   enumeration and installed metadata witnesses remain required. Missing private
   originals, frame/row/capture overflow, unsupported families or incomplete
   inventory abstain. These native acquisition receipts do not authenticate a
   mutable target's package claims against an adversarial host/worker.
3. Reads **every** selected catalog original, one at a time, checking object
   digest/length/EOF/stability and actual OSV projections. Routing requires the
   current supported OSV-v1 npm identity profile for every affected slot. Unknown,
   absent, non-npm or otherwise unroutable originals abstain, rather than certify
   absence. The finite audit supports at most the existing 1024 original ordinals
   and 4096 selected bindings; parser retention and metadata caps are not raised.
4. Derives selected identity/source-ordinal/affected-slot/original bindings from
   those actual originals, then compares every selected index lookup's bindings
   exactly against them. A catalog digest, declaration bit, row count or successful
   empty index read alone cannot establish this relationship. Index omissions,
   extra rows, wrong originals, identity hashes, buckets and affected slots fail.
5. Requires the existing concrete source/category/correction/activity profiles for
   **every relevant original**. Unrelated records need positively supported routing
   but do not need a selected-category interpretation. A mixed/ambiguous original
   containing a selected identity cannot borrow another slot's category authority.
6. Independently replays the existing bounded version evaluator and matching flow
   on the retained originals and original inventory, comparing every decision and
   the original read/work accounting. All selected dependency and installed
   observations must be accounted for, not candidates or origin-only matches.
   Partial evaluation, unknown activity/profile/corrections, reads/close/lease
   failures, cancellation and exhausted budgets keep both categories incomplete.

The supported declaration subset is intentionally exact and useful, not a new
resolver: **every requirement in every original declared/locked/installed row**
must be an exact supported semver equal to one unambiguous selected lock identity,
with admitted origin and flat root location (`node_modules/name` for npm; the
simple tuple key `name` for Bun). Ranges, aliases, unsatisfied/missing requirements,
multiple versions/ambiguous bindings, optional absence without a lock, unresolved
peers and workspace resolution abstain. Existing origin permissions are unchanged;
old npm locked-only rules do not silently gain installed or Bun authority.

A Bun root workspace row is positively accounted as declaration context only when
its original root location and absent name/version prove it is not a dependency
identity. Its entire requirement set is still checked; it is not silently dropped.
Named/versioned or non-root ambiguous Bun workspace rows remain incomplete. npm
root project rows retain their existing project/declaration meaning.

## Empty lookups and compatibility

A verified empty lookup only means **no known record for that identity in this
admitted selected generation**. It never invents an advisory/no-match decision.
Historical `identity-empty` placeholder decisions remain indeterminate; the new
selected scope is the separately verified reason they no longer imply a missing
index investigation. Original version-negative decisions and eligible findings
remain unchanged and visible.

Historical `SnapshotNPMEvidence`, `MatchInventoryWithPolicyEvidence` and
`ValidateAdvisorySummary` retain their original mandatory declaration/index gaps
and source/correction/activity/finding-authority limitations. They never gain
completeness from declaration verification or catalog counts. Historical builders
cannot use the new receipt to complete checks.

The necessary unreleased-1.8 report distinction is explicit: **only** an admitted
operational report removes the two historical summary baseline gaps, accompanying
that replacement with `selectedScope` and a scoped coverage reason. The independent
`source-stale` gap, when applicable, is retained rather than waived or deleted.
Operational report validation first checks the private original-bound receipt and
independent stale-gap consistency, then restores the historical baseline gaps in
a temporary validation copy. Calling the historical
summary validator alone on that new operational summary therefore rejects it;
consumers must honor the new companion contract, not infer authority from missing
gaps. An unresolved same-obligation gap is never displayed beside completed
coverage; source age belongs to the separate required freshness obligation. Other historical inputs and immutable bundles are not reinterpreted.

The private receipt binds plan, original inventory/evidence, intelligence,
observations, decisions, category scope and accounting; operational report sealing
freezes those inputs. Public JSON, claimed child completion, gap deletion, copied
hashes, field substitution, downgrade, or exceptions cannot recreate it. Portable
reports add no private identities, paths, hashes or raw originals. No snapshot
storage-usage observations or final-lifecycle promises are invented.

## Integrated acceptance and residual qualification

The real supervised CLI regression uses the checked-in inert `full.bundle` and
its independent original-generator oracle, not controller grants or a synthesized
completion report. It checks malicious and vulnerability positives, supported
version negatives, and original/catalog/index-backed absence, each in default
portable and explicit local JSON. It checks unchanged target bytes/types,
equivalent decisions/enforcement/coverage and presentation privacy. Nine controls
retain incompleteness for candidates without grants, undesignated generation,
withdrawn/corrected originals, unknown source, unlocked declarations/installed
observations, unavailable manifest and missing/corrupt originals. No-match is
never manufactured for failed reads or unsupported originals.

Integration first reproduced RED on all five positive cases: the initial admission
incorrectly required current age. Separating finite snapshot scope from freshness
made these GREEN without changing the fixture timestamps, qualifying native work,
removing stale evidence or changing actual/frozen exit3. Review also found that
repeated source-observation object reads needed cumulative accounting; bounded
observation now preserves existing evidence semantics and charges failure paths.
Its new regression initially failed compilation because the bounded method did
not exist; this was not an executed semantic assertion. A subsequent test-helper
compile failure (nonexistent snapshot accessor) was corrected using the existing
explicit digest API. All intermediate evidence is retained in the external handoff.

Executed integration checks: full non-race `intel`, `intelstore`,
`projectinventory`, `integrityscan`, `execution` and `cmd/packtrace` packages;
affected vet and offline CLI build; targeted serial races for original audit,
parent acquisition/observation, selected advisory admission, matching/original/
material protocol, CLI advisory completeness, previous whole-integrity scope and
failed-public-output receipt regressions. These are owned fixture/source tests,
not native qualification, a root/full execution race, a performance campaign or
proof that all beta gates/global operational0/1 are complete. Required native,
resident, freshness and final-lifecycle obligations remain independent.
