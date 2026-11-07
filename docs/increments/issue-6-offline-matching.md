# Issue 6: bounded offline advisory matching

## Scope

Connect actual native npm locked evidence to the already selected immutable disk
snapshot in `scan`. No new collector, online scan, dependency, worker role or
version evaluator. This is a first functional slice, not completion of #6 or
release/platform qualification.

The operator selected **explicit verifiable rules**: exact npm correspondence in
a pinned policy plus a documented source metadata profile. Existing integrity
references and `classification: public` do not implicitly grant npm equivalence.

## Exact npm correspondence

Policy version1 optionally accepts `npmOrigins`:

```json
{
  "location": "node_modules/left-pad",
  "name": "left-pad",
  "version": "1.0.0",
  "origin": "https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz"
}
```

These entries supplement the ordinary policy fields; the object above is one
array entry, not a complete policy. A nonempty array requires the independently
supplied `--trusted-policy-digest`. Each rule associates one exact complete locked
tuple with the public npm namespace. Names and strict concrete versions must be
qualified, locations unique, and the origin the canonical public-npm tarball URL.
No URL substring, target configuration, copied digest, old public classification,
alias, mirror, Git/file/workspace resolution or Bun tuple grants this authority.
The rule does not authenticate installed bytes, a registry or an advisory author,
and never authorizes networking.

Locked evidence remains distinct from physical installed observations. Declared
constraints are not concrete versions. Installed applicability and declarations
are explicitly unassessed for advisory matching in this slice.

## Source profile and outcomes

The first supported category is `openssf-malicious-v1`, delivered through the
qualified OSV npm snapshot. Local acquisition and invocation-selected generation
authority retain their existing meanings; neither is publisher authentication.
An unqualified import cannot authorize findings on its own.

The classifier requires the MAL namespace **and** validated, nonempty documented
`database_specific.malicious-packages-origins` metadata. ID prefixes, summaries,
severity or CWE alone cannot classify records. Supported metadata is closed and
bounded. Unknown source/correction fields, including false-positive version
arrays, block promotion. Recognized informational fields are not followed or
used as authority. Unknown affected/package/range extensions likewise remain
unsupported. Whole-record withdrawals suppress active matches; malformed,
contradictory or future activity evidence remains unknown. Aliases are not merged.
Other publisher/category profiles—including GHSA—remain unknown, not implicitly
vulnerabilities.

The unchanged SemVer/version evaluator supplies per-affected-slot version
`match`, `no-match` or `indeterminate`. Only verified bindings to the same original
and affected slot can support a decision. Enumerated versions and supported
SEMVER ranges retain their existing OR semantics; an unrelated unsupported
version condition does not erase a valid positive. An unknown correction that
could invalidate that positive does block final eligibility. A final negative
requires supported complete evaluation of the applicable record; an empty index
hit is not proof of globally successful absence.

Final eligibility also requires the explicit origin rule, qualified source,
supported category/activity/corrections, and selected check. Stale usable source
retains supported matches but leaves coverage incomplete. Missing/corrupt source,
resource exhaustion or unknown applicability never becomes a successful zero.

Primary profile references:

- [OpenSSF scope and false-positive handling](https://github.com/ossf/malicious-packages/blob/main/README.md).
- [Origins and informational metadata](https://github.com/ossf/malicious-packages/blob/main/docs/schema_additions.md).
- [OpenSSF contributing/schema notes](https://github.com/ossf/malicious-packages/blob/main/CONTRIBUTING.md).
- [OSV activity and evaluation](https://github.com/ossf/osv-schema/blob/main/docs/schema.md).
- [GHSA type and internal-metadata limitations](https://github.com/github/advisory-database/blob/main/README.md).

## Resource, lifetime and reporting contract

- At most64 locked observations and4096 work units/decision rows. Unsupported or
  unprocessed scope is visible, never silently omitted as complete.
- At most512MiB aggregate **actual identity reads**, including both index passes,
  originals, failures and cancellation; catalog acquisition has its existing
  separate limit. Existing tighter per-identity and native guards remain.
- At most256 support locators and32 controlled gap labels per decision.
- Existing five-minute scan, resident observations,1MiB frames and64MiB shared
  traffic limit are unchanged. No additional acquisition/platform campaign.
- Matching runs inside the existing inventory callback. Worker reads the same
  admitted snapshot; parent retains its original roots and generation lease
  through output and confirmed cleanup/reap. No new selection of `current`.
- Matching IPC requires ordered decisions and an exact closure before integrity
  instances or successful `done`. Forged, duplicate, missing and late frames are
  refused. Closed partial evidence is not global execution success.
- Advisory-selected scan output adds schema1.3 and an `advisories` section;
  unselected1.0/1.1/1.2 builders and historical supplied-input contracts stay
  unchanged. Advisory finding counts are separate from integrity drift.
- Terminal, JSON and SARIF share one model. Portable output has numeric inventory
  and local advisory/support locators—not names, versions, paths, URLs, raw record
  IDs/digests or original JSON. Eligible malicious matches are SARIF warnings;
  candidates do not become findings.

Required coverage remains incomplete, independently of finding presence. Ordinary
usable scans in this slice still return3; operational/output failure and
interruption keep their existing higher precedence. No exit value asserts safety.

## Implementation and verification

Reuse `AcquireFromRoot`'s existing callback, `Snapshot.ReadIdentity`, verified
same-slot evidence and `EvaluateOSVVersionConditions`. Add only the explicit rule,
bounded reader/matching result and existing pipeline/report connections.

Authored inert fixtures exercise actual source preparation/sealing/export/import
and real CLI matching, supported negatives, withdrawals, unknown corrections,
missing rule and unqualified imports. Targeted checks cover budgets, corruption,
cancellation, protocol closure/forgery, privacy and legacy output. Run full offline
root tests/race/vet and independent criticism before integration. Test fixtures
are not a live feed campaign or publisher-authenticated reports. No publication,
new platform qualification or #6 closure follows from this document alone.
