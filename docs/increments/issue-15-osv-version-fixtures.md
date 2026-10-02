# Issue 15: strict concrete-version and OSV fixture contract

Status: **written specification approved**. The user authorized preparation,
selected strict SemVer 2 syntax, approved the single-document design/reference
consultation, then approved this written artifact and publication in a draft PR.
No evaluator/dependency acquisition, implementation, CI/native work, ready/reviewer
request or merge is authorized. #15 remains Preparation pending its later gates.
Tracking: [issue #15](https://github.com/landroval/PackTrace/issues/15).
Authority: [matching decisions](../design-decisions.md#10-advisory-matching-semantics).
Base: integrated development `89a76e5f`; reviewed [range structure](issue-14-osv-range-structure.md)
through PR #27. The historical pending-review wording in that artifact describes its
original publication, not the current GitHub queue. Open PR #28 is not this task's
base or a prerequisite for these synthetic version-only examples.

## Purpose and deliverable

Define independently reviewable literal expectations for future concrete-version
qualification, ordering and OSV version-condition evaluation. The entire deliverable
is this document: no Go API/model, JSON fixture file, runner, parser, matching engine,
shared-checklist edit or dependency. Stable row IDs allow later approved tests to
cite their source without computing expectations using the tested evaluator.

These are synthetic reference cases, **not executed tests**. They do not qualify a
library, npm producer, installed version, advisory identity/origin/activity, scanner,
coverage, enforcement or release. `match` below means only that the hypothetical
version satisfies the selected synthetic version condition under stated assumptions.
It is not a confirmed finding. A declaration such as `^1.2.0` is never resolved into
a concrete version or substituted with a minimum version.

## References and provenance

- [SemVer 2.0.0](https://semver.org/spec/v2.0.0.html), clauses 2, 9, 10 and 11 plus
  its grammar: canonical core, prerelease/build syntax and precedence.
- [OSV 1.9.1, pinned source `8e3305dedc0786c4869c7bb0b14564e03ec277b3`](https://github.com/ossf/osv-schema/blob/8e3305dedc0786c4869c7bb0b14564e03ec277b3/docs/schema.md):
  `affected[].versions`, range types/events and the Evaluation pseudocode.
- Existing [recorded version evidence](10-osv-versions.md), [recorded ranges](11-osv-ranges.md)
  and [bounded structure profile](issue-14-osv-range-structure.md) remain unchanged.

Only the two public specification texts were consulted for this draft. No advisory
feed/corpus, investigated tree, dependency source or package manager was acquired or
executed. All fixture literals are authored synthetic examples, not copied advisory
records. They assert no package registration or public-registry origin. Normative
reference behavior and PackTrace's conservative qualification policies are identified
separately below; none is measured behavior of a candidate evaluator.

## Notation and qualification gates

- Table string values are JSON string literals: escapes identify decoded characters,
  not characters to strip. Preserve original source bytes, decoded text, positions,
  duplicates, header state and digest independently of any derived comparison view.
- Syntax outcome `within-profile` means only the selected SemVer grammar accepts the
  exact text; `outside-profile` does not mean universally invalid npm/OSV evidence.
- Pair outcomes are `less`, `equal-precedence`, `greater` or `indeterminate`. Equal
  precedence is neither literal equality nor proof that two package artifacts agree.
- Version-condition outcomes are `match`, `no-match` or `indeterminate`. A negative
  requires complete, qualified evaluation of all applicable alternatives. Unsupported,
  missing or malformed evidence cannot be discarded to manufacture a negative.
- Range/aggregation cases assume a synthetic inspectable v1 envelope and a usable
  concrete query, unless the row states otherwise. A qualified structure result
  from #14 is necessary for the selected range profile, not sufficient for semantics.
  No real package identity/origin/withdrawal claim is qualified by these assumptions.
- SemVer input qualification is separate from `ECOSYSTEM` ordering. This task does
  not qualify npm's ecosystem comparator or justify substituting npm dependency
  constraints for OSV event evaluation. ECOSYSTEM range results remain indeterminate
  until a separately approved npm profile has its own reference/acceptance evidence.

For later approved reader-based tests, use this authored envelope and replace only
the named affected object's `versions`/`ranges`, or the explicitly stated gate field.
Omission remains omission; no missing optional list or implicit limit is written into
source evidence. A scalar/fragment in a table is not itself a full OSV document.

```json
{
  "schema_version": "1.9.1",
  "id": "PACKTRACE-SYNTHETIC-I15",
  "modified": "2026-10-02T00:00:00Z",
  "affected": [{
    "package": {"ecosystem": "npm", "name": "packtrace-synthetic"},
    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
  }]
}
```

## Strict syntax fixtures

Exactly `MAJOR.MINOR.PATCH`, with optional prerelease then optional build metadata.
Core and numeric prerelease identifiers have no leading zeroes. Identifiers are
nonempty ASCII alphanumeric/hyphen components; numeric build identifiers may have
leading zeroes. No trimming, prefix removal, case folding, Unicode normalization,
coercion or constraint resolution. These rules describe version syntax, not every
publisher/API obligation in SemVer or npm.

SemVer imposes no integer/string-size ceiling. Large numeric literals below are
within the grammar and mathematically ordered without rounding, saturation or
machine-integer wrap. A future implementation's operational ceiling must be explicit:
unsupported/limited work is indeterminate, not an invented version or no-match. This
document does not introduce a new runtime quota or replace existing reader budgets.

| ID | Exact input | Syntax outcome | Distinction |
| --- | --- | --- | --- |
| S01 | "0.0.0" | within-profile | Actual concrete zero core |
| S02 | "1.2.3" | within-profile | Normal core |
| S03 | "1.2.3-alpha.1" | within-profile | Prerelease |
| S04 | "1.2.3-0" | within-profile | Numeric zero prerelease |
| S05 | "1.2.3-001x" | within-profile | Nonnumeric identifier |
| S06 | "1.2.3--" | within-profile | Hyphen identifier is nonempty |
| S07 | "1.2.3-Alpha" | within-profile | Preserve ASCII case |
| S08 | "1.2.3+001" | within-profile | Build zeroes allowed |
| S09 | "1.2.3-alpha.1+build.001" | within-profile | Both suffixes |
| S10 | "18446744073709551616.0.0" | within-profile | Core exceeds uint64 |
| S11 | "1.0.0-18446744073709551616" | within-profile | Large numeric prerelease |
| S12 | "" | outside-profile | Empty recorded string |
| S13 | "0" | outside-profile | Not a concrete version; event sentinel is separate |
| S14 | "1.2" | outside-profile | Missing component |
| S15 | "1.2.3.4" | outside-profile | Extra component |
| S16 | "01.2.3" | outside-profile | Core leading zero |
| S17 | "1.02.3" | outside-profile | Core leading zero |
| S18 | "1.2.03" | outside-profile | Core leading zero |
| S19 | "1.2.3-01" | outside-profile | Numeric prerelease leading zero |
| S20 | "1.2.3-alpha..1" | outside-profile | Empty prerelease component |
| S21 | "1.2.3-" | outside-profile | Empty prerelease |
| S22 | "1.2.3+" | outside-profile | Empty build |
| S23 | "1.2.3+build..1" | outside-profile | Empty build component |
| S24 | "1.2.3+one+two" | outside-profile | Extra build delimiter |
| S25 | "v1.2.3" | outside-profile | No prefix normalization |
| S26 | "=1.2.3" | outside-profile | No npm cleaning |
| S27 | " 1.2.3" | outside-profile | No trim |
| S28 | "1.2.3\n" | outside-profile | No trailing-control acceptance |
| S29 | "1.2.3-α" | outside-profile | Non-ASCII identifier |
| S30 | "1.2.3_alpha" | outside-profile | Wrong delimiter |
| S31 | "^1.2.0" | outside-profile | Declaration, not an installed version |
| S32 | "*" | outside-profile | Not concrete; limit sentinel is separate |
| S33 | "-1.2.3" | outside-profile | Signed core |
| S34 | "1e2.0.0" | outside-profile | No exponent numeric syntax |

## Precedence fixtures

Compare numeric core/prerelease identifiers numerically, nonnumeric prerelease
identifiers lexically in ASCII order, and numeric identifiers below nonnumeric ones.
A longer equal-prefix prerelease sequence has greater precedence; a release exceeds
its prereleases. Build metadata does not affect precedence. Do not sort source arrays
or discard metadata to implement these mathematical comparisons.

| ID | Left | Right | Expected pair outcome |
| --- | --- | --- | --- |
| O01 | "1.9.0" | "1.10.0" | less |
| O02 | "2.0.0" | "1.99.99" | greater |
| O03 | "1.0.0-alpha" | "1.0.0-alpha.1" | less |
| O04 | "1.0.0-alpha.1" | "1.0.0-alpha.beta" | less |
| O05 | "1.0.0-alpha.beta" | "1.0.0-beta" | less |
| O06 | "1.0.0-beta.2" | "1.0.0-beta.11" | less |
| O07 | "1.0.0-rc.1" | "1.0.0" | less |
| O08 | "1.0.0-1" | "1.0.0-alpha" | less |
| O09 | "1.0.0-A" | "1.0.0-a" | less |
| O10 | "1.0.0+one" | "1.0.0+two" | equal-precedence |
| O11 | "1.0.0-alpha+001" | "1.0.0-alpha" | equal-precedence |
| O12 | "18446744073709551615.0.0" | "18446744073709551616.0.0" | less |
| O13 | "1.0.0-18446744073709551615" | "1.0.0-18446744073709551616" | less |
| O14 | "1.0.0" | "1.0.0" | equal-precedence |
| O15 | "v1.0.0" | "1.0.0" | indeterminate |
| O16 | null | "1.0.0" | indeterminate |

## SEMVER event reference cases

Each `events` cell is the exact source array for one type `SEMVER` range. Introduced
is inclusive, fixed exclusive and last_affected inclusive under OSV's evaluation.
`introduced:"0"` sorts before every concrete version; only exact `limit:"*"` is in
this draft's infinity subset. These sentinels are not concrete-version syntax.
Other star-containing limit forms remain outside the chosen subset, not declared
universally invalid OSV. No explicit limit means the reference evaluation allows an
implicit infinite ceiling, **without fabricating a source event**.

OSV's pseudocode sorts events for evaluation; a future owned derived view may do so,
while original indices/order/duplicates remain untouched. Multiple limit events are
alternatives: passing any one limit permits evaluation, not an intersection/minimum
ceiling. For this linear profile, non-limit status transitions then determine whether
the query is affected. Never require first-introduced, source sorting or alternation.

PackTrace conservative policy: a range with different status-changing event kinds
at equal SemVer precedence is indeterminate until a separately reviewed tie policy
exists. The reference does not specify an explicit tie-breaker; do not silently use
source order, lexical field names or a library's sort behavior to select a status.
Identical-kind duplicate transitions and alternative limits are not that ambiguity.

| ID | events | Query | Expected version condition |
| --- | --- | --- | --- |
| R01 | [{"introduced":"1.0.0"},{"fixed":"2.0.0"}] | "0.9.9" | no-match |
| R02 | [{"introduced":"1.0.0"},{"fixed":"2.0.0"}] | "1.0.0" | match |
| R03 | [{"introduced":"1.0.0"},{"fixed":"2.0.0"}] | "2.0.0-rc.1" | match |
| R04 | [{"introduced":"1.0.0"},{"fixed":"2.0.0"}] | "2.0.0" | no-match |
| R05 | [{"introduced":"1.0.0"},{"fixed":"2.0.0"}] | "2.0.0+build" | no-match |
| R06 | [{"introduced":"1.0.0"},{"last_affected":"2.0.0"}] | "2.0.0" | match |
| R07 | [{"introduced":"1.0.0"},{"last_affected":"2.0.0"}] | "2.0.1-alpha" | no-match |
| R08 | [{"introduced":"0"}] | "0.0.0-0" | match |
| R09 | [{"introduced":"0.0.0"}] | "0.0.0-0" | no-match |
| R10 | [{"introduced":"0"}] | "999.0.0" | match |
| R11 | [{"introduced":"1.0.0-alpha"},{"fixed":"1.0.0"}] | "1.0.0-beta" | match |
| R12 | [{"introduced":"1.0.0"}] | "1.0.0-rc.1" | no-match |
| R13 | [{"introduced":"0"},{"limit":"2.0.0"}] | "2.0.0" | no-match |
| R14 | [{"introduced":"0"},{"limit":"2.0.0"}] | "2.0.0-rc.1" | match |
| R15 | [{"introduced":"0"},{"limit":"1.0.0"},{"limit":"2.0.0"}] | "1.5.0" | match |
| R16 | [{"introduced":"0"},{"limit":"1.0.0"},{"limit":"2.0.0"}] | "2.0.0" | no-match |
| R17 | [{"introduced":"0"},{"limit":"1.0.0"},{"limit":"*"}] | "9.0.0" | match |
| R18 | [{"fixed":"2.0.0"},{"introduced":"1.0.0"}] | "1.5.0" | match |
| R19 | [{"fixed":"0.5.0"},{"introduced":"1.0.0"}] | "1.5.0" | match |
| R20 | [{"introduced":"1.0.0"},{"introduced":"1.5.0"},{"fixed":"2.0.0"}] | "1.7.0" | match |
| R21 | [{"introduced":"1.0.0"},{"fixed":"2.0.0"},{"fixed":"2.0.0"}] | "2.0.0" | no-match |
| R22 | [{"introduced":"1.0.0"},{"fixed":"2.0.0"},{"introduced":"3.0.0"},{"fixed":"4.0.0"}] | "2.5.0" | no-match |
| R23 | [{"introduced":"1.0.0"},{"fixed":"2.0.0"},{"introduced":"3.0.0"},{"fixed":"4.0.0"}] | "3.0.0" | match |
| R24 | [{"introduced":"1.0.0+one"},{"fixed":"1.0.0+two"}] | "1.0.0" | indeterminate |
| R25 | [{"introduced":"1.0.0"},{"fixed":"1.0.0"}] | "1.1.0" | indeterminate |
| R26 | [{"introduced":"0"},{"limit":"*suffix"}] | "1.0.0" | indeterminate |
| R27 | [{"introduced":"0"},{"fixed":"0"}] | "1.0.0" | indeterminate; sentinel not a fixed version |
| R28 | [{"introduced":"0"},{"limit":"0"}] | "1.0.0" | indeterminate; zero is not a limit sentinel |

## Enumerated versions and OR aggregation

For this strict literal-list profile, OSV's `IncludedInVersions` equality is exact
text equality between qualified concrete strings, not SemVer precedence equality.
This is an explicit bounded interpretation of the string-membership pseudocode,
not qualification of npm's accepted spelling/normalization or producer equivalences.
Metadata/case/prefix claims remain recorded, never silently rewritten. Differing
build metadata can compare equal in O10 yet fail this list's literal membership.
A future producer contract outside this subset requires separate qualification.

A supported positive clause may coexist with an unevaluated sibling and retain its
positive version-only result **with incomplete-evaluation limitations**. An unknown
condition within the purported winning range cannot be ignored to certify that
range. No version-only positive can bypass unqualified query/header/identity/origin/
activity gates in an eventual advisory evaluator. Invalid-present optional lists
are not the same as absent lists. Absent/empty lists only remove that optional
alternative; they do not establish a global no-match by themselves.

Here `affected` is the exact version-bearing portion of the synthetic affected object;
all omitted optional lists remain omitted. Range arrays contain full type/events.

| ID | affected fragment | Query | Expected version condition |
| --- | --- | --- | --- |
| A01 | {"versions":["1.2.3"]} | "1.2.3" | match |
| A02 | {"versions":["1.2.3"]} | "1.2.4" | no-match |
| A03 | {"versions":["1.2.3+one"]} | "1.2.3+two" | no-match |
| A04 | {"versions":["1.2.3+one"]} | "1.2.3+one" | match |
| A05 | {"versions":["1.2.3","1.2.3"]} | "1.2.3" | match |
| A06 | {"versions":["1.2.3",null]} | "1.2.3" | match, incomplete sibling evaluation |
| A07 | {"versions":["1.2.3",null]} | "1.2.4" | indeterminate |
| A08 | {"versions":["1.2.3","v1.2.4"]} | "1.2.4" | indeterminate |
| A09 | {"versions":["1.2.3"],"ranges":[{"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"3.0.0"}]}]} | "2.5.0" | match |
| A10 | {"versions":["1.2.3"],"ranges":[{"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"3.0.0"}]}]} | "1.5.0" | no-match |
| A11 | {"versions":[],"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]} | "1.0.0" | match |
| A12 | {"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]} | "2.0.0" | no-match |
| A13 | {"versions":["1.2.3"],"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]} | "1.2.3" | match, incomplete ECOSYSTEM evaluation |
| A14 | {"versions":["1.2.3"],"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]} | "1.2.4" | indeterminate |
| A15 | {"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"}]},{"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"3.0.0"}]}]} | "2.0.0" | match |
| A16 | {"versions":[]} | "1.0.0" | indeterminate; no usable version condition |
| A17 | {} | "1.0.0" | indeterminate; no usable version condition |
| A18 | {"versions":null} | "1.0.0" | indeterminate |
| A19 | {"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"}]},{"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"3.0.0"}]}]} | "1.5.0" | no-match |
| A20 | {"ranges":[{"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"3.0.0"}]},{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]} | "2.5.0" | match, incomplete ECOSYSTEM evaluation |

## Abstention and malformed-evidence cases

These are PackTrace qualification policies, not claims that OSV's Boolean pseudocode
alone represents partial/malformed evidence. Locators/states/problems remain visible;
no field is coerced or erased. GIT/unknown types and unsupported ecosystem semantics
are not necessarily invalid advisory data. A canonical query cannot qualify them.

| ID | Explicit condition or exact fragment | Query | Expected version condition |
| --- | --- | --- | --- |
| U01 | Header schema unknown/unsupported | "1.0.0" | indeterminate; no v1 semantics |
| U02 | Otherwise usable SEMVER range | "^1.0.0" | indeterminate; no concrete query |
| U03 | Otherwise usable SEMVER range | null | indeterminate; query unavailable |
| U04 | {"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0.0"}]} | "1.0.0" | indeterminate; npm comparator not qualified |
| U05 | {"type":"GIT","events":[{"introduced":"0"}]} | "1.0.0" | indeterminate; no Git reconstruction |
| U06 | {"type":"OTHER","events":[{"introduced":"0"}]} | "1.0.0" | indeterminate; unsupported type |
| U07 | {"type":"SEMVER","events":null} | "1.0.0" | indeterminate; events not inspectable |
| U08 | {"type":"SEMVER","events":[]} | "1.0.0" | indeterminate; not a satisfied empty range |
| U09 | {"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"not-a-version"}]} | "1.0.0" | indeterminate; relevant unusable bound |
| U10 | {"type":"SEMVER","events":[{"introduced":"0","fixed":"2.0.0"}]} | "1.0.0" | indeterminate; no preferred event kind |
| U11 | {"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"},{"last_affected":"1.5.0"}]} | "1.0.0" | indeterminate; structural contradiction |
| U12 | {"type":"SEMVER","events":[{"introduced":"0"},{"future_bound":"2.0.0"}]} | "1.0.0" | indeterminate; unsupported field retained |
| U13 | {"type":"SEMVER","events":[{"introduced":"0"},null]} | "1.0.0" | indeterminate; non-object evidence retained |
| U14 | {"type":"SEMVER","events":[{"introduced":"0"},{"limit":"not-a-version"}]} | "1.0.0" | indeterminate; upper permission unqualified |
| U15 | Root affected:null | "1.0.0" | indeterminate; affected list uninspectable |
| U16 | Root affected:[null] | "1.0.0" | indeterminate; affected member uninspectable |

## Required later acquisition/execution plan — not authorized here

A later evaluator increment needs its own approved specification and implementation
plan before production work, and separate approval for any dependency/source/toolchain
acquisition or execution. The previously discussed semver candidate is **not adopted**
by these examples. That future plan must explicitly:

1. Pin the candidate/version/license and review source/security/notice obligations
   under authorized acquisition; no implicit toolchain/module download during checks.
2. Map strict text qualification, large numeric handling, precedence, exact list
   membership, sentinels, derived event ordering, ties and alternative limits to
   candidate capabilities plus minimum PackTrace-owned logic. Default/loose parsing,
   generic constraint helpers or invalid-string ordering cannot define the contract.
3. Define consumed projection guards, same-document provenance, all-slot work limits,
   owned outputs and incomplete-evaluation diagnostics; preserve existing raw reader,
   version/range budgets and uncertainty, without inventing a shared public model.
4. Specify synthetic behavioral RED/GREEN, including every row ID, original-source
   snapshots and targeted mutations for fixed/last_affected inclusivity, prerelease
   exclusion, metadata membership conflation, minimum-limit intersection and source
   sorting/tie dependence. Do not generate the expected side using the tested code.
5. Execute fresh actual-tree root tests/vet only under approval; report candidate
   limitations/native/producer gaps, exact test counts/toolchain and independent
   review. A limitation cannot be hidden as no-match or resolved by weakening fixtures.

This preparation documents requirements for that separate plan; it does not create,
approve or execute it. ECOSYSTEM npm syntax/comparison and producer compatibility,
identity/origin/withdrawal qualification, installed evidence and full advisory
aggregation need their own acceptance rather than being inferred from these tables.

## Documentary acceptance and coordination

- Every row has a stable unique ID, exact literal input/conditions, expected outcome
  and a cited rule or explicitly stated conservative/profile policy. Positive partial
  cases disclose limitations; empty/unsupported data never invents a clean result.
- Reference consultation, synthetic authorship, the strict-profile choices and
  non-normative abstentions are distinguishable from observed implementation evidence.
- Self-review checks JSON literal readability, links, grammar/precedence/boundary
  expectations, ambiguity, contradictions, scope and unchanged existing tracked files.
  Syntax/link checks are not executions of a version evaluator or conformance tests.
- The user approved this written artifact and draft publication. The future written
  qualification/acquisition/execution plan and its approvals remain separate.
  A separately agreed independent reviewer must review the final published artifact;
  a request is not approval. #15 remains open/Preparation until its own gates advance.
- No shared milestone edit, production Go, new Go tests, dependencies/go.sum, public
  API, corpus/target/native/CI execution, PR #28 merge or capability/shipping closure.
