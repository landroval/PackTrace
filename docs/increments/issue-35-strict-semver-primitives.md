# Issue 35: strict concrete-SemVer primitives

Status: **approved specification; local implementation verified; peer review/publication pending**. The user approved this complete
written artifact and its complete implementation plan. The user then explicitly
authorized local inline execution of #35: its two Go files, TDD, owned offline
tests/vet, restored mutations and scoped local code/evidence commits. I completed
that local increment with the observed evidence below; publication, agents/workflows,
executable or dependency acquisition, CI, merge and closure are not authorized. I keep [#35](https://github.com/landroval/PackTrace/issues/35)
OPEN / Preparation, owned by `landroval`, under capability #6.

Base: integrated development `76ef90daf36c4b4fae2b234369859108440fc24e`.
Authority: [matching decisions](../design-decisions.md#10-advisory-matching-semantics),
[toolchain/dependency baseline](../design-decisions.md#24-toolchain-and-dependency-baseline)
and [collaboration gates](../github-collaboration.md).

## Purpose and ownership

I want to unlock later OSV SEMVER evaluation with the smallest owned strict parser
and precedence comparator. I reuse the approved [#15 reference contract](issue-15-osv-version-fixtures.md#strict-syntax-fixtures),
not the permissive external candidate. I do not reopen #15's optional probe.

This specification defines primitives, not an advisory evaluator. I qualify exact
text syntax and ordering only. Neither success nor equal precedence establishes
literal equality, package identity, registry origin, activity, installation,
affectedness, findings, coverage, safety or producer compatibility.

My documentary scope is this file alone. Later implementation, if separately
approved, owns only `internal/intel/semver.go` and `internal/intel/semver_test.go`.
I leave readers, projections, error implementation, module files, shared design
and shipping milestones unchanged. #23 owns its separate documentary lane; neither
lane depends on the other's implementation or changes its interfaces.

## Proposed internal API

These declarations describe the complete proposed API and opaque representation;
they are not implementation code. The fields are unexported and have no setters,
constructors, JSON/wire contract or public SDK promise.

```go
package intel

type SemVer struct {
	text       string
	core       [3]string
	prerelease string
	qualified  bool
}

func ParseSemVer(text string) (SemVer, error)
func (v SemVer) Text() string
func CompareSemVer(left, right SemVer) (int, error)
```

- `ParseSemVer` returns a qualified value and nil error only for exact in-profile
  text within the byte allowance. Any error returns the whole zero `SemVer{}`.
- `Text` returns the exact original decoded text, including case and build metadata,
  without normalization. For the zero value it returns `""`; this does not qualify
  an empty version. Successful values own their bounded stored text; component
  views reference that owned text, not a larger caller string's backing storage.
- `CompareSemVer` accepts successful parser values and copies thereof. It rejects
  either unqualified/zero operand before comparison. Success returns exactly -1,
  0 or +1 for less, equal precedence or greater. Error returns 0 **with a non-nil
  error**; that zero is not a qualified equality result.
- The empty prerelease view on a qualified value means a release, because the
  parser rejects an explicit empty prerelease. Build is validated and retained in
  `text`, never used for precedence. I introduce no independent build-identity API.
- Ordinary callers cannot mutate private fields. Same-package fabrication, unsafe
  string mutation and concurrent unsafe mutation are outside the precondition;
  these functions do not authenticate fabricated private representations.

## Exact grammar

I apply [SemVer 2.0.0](https://semver.org/spec/v2.0.0.html), clauses 2, 9–11 and its
grammar, as selected in #15. I preserve that contract rather than consult or adopt
new dependency behavior. No new external source acquisition was performed here.

1. The core is exactly three nonempty ASCII decimal components separated by dots.
   Each is `0` or starts with `1`–`9`. There is no sign, fraction, exponent or
   machine-integer ceiling; each component remains canonical digit text.
2. Optional prerelease starts with one `-` after the core. Its dot-separated
   identifiers are nonempty ASCII `[0-9A-Za-z-]`. An all-digit identifier has no
   leading zero except the single `0`; nonnumeric identifiers may contain leading
   digits and zeroes. A single hyphen is a legal identifier.
3. Optional build metadata starts with one `+`, after core or prerelease. Its
   identifiers use the same nonempty ASCII character set, but numeric build
   identifiers may have leading zeroes. A second `+` is invalid.
4. I do not trim, strip `v`/`=`, fold case, normalize Unicode, resolve declarations,
   invent missing components or clean invalid spellings. NUL, controls, whitespace,
   invalid UTF-8 and all non-ASCII bytes are outside this profile.
5. Exact `"0"` and `"*"` remain outside concrete-version syntax. Their event-sentinel
   roles belong to a later separately approved range evaluator.

Outside-profile is not a claim that evidence is invalid in every npm/OSV context.
It cannot be converted into an invented version or no-match.

## Precedence and work allowance

I compare major, minor and patch numerically in that order. Canonical decimal
length then lexicographic digit order supplies arbitrary-size numeric comparison;
no integer conversion, floating point, saturation, truncation or rounding is allowed.

When cores agree, a release exceeds any prerelease. Prerelease identifiers compare
left-to-right: numeric identifiers numerically, numeric below nonnumeric, nonnumeric
lexically by ASCII byte order. After an equal prefix, the shorter identifier sequence
has lower precedence. Build metadata has no effect. I neither rewrite input nor sort
any source evidence arrays to compare two values.

The agreed per-text maximum is **1 MiB = 1,048,576 bytes**, inclusive, measured by
`len(text)` before scanning, copying or decomposing text. An oversized input returns
`limit-exceeded` even when its syntax is also malformed. This is a PackTrace work
ceiling, not a SemVer numerical rule. Within it, neither numeric magnitude nor
identifier count has a separate ceiling; the total bytes bound both. I require
linear parsing/comparison work, no recursive descent over identifiers or repeated
prefix copying. At most two qualified 1 MiB texts participate in one comparison.
The allowance is not an RSS guarantee or native qualification.

## Controlled errors and separation

I reuse the existing `*intel.ParseError` without modifying it. The only errors this
API may emit are:

| Operation/condition | Code | Exact `Error()` text | Result |
| --- | --- | --- | --- |
| Parse input exceeds 1 MiB | `limit-exceeded` | `intel: limit-exceeded` | Whole zero value |
| Parse within allowance but outside exact grammar | `invalid-semver` | `intel: invalid-semver` | Whole zero value |
| Compare either unqualified operand | `invalid-shape` | `intel: invalid-shape` | 0 plus error |

I return fixed categories, never text, lengths, component indices, decoder details
or wrapped input-dependent errors. `invalid-semver` means outside this selected
profile; it does not make a malformed advisory disappear from coverage. No error
is a matching decision. Successful values can contain sensitive version text and
are not automatically public-log/report-safe output.

I do not consume `OSVString` or lockfile fields directly. Callers retain absent,
null, invalid-type, unsupported and provenance states independently. A caller must
not pass a fabricated fallback string to rescue missing/unusable evidence. In
particular, #15 O16's null/unavailable side maps to an unqualified zero operand,
not the concrete text `"null"` or a silently invented version.

## Independent reference and boundary expectations

These tables are documentary expectations, not a runtime corpus. My corresponding
Go tests now carry independently authored literal expected outcomes and cite their
IDs; they do not read Markdown at runtime or derive expectations through this
parser/comparator. Actual execution evidence appears below.

I reuse all **S01–S34** and **O01–O16** from #15, unchanged:

- S01–S11 parse successfully and return exact text; S12–S34 return whole-zero
  `invalid-semver` within the work allowance.
- O01–O14 compare qualified parser values against the literal less/equal/greater
  expectations, including values beyond uint64 and distinct build spellings.
- O15 first rejects the prefixed input; comparing its unqualified result is also
  rejected. O16 preserves unavailable evidence through a zero operand. Both stay
  indeterminate in the source contract; neither is returned as an ordering.

For the following recipes, `repeat(c,n)` means exactly n copies of the stated
ASCII character. This is deterministic authored input construction, not an oracle.

| ID | Exact input or condition | Expected observation |
| --- | --- | --- |
| P01 | `repeat("1",1048572) + ".0.0"` | Exactly 1 MiB; successful core and exact text |
| P02 | `repeat("1",1048573) + ".0.0"` | 1 MiB + 1; whole-zero limit-exceeded |
| P03 | `"1.0.0-" + repeat("1",1048570)` | Exactly 1 MiB; successful numeric prerelease |
| P04 | `"1.0.0+" + repeat("0",1048570)` | Exactly 1 MiB; successful numeric build |
| P05 | `repeat("!",1048577)` | Oversized malformed text; limit before grammar |
| P06 | `repeat("1",1048571) + ".0.0"` | 1 MiB - 1; successful, no integer ceiling |
| P07 | P06 versus P01 | -1; independently known digit-length ordering |
| P08 | `"1.0.0-a-b"` | Successful nonnumeric prerelease |
| P09 | `"1.0.0+001.000"` | Successful build numeric zeroes |
| P10 | `"1.0.0-0.1"` | Successful numeric prerelease components |
| P11 | `"1.0.0-00"` | Whole-zero invalid-semver |
| P12 | `"1.0.0\u0000"` | Whole-zero invalid-semver; decoded NUL not stripped |
| P13 | bytes `31 2e 30 2e 30 2d ff` converted directly to a Go string | Whole-zero invalid-semver; invalid UTF-8 |
| P14 | `"１.0.0"` | Whole-zero invalid-semver; fullwidth digit not normalized |
| P15 | `"1.0.0++"` and `"1.0.0-+x"`, separately | Whole-zero invalid-semver for each |
| P16 | `"1.0.0-x+build"` versus `"1.0.0-x+other"` | 0, nil error; texts remain unequal |
| P17 | `"1.0.0-001x"` versus `"1.0.0-1"` | +1; first identifier is nonnumeric |
| P18 | `"1.0.0--"` versus `"1.0.0-0"` | +1; hyphen identifier is nonnumeric |
| P19 | `"1.0.0-a.1"` versus `"1.0.0-a.1.0"` | -1; equal-prefix sequence length |
| P20 | Zero versus valid `"0.0.0"`, valid versus zero, both zero | 0 plus invalid-shape for each |
| P21 | Zero value `Text()` | Empty string; still unqualified, never concrete zero |
| P22 | Valid value copied; original/input variables subsequently reassigned | Copy retains exact text and identical qualified precedence |
| P23 | Valid parsing/comparison repeated, and both directions of each successful O row | Identical results; reversal has the independently reversed sign |
| P24 | `"1.0.0-private-marker!"` | Whole-zero invalid-semver; fixed error without prefix or marker disclosure |
| P25 | `"1.0.0-" + repeat("a.",524284) + "a"` | 1 MiB - 1; successful, no independent identifier-count cap |
| P26 | P25 versus `"1.0.0-" + repeat("a.",524283) + "a"` | +1; late equal-prefix sequence length, bounded iterative work |

No returned comparison establishes exact-list membership. O10/P16 are explicit
counterexamples: equal precedence retains unequal original spellings. Range,
enumerated-version and OR-aggregation interpretation remain excluded.

## Review and later execution gates

I require five review classes: exact grammar; numeric/prerelease precedence;
independent allowance/error precedence; immutable text/zero-value guards; and
privacy plus the distinction between ordering and advisory conclusions.

The approved plan requires observed API RED, behavioral RED/GREEN, fresh
owned offline focused/root tests and vet, and independent restored mutations for
normalization, leading zeroes, lexical numeric comparison, build-as-precedence,
missing qualification guards, and byte-boundary/late-identifier errors. Compiler
failure is not behavioral RED, zero selected tests are not evidence, and every
mutation must be restored before final checks/commits. I observed these gates in
local execution, without treating them as product or native qualification.

I will request independent final-head review separately; author review or an agent
critic is not peer approval. I will not close #35/#6, check shipping milestones,
publish, acquire dependencies/toolchains, access targets, run package managers,
change CI/runners or claim operational/native/producer/pilot qualification here.

## Documentary acceptance

- [x] I obtain approval of this complete written specification before preparing its plan.
- [x] I verify API syntax, all 50 source reference IDs, 26 new row IDs, literal/recipe
  boundaries, links, scope and unchanged integrated source without executing Go tests.
- [x] I record local scoped specification/approval, implementation and evidence commits,
  with actual author-review limits. Publication and independent review remain separate.
- [ ] I obtain separately authorized publication/review and final-head peer approval;
  no draft publication or review request is implied by local drafting.

## Local implementation evidence and limits

I recorded explicit local inline execution authority in `ca2b00b0` before Go,
then committed only the two planned Go files in `79e5db47`. I reused the complete
approved GREEN bodies and unchanged private error implementation; I added no
consumer, dependency, go.sum, workflow or shipping milestone.

I observed fresh offline baseline **2,709** tests/subtests plus vet exit 0;
missing-API compilation RED; then a compiling stub with **79 failed / 1 passed**
tests/subtests (all 75 nontrivial reference IDs failed, zero Text P21 passed).
Initial GREEN was **80 focused / 2,789 root** plus vet. I independently observed
and SHA-restored 12 grammar/order/guard/privacy/count mutants. In author review,
a patch-omission mutant survived the initial tests; I added six literal
axis-discriminating cases in the same test file and observed five failures against
that mutant before restoration and full GREEN.

My fresh final root JSON stream has **2,796 passed tests/subtests**, including
**87 SemVer** (4 suites / 83 leaves), all **50 S/O + 26 P source IDs**; no
fail/build-fail events or stderr. Final owned offline vet exits 0. I count one
root stream, not a sum of focused/parallel runs. The compiler is the existing local
`go1.27.1-X:nodwarf5 linux/amd64`, not official reproducible/native qualification.
The [plan](issue-35-strict-semver-primitives-plan.md#observed-local-execution)
records individual mutant results, review classes, methodological rulings and
limitations.

I completed author self-review only; no independent agent/human approval occurred.
No remaining in-scope blocker or deferred minor was identified by that review.
Backing-storage cloning/component views were reviewed in source, not qualified
through RSS measurements or unsafe mutation experiments. Tests/order equality do
not prove matching, completeness, safety, producer compatibility or platform support.
I keep the original checkout, #23, the local-only unrelated deletion checkpoint,
shared design/milestones and routing untouched. Publication, final-head peer
review, integration and issue/parent closure remain separately gated.
