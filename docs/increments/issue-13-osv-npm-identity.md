# Issue 13: bounded OSV npm identity candidates

Status: the bounded PURL profile and case-preserving ASCII/legacy-name direction
are approved for drafting. This written specification, implementation plan and
explicit production execution authorization remain pending.
Tracking: [issue #13](https://github.com/landroval/PackTrace/issues/13).
Authority: [design decisions](../design-decisions.md#10-advisory-matching-semantics).
Prerequisites: integrated [header evidence](issue-12-osv-header.md) and
[affected identity claims](09-osv-affected.md). No dependency on open #14/PR #27.

## Goal and references

Interpret explicit advisory npm identity claims into an **unconfirmed identity
candidate**, unqualified result or visible conflict. This is lexical/profile
interpretation, not registration/publication validation, origin equivalence,
installed evidence, advisory activity or matching/enforcement eligibility.

Public specification references only; no corpus, package, target or dependency:

- [Pinned OSV 1.9.1 package rules](https://github.com/ossf/osv-schema/blob/8e3305dedc0786c4869c7bb0b14564e03ec277b3/docs/schema.md#affectedpackage-field):
  package ecosystem and name are required **inside the object**; npm is spelled
  exactly `npm`. PURL is optional and without a version component. Package itself
  can be absent, notably in Git-only evidence. The OSV query API's alternative
  PURL-only request form is not this advisory-record contract.
- [Pinned npm PURL definition](https://github.com/package-url/purl-spec/blob/7cd2d3442fb9c88155db17ada7c911b40ec22d41/docs/types/definitions/npm-definition.md):
  namespace/name are case-sensitive, the scope @ prefix is percent encoded, and
  old mixed-case names were grandfathered in. Default-repository syntax is not
  evidence confirming an investigated dependency's public origin.
- [npm v10 package.json name rules](https://docs.npmjs.com/cli/v10/configuring-npm/package-json/):
  total name length including scope is at most 214 characters; scoped package
  names may begin with dot/underscore; the lowercase rule is for new packages.
  This reference is not a claim of producer/runtime qualification.

The selected lexical subset deliberately does not implement a full npm publishing
validator or all PURL types/forms. Unsupported evidence is not silently invalidated
or treated as negative affectedness. The original document remains source authority.

## Proposed internal interface

Only new `internal/intel/osv_npm_identity.go` and `osv_npm_identity_test.go`.
Do not change readers, OSVAffectedEntry, OSVHeader, shared states or inventory types.
No generic inventory/intel identity model, dependency or network operation.

```go
type OSVNPMIdentityQualification uint8

const (
    OSVNPMIdentityUnknown OSVNPMIdentityQualification = iota
    OSVNPMIdentityCandidate
    OSVNPMIdentityUnqualified
    OSVNPMIdentityConflict
)

type OSVNPMIdentityProblemKind uint8

const (
    OSVNPMIdentityProblemUnknown OSVNPMIdentityProblemKind = iota
    OSVNPMIdentityProblemEcosystemUnusable
    OSVNPMIdentityProblemEcosystemOutsideProfile
    OSVNPMIdentityProblemNameUnusable
    OSVNPMIdentityProblemNameOutsideProfile
    OSVNPMIdentityProblemPURLUnusable
    OSVNPMIdentityProblemPURLOutsideProfile
    OSVNPMIdentityProblemPURLNameConflict
)

type OSVNPMIdentityProblem struct {
    Kind OSVNPMIdentityProblemKind
    Field string
}

type OSVNPMIdentityEntry struct {
    Index int
    State, PackageState OSVFieldState
    Ecosystem, Name, PURL OSVString
    Qualification OSVNPMIdentityQualification
    PURLUsable bool
    PURLName string
    Problems []OSVNPMIdentityProblem
}

type OSVNPMIdentityProjection struct {
    SourceSHA256 [32]byte
    HeaderSchema OSVHeaderSchemaState
    State OSVFieldState
    Entries []OSVNPMIdentityEntry
}

func QualifyOSVNPMIdentities(header OSVHeader, affected OSVAffectedProjection) (OSVNPMIdentityProjection, error)
```

Consume unchanged successful header/affected projections from the same unchanged
successful OSVDocument, without concurrent mutation. Digest equality/basic guards
are not authentication of forged data. Output fields retain exact source claims;
PURLName is a separately derived lexical claim, never a replacement for missing
explicit ecosystem/name. Source locator: digest + affected Index + package field.
All output collections are owned; later input/output mutation is independent.

## Hierarchy, gate and qualification

- Copy SourceSHA256, HeaderSchema, affected State and every original affected slot,
  preserving order/duplicates. Copy element/package states and all three OSVStrings.
- Non-value top lists have nil Entries; enumerable empty lists have non-nil empty
  Entries. Unusable element/package parents leave children unavailable, not absent.
- Only header V1Implicit/V1Declared permits interpretation. Other header states keep
  exact source hierarchy/claims but Qualification=Unknown, PURLUsable=false,
  PURLName empty, Problems=nil. No unsupported-header negative is inferred.
- An unusable element or non-object/missing package similarly remains Unknown with
  nil Problems/derived PURL. An empty package object is inspectable: absent required
  fields yield Unqualified, not invented children from an unavailable parent.
- For an inspectable package allocate non-nil Problems, even empty. Inspect all
  relevant siblings, rather than stopping after one bad field.
- Ecosystem must be value state and exact `npm`. Absent/null/invalid type yields
  EcosystemUnusable; any other exact string, including empty/space/case variants,
  yields EcosystemOutsideProfile. No trim, case-fold or ecosystem inference.
- Name absent/null/invalid type yields NameUnusable. A string outside the lexical
  subset below yields NameOutsideProfile. Source text is retained unchanged.
- PURL absent is optional, with PURLUsable=false and empty PURLName; it does not
  prevent a tuple candidate. Present null/invalid type yields PURLUnusable and
  prevents Candidate. Present string is parsed by the bounded profile below;
  failure yields PURLOutsideProfile, not absent or a parse-fatal result.
- Independently derive PURLName/PURLUsable for a supported PURL even when explicit
  ecosystem/name is unusable. It never rescues missing/ambiguous required siblings.
- Compare names only when the explicit tuple is usable (ecosystem exact npm, name
  within subset) and PURLUsable=true. Exact case-sensitive mismatch adds
  PURLNameConflict and Qualification=Conflict; equal names leave no conflict.
- Candidate requires the explicit tuple and absent-or-supported-consistent PURL,
  with no problems. Otherwise Unqualified, except the detected two-usable-npm-name
  conflict above. Other ecosystem/PURL forms remain unqualified; do not claim a
  fully parsed cross-ecosystem contradiction from an unsupported PURL domain.
- Problem zero enum values are never emitted. Qualification Unknown is explicit
  abstention, not successful identity evidence.
  Candidate is **not a confirmed or enforceable finding**. A supported lexical
  identity cannot establish public npm origin or complete advisory eligibility.

Problems are emitted in ecosystem, name, PURL order, with NameConflict last.
Fields are fixed `ecosystem`, `name`, `purl` strings, not raw error messages.
Original contradictions and unsupported sibling values remain visible in OSVStrings.

## Case-preserving ASCII name subset

This profile describes identity syntax, not new-package publishing permission:

1. Total decoded name length is 1..214 ASCII bytes/characters, including @ and slash
   when scoped. Preserve every letter's case, including mixed/uppercase legacy names.
2. Allowed component characters are ASCII A-Z, a-z, 0-9, hyphen, dot, underscore and
   tilde. No spaces, controls, non-ASCII, percent signs, colon, backslash, URL/query/
   fragment delimiters, wildcard/asterisk or other punctuation in decoded components.
3. Unscoped form has one nonempty component, no @ or slash, and cannot start with
   dot/underscore. Scoped form is exactly @scope/name, two nonempty components and
   exactly one slash; dot/underscore starts are allowed in scoped components.
4. No canonicalization, Unicode normalization, case-folding, percent decoding of
   package.name, filesystem/path interpretation, alias inference, or registry lookup.
   `*` is outside this single-identity profile even though OSV can record ecosystem-
   wide wildcard advisories. Unsupported does not mean every excluded name is invalid.
5. This subset excludes additional grandfathered punctuation. Do not label it full
   npm compatibility or change the original name claim to make it fit.

## Bounded optional npm PURL profile

- Require exact `pkg:npm/` prefix, no leading/trailing whitespace or case-folding.
  Only unversioned forms: pkg:npm/name or pkg:npm/%40scope/name.
- No literal @, ?, or # in the tail: version, qualifiers and subpath are outside
  the profile. Bare @scope is not accepted in PURL namespace syntax.
- Split the encoded tail into exactly one unscoped component or two scoped components
  **before decoding**. No leading/trailing/doubled slash or extra namespace segments.
- Percent-decode each component once with standard-library path decoding, not query
  decoding. This is interpretation of an explicit PURL claim, not source mutation.
  Valid escapes of unreserved characters are accepted; their decoded case remains
  exact. Malformed escapes, double-encoded scope prefixes, encoded separators/control/
  non-ASCII/disallowed characters fall outside the profile.
- A scoped decoded namespace must start with exactly one @ and have a nonempty scope.
  Reconstruct @scope/name only as PURLName and apply the same lexical name subset.
  A decoded unscoped component must itself be unscoped; escaped @ cannot invent scope.
- Bound raw PURL text at 650 bytes (= 8-byte prefix + 3 * 214); larger text cannot be
  in this ASCII identity subset and yields PURLOutsideProfile before decoding. This
  is a derived profile bound, not a new reader quota or fatal limit-exceeded category.
- No generic URI parser, version parsing, qualifier stripping/fallback, URL opening,
  repository authorization, redirection or public-origin inference.

## Bounds, guards and errors

Reuse existing 20,000 affected slots, counting every position, including unusable and
repeated claims. Check pairing/layout/counts before allocating outputs, regardless
of header/identity abstention; no prefix, filtering or per-identity quota reset.

Basic guards: digest agreement; top list nil/value layout and allowed states;
contiguous original element indices; array-member object/null/invalid states;
package state and immediate child availability consistent with the unchanged
projector. Do not revalidate or copy unrelated versions/ranges. Forged-input
checks are limited to consumed layout, not authentication/full source conformance.

Bad consumed layout/pairing returns existing ParseError invalid-shape; excessive
affected slots returns limit-exceeded. Both produce zero whole output and exact
intel: CODE text, no source values/decoder diagnostics. Semantic/profile problems
produce owned structured results, nil error. Reader 4 MiB/depth-128 and successful
projector budgets remain preconditions, not official/native hard-RSS qualification.

At most three field problems plus one name conflict per inspected package, a
conservative bound of 80,000 problems at 20,000 entries. No result truncation.

## Acceptance and scope checks

Reader-valid in-memory envelopes, except clearly marked forged-guard/budget fixtures:

- All affected/element/package/string states; unavailable vs absent; nil vs empty;
  value siblings beside unusable ones; duplicates, source ordering/locators/digest.
- Both v1 header modes, unknown/unsupported headers and budget guards even on abstention.
- Exact npm/non-npm/space/case ecosystem claims; no inference from PURL/target names.
- Scoped/unscoped names, exact mixed-case legacy names, scoped dot/underscore starts,
  unscoped exclusions; 214/215 total length, malformed structures and opaque exclusions.
- Absent PURL allows tuple candidate; null/invalid/malformed/empty does not. Exact npm
  scoped/unscoped PURLs, escapes, encoding-before-split, case equality/conflicts and
  one-time decoding. Wrong scheme/type, version/query/fragment/bare scope, separators,
  multiple segments, invalid UTF-8/control, 650/651 lexical bounds remain unqualified.
- PURL-only or PURL beside invalid required fields does not become Candidate. Non-npm
  domain comparison stays unqualified, not falsely parsed as a known npm conflict.
- Complete deterministic problems and all source states, nested ownership snapshots,
  unchanged document/projector/reader/module/probes; no new common-model dependency.
- Observed compile then behavioral RED, fresh root tests/vet after inline review and
  actual tested-branch counts only, after separate spec/plan/execution authorization.

No implementation or new test execution is claimed. Preparation is based directly on
integrated development c5337ea8; unreviewed #14 source is absent on this branch. Synthetic
identity cases cannot qualify installed/origin/matching/runtime/native/producer/release.

## Coordination

Owner: landroval, preparation only. Bookmark: issue-13-osv-npm-identity-spec.
Keep #13 Preparation until written spec, plan and explicit execution approvals.
Independent review/integration retain their own gates. PR #27 is ready with jsustt
requested, not approved/integrated merely because this preparation proceeds.

No Go code, downloads/dependencies/corpus/targets, origin equivalence, version/interval
assessment, generic identity model, matcher/negative results, worker/CLI/report/storage,
CI/native probes or capability/shipping closure is authorized by this draft.
