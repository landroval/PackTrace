# Issue 6: explicit offline investigation of ambiguous origins

## Functional result and authorization

The owner explicitly chose policy-authorized local candidate lookup after the
remaining design10 acceptance gap was identified. Previously the operational
scanner emitted unknown rows without looking up any unqualified origin. That
remains the default; a new optional boolean changes investigation, not trust:

```json
{"advisoryCandidates": true}
```

This field belongs to the existing complete policy and requires its independent
operator digest pin before target content access. Only the current npm manager
profiles are admitted. `false` or omission preserves prior behavior; null and
unsupported policy forms are refused. No implicit Bun interpretation, network,
source acquisition, credential loading, origin authentication or enforcement
permission is added. Existing public registry/exact-origin grants are unchanged.

## What can be investigated

With the option enabled, a canonical recorded npm name and strict concrete
version may be queried in the already selected **local** intelligence snapshot,
even when its origin is private, unknown or fails namespace correspondence.
Declared selectors are not concrete queries. Unsupported alias resolution
strings are not split/normalized into identities. File, Git, workspace and link
claims do not silently gain public npm interpretation.

Locked candidate assessments require their selected native npm lock evidence.
Installed candidate assessments require their **own** complete physical manifest,
concrete version and specific complete native directory-metadata witness. A
qualified selected lock is not required merely to investigate a physical
candidate, and no qualified `lockedObservation` relationship is invented.
This does not prove that package contents are authentic or code executed.

The existing grouped reader/evaluator is reused for all observations of the same
identity/version without merging physical instances. The grant does not reset
64-active,4096-total work/decision,512MiB actual-read, five-minute, IPC, retention
or original-generation lifecycle limits. Failed reads and cancellation remain
charged; original/catalog/EOF/digest/stability/lease checks stay mandatory.

## Candidate versus finding

A supported version-positive original becomes an active **candidate** only when
its source and type profile qualify and activity is known/not withdrawn. Unknown
profiles/corrections/activity and withdrawals cannot manufacture active candidates.
A candidate is always:

- `candidate: true`, with version support retained;
- final `outcome: indeterminate`, origin unqualified and no invented lock grant;
- `enforcementEligible: false`, with unresolved-origin and other gaps visible.

A per-record version negative under ambiguous origin remains final indeterminate,
not a qualified negative. Partial version positives retain their limitations and
first-condition diagnostics. Existing qualified public observations still produce
ordinary eligible findings and never become candidates merely because the option
is enabled. An exact origin-rule mismatch cannot use candidate investigation to
fall back to confirmed registry authority.

Parent admission checks lookup permission, pin, typed endpoint evidence, allowed
candidate state and assessment shape. The matching-only portable graph separately
binds the selected-lock evidence ID and each installed manifest's directory-witness
ID; observation references must agree with those joins. Same-workspace completeness
alone cannot substitute another source or directory witness. These opaque numeric
joins contain no names or paths and do not claim parent-side physical reexecution.
Truncated requirement/alias evidence suppresses locked candidate lookup for the
affected source; independent complete physical manifests may still be investigated. Even an assessed row with `candidate: false`
and an advisory ID needs the opt-in; a forged inactive assessment cannot bypass
the permission. This is structural protocol validation, not independent parent
reexecution of original semantics.

## Presentation and privacy

Advisory-selected schema **1.6** separates `advisories.candidates` from confirmed
eligible `advisories.findings`; both count observation rows, not distinct incidents.
Terminal marks candidate-only rows. JSON carries the same state. SARIF keeps
candidates in the structured run report but does not turn them into alerts.
Portable output retains opaque observation/advisory relationships and no private
names, URLs, hashes or local paths. Explicit local output may include the existing
approved bounded investigation details; neither lookup nor local mode grants
upload permission. Policy may still require portable. Historical builders and
report-shape safeguards are preserved.

## Verification boundary

The functional fixture uses the existing authored `matching.bundle`, a private
credential-bearing inert resolution string and physical name/version manifests,
never package code. Checks compare opt-out zero identity reads with opted-in
locked/installed candidates, private-value non-disclosure, policy pin refusal,
known withdrawal/unknown-correction suppression, qualified-public behavior,
portable/local parity, protocol forgeries and unchanged global coverage/exit3.
An additional authored two-original fixture shares an advisory alias while keeping
its matching and negative version conditions independent. Actual CLI acceptance
covers local target-name versus alias-directory preservation, portable opacity,
opt-out zero identity reads, indeterminate alias locks, and a qualified public
control with separate findings/negatives rather than merged ranges.
Actual standalone CLI output, focused controls, source criticism and final root
race/vet support delivery; they do not establish full-source/platform qualification.

This implements the missing visible-candidate behavior, not general #8 exceptions
or proof that every #6 shipping case is accepted. No already exhausted real-record
read/scan or native/source/SDK campaign is renewed. Issue closure requires actual
capability acceptance and integration, not a new counter or an isolated test pass.
