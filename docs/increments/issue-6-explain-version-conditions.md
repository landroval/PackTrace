# Issue 6: explain the first blocking version condition

This local successor extends the [usable offline advisory scanner](issue-6-usable-advisory-scan.md).
It does not broaden identity/origin authority or turn incomplete investigation
into successful negative coverage.

## Useful scanner behavior

The existing version evaluator already produces typed condition problems. The
operational matcher previously discarded them, leaving only `version-unsupported`.
Advisory-selected schema **1.5** now retains optional `firstVersionProblem`:

```json
{"scope":"affected","kind":"version-outside-profile","version":1,"range":-1,"event":-1}
```

This is the **first** fixed evaluator reason, not an exhaustive diagnostics list.
The first global problem takes precedence; otherwise use the first problem from
the selected original's same affected slot. Never borrow another slot's reason.
Absent means no first reason supplied, not full evaluation or complete coverage.
No raw invalid version, boundary, URL, name or advisory contents is copied into
this diagnostic. Portable and local carry identical safe codes and positions.

A supported positive with an unsupported extra condition keeps its match,
support and `fullyEvaluated: false`, plus the reason. A version without positive
support remains indeterminate when a relevant condition is unsupported; it must
not become a negative. A fully evaluated per-record negative has no blocker.
The existing `version-unsupported` gap remains. Unknown corrections still block
promotion independently of version support.

Parent admission closes the kind/scope and kind-specific locator shapes. A
bound advisory and affected slot, partial evaluation and the existing gap are
required. Positions are either the exact allowed `-1` sentinel or below20000;
unknown worker text, contradictory/full-state values and unbound diagnostics
are rejected. This validates public protocol shape, not independent replay of
raw original semantics. Report construction deep-copies the optional value.
Terminal, JSON and SARIF use that report; indeterminate rows are not SARIF
alerts. Historical builders and supplied-input metadata tools are unchanged.

Only one small bounded value is retained per existing decision. Existing64
active identities,4096 total work/decision units,512MiB actual reads, five-minute
scan, IPC/retention/resource guards and original-generation lifecycle are not
raised or reset. No extra source lookups or original reads are introduced.

## Observed OpenSSF descriptive metadata incompatibility

A separately authorized single offline investigation against already acquired
public OSV data reproduced a profile rejection: OpenSSF affected `cwes` contained
bounded descriptive objects, whereas the scanner accepted only string lists.
The original version support and source path were preserved; the old run
correctly remained indeterminate rather than silently promoting a candidate.
That run is historical evidence, not a later successful scan after this fix.

The OpenSSF source profile now additionally accepts a bounded list of objects
with **only** `cweId`, `name` and `description`, requiring a canonical nonzero
numeric CWE identifier and bounded nonempty descriptive text. This shape is
limited to the already supported exact OpenSSF source profile. Existing string
lists remain compatible. CWE text/IDs never choose category: the independently
qualified exact source path is still mandatory. Unknown keys/shapes, missing or
oversized text, conflicting source types and correction fields still fail closed.
No new provider, namespace, publisher authentication or network grant is added.

## Functional checks and limits

The authored `explanation.bundle` is prepared/sealed/exported by the real source
pipeline. It contains a partial version condition with an inert invalid-string
canary and a separate scoped OpenSSF descriptive-CWE record; neither contains
package code or a copied real advisory. Its reproducibility and legacy fixture
bytes are checked. Actual supervised CLI cases verify both privacy modes,
partial-positive/indeterminate outcomes, fixed numeric diagnostics and no raw
canary leakage. Standalone CLI checks cover terminal/JSON/SARIF and observed
installed versus locked evidence through the ordinary import and scan pipeline.

The real-public-data observation uses authored inert name/version manifests, not
real installed package contents; acquisition, freshness, publisher authenticity,
full corpus/platform qualification and overall issue acceptance remain separate.
No real scan is automatically repeated after a fix, no unknown global coverage
is removed, and ordinary incomplete investigation continues to exit3. No merge
or protection exception follows from a local feature or a successful CI run.
