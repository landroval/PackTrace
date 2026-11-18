# Bounded compact policy source fix (local, partial)

This additive development change repairs **policy source admission only**. It does
not claim B6 completeness, native qualification or performance qualification.
The existing [metadata capacity finding](b6-metadata-capacity-check.md) remains
valid for the unchanged legacy policy and original witness.

## Authority and limits

Version-1 policies may explicitly select `referenceTable` instead of `references`.
`same-location-lockkey-v1` has six explicit string cells per row (location, name,
version, origin, expected SRI, archive), an explicit shared classification and an
explicit shared context. It asserts only `lockKey == location`. Nothing is inferred
from the target, lockfile, registry, archive name or package name. Differing lock
keys or per-row classification/context require legacy objects.

The parser immediately expands to the existing ordered `[]Reference`, then calls
`ValidatePolicy`. There is no parallel authoritative catalog or wire format. Both
encodings together, neither encoding, unknown formats/fields, alternate-case or
duplicate keys, nulls and malformed tuples fail closed. All legacy validation is
retained. Pins/continuity still authenticate the actual external **source bytes**;
source reread and normalized-plan equality still precede target collection. An
encoding change needs explicit review and a new pin; no old policy gains grants.
See the synchronized [English](../user-guide.md#integrity-references) and
[Spanish](../user-guide.es.md#referencias-de-integridad) user contracts.

The existing 262,144-byte source ceiling, 20,000-reference ceiling, JSON depth,
frame/traffic ceilings and every private budget are unchanged. Source JSON receives
the existing bounded syntax/duplicate/surrogate check. Expansion streams fixed
six-string tuples; no variable-width row arrays are retained. Decoded row text is
bounded by source bytes; lock keys share the location string. Shared values are
validated short enums *before* expansion. Reference structs/slice growth and
semantic-validation work are bounded by the existing reference count (including
failed parsing); there is no decompression, recursive expansion, chunk retry or
budget renewal. This is a bounded-allocation/work argument, not a hard RSS claim.
The existing normalized policy/config wire admission is deliberately not enlarged.

## Measured frozen 1,000-package metadata fixture

The unchanged `check_metadata_capacity.py` generated the same fixture names and
source metadata. All 1,000 authored reference values are retained, in order.
`TestOfflineCompactPolicyCapacity` checks actual native source acquisition,
production channel envelopes/decoding and both sender/parent original admission.
It does not compare 1,000 package payloads or run a 1-GiB/50,000-package campaign.

| Measurement | Bytes/count |
| --- | ---: |
| Legacy policy source (including LF), still rejected | 392,346 |
| Explicit compact policy source, admitted | 247,438 |
| Exact expanded references | 1,000 |
| Normalized policy frame including envelope/LF | 392,555 |
| Normalized config frame including envelope/LF, local run paths | 393,147 |
| Original semantic rows, unchanged | 6,006 |
| Original envelope including LF, unchanged | 2,848,088 |

### Remaining first gate, not bypassed

`scanPolicyMaterialBuffer.emitOriginal` checks
`observations + evidence + original inputs` against the shared 4,096 private-row
capacity **before** normalization, validation, marshaling or sending. This fixture
still has `3,001 + 2,003 + 1,002 = 6,006`. `addOriginal` independently refuses the
same witness. No original frame is sent or retained, and no prefix authorizes
completion. The original frame would independently exceed the unchanged 1-MiB
limit. The actual compact source now passes the earlier source gate, but whole
integrity is not established.

Replaying the existing full `Result` and passing it to unchanged `addOriginal`
cannot solve this invariant. Recounting that result as 2,003 primitive rows or
charging only its 1,002 inputs would change the current private-row metric; this
patch does neither. A future replay protocol would need an explicitly reviewed
accounting/retention contract for both primitive acquisition and decoded derived
work, not just a smaller encoding of the same result. Public numeric evidence
alone does not reconstruct physical paths, stable-read hashes or slot bindings.
No source bytes, observations, native bindings, comparison witnesses or public
joins are skipped here. Private accounting, including failed work, is untouched.

## Evidence and checks

Exact local commands, RED/GREEN output, generated source manifest, compact source,
capacity report and verification exits are retained outside the repository under:

`/home/justcharles/.local/state/packtrace/advisory-completeness-RIKjKdJf/scale-fix/local-fix-kZUpFqTf`

The new parser/native tests cover legacy-normalized equivalence, ordered expansion,
strict rejection, original-byte pinning and external-source mutation. The real
supervised CLI tests exercise valid evidence, modified content, absent archive,
missing installed manifest and conflicting identity, with both privacy modes and
unchanged target bytes. Positive integrity coverage still does not turn the
separate native/global gates into success. Existing validators and whole-integrity
joins remain the production authority path.

Root `go test ./...` and `go vet ./...` passed through the pinned offline `go.sh`.
Serial affected races passed for integrityscan, projectinventory, execution and
CLI, plus a fresh opt-in metadata-capacity fixture. Every race partition retained
the 180-second wall/test ceiling. Three overcombined preliminary partitions timed
out (execution, whole CLI, remaining CLI); their exit-124 logs are retained, not
reported as passes. Smaller serial partitions subsequently covered all their
cases. Existing unrelated opt-in campaign tests remained skipped; no native/perf
campaign, network, install, push, operator-key or real-store operation was run.
