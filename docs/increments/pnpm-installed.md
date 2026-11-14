# Bounded pnpm installed observations and candidate reconciliation

## Approved scope

The owner selected publication of the completed FORMAT 9 reader PR and development
of this separate local increment. PR #108 remains frozen at its reviewed head;
this work is based on that head and is not included in that PR. Merge, publication
of this successor, native CI, releases, installed-binary replacement, real targets,
new acquisitions, advisory refresh and user-policy changes are not authorized.

A new bounded fixture grant permits only the already verified pnpm 9.15.9 and
10.34.9 tools, at most 12 invocations, 300 seconds and 512 MiB scratch. Scripts
are disabled; networking is restricted to an owned loopback registry in a private
namespace. Copy/peer-context installations are positive evidence; hardlinks are
negative evidence. No system/global pnpm installation or downloads are included.

## Minimal implementation

- Reuse native metadata/input leases and the existing installed walker. Read only
  necessary stable manifests from observed active slots. Single-link means the
  regular manifest has nlink=1, not that only one symlink hop is allowed. Retain
  the existing bounded contained-link chain and all ancestor guards.
- Enable collection only for a usable selected pnpm lock. Never read installed
  manifests after conflicting/uncertain/invalid selection. Keep workspaces out
  of scope and preserve all three mandatory pnpm gaps, one scope and exit 3.
- Activate `.pnpm/<opaque>/node_modules` siblings only through an observed active
  stable linked package in that exact structural layout. Do not derive paths or
  peer identity from lock/snapshot keys; do not activate orphan store containers.
- Generic hardlink refusal and physical containment stay unchanged. No paired
  cache exception, external-store acquisition, `.npmrc`, hooks, config execution
  or dependency-source reads are added. Instability after visiting children must
  invalidate dependent observations and their evidence rather than retaining
  stale activation authority.
- Reuse identity candidate reconciliation, with all pnpm package keys explicitly
  marked as logical tuples. Consider only complete supported package claims and
  complete identified installed observations. Preserve aliases, logical slots,
  duplicate physical instances and ambiguous peer contexts. Relations are only
  `candidate-correspondence/indeterminate`: no physical locked joins, absence,
  conflicts, unique snapshot bindings or declared/specifier agreement claims.
- Public installed observations carry numeric native metadata and manifest
  witnesses, without publishing identities/paths. Parent validation keeps all
  mandatory gaps and incompleteness, accepts older zero-observation reports and
  rejects unsupported relations, false completion and forged witnesses.
- No advisory lookup, eligible finding, integrity comparison/binding, policy
  witness or exception authority is added. Integrity `ObservedEntries` remains
  zero; it is distinct from installed inventory observations.

## Verification

Start with failing owned replay/negative boundary tests, then scoped GREEN.
Cover copy/peer/alias/scoped/bundled layouts, multiple contexts and versions,
orphan stores, link escape/cycles, ancestor instability after child traversal,
hardlinked manifests, conflicting/invalid selection, mandatory gaps under budget
pressure, portable privacy and parent forgeries. Run actual supervised CLI
terminal/JSON/SARIF cases, unchanged-target checks, root tests/vet, relevant races,
and scoped compile-only checks. Update current bilingual docs without rewriting
the historical first-reader contract or claiming full pnpm/native qualification.
