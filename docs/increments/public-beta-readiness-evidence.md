# Public beta: static capability and evidence matrix

Companion: [readiness and implementation plan](public-beta-readiness-plan.md).
This is a **static audit**, not beta acceptance, a new test result or execution
permission. All source references below are pinned to integrated
`c2ba5b93dc121ba7fd4615c11314203a947d1434`, tree
`cc73480cb264d9a929ad504c09a6c712297d3196`, unless marked release evidence.

## 1. Evidence vocabulary and current release state

| Classification | Meaning |
| --- | --- |
| Implemented; historical executed evidence | Code plus recorded execution within the cited host/tree/fixture scope. Not universal support or proof each cited test ran on every row. |
| Implemented; acceptance evidence missing | Mechanism/test exists, but fresh candidate/target/causal evidence for the beta claim is not established. |
| Implementation gap | A specific absent or permanently gated behavior identified in source, not an unchecked old roadmap box. |
| Decision required | Owner/contract/rights/measurement choice; no permission to choose credentials, license or execute a campaign. |
| Deferred/excluded | Outside this beta core, not a passing test or a completed product capability. |

Published alpha.2 source is immutable `1b8203e8172c5d9cc1aaab2a076f91e544dbc3d7`,
tree `c1cd127369dbf0609872b79a4a780cfaf12849ce`. Its delta from the integrated
baseline is nine version/documentation paths, including only a version-string
production Go change. Scanner behavior is identical; version integration is not.
[PR113](https://github.com/landroval/PackTrace/pull/113) was rechecked OPEN in the
principal's final planning readback, not assumed merged from release publication.

Historical release metadata/receipts record 5,904 passes, seven skips, vet and154
owned Linux CLI commands (28 npm/Bun,14 standalone,112 pnpm); the Windows artifact
was cross-compiled only. These figures were NOT rerun in this planning task.
The release manifest deliberately distinguishes later hosted CI from the earlier
published build record. Same-host identical builds and PE headers are not native
acceptance or independent reproduction.

## 2. Current capability, actual gap and beta consequence

| Area / classification | Concrete implementation or test evidence | Consequence for the selected public beta |
| --- | --- | --- |
| Inventory — implemented; historical owned Linux evidence | `internal/projectinventory/collect.go:43`, `selection.go:60`, `locked.go:37`, `installed.go:46`; producer replay tests and current compatibility document | Reuse declared/locked/installed separation, native witnesses, scope/counts and refusal. Qualify actual beta artifacts/FS/rows; do not rebuild inventory because old shipping boxes are unchecked. |
| npm eligible advisory matching — implemented; historical authored evidence | `internal/integrityscan/matching.go:118–270`; `cmd/packtrace/full_matching_scan_test.go:104`; `matching_installed_test.go`; `internal/intel/osv_version_conditions.go` | Positive, negative, version/category/activity/origin and native selected-lock joins already exist. Candidate-bound causal acceptance still needed; a package-name match is not eligible evidence. |
| Bun eligible advisory matching — IMPLEMENTATION GAP for selected scope | `matching.go:118–125,169–175,855–930` requires npm policy/family; `matching_candidates.go`; `matching_bun_candidates_test.go:10` | Existing Bun candidates are indeterminate/non-enforceable. Owner chose bounded full Bun, so eligible source/material/parent validation and tests are REQUIRED, not optional beta parity. Never broaden old policy pins automatically. |
| References/integrity — implemented engine; practical beta-row evidence missing | `internal/integrity/reference_binding.go`, `reference_archive.go`, `reference_compare.go`; `internal/integrityscan/acquire.go`; `cmd/packtrace/policy_integrity_acceptance_test.go:16` | Validate explicit prepared archive/baseline mappings and actual scope for npm and admitted Bun. Equal bytes do not mean safe; absent/invalid references cannot fabricate drift or completion. No general downloader required. |
| Policies/exceptions — implemented; acceptance extension needed | `internal/integrityscan/{policy.go,exceptions.go,policy_evidence_build.go,policy_evaluate.go}`; `cmd/packtrace/policy_acceptance_scan_test.go`; `policy_report_test.go` | Preserve exact expiry/evidence binding, visible accepted findings, original source witnesses and private context. New Bun permissions/completion need consciously reviewed policy semantics; exception cannot waive coverage. |
| Intelligence sync/import/export/freshness — implemented; current-row/lifecycle evidence missing | `internal/intelstore/{source_osv.go,bundle_import.go,bundle.go,prune.go}`; `internal/intel/snapshot_freshness.go`; `docs/intelligence-compatibility.md` | Existing immutable generations, explicit acquisition, original seals and24h/7d freshness stay. Imports/pins/mtime do not renew age. Unknown publishers, index gaps and malformed sources remain explicit. No new live acquisition authorized. |
| Corrections/withdrawals/acceptance causal chain — test/evidence linkage gap, not absent engines | `internal/execution/testdata/intel/README.md` documents `full.bundle`/`corrected.bundle`; generator `internal/intelstore/full_matching_fixture_test.go:86`; evaluator/policy tests | Bounded searches found corrected bundle construction/docs but not actual scan consumption. Check for equivalents first; add only the missing causal CLI link required by the beta lifecycle claim. |
| Required native/resource completion — IMPLEMENTATION GAP for operational0/1 | `internal/integrityscan/result.go:168–202` creates required incomplete native/resident rows; `acquire.go:298–305` denies child/operator qualification | Existing safeguards are not absent, but no positive parent-owned beta completion contract is implemented. Do not turn a worker bit, pin, operator checkbox or dropped row into qualification. |
| Required integrity/advisory completion — additional IMPLEMENTATION GAP | `result.go:178–181`; `advisory_report.go:104–120` leaves selected categories incomplete even with observed decisions | Fixing only native/resident flags is insufficient. B1/B3 must define positive completion for every selected required obligation, preserving relevant unsupported/source/index/read/limit gaps. |
| Aggregate exit selection — implemented selector, positive actual scans missing | `internal/cli/exits.go:15–31`; `exits_test.go:8` covers16 combinations; `policy_report.go:37–114`; `cmd/packtrace/scan.go:32–96` | Owner requires actual complete0/1, not pure-selector results or permanent3. Enforced eligible findings, report-only/accepted findings and all3/2/130 overlaps must be demonstrated on the new core flow. |
| Frozen report and final operation — implemented; new semantics need reviewed integration | `policy_report.go:37–98,135–175`; `ScanRun.WriteReportOutput`/`Finish`; `cmd/packtrace/scan.go:42–55,77–95`; `scan_receipt_test.go:32` | Private parent authority survives rendering; saved JSON cannot recreate it. Comparison precedes output; later output/close/query/reap fault may yield final2/130 without rewriting bytes. No public final-receipt API is assumed. |
| Native Linux/Windows backends — implemented; exact artifact/platform evidence missing | `internal/nativefs/backend_linux.go`, `backend_windows.go`; `internal/nativeresource/child_linux.go`, `child_windows.go`; nativefs/lifecycle tests | Old unfinished tagged probe does not mean Windows backend is absent. Current PE compile-only is insufficient. Require exact runtime/FS/roots and relevant source-test plus actual artifact evidence. |
| Durable Linux state — implemented finite profiles; selected FS execution gap | `internal/nativefs/owned_identity_linux.go:24–149`; `owned_identity_linux_test.go`; intelligence compatibility native-binding description | ext4/XFS/Btrfs query/handle shape support is not runtime qualification. Check original retained UUID/object generation on the actual chosen FS. tmpfs/overlay read-only target admission does not grant durable state support; no unsafe fallback. |
| Runtime supervision/resources — implemented; measured peak/lifetime qualification missing | `internal/execution/scan_lifecycle.go:63–149,200–234,270–389`; Linux/Windows lifecycle tests; `nativeresource` | Samples/1-GiB stop are not a hard RSS ceiling, lifetime peaks, Job commit or complete source-close observation. Final tick precedes later binding closes. Preserve query/gap refusal and actual owned Wait/joins/reap while designing precise final accounting. |
| Fixed numerical performance — owner-selected gate; NOT RUN for this beta | `docs/design-decisions.md`, section18 | 1000instances/50000files/1GiB;4vCPU8GiBSSD; five complete runs median≤90s and conservative sum individual peaks≤1GiB. Freeze identities, method/cache/roots and total budgets before any run; small safety-probe caps cannot be reused for this larger corpus. |
| Setup/privacy/output — implemented; native walkthrough evidence missing | `internal/execution/setup.go`; `cmd/packtrace/setup_scan_test.go:19`; `terminal_summary_test.go`; `policy_output_scan_test.go`; current manuals | Setup/no-clobber/no-reapproval/local/portable and report pipeline exist. Validate fresh-user scenarios and exact core outcome on both rows. Windows stdout is distinct from unsupported guarded file publication. No new wizard, installer or updater is needed. |
| Distribution notices/metadata — implemented; runtime authenticity distinct | Published alpha.2 archives contain16 notice files plus executable/EN/ES readmes; `THIRD_PARTY_NOTICES.md`, vendor YAML LICENSE/NOTICE, `LICENSES/Apache-2.0.txt`; release build manifest | Recorded hashes bind bytes/source; unsigned adjacent hashes are not signatures. Keep proper MIT/Apache portions, software versus dataset rights and no invented project license. |
| Project rights/security/support/authenticity — DECISION + documentation required | No root project `LICENSE`/`SECURITY.md` at frozen baseline; manifest `signatures`/`attestation` null | Owner chooses rights, real monitored intake, maintenance and authenticity route; do not choose a license/address/SLA/key/OIDC policy on their behalf. Full public-beta handoff remains blocked until approved terms exist. |
| Current readiness documentation — reconciliation gap | `docs/development-roadmap.md` says no Go module; pre1.0 checklist has obsolete current schema/missing-engine claims despite `go.mod`, `RunScan` and schema1.7 builder | Correct current claims with evidence, retain dated milestones. Neither unchecked boxes nor closed issues are authoritative implementation/acceptance status. No blanket1.0 completion is implied. |
| pnpm, macOS and extra scope — DEFERRED/EXPERIMENTAL | Current PNPM contracts/corpora and compatibility docs; existing Windows/macOS delivery direction | pnpm9.x–12.x remains bounded FORMAT9 candidate-only partial support with three mandatory gaps; no full PNPM requirement. macOS, additional architectures/FS/distros, hard-RSS, dashboards/TUI and new package families are not silently added. |

## 3. Decisions resolving the audit disagreements

| Audit alternative | Final plan disposition |
| --- | --- |
| A permanently exit-3 public beta could be sufficient | Owner explicitly rejected this for the goal: actual supported complete0/1 is REQUIRED, with genuine3/2/130 preserved. |
| Bun beta could remain inventory/candidates only | Owner selected bounded full Bun. Eligible matching/parent-policy authority and valid-reference evidence are REQUIRED within admitted scope. |
| Performance could be a later optional claim | Owner selected the existing numerical target as a beta gate. No benchmark or larger budget was authorized. |
| WindowsServer-only could substitute for desktop | Not adopted. Versioned design section2 already identifies Windows11 desktop and ServerCI as supporting evidence. Preferred new-beta row is native desktopx64; a limited emulated alternative needs an explicit new scope amendment. |
| Must complete every old five-target/1.0 checkbox | Not adopted. Linux+Windows core, macOS deferred and PNPM experimental are selected. Real safety obligations cannot be removed because old wording was stale. |

Scope decisions do not approve implementation, tool acquisition, signing/security
changes, actual projects or runner/VM actions. Exact architecture/distro/build/FS/
producer-evidence rows and campaign envelopes remain explicit approval gates.

## 4. Required evidence ledger for future work

Each selected claim/case records:

1. Approved scope, original authorization/attempt limit and owner; separate safety,
   performance, producer, preparation, pilot and release envelopes.
2. Immutable source/tree, candidate/archive/executable digests, compiler/settings,
   corpus/hash/independent expected outcomes and prepared reference/snapshot IDs.
3. Actual OS/build/kernel, host/process architecture/emulation, target/config/state/
   reference/output FS and native feature facts. Keep sensitive paths privately.
4. Source-test/fault-injection versus exact-artifact observable method; command,
   named tests/cases that actually ran, expected and actual final process statuses.
5. PASS/FAIL/BLOCKED/NOT RUN per required cell; skip/first-fault/cleanup reason and
   bounded captured diagnostics, complete streams/byte counts/digests where promised.
6. No target write/network/execution, original leases/witnesses, generation retention,
   privacy/local-portable equivalence, query/sample gaps and actual reap observations.
7. Controller-through-finalization wall time, every-role memory method/limits,
   cold/warm conditions and all repeats; missing/unavailable measurements stay unknown.
8. Independent review/disposition and which claims are invalidated if candidate,
   input, platform or relevant code changes. A repaired failure does not reset grants.

Actual final0/1 proof remains missing. Existing test processes may exit0 while their
child scans intentionally exit3. Existing unprivileged source tests, historical
native acceptance, pure selectors and a finished receipt are not interchangeable
with a complete supported beta scan. No result certifies a project or host safe.

## 5. What this planning audit actually did

Four static specialist audits, critical review and synthesis inspected relevant
source/test/docs and bounded retained metadata. The principal checked key gates,
Bun eligibility restriction, the16-case exit selector, existing performance contract,
release/source delta and live GitHub baseline/PR state. The delivery audit also
recomputed local archive/executable/notice hashes without extracting or executing
them; those are that audit's artifact consistency observations, not native proof.

No new product test, build, benchmark, producer/Node invocation, real-target scan,
intelligence synchronization, native/CI run, SDK download, VM/system/security/
credential/signing/permission change, publication or merge occurred. No skills or
historical evidence were modified. Old runtime receipts remain historical; the
source presence of a test is not a claim it ran for every cited row. Exact oracle,
Bun binding usability, environment availability and trusted positive completion
mechanism still need the plan's design and execution contracts.
