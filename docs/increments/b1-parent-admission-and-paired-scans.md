# B1: parent admission boundary and paired actual scans

Parent: `a5d7fda4`. This is a bounded implementation of missing integration
assertions and a reviewable **empty admission contract**, not approval of native
qualification or completion of B1/B3. The controlling requirements are
[versioned B1](public-beta-readiness-plan.md#b1--positive-evidence-and-final-status-design).
No production admission issuer, trust anchor, operator option, wire field, report
schema change or new completion boolean is introduced.

## Private native qualification contract (no admitted entries)

Current production authority is empty. `BuildReportWithPolicy` must continue to
leave required `native-qualification` incomplete. `Summary.Qualified` is rejected
by the parent protocol; neither same-executable launch nor successful native
opening establishes reviewed source/artifact acceptance. Existing parent report
sealing and selected advisory scope receipts are not native acceptance receipts.

The minimum admissible future flow is:

1. An approved acceptance authority identifies reviewed source, tested executable
   and a finite supported native profile. Its verification mechanism is selected
   by review, **not** by CLI input, saved policy, imported snapshot, environment,
   worker message or public JSON. There are presently no approved entries.
2. The parent verifies the acceptance against the actual running executable and
   source/build identity. Acceptance must specify how source/tree identity,
   dirty trees, generated inputs, toolchain/build variation, and tested-artifact
   to executing-image binding are checked. Missing proof is rejection, not an
   invitation to infer identity from an image name or build success.
3. The parent verifies native prerequisites on the **actual retained process and
   admitted root handles** for the selected run. Target, external policy/reference,
   state and output roots involved in that run must be within the accepted scope.
   GOOS/GOARCH and broad backend availability alone are insufficient. Child
   assertions may be checked against parent evidence, never substituted for it.
4. Only verified, live evidence could mint a private run-bound receipt. It must
   bind the acceptance identity, executing image, supported profile, parent run,
   and retained root/process evidence. No public constructor or serializable
   authority is permitted. A receipt from another run/root cannot be replayed.
5. Report construction consumes that receipt **before** computing coverage,
   policy exit conditions and the private snapshot seal. It cannot complete
   unrelated rows or amend a previously sealed report. The issuing owner's
   validity/binding checks remain obligations through finalization.

Refusal contract: absent, unverifiable, stale, invalidated, wrong-source,
wrong-artifact, wrong-platform/API/architecture/filesystem, wrong-root or replayed
acceptance leaves the row required/incomplete. A valid native acceptance alone
must still leave independent advisory, freshness, inventory, resident and
execution gaps intact. Public deserialization cannot recreate authority.

**Decision required before implementing a positive issuer:** name the acceptance
authorizer and reviewed trust anchor (compiled reviewed acceptance versus
independently authenticated artifact evidence, for example); approve the exact
source/build/executable identity rules and tested-to-running binding; enumerate
OS/architecture/filesystem/API/root requirements; specify expiry, revocation,
rebuild/requalification rules; approve how parent-observed runtime/root evidence
is retained and checked. These are not selected by this change. Do not implement
a permissive placeholder while waiting for that decision.

## Final adjudication is not qualification

`cmd/packtrace/scan.go` already overlays actual output/checkpoint/Finish failures
and interruption on the privately sealed comparison conditions. Preserve
`130 > 2 > 3 > 1 > 0`. A healthy post-Finish receipt cannot rewrite pre-output
`resident-observation`, predict future success in the comparison JSON, or grant
native qualification. Linux wait-peak finalization is a separate bounded
observation; sampling is not a hard RSS ceiling or evidence through supervisor
exit. Monitoring stops before some binding closes; a stronger whole-lifetime
completion contract still needs an explicit ordering design and review.

## Executable integration assertions

`cmd/packtrace/matching_scan_test.go` now extends the existing actual CLI-process
matching test, rather than manufacturing a completed report or adding a selector:

- Independent expected policy findings and all ten coverage rows, including
  requiredness, duplicate/missing rows and optional unselected checks.
- Actual child status checked separately from report `ExitCode`.
- Successful JSON/terminal/SARIF paths inspect retained post-Finish receipts:
  cleanup, resources, first fault, actual Wait/reap and control/stderr joins.
- Both pinned-origin JSON cases repeat the identical executable, arguments,
  inputs, policy and generation with only a closed inherited output sink.
  Actual final status must be 2, with the original writer fault retained even
  after the attempted diagnostic writer also fails. No failed-output comparison
  bytes are available from that sink; the preceding comparison remains evidence
  of the unchanged inputs, not a claim that failed output produced a final report.
- Existing blocked-writer interruption acceptance remains 130.

## Controlled current-binary evidence

External evidence directory:

`/home/justcharles/.local/state/packtrace/advisory-completeness-RIKjKdJf/scale-fix/b1-paired-u8FJT6JU`

The pinned offline wrapper built `packtrace` there. `controlled.py` authored only
inert npm fixtures and imported the repository's authored `matching.bundle` into
an owned temporary store. `run-scans.py` ran the production binary with identical
settings: both checks selected, fail-on malicious, portable JSON, explicit policy
and generation pins, isolated empty user configuration. Only fixture version and
its corresponding exact origin/policy binding differ. No npm command or package
code ran. `clean` means the supported negative control, **not** proven benign or
complete coverage.

| Required coverage row | Negative 2.0.0 | Finding 1.0.0 |
| --- | --- | --- |
| inventory | completed | completed |
| malicious | incomplete | incomplete |
| vulnerability | incomplete | incomplete |
| native-qualification | incomplete | incomplete |
| resident-observation | incomplete | incomplete |
| execution (comparison only) | completed | completed |
| intelligence-access | completed | completed |
| intelligence-freshness | incomplete | incomplete |

Optional `integrity` and `reference-authority` are `not-run`, not completed.
Actual production exits and comparison exits are **3 / 3** in both cases;
enforced-unaccepted policy findings are respectively **0 / 1**. Both advisory
summaries retain `declared-unassessed`, `index-completeness`, `source-stale`.
Both source-check and reconciliation ages are `expired`; pins did not renew them.
The fixture includes withdrawn and unsupported-profile/correction records.

Evidence: `clean.stdout`, `finding.stdout`, their `.stderr`, `.exit` and
`.command.json` files, `production-outcomes.json`, `build.log`; integration logs
`paired-final.jsonl`, selected regression `regression-race.jsonl`, `vet.log`.
`artifact-index.json` names extracted comparison and post-Finish receipt files,
including each `json__late-output-failure.receipt.json`. Production CLI has no
receipt export option: these private receipts are from the actual same-executable
test-process path, not fabricated production outputs. Initial test-development
failures are retained in `initial.jsonl` and `paired.jsonl`; the final assertions
passed, including failure-path diagnostic writer accounting.

## Remaining blockers: local code versus external approval/evidence

- **External authority/evidence:** no approved source/artifact acceptance or
  supported native profile/runtime evidence exists for this build. A digest pin
  or a local test run cannot supply that approval. The explicit decision above
  is needed; this change makes no grant request to an operator flag.
- **Local admission implementation, after approval:** there is no native receipt
  issuer/verifier or parent acquisition of the narrower acceptance-profile facts.
  Implement those against the approved identity/profile contract, then consume
  the receipt before sealing. Do not expand the current backend's admission into
  automatic acceptance.
- **Local lifecycle completion design:** resident coverage is intentionally
  incomplete in the comparison. Existing final adjudication correctly refuses
  operational failures, but does not solve positive lifetime coverage. Specify
  the final operational completion predicate and source-close ordering without
  retrospectively upgrading the public snapshot; retest shared Intel/batch paths
  if that ordering changes.
- **Controlled-fixture evidence gaps, not exit-selector bugs:** this imported
  generation is stale and selected advisory scope is not positively admitted.
  Freshness requires genuine admitted source-check/reconciliation evidence;
  unsupported originals and unaccounted selected observations cannot be erased
  to obtain a complete category. No acquisition was authorized here. Native
  acceptance alone would therefore still not yield 0/1 for these fixtures.

Next review can approve or reject the narrow admission contract without enabling
it. Actual 0/1 acceptance additionally needs every required positive row and the
caller-owned final lifecycle verdict; none is replaced by this document.
