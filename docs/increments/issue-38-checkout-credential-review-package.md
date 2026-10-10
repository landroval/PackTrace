# Issue 38: local credential-harness review package

Status: **package prepared locally; independent review NOT REQUESTED / NOT RECEIVED**.
I have explicit permission to **“Preparar revisión”** only. I prepare this document
and verify its local anchors; I do not send it, dispatch agents, consult GitHub,
publish a branch, run the Action/native experiment, supply a runtime or close gates.
The owner-authorized pure Python suite is separate from controlled execution.

## Request and exact review target

I request a future independent, read-only review of the owned checkout credential
harness and its plan, **not a claim of runtime qualification or an adoption verdict**.
This package is an invitation/checklist, not an actual request already delivered.
No reviewer identity, approval, review service or model execution is inferred.

- Implementation range base: `3ab6bca8c218d07573fcae700b01943f15481f09`.
- Plan approval / owned implementation and pure-test authority:
  `da0d4144d4123e318b49f91e6aeac5bd1539aad2`.
- Exact implementation head: `674d95d199ea168ea91a4d9ba892e64f4b04d96b`.
- Integrated base of this isolated lane: `76ef90daf36c4b4fae2b234369859108440fc24e`.
  I do not claim it is current remote development: no refresh was authorized here.
- Local issue bookmark: `issue-38-checkout-assessment-scope`; it may move. The
  immutable implementation head/hashes below, not the name alone, anchor code review.
- Packaging adds only this document. The separate local packaging receipt records
  the resulting exact commit after creation. A future final-head approval must name
  that actual received head and verify its implementation bytes still equal this
  table; approval of an ancestor does not automatically approve later changed code.

The implementation range changes **four paths**: one plan and three owned scripts.
It contains no workflow, product Go change, root dependency, investigated tree,
acquired checkout code, source synchronization, shared task-ledger or routing change.
I did not mutate source while preparing the package. The code is reproducible from
the owner-authored plan fences: Task 1's exact class precedes Task 2's main branch;
Git/preload script bodies are copied exactly. This proves transcription, not behavior.

### Frozen implementation files

| File at the implementation head | SHA-256 of exact UTF-8 bytes |
| --- | --- |
| [Owned plan](issue-38-checkout-credential-qualification-plan.md) | `241f525b911b369421b07a10dc4435fcf8d17ebdfe8861183cfe510a618c03ba` |
| [Supervisor and pure tests](../../probes/checkout-credentials/probe.py) | `aa99bad3ab986bf739ea0509765a582cd0d668fe204db36c516a8ab9fd4ec48f` |
| [Git wrapper](../../probes/checkout-credentials/git.py) | `b5bb3e5c70669d458517007969998d44ce946fcd902e2e4a565b99c3590bc893` |
| [Node preload](../../probes/checkout-credentials/hooks.mjs) | `fea67ec0bd226db9b6e0b20fd5cb9ac1ef7288207e87fdb558a7310c82e9f4fb` |

I require reading these actual source files and the complete plan, not only this
summary or selected snippets. The following Nushell-compatible commands are local
history/source inspection examples, not fetch/checkout or experiment instructions:

```nu
jj diff --from 3ab6bca8c218d07573fcae700b01943f15481f09 --to 674d95d199ea168ea91a4d9ba892e64f4b04d96b --name-only
jj diff --from 3ab6bca8c218d07573fcae700b01943f15481f09 --to 674d95d199ea168ea91a4d9ba892e64f4b04d96b
jj file show -r 674d95d199ea168ea91a4d9ba892e64f4b04d96b probes/checkout-credentials/probe.py
jj file show -r 674d95d199ea168ea91a4d9ba892e64f4b04d96b probes/checkout-credentials/git.py
jj file show -r 674d95d199ea168ea91a4d9ba892e64f4b04d96b probes/checkout-credentials/hooks.mjs
```

## Requirements and context to read

1. [Assessment scope](issue-38-checkout-assessment-scope.md): approved documentary
   profile/permission boundaries and A06-A14. Its initial acquisition status is
   historical, not a statement that later explicitly authorized acquisition failed.
2. [Static assessment](issue-38-checkout-static-assessment.md): S01 best-effort
   cleanup, S02 conditional pre-first-include orphan, S03 prefix ownership, S04
   unawaited main global cleanup, S05 inherited/fallback/profile paths, S06 coverage.
   S01/S02 are static conditions, **not observed token leaks or demonstrated exploits**.
3. [Credential plan](issue-38-checkout-credential-qualification-plan.md): owner
   approval, exact owned source, budgets/manifest, expected-observation matrix and
   local pure-code checkpoint. Documented controls/fixtures are not runtime proof.
4. [Raw acquisition record](issue-38-checkout-raw-acquisition-plan.md) and
   [metadata record](issue-38-checkout-metadata-bootstrap-plan.md): 37 selected data
   files plus two GETs, no automatic request expansion/recollection/execution.
5. [Project gates](../github-collaboration.md) and
   [toolchain/dependency baseline](../design-decisions.md#24-toolchain-and-dependency-baseline).
   Parent/native/CI/product acceptance and independent final-head approval remain
   distinct. The old default checkout or historical ledgers are not the live queue.

The candidate remains `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1`.
The actual received opaque bundle hash is
`b604bf1c08a471aedf51ddddbd3e8d03041683db270692d66cd1b4b097457818`.
This package includes **no acquired bundle, SDK source, license corpus, private
configuration, real credential, environment dump or machine-specific execution input**.
The full Action/bundling/notices/advisory assessment remains incomplete; a review of
owned probe code cannot substitute for it. The last unallocated request stays unused.

## What was implemented and what was observed

I created a local three-script harness proposal: real Git over synthetic local
repositories, exact unchanged bundle files in a proposed sterile namespace, optional
instrumentation/fault hooks, and an independent name-only/presence observer. The code
contains native/process effects but **none of those branches has been executed**.
Only its pure guard/profile/state/lifecycle-decision functions were exercised.

| Evidence role | Observed result | What it does not establish |
| --- | --- | --- |
| API-stage owned tests | 8 methods selected, 14 missing-name error/subtest records | Not behavioral RED, no credential observation |
| Always-deny stub | 8 selected; C01 clean-positive failed, seven passed | Shows clean positive cannot be replaced by refusal; no native setup proof |
| Pure GREEN | Final one suite: **8/8 methods**, exit 0 | No Node, Git, main/post, runtime/image or SDK cleanup evidence |
| Owned counterfactuals | Ignore residue/query failure/lifecycle: each failed one method out of eight; original bytes unchanged | Not mutations or execution of checkout |
| Additional audit guard | Final pure suite rejects process/network/private-input activity | Not a production sandbox or containment/native qualification |
| Python AST/composition | Two owned Python files parse; exact plan bodies/class composition verified | Not hosting/type/native behavior; JS syntax/runtime not qualified |
| C01-C26 matrix | 26 authored expectation IDs; eight pure methods and 21 proposed controlled rows | IDs/subtests/rows are not summed into executed fixture passes |
| Proposed phase budget | Static branch accounting 116 phases <=120 | No measured native execution/time/memory/CPU result |

### Actually executed pure method names

- `test_C01_clean_positive`
- `test_C02_orphan_negative`
- `test_C03_each_forbidden_key`
- `test_C04_invalid_or_failed`
- `test_C24_missing_required_config`
- `test_profile_and_lifecycle`
- `test_state_missing_not_fabricated`
- `test_C25_each_forbidden_input`

I count methods in one actual final suite; I do not add runs, package/API errors,
subtests, documentary expectation IDs or unexecuted main/post rows. Current owned
code and retained receipts were rechecked when packaging. A missing temporary
receipt would mean unavailable historical detail, not permission to fabricate/re-run
native evidence. No Go root tests/vet or parser/fuzz/native shipping gates were run.

The pure command that was authorized/executed is reproduced below as evidence, not
as authorization for the reviewer or anyone else to execute further operations:

```nu
python3 -I -S -B probes/checkout-credentials/probe.py --self-test
```

The private temporary execution ledger/receipt and RED/GREEN/counterfactual streams
remain external to the tracked package. I checked their retained outcomes without
copying raw tracebacks, paths, source/input contents or output into a public request.
The versioned plan checkpoint records durable bounded observations. If a future
reviewer needs receipts or a rerun, I require a separately scoped handoff/permission.

## Review Focus (exact approved plan priorities)

1. Main exit 0 with denied config enumeration/unset/deletion must not certify removal.
2. Failure after token-file rewrite but before first include must remain observable;
   repeated main/post must not erase an orphan's coverage gap.
3. A clean negative observer must enable the owned `wouldEnableGo` boolean, while
   residue/unknown/lifecycle failures must disable it. I never actually invoke Go.
4. Post routing must use actual bounded main state; missing state/config/Git or
   skipped/cancelled post cannot inherit a prior cleanup success.
5. Instrumentation/local fetch differs from actual Runner/network/timing. Even all
   expected-observation cases passing cannot close notice/advisory/platform/adoption.

## Source map and independent checklist

Line spans refer to the frozen implementation head above. They locate review work,
not an author assertion that the listed code is correct or qualified.

| Area | Frozen source span | Required review question |
| --- | --- | --- |
| Pure guard/state/profile | `probe.py:53-108,552-584` | Does the API preserve failed/unavailable evidence, a real positive control and exact known state/input boundaries? |
| Owned command capture | `probe.py:110-147` | Are byte/time/EOF/error paths bounded without exposing names/values or silently accepting a prefix? |
| Seed and observer | `probe.py:149-191` | Are all operations restricted to owned paths and real name-only Git queries? Are missing required config/residue/query failure independently retained? |
| Namespace metadata/action routing | `probe.py:194-261` | Does preflight really distinguish approved Node/Ubuntu/Git identity, no external routes, read-only mounts, nonroot and actual bounded main state? |
| Manifest and input identities | `probe.py:264-331` | Are path overlaps/repo outputs/tool identities rejected, and are trusted-input/native race assumptions explicit rather than authenticated by a digest alone? |
| Child lifecycle and limits | `probe.py:334-409` | Are deadlines/capture/resource counters/group closure evaluated before cleanup, with no next case on unknown kill/reap/EOF status? |
| Experiment/results | `probe.py:412-549` | Are injections reached and positive/negative predicates independent? Are expected failures, partial ledgers and final qualification distinguished correctly? |
| Real Git wrapper | `git.py:1-52` | Does exact `-c protocol.version=2 fetch` handling redirect only the owned remote, preserve actual config semantics and never log argv/values? |
| Node preload | `hooks.mjs:1-54` | Are intercepted builtin functions/typed path selection valid for this exact bundle? Are absent hooks/faults detected, instrumentation and event tampering limits explicit? |

- [ ] Read the complete plan/spec and actual four-path implementation range.
- [ ] Confirm code/source hashes and actual received packaging head before reporting
  review. Inspect packaging document too; do not approve a moving bookmark implicitly.
- [ ] Check all pure and native branches statically, not only the eight passing methods.
- [ ] Review memory.max/swap/pids/cpu controls, preexec/namespace assumptions, parent
  and descendant lifecycle, normal EOF versus killed/incomplete output, cumulative
  capture versus SDK-internal buffers, observed filesystem stop versus hard quota.
- [ ] Review independent observation versus writable Action event/state files; do not
  turn controlled markers into adversarial tamper-proof evidence or a benign verdict.
- [ ] Review direct launch metadata defaults, hyphen-preserving INPUT names, synthetic
  token restrictions, persistence-true post controls versus the exact CI profile,
  no-SSH/no-LFS/no-submodule/unsafe event rejection and missing/runtime drift handling.
- [ ] Check fault selectors, unchanged bundle/source binding and predicted main/post
  predicates; a plan defect must be reported as such, not hidden by exact transcription.
- [ ] Check missing/invalid/partial receipts, fixed public error categories, no raw
  config/output/environment/credential-key hashing, exclusive private output and
  actual-manifest authority. Read-only review does not approve destructive operations.
- [ ] Report all evidence/test gaps by effect, not as clean negatives. Pure success
  cannot qualify native/sandbox/SDK/image behavior or change S06/parent gates.

## Review permission and requested response format

I prepare for a read-only independent review. **I have not authorized a reviewer
session, agent, model budget, remote message, peer assignment or public request.**
Before actual dispatch/handoff I must agree the reviewer, scope, exact head and any
cost or additional local access. Existing owner permissions are not credentials or
standing delegation to execute arbitrary code for a reviewer.

For the future reviewer I require:

- No edits, branch/worktree movement, fixture creation, packages/downloads, network,
  real key/token/config inspection, Git/Node/bwrap/runner/Go execution or cgroup/native
  changes. Local `jj` history/source inspection is different from spawning Git for
  an experiment. No subreviewers/agents or role escalation by inference.
- No reclassification of execution authority from CLI flags, matching hashes,
  a synthetic token, board state or this package. A matching input is not permission.
- No claims about source that was not read, no automatic adoption/merge/closure,
  and no unperformed test results. The full bundle/SDK audit stays a separate scope.
- If runtime evidence is necessary to decide a point, mark it **NOT RUN / unable to
  conclude statically** and describe the exact additional observation required;
  do not run it to finish the review without separate permission.

I ask the actual reviewer to return:

1. Reviewer identity, received exact head, reviewed range/files/hashes, method and
   any permitted commands actually run. Independence from authorship must be clear.
2. Specific strengths supported by actual source; no blanket “safe” statement.
3. Critical / Important / Minor findings, each with exact file:line, condition,
   effect, minimum correction/observation, and whether it is a plan or code defect.
4. Every behavior considered but declined to judge, with a reason and missing
   evidence; nothing disappears because the plan is silent. Empty means none.
5. Separate decisions: static owned-code acceptability, sufficiency to authorize a
   future controlled experiment, actual runtime/platform/adoption qualification.
   The last remains unavailable from this package. Do not conflate them into “CI ready”.
6. Exact-head approval/rejection or request for changes, with unresolved blockers.
   Important/Critical findings need disposition and, where authorized, owned RED/GREEN
   correction; changed code/head requires fresh independent review under project rules.

## Handoff state and preserved boundaries

I leave this package local. **Prepared is not sent; sent is not reviewed; reviewed
owned code is not executed/qualified/adopted.** Runtime/artifact/manifest readiness,
controlled experiment and its permission, external platform closure, complete
static/notices/advisory assessment, reviewed #23 integration and #38 activation/
publication/integration/acceptance remain pending and separately gated.

I preserve the three-script/four-path implementation bytes, earlier assessment docs,
default unrelated `.pi/todos` changes, sibling PR bookmarks/workspaces, local-only
checkpoint and routing. No queue/assignee/Project updates or live PR status refresh
were performed. Acquisition is still 39 requests; the last request is unallocated.
This author-prepared package and its checks are **not independent review evidence**.
