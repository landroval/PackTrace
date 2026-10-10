# Issue 38: pinned checkout assessment scope and permission proposal

Status: **written scope and proposed limits approved; assessment acquisition/execution not authorized**.
I recorded the user's explicit “Aprobar sólo alcance”: local documentary approval
only, without consultations, downloads, execution, agents or publication.
I do not change the published specification/plan or head of PR #39.

**Goal:** I define a bounded assessment of the proposed checkout Action before
adoption, without converting partial source/metadata inspection into qualification.

**Approach:** I reuse verified existing named texts to identify the review questions.
Any future selective acquisition remains a separate permission. Static distribution,
dependency/notice and security review is separate from runtime credential evidence;
this document is not a complete executable credential-probe plan or authorization.

**Authority:** The owner-approved issue-38
[specification](https://github.com/landroval/PackTrace/blob/6362a944e0ff6041ac2243de5d92549990c3bc4c/docs/increments/issue-38-root-verification-ci.md)
and [plan](https://github.com/landroval/PackTrace/blob/6362a944e0ff6041ac2243de5d92549990c3bc4c/docs/increments/issue-38-root-verification-ci-plan.md),
[toolchain baseline](../design-decisions.md#24-toolchain-and-dependency-baseline)
and [collaboration gates](../github-collaboration.md).

I use an independent local bookmark `issue-38-checkout-assessment-scope`, based on
last verified integrated development `76ef90daf36c4b4fae2b234369859108440fc24e`.
This preparation creates only this document, with no new public issue/reservation,
Project transition, source synchronization or commit on a sibling bookmark.

## Candidate and current evidence boundary

Candidate: **`actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1`**,
previously observed v7.0.1. I do not replace the SHA/version or adopt a candidate
merely because a tag, Git tree or digest exists.

I freshly checked six already cached named texts against their historical recorded
byte counts, SHA-256 and Git blob identities. No new request or distribution transfer
was made. The historical association with that commit/tree is provenance evidence,
not a fresh network/signature check, a full source tree or a reproducible build.

| Existing named text | Bytes | Observed relevance, not complete qualification |
| --- | ---: | --- |
| `action.yml` | 5,144 | Node 24; main and post both `dist/index.js`; persistence default true |
| `LICENSE` | 1,097 | Root MIT notice, GitHub/contributors copyright; not bundled notices |
| `package.json` | 1,580 | Declared v7.0.1, Node >=24 and five direct runtime dependency ranges |
| `README.md` | 14,138 | Existing named documentation, not actual hosted acceptance |
| `src/input-helper.ts` | 7,318 | Required token input, exact checkout inputs and fork-context guard |
| `src/git-auth-helper.ts` | 21,925 | Credential temp-file/include cleanup paths; failure branches need review |

The five declared runtime dependencies are `@actions/core` `^3.0.1`,
`@actions/exec` `^3.0.0`, `@actions/github` `^9.1.1`, `@actions/io` `^3.0.2` and
`@actions/tool-cache` `^4.0.0`. I retain ranges as declarations, not exact resolved
or actual bundled versions. Dev/build dependencies are not automatically runtime
content, but I do not exclude them if evidence shows their code is shipped.

The executable bundle, resolved/bundled graph, distributed notices, current advisory
review and actual credential cleanup remain **NOT ACQUIRED / NOT REVIEWED /
NOT RUN**, as applicable. Root MIT or a matching named-text hash does not close them.

## Proposed profile and exclusions

I assess only the proposed issue-38 profile: Ubuntu 24.04 Linux amd64, supported
runner >=2.327.1, bundled Node 24, read-only contents token, default owned repository
checkout, no persistent credentials/submodules/LFS/tags/privileged fork checkout or
host-global safe.directory modification. These are scoped conditions to qualify,
not measurements already obtained.

I review normal and failure main/post paths under that profile. I trace fallback
behavior even where the profile should exclude it: absent Git, API/archive checkout,
retry, additional downloads, URL rewriting and cleanup exceptions must not disappear
because a documented happy path appears acceptable.

I exclude Go/Node/runner distribution acquisition, product workflow installation,
real credentials/private keys, investigated projects, package-manager commands,
`npm audit`/install/build/test/license-generation scripts, bundle evaluation/import,
source compilation, native/producer/fuzz/scan qualification, release redistribution,
account/security-setting changes, privileged events and automatic source upgrades.
I never relaunch Runner.Listener or read its `.env` for metadata; selected platform
`Set up job` observations close runner/package/image evidence externally.

## Proposed future acquisition boundary — not granted

If separately approved, I request **data-only selective acquisition**, not execution.
I do not fetch a whole repository/archive or recursively clone/submodule the candidate.
I first inspect bounded immutable commit/tree metadata, then freeze an explicit file
manifest before acquiring selected raw files. Any expansion needs owner permission.

| Resource | Proposed ceiling / stop condition |
| --- | --- |
| Public API/HTTP work | 40 requests total, including redirects/HEAD; no retries |
| Metadata/lock/license/source text | 2 MiB per response; 12 MiB cumulative |
| Executable distribution as opaque review data | `dist/index.js` <=16 MiB; no execution |
| Distribution maps/notice companions | <=8 MiB each; <=16 MiB cumulative |
| Total response bytes across roles | 48 MiB, count duplicates/errors before success |
| Redirects | <=2 per request, only immutable approved path/host; no auth forwarding |
| Time | 10-second socket operations, 30-second response and 30-minute acquisition ceiling |
| Owned retention | 128 MiB including data, receipts and temporary copies; no archive extraction |
| Parsed dependency/evidence rows | <=10,000; excess/ambiguity leaves assessment incomplete |
| Review output | <=1 MiB report; <=64 KiB operation receipt; no secret/raw environment logging |

I propose HTTPS only to `api.github.com` and `raw.githubusercontent.com`, for the
exact public candidate repository/commit and explicitly identified immutable
notice/source material. Public GitHub advisory metadata queries must identify only
qualified public dependency names from acquired evidence; no private target identity
or source goes into a query. I do not add npm/OSV registries, mirrors, proxy/credential
loading or general Internet access without a separate permission change.

I keep API authentication, if existing and separately permitted, only in the configured
GitHub client; I never export/print its token or send it to raw/redirect destinations.
Changing authentication/scopes or configuring credential helpers is outside this
proposal. Failure/403/404/truncation/budget exhaustion does not authorize retries,
new hosts, larger ceilings or adoption from cached unqualified content.

Before any transfer, the implementer must submit the exact URL/file manifest and a
complete bounded acquisition procedure for approval, using these ceilings. This
scope proposal does not provide or authorize an executable downloader/probe. Treat
metadata sizes/digests as expected declarations and record actual acquired bytes/
digests separately; neither field alone authenticates the publisher or build.

## Assessment tasks and concrete acceptance records

### Task 1: establish acquisition/identity permission

- [x] Obtain approval of this actual scope and ceilings: the user explicitly approved only this documentary artifact, not acquisition, execution or publication.
- [ ] Obtain separate data-only acquisition permission and exact-manifest/procedure approval; keep runtime permission absent.
- [ ] Confirm immutable commit/tree and selected blob identities against acquired raw bytes; preserve uncertainty in unavailable metadata.
- [ ] Record URL/role/commit/blob ID/expected metadata size, actual bytes/SHA-256, retrieval observation and completeness for each selected file.
- [ ] Reject changed pin, missing distribution, truncation or mismatched identity; do not execute/build to manufacture a missing binding.

**Record:** Per-file rows with independent expected/observed identity and completion.
No row is a public report/ABI or blanket safety verdict.

### Task 2: distinguish declaration, resolution, bundle and notices

- [ ] Inspect tree metadata for `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml` or `yarn.lock`; record which actually exists and any conflicting locks. Do not infer a graph from package.json ranges or run a manager to resolve them.
- [ ] Review the actual `dist/index.js` entrypoint used for both main/post as data. Identify its distribution-map/notice companions from tree metadata, not invented filenames or assumptions from TypeScript alone.
- [ ] Trace actual bundled dependency/version evidence to resolved records where available. Record declared-only, resolved-only, proven bundled, possibly bundled and unmapped content separately, preserving conflicts/unknowns.
- [ ] For each proven/possible shipped dependency, record exact identity/version evidence, declared license expression, actual applicable license/notice text and provenance, bundled-content linkage and unresolved obligations.
- [ ] Preserve the root MIT copyright/license notice. Assess runtime use separately from future redistribution; do not claim full notice compliance from root LICENSE or metadata expressions.
- [ ] Treat absent maps/notices, unresolved license conflicts or unmapped material affecting shipped content as a blocker/limitation, not as an empty graph or permissive license. Do not certify source-to-bundle/reproducible-build equivalence without evidence.

**Record:** Separate declaration/resolution/bundling/notice columns; totals count
examined rows only and never imply complete coverage when mappings are unknown.

### Task 3: static security and credential-boundary review

- [ ] Trace main/post dispatch and token input into auth configuration, Git/API children, masking, cleanup and exceptions in the actual distribution and relevant source.
- [ ] Check the planned explicit false inputs against metadata defaults: persistence and safe.directory default true; absence of an override must not silently satisfy the profile.
- [ ] Trace normal return, thrown error, ignored cleanup exception, cancellation/post not reached, repeated invocation and multiple include/temp credential paths. Cleanup after the job cannot be treated as cleanup before Go.
- [ ] Review submodule/LFS/REST/archive fallback and retry/download paths for actual egress, work/retention and credential forwarding; mark unreachable-only assumptions conditional on observed profile evidence.
- [ ] Review shell/argument/environment handling, fork/privileged event guards, URL rewrites and SDK dependency behavior. Secret masking is not removal, isolation or proof that Go cannot read host files/processes.
- [ ] Review available public advisory/release/security evidence for exact mapped shipped versions, with consultation provenance/date and unavailable coverage. No advisory retrieved is not proof of no vulnerabilities.
- [ ] Report concrete blocker/important/limited-review findings with pinned path/span, triggering condition, consequence and minimum correction/qualification required. Do not turn absence of findings into a safety claim.

**Record:** A review matrix separating observed control, inference/precondition,
missing evidence, severity and whether it blocks the exact proposed profile.

### Task 4: state runtime evidence requirements without performing a probe

I require a separately approved complete executable credential-qualification plan
before any Node/Action/Git fixture or hosted run. This document supplies expectations,
not executable fixtures, fake behavioral RED, an always-deny success or runtime proof.
Use owned synthetic credentials only in controlled fixture work; real runner token
contents/config values/private keys must never be inspected or exported as evidence.

| ID | Independent condition | Required observation before claiming qualification |
| --- | --- | --- |
| A01 | Pin/blob/distribution identity missing or conflicting | Data acquisition incomplete; no adoption/execution |
| A02 | Declared dependency range without resolution/bundle link | Unknown exact shipped version retained |
| A03 | Root MIT present but bundled notices unresolved | Notice/license gate still open |
| A04 | Static graph/advisory review partial or budget exhausted | Review coverage limitation, not no-risk verdict |
| A05 | Persistence/safe.directory override absent | Profile not satisfied; no implicit default approval |
| A06 | Main returns normally with false persistence | Actual before-Go absence check; no token/config-value inspection |
| A07 | Auth setup fails after temp/include creation | Residue/uncertainty blocks Go, despite masked logs or planned post |
| A08 | Cleanup catches/ignores error or leaves another include/file | Unknown/remaining auth state preserved; no qualified pass |
| A09 | Post skipped, cancellation or repeated execution | No assumed cleanup; prior positive evidence cannot fill a missing phase |
| A10 | Git absent or REST/archive/submodule/LFS/retry path selected | Unsupported/profile-limit or separately qualified exact effects |
| A11 | Fork/privileged context or shell/ref injection attempt | Outside privileged profile; no promoted fork/token authority |
| A12 | Actual worker Node/profile differs or metadata missing | Setup/closure blocked or pending; no PATH Node substitute |
| A13 | Checks succeed but platform image/package proof absent | Environment qualification pending; no installation acceptance |
| A14 | Environment sanitized but host credentials exist elsewhere | No host/filesystem/process-isolation claim |

I map A06-A12 to future observed fixture/platform evidence, not documentary test counts.
The executable plan must define exact fixtures/scripts, resource/lifecycle limits,
synthetic credential handling, expected presence-only observations and acquisition/
execution permissions before it is approved. No speculative YAML/probe is installed
through this scope and no framework/runner is introduced to make the gate pass.

## Verdict, review and later permissions

I use **blocked**, **incomplete** or **conditionally acceptable for the exact reviewed
profile** for the scoped assessment, with independent static/notice/runtime/platform
states. Conditional static acceptability cannot satisfy missing runtime credential
or external platform evidence; none is a declaration that the Action is safe.
I require independent review of the actual assessment evidence before adoption.

Written scope approval, selective data acquisition, static assessment, executable
probe-plan approval, controlled execution, workflow installation, activating
publication/integration and issue closure remain distinct permissions. The existing
#23/#38 integration/review requirements, source heads and native/product gates remain
unchanged. I do not ask for a single bundled permission that implicitly grants them.

The owner approved this written scope only; the exact acquisition manifest/procedure,
transfer permission and complete executable credential-probe plan remain separate gates.
Preparation verification is local links/anchors, exact one-document scope, preserved
sibling/bookmark/default/checkpoint/routing identities, cached named-text fingerprint
consistency and A01-A14 coverage. These checks do not run A01-A14 as tests or complete
an assessment. I leave acquisition, static full-bundle review, actual credential
probe, platform qualification and publication unperformed.
