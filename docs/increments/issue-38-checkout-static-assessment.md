# Issue 38: pinned checkout offline static assessment

Status: **local assessment report; adoption BLOCKED / qualification incomplete**.
I have explicit permission to **“Auditar sin red”**: inspect the acquired corpus as
data, record findings/coverage locally, without queries/downloads, acquired-code or
real-credential execution, agents, CI or publication. I grant no implementation,
new pin, upstream report, workflow activation or issue closure through this report.

## Scope, identity and method

I assessed `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1` under the
[approved scope](issue-38-checkout-assessment-scope.md), using only the
[37-file acquired corpus](issue-38-checkout-raw-acquisition-plan.md) and the preceding
[metadata evidence](issue-38-checkout-metadata-bootstrap-plan.md). I did not use the
remaining unallocated request: cumulative acquisition stays 39 requests / 1,894,265
owned payload bytes. The nominal v7.0.1, Node 24, Ubuntu 24.04/amd64/read-only-token,
no persistence/submodule/LFS/safe.directory profile remains conditional on actual
qualified hosting, not on these static observations.

I reverified all 37 actual byte counts, measured SHA-256 and Git blob SHA-1 against
the frozen manifest. The actual bundle is 1,452,503 bytes / 42,269 lines, SHA-256
`b604bf1c08a471aedf51ddddbd3e8d03041683db270692d66cd1b4b097457818`.
The lockfile SHA-256 is
`4f8c64aa3807a20365c0b9c1ef4c4639549146a1ebd9ebe379e8fde1dff7938e`.
These are identified received bytes, not independently authenticated builds.

I read all six selected source files, Action/distribution metadata/root LICENSE and
all 24 publisher license-cache records. I traced the selected main/post/auth/error
paths in the actual bundle and inspected relevant compiled URL/ref/fork/retry/API/
Git-directory/proxy/extraction helpers. I enumerated 175 numeric registry headers
and 16 source-module labels; **I did not deeply audit every third-party module or
all 42,269 lines**. Enumeration/markers/hash checks are not full security review.

I parsed the lock as bounded local JSON data with decoded-key duplicate checks. I
parsed publisher YAML through existing PyYAML **BaseLoader**, with single-file event
bounds and no anchors; no custom YAML construction, imports, scripts or URL visits.
I performed finite lock-location lookups only, without a package manager, registry
resolution, SemVer range satisfaction, installation, Go reader execution or changing
PackTrace's dependency/toolchain policy. The derived graph is documentary metadata,
not producer/native/npm installation qualification or effective observed inventory.

Temporary evidence is under `/tmp/packtrace-checkout-raw-qqtkiw2_` and the derived
`/tmp/packtrace-issue38-static-*` receipts. It may disappear; it is not authority.
All citations below refer to exact pinned candidate files/line spans, not live tags.

## Verdict and independent states

| Dimension | Result |
| --- | --- |
| Selected corpus identity/acquisition | 37/37 byte counts and both digests rechecked; selected scope only |
| Main/post/auth static paths | Reviewed; important best-effort/orphan cleanup conditions below |
| Declarations/lock/publisher records | Five direct declarations, 24 non-dev-flagged lock locations, 24 exact name/version cache matches |
| Bundle attribution | Positive publisher module-location markers for 22 of those 24 locations; incomplete independent source/version/build binding |
| License text review | Read root and all 24 cache records; MIT/ISC/Apache text observations, two metadata discrepancies; complete shipped notice compliance unqualified |
| Current vulnerability/advisory coverage | NOT CONSULTED in this offline audit; no vulnerability-free claim |
| Actual normal/failure credential removal | NOT RUN / NOT QUALIFIED; no real credential/config/private-key inspection |
| Runner/Node/image/profile evidence | NOT RUN / NOT QUALIFIED by this report |
| Independent assessment approval / CI adoption | NOT RECEIVED here; no adoption, installation or release acceptance |

I finish the authorized bounded offline review, **not a complete adoption assessment**.
I cannot close #38's installation gate or mark the Action safe from this report.
Static findings and unqualified coverage are separate: a missing advisory or runtime
observation is not a negative finding and does not erase concrete source observations.

## Findings and required follow-up

### S01 — Important: cleanup success is not evidence that auth was removed

**Condition:** Git config enumeration/unset or credential-file removal fails.
I observe `tryGetConfigKeys`/`tryGetConfigValues` converting nonzero Git exit into
empty lists, include cleanup catching errors and ignoring unset-value success,
`removeGitConfig` warning rather than rejecting a failed unset, and file deletion
catching errors and continuing. Post cleanup returns early when repository/Git is
unavailable and its top-level catch logs a warning. A normal Action/job outcome
therefore cannot certify credential absence.

**Pinned evidence:** `src/git-auth-helper.ts:473-596`,
`src/git-command-manager.ts:483-593`, `src/main.ts:30-38`;
[bundle auth cleanup L35358-L35464](https://github.com/actions/checkout/blob/3d3c42e5aac5ba805825da76410c181273ba90b1/dist/index.js#L35358-L35464),
[bundle post/main L41921-L41951](https://github.com/actions/checkout/blob/3d3c42e5aac5ba805825da76410c181273ba90b1/dist/index.js#L41921-L41951)
and `dist/index.js:42253-42259`.

**Consequence / minimum requirement:** I treat warning/ignored/unknown cleanup as
unqualified, not a pass. The approved #38 plan's before-Go name-only config/residual
file guard is required, but it is still a proposal, not qualified runtime evidence.
A separately approved controlled plan must exercise unset/enumeration/delete failure,
post unavailable/cancelled and retained-residue cases, without real credentials or
reading/logging their values. I do not patch the Action or install that guard here.

### S02 — Important conditional failure path: a pre-include token file can become orphaned

**Condition:** Token replacement completes, then the first repository include write
fails before any include references that file. `configureToken` creates a unique
`RUNNER_TEMP/git-credentials-<uuid>.config` and writes its auth value **before** linking
it. `removeToken` builds its deletion set only from discovered main/submodule include
values; it does not add its own `credentialsConfigPath`. Token config path is not
saved alongside SSH paths in Action state. Thus the visible cleanup logic lacks a
recorded file-discovery path for this conditional orphan.

**Pinned evidence:** `src/git-auth-helper.ts:326-427,473-513`,
[bundle token write/link L35250-L35310](https://github.com/actions/checkout/blob/3d3c42e5aac5ba805825da76410c181273ba90b1/dist/index.js#L35250-L35310),
`dist/index.js:35313-35327,35360-35398`, and `src/state-helper.ts:17-53`.

**Consequence / minimum requirement:** I identify a static failure-path gap, **not an
observed token leak or demonstrated exploit**. Main setup failure ordinarily prevents
later default-success steps; it still does not qualify failure cleanup, repeated
invocations or post. A synthetic pre-first-include failure must be specified and
observed under separate execution permission; residual/uncertain files must block Go
and qualification. No actual filesystem credential proof was attempted here.

### S03 — Limited/outside-profile: cleanup path ownership is a string prefix, not containment

I observe `credentialsPath.startsWith(runnerTemp)` before recursive removal, after
accepting matching credential filenames from config values. This does not distinguish
a same-prefix sibling directory, establish component boundaries or resist link/alias
substitution. It is not a native-safe deletion proof.

**Pinned evidence:** `src/git-auth-helper.ts:492-513,591-599`,
`dist/index.js:35379-35396,35458-35462`.

I do not establish an exploit against the fresh owned checkout profile; arbitrary
config mutation, link/native and hostile-runner containment remain outside its proven
conditions. I require this assumption to stay explicit and to be separately resolved
before expanding profile/containment claims. No destructive experiment is authorized.

### S04 — Limited/outside-profile: main's temporary-global cleanup is not awaited

`getSource`'s finally block invokes `authHelper.removeGlobalConfig()` without awaiting
it; post's finally does await it. I cannot infer main cleanup completion or error
propagation from that call. The selected false safe.directory/submodule settings
normally avoid creating that temporary home, so I do not present this as an observed
failure in the exact narrow profile.

**Pinned evidence:** `src/git-source-provider.ts:316-326,366-370`,
`dist/index.js:41909-41918,41945-41952`, and `src/git-auth-helper.ts:238-244`.

I require explicit handling/qualification if those inputs/profile conditions change;
no claim that Node necessarily exits before pending I/O, and no runtime reproduction.

### S05 — Important profile boundary: inherited Git state, fallback and retries remain active mechanisms

I observe Git children inheriting `process.env` and overlaying only selected values,
not a sandbox/complete credential environment. Main uses argument arrays for ordinary
Git invocations, but cleanup includes a submodule shell pipeline; I do not claim a
universal no-shell property. Temporary Git global configuration copying is conditional
on excluded profile inputs, but false safe.directory does not stop Git itself from
reading inherited system/global configuration.

Git-manager initialization failure silently selects REST fallback when LFS is false.
The compiled fallback downloads an archive into memory, writes/extracts it with
platform tools and moves files; it is not the approved bounded Go-archive extractor
or a qualified hostile-archive path. Fetch/API retries have three attempts with
10-20-second waits. Public PR stale-merge telemetry can send repository/run/commit
identifiers in an additional authenticated API GET's user agent. Compiled toolkit
proxy code consumes proxy environment settings. These are potential Action-runtime
paths, **not requests made by this offline audit**.

**Pinned evidence:** `src/git-command-manager.ts:617-658`,
`src/git-source-provider.ts:75-98,373-392`,
`dist/index.js:32068-32160,35466-35513,36091-36191,41319-41451,41628-41691,41954-41966`.

I require actual qualified Git/profile observations and explicit rejection/handling of
unexpected fallback, rather than assuming selected inputs make all mechanisms
unreachable. The root CI clean command environment is not host/process/filesystem
isolation and its after-checkout checks do not retroactively prove checkout isolation.
The SSH key write has an explicit 0600 mode, while the token-file path is created via
Git and then rewritten without an explicit 0600 mode in the visible caller; actual
Git/umask/ACL/file-mode effects are unqualified, not an observed permission leak.
No arbitrary-event, SSH, submodule/LFS, proxy, helper/archive or privilege expansion is
approved by the findings. The source-supported fork guard remains defense-in-depth;
privileged events stay excluded regardless of it (`dist/index.js:41969-42035`).

### S06 — Assessment blockers: bundle binding, notice completeness, advisories and runtime remain incomplete

I have positive lock/cache/location-marker evidence, but no independent reproducible
source-to-bundle or complete third-party code/notice provenance proof. I did not
consult fresh advisories or inspect every registry module; I did not execute main/
post/SDK helpers or qualify the actual runner/Node/package/image. These are **coverage
blockers**, not assertions of a known malicious dependency, absent license or CVE.

I require an independently reviewed disposition of these remaining adoption gates,
with separately authorized acquisitions/controlled execution as needed. I do not
consume the last request, change budgets, select a replacement SHA, weaken guards,
run a scanner/package manager or publish an upstream accusation to fill those gaps.

## Declaration, lock, bundle and license evidence

The five package.json ranges equal the lock root's declarations:
`@actions/core ^3.0.1`, `@actions/exec ^3.0.0`, `@actions/github ^9.1.1`,
`@actions/io ^3.0.2`, `@actions/tool-cache ^4.0.0`.
The v3 lock has **587 rows including root / 586 nonroot**. A finite location-based
lookup of root dependency closure produces **24 rows / 41 declared edges**, matching
its 24 non-dev-flagged rows. I have not evaluated range compatibility, optional/peer
installation behavior, executed npm or qualified a producer. Dev flags do not alone
prove runtime inclusion/exclusion.

All 24 publisher records match an exact lock location/name/version, with nonempty
license text. The bundle exposes location-marker evidence for 22 locations; that
provides a positive attribution observation, not independent authentication of their
exact code/versions. The two unmapped type-labelled packages remain metadata-only or
unmapped, not a proven absence. Version-string search is not the mapping procedure.

| Lock/cache identity | Cache label / lock label | Bundle marker line(s), not version authentication |
| --- | --- | --- |
| `@actions/core 3.0.1` | `mit` / `MIT` | 31895 onward |
| `@actions/exec 3.0.0` | `mit` / `MIT` | 33787,34375 |
| `@actions/github 9.1.1` | `mit` / `MIT` | 36193,36248,40455,40494 |
| `@actions/http-client 3.0.2` (nested github) | `other` / `MIT` | 36246 external-module label to registry |
| `@actions/http-client 4.0.1` (root) | `other` / `MIT` | 32068,32163,32860 |
| `@actions/io 3.0.2` | `mit` / `MIT` | 33333,33513 |
| `@actions/tool-cache 4.0.0` | `mit` / `MIT` | 40511,40621,40682 |
| `semver 7.8.4` (nested tool-cache) | `isc` / `ISC` | 40509 external-module label to registry |
| `@octokit/auth-token 6.0.0` | `mit` / `MIT` | 37397 |
| `@octokit/core 7.0.6` | `mit` / `MIT` | 37452,37456 |
| `@octokit/endpoint 11.0.3` | `mit` / `MIT` | 36461 |
| `@octokit/graphql 9.0.3` | `mit` / `MIT` | 37270 |
| `@octokit/openapi-types 27.0.0` | `mit` / `MIT` | Unmapped/type-labelled metadata; no absence inference |
| `@octokit/plugin-paginate-rest 14.0.0` | `mit` / `MIT` | 40043 |
| `@octokit/plugin-rest-endpoint-methods 17.0.0` | `mit` / `MIT` | 37597,37602,39896,40022 |
| `@octokit/request 10.0.10` | `mit` / `MIT` | 37067 |
| `@octokit/request-error 7.1.0` | `mit` / `MIT` | 37026 |
| `@octokit/types 16.0.0` | `mit` / `MIT` | Unmapped/type-labelled metadata; no absence inference |
| `before-after-hook 4.0.0` | `apache-2.0` / `Apache-2.0` | 36316-36414 |
| `content-type 2.0.0` | `mit` / `MIT` | 36807 external-module label to registry |
| `json-with-bigint 3.5.8` | `mit` / `MIT` | 36809 |
| `tunnel 0.0.6` | `mit` / `MIT` | 32159 external-module label to registry |
| `undici 6.27.0` | `mit` / `MIT` | 32161 external-module label to registry |
| `universal-user-agent 7.0.3` | `isc` / `ISC` | 36301 |

I retain the nested http-client/semver locations rather than collapsing by name.
The graph and labels belong to the candidate's metadata; none becomes a new PackTrace
root dependency, initial runtime database or public report schema.

### License/notice disposition

Root LICENSE is MIT, copyright 2018 GitHub, Inc. and contributors. The publisher cache
has 19 `mit`, two `other`, one `apache-2.0` and two `isc` labels. Both `other` http-client
texts actually display GitHub copyright, MIT permission/notice/warranty terms while
the lock claims MIT; I preserve this classifier discrepancy, not invent a different
license or silently convert the raw label. All 24 cache `notices` lists are empty;
that records publisher claims only, **not proof no applicable upstream NOTICE exists**.

I read the MIT/ISC copyright and permission-preservation conditions and the
before-after-hook Apache-2.0 full text, including redistribution/license/modified-file/
attribution and conditional NOTICE provisions. Cached README license pointers are
not substitutes for the full included LICENSE text. Positive retained texts reduce a
specific missing-document uncertainty but do not establish complete shipped content
provenance or legal compliance for every bundled/copied/generated component.

I make no confirmed license-incompatibility finding from this corpus. For any future
redistribution, I require all applicable copyright/license/notice texts, Apache
modification/attribution obligations and upstream NOTICE uncertainty to be resolved
against the actual shipped content. I do not approve redistribution or introduce a
new NOTICE file here. CI use and redistribution remain separate decisions.

## Main/post and guard mapping

The Action declares main/post `dist/index.js`, Node 24; `dist/package.json` is ESM.
Its metadata defaults persistence and safe.directory to true, so I require the
planned explicit false overrides; TypeScript fallback values alone do not override
Action metadata. Source and bundle route `IsPost` from saved state to getInputs/
getSource or cleanup. Token input is required and is materialized transiently despite
false persistence. Masking its Base64 representation is not credential erasure.

The approved #38 proposal checks name-only Git config keys with `--no-includes` and
residual `git-credentials-*.config` presence before Go. I verified this documentary
mapping at plan lines 180-185,201-207,294-312, without executing it. It can be a
fail-closed condition for S01/S02 if separately qualified; it is not proof of absence
from all other host files/services/processes or proof that controlled failure cases
already ran. The selected event/profile excludes privileged fork contexts, custom
SSH credentials, submodules/LFS/global safe.directory; source guard alone is not a
complete security boundary or reason to expand that scope.

| Scope expectations | Static disposition / remaining gate |
| --- | --- |
| A01-A04 | Selected identities and declarations/cache mapping positive; independent build/bundle/notice/advisory coverage incomplete |
| A05 | Metadata defaults and explicit-override requirement confirmed as text; actual input receipt unqualified |
| A06 | Main finally removes auth when persistence false; actual before-Go absence remains NOT RUN |
| A07-A08 | S01/S02 failure/orphan paths identified; qualified negative/failure observations absent |
| A09 | Post state routing read; early return/warning/unawaited cases retained; cancellation/repetition NOT RUN |
| A10-A11 | Compiled fallback/retry/fork-guard paths inspected; profile exclusion does not become arbitrary native/event safety |
| A12-A14 | Actual worker Node/platform/image/credential/process isolation still unqualified; nominal success cannot close them |

## Report acceptance and preservation

This is author static review, not independent final-head approval. I leave the report
for owner/peer review without pushing, changing the published PR39 head, assigning
new issues/Project states, running Go/fixtures/Node/package managers, querying
advisories, modifying source/policies or closing #23/#38/native/product gates.

I verify this report's links/line references/counts against retained data, keep its
size below the 1-MiB report ceiling and preserve the existing approved scope/bootstrap/
raw plans, three published local sibling bookmarks, local-only deletion checkpoint
and global routing. The unrelated default `.pi/todos` changes are left untouched.
Acquisition stays 39 requests; the one remaining request is still unallocated.
