# Probe B: native guardrail feasibility

## Status and authorization

**Written probe scope, limits, and stop conditions approved. No prototype creation
or execution is authorized.** The user requested this plan after source inspection
exposed unresolved native safety assumptions. This is neither the complete
PackTrace specification nor its implementation plan.

The governing contracts are in [design decisions](design-decisions.md), especially
sections 2, 4, 16–18, and 24–27. Keep all five native targets and the existing safety
requirements unless the user explicitly changes them. Do not turn an unavailable
safeguard into a weaker fallback or an assertion of platform support.

Further authorization must explicitly cover:

1. Creating the isolated prototype.
2. Any dependency/toolchain acquisition, runner provisioning, paid infrastructure,
   privileged fixture setup, or security-setting changes.
3. Execution on explicitly identified runners and case groups.

Approval of this written plan satisfies none of those later steps. No production
code, new module, fixtures, runners, or downloaded toolchains are created by it.

## Question and smallest useful outcome

Can a small same-binary supervisor/worker, using official Go 1.27.1 with
`CGO_ENABLED=0` and at most the already-selected `golang.org/x/sys v0.44.0`, enforce
the mandatory file-access and portable resource contracts on the planned native
matrix?

Start with the unresolved macOS file-opening problem rather than provisioning
five runners at once. A useful result may be **blocked** with a specific missing
mechanism. Do not broaden dependencies, enable cgo, weaken safety, or change OS
scope merely to make the probe pass. Such changes need another design decision.

This is not an inventory implementation, npm/Bun producer qualification, package
scan, live feed import, artifact download, or production benchmark. It must not
execute JavaScript, package managers, project scripts, or target binaries.

## Current evidence: source inspection only

| Area | Evidence | Consequence for the probe |
| --- | --- | --- |
| Go filesystem access | `os.Root` does not exclude mount crossings or Unix special devices | Containment alone is insufficient |
| Linux | `openat2` exposes beneath/no-magic-link/no-mount-crossing controls; `O_PATH` allows a non-I/O reference to an object | Evaluate the whole inspect-then-read chain, not just flags |
| macOS | The pinned XNU `spec_open` below invokes character/block driver open functions and has no `O_EVTONLY` early-return branch | Event-only/nonblocking flags are not established substitutes for a safe metadata-only open |
| Windows | Cached `x/sys/windows` exposes `NtCreateFile`, reparse controls, handle queries, and Job APIs | API availability does not establish correct containment, object type, or lifecycle handling |
| Linux memory | cgroup charged memory is not summed process RSS; temporary `memory.max` overruns are documented; migration does not transfer existing charges | Do not claim an exact RSS ceiling or startup-wide coverage from late process migration |
| Windows memory | Job memory limits concern committed memory; pre-assignment memory operations are not examined | Do not equate Job commit limits with RSS or assume late assignment covers all startup allocations |

These observations do not demonstrate that macOS support is impossible. A source
path, successful cross-build, or expected refusal also does not qualify an OS.
The pinned XNU source is an analysis reference, not proof of the kernel installed
on a future runner; record the actual kernel and matching source/API contracts.

## Candidate mechanisms, not approved implementations

### Filesystem access

- **Linux:** a pinned root directory handle; `openat2` with explicit beneath,
  no-magic-link, and no-cross-mount restrictions; obtain `O_PATH` descriptors and
  inspect type before any content open. A candidate descriptor-bound reopen via
  the process's trusted procfs descriptor view needs its own proof and tests:
  same object, no target-controlled path resolution, no special-device opening,
  and safe failure when the interface is unavailable. Do not infer that arbitrary
  target `/proc` links are permitted. Do not assume newer `OPENAT2_REGULAR` support
  exists on the Ubuntu 24.04 kernel selected for testing.
- **macOS:** determine an end-to-end method before conducting stress tests.
  Handle-relative traversal and metadata checks remain necessary, but do not
  resolve the regular-file/device substitution problem by themselves. Reject
  `Lstat → Open → Fstat` as sufficient proof: the unsafe open may already occur.
  Evaluate any additional native restriction against its complete open path.
  Requiring a special mount, sandbox, helper, binding, or build change is a design
  finding, not permission to introduce it.
- **Windows:** evaluate handle-relative native opens, explicit reparse inspection,
  file/volume identities, and regular-disk-file validation before content reads.
  Non-directory alone does not mean regular file. Cover namespace escapes,
  reserved names, junctions, unexpected reparse tags, and alternate-stream names;
  do not use lexical path-prefix comparisons as the boundary.

All variants must follow qualified in-root links with cycle detection, refuse
outside-root traversal, identify unsupported cases, and retain uncertainty about
live changes. A mechanism that denies every read does not meet the contract.

### Portable memory observation

Candidate external samples of supervisor and worker:

- Linux: `/proc/<pid>/smaps_rollup` RSS; require access and account for collection
  cost. If another counter is proposed, document its accuracy instead of silently
  treating approximate `statm`/`VmRSS` data as equivalent.
- macOS: the `proc_pidinfo` task-information interface's `pti_resident_size`.
  Establish whether the pinned Go/x/sys baseline can call the needed interface
  correctly on both architectures without another dependency. Verify ABI, returned
  size, units, errors, and process identity; an exported syscall number is not
  sufficient qualification.
- Windows: `GetProcessMemoryInfo`/`K32GetProcessMemoryInfo` working-set bytes from
  retained process handles. Do not substitute commit charge for working set.

Exercise the approved 100 ms sampling design, sum the two process measurements,
and record actual sampling gaps and overhead. Shared pages can be counted twice;
the observations are not a unique physical-memory total or a hard ceiling.
Maintain the existing distinction between Go soft targets, sampled resident
usage, and OS-specific enforcement. Missing/failed monitoring must be surfaced,
not interpreted as zero usage.

Optional hard-limit integration is **not** a required first-probe outcome. Record
what could be provided by a qualified pre-launch cgroup or Windows Job, its metric,
startup coverage, and failure behavior. If no qualified mechanism is available,
a policy demanding it must prevent target access. Do not run OOM/commit-denial
experiments or alter a live cgroup/job without separately reviewed authorization.

### Termination

Evaluate owned-process cancellation and bounded forced termination: private-pipe
cancellation, POSIX process/group signaling, and Windows worker Job/handle control.
Test parent death and handle inheritance as well as a cooperative worker. Retain
identity/ownership when acting on processes; never kill by a broad process name.

A process group is not a sandbox. A Windows Job covering only the worker is not
an aggregate memory cap covering its supervisor. Record actual cleanup completion;
a signal request or timeout does not prove the process has exited. External OOM,
forced parent termination, and uninterruptible kernel work can prevent reports or
application-selected exit codes. Do not promise an instantaneous kernel kill.

## Native matrix and order

| Environment | Architecture | Current execution status |
| --- | --- | --- |
| macOS 15 | arm64 | NOT RUN |
| macOS 15 | amd64 | NOT RUN |
| Ubuntu 24.04 | amd64 | NOT RUN |
| Ubuntu 24.04 | arm64 | NOT RUN |
| Windows Server 2022 | amd64 | NOT RUN |

1. Resolve the macOS source/API opening argument first. Stop with a blocker if
   there is no credible mechanism under the approved constraints.
2. After separate authorization, use one explicitly chosen native macOS 15 runner
   for the smallest positive/negative opening cases, then deterministic races.
3. Only if that approach is viable, authorize expansion to the remaining native
   rows and the portable memory/termination cases.

No runners are currently designated or provisioned by this plan. Cross-compilation,
emulation, or successful execution on only one architecture cannot fill another
row. Record runner image, kernel, filesystem/mount settings, case sensitivity,
privileges, Go artifact/checksum, dependency/build provenance, and available APIs.
Do not silently narrow supported filesystems from what was promised elsewhere;
report exactly which configurations were exercised and what remains unknown.

## Minimum case groups and required observations

| Group | Controlled cases | Required observation |
| --- | --- | --- |
| Positive access | Ordinary files/directories, in-root links, distinct physical instances | Correct bytes/identities; no target writes; not an always-deny implementation |
| Boundary access | Relative escapes, outside-root links, cycles, mount/bind boundaries, Windows junction/reparse/namespace cases | Refuse prohibited access; never read the outside canary; explicit unsupported cases |
| Special files | FIFO, socket, and separately authorized inert device fixtures | No content I/O on special objects and no unsafe device-open side effect; no blocking open mistaken for a safe rejection |
| Replacement races | Replace a checked regular entry or ancestor with a link, directory, or special object; rename/remove during access | Enforce the boundary at access time; detect relevant identity/change disagreement; no safety inference from a later `Fstat` |
| Live content | Truncate/grow/rewrite controlled regular files during reading | Bounded reads and explicit instability; unchanged metadata is not an immutable-snapshot guarantee |
| Sampling | Bounded touched-memory steps in worker and supervisor, known process exit, query failure | Correct process/unit attribution, nonzero usage where expected, recorded sampling gaps, no false hard-limit claim |
| Termination | Cooperative cancellation, stalled worker, pipe backpressure, worker crash, parent death | Bounded attempts, validated partial evidence, known remaining processes, no hang presented as success |
| Preflight refusal | Missing mandatory opening/sampling mechanism or unavailable policy-required hard cap | No target access before refusal; diagnostic distinguishes unsupported environment from an empty/successful scan |

Use a controlled outside-root canary, not real host files. Use deterministic
synchronization around vulnerable windows where possible, with a small bounded
stress repetition as a supplement. Record the schedule and instrumentation.
Stress that does not hit the race window is not proof the race is prevented.
If instrumentation cannot establish whether driver-open occurred, that assurance
remains unproven rather than becoming a passing check.

## Isolation and approved probe limits

These are **approved probe limits**, not modifications to production budgets or
permission to consume these resources now.

- Future prototype location: `probes/native-safety/`, as an isolated module, only
  after authorization. Do not create a root production module or promote probe
  code into production implicitly.
- Use disposable, explicitly approved native runners for dangerous race fixtures.
  No real projects, credentials, host-directory passthroughs, remote filesystems,
  external services, kernel extensions, or untrusted binaries.
- Fixture setup/mutation belongs to a trusted harness. The observer itself must
  not write its investigated tree. Separate and audit those roles; report harness
  memory separately from supervisor-plus-worker observations.
- Privileged fixture setup, symlink privileges, special mounts, and security
  changes need their own approval. Never automatically enable Developer Mode,
  disable SIP, elevate the observer, install drivers, or relax access controls.
- Device experiments are limited to specifically reviewed inert fixtures such as
  a null-device equivalent inside the disposable environment. No disk, terminal,
  physical hardware, or arbitrary device nodes. If safe setup is unavailable,
  mark the case BLOCKED. Intentional unsafe negative controls need the same gate.
- Tests use no network. Any missing official toolchain/module artifacts require a
  separately authorized preparation step; do not inherit a downloader fallback.

| Resource | Probe bound |
| --- | --- |
| Native test execution per authorized row | 15 minutes, including cleanup attempts |
| Individual test child | 10 seconds; cleanup must also remain inside the row deadline |
| Test child launches / stress repetitions per race | 100 / 50 |
| Concurrent test workers / fixture mutators | 1 / 1, plus the trusted supervisor |
| Synthetic fixture data / entries | 32 MiB / 1,000 |
| Deliberately touched allocation per allocating process | 64 MiB maximum |
| Harness-observed aggregate process stop threshold | 512 MiB; not represented as hard prevention |
| Captured evidence / stderr per child | 32 MiB per row / 64 KiB |
| New build cache per runner | 2 GiB |

Limits apply together, not as a promise that every maximum fits simultaneously.
Lower memory thresholds may exercise stop logic without inducing real memory
exhaustion. Actual runtime/RSS observations are feasibility measurements, not the
production 1,000-instance benchmark. Provisioning/build preparation is separate
from the test deadline and requires its own approved resources before execution.

An independent runner timeout/recovery mechanism is required before potentially
blocking or unsafe experiments; do not rely solely on the guard under test.
Specify that mechanism and its authorization for the selected runner. If it is
unavailable, stop before the experiment. Cleanup may touch only proven-owned
probe artifacts and processes; uncertain leftovers are reported, not removed.

## Evidence and stop decisions

For every case, retain bounded structured inputs, fixture identities/hashes,
expected outcome, actual result, diagnostics, API errors, relevant operation trace,
child termination status, and measurements with units. Preserve source reasoning
separately from native observations. Keep synthetic labels in shareable reports;
redact host paths, usernames, secrets, and raw native errors as needed.

- **PASS:** the specific expected result was observed with sufficient evidence.
- **FAIL:** an expected boundary or behavior was violated; preserve evidence and
  stop the affected path. Do not retry until success and discard the failure.
- **BLOCKED:** missing prerequisite, permission, instrument, or credible mechanism.
- **NOT RUN:** not executed. A reached resource limit is an explicit stop reason,
  never successful completion of omitted cases.

Stop on any outside-root access, observer write, unsafe device open, uncontrolled
process, or absent mandatory safeguard. Do not run further dangerous variants to
collect more examples. Record required changes as proposals for user review.

The deliverable is a feasibility report mapping each mechanism and native row to
observed evidence and unresolved obligations, plus a recommendation to retain or
revise the design. Passing isolated cases is not full scanner/platform acceptance.
Only after reviewing that report should the affected production mechanisms be
fixed in the consolidated specification. Written-spec approval, implementation
planning, and production execution authorization remain separate gates.

## Sources inspected

- [Go os.Root contract](https://pkg.go.dev/os#Root).
- [Linux openat2](https://man7.org/linux/man-pages/man2/openat2.2.html).
- [Linux open/O_PATH](https://man7.org/linux/man-pages/man2/open.2.html).
- [Pinned XNU spec_open](https://github.com/apple-oss-distributions/xnu/blob/xnu-11215.1.10/bsd/miscfs/specfs/spec_vnops.c).
- [Pinned XNU VNOP_OPEN dispatch](https://github.com/apple-oss-distributions/xnu/blob/xnu-11215.1.10/bsd/vfs/kpi_vfs.c): the inspected wrapper also dispatches without an `O_EVTONLY` bypass.
- [XNU task-information structure](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info.h).
- [Linux cgroup v2 memory and delegation](https://docs.kernel.org/admin-guide/cgroup-v2.html).
- [Windows process memory counters](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-process_memory_counters).
- [Windows Job extended limits](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information).
- [Windows process-to-Job assignment](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject).

Local source inspection also used the existing probe cache's pinned x/sys Darwin
constants/types and Windows API declarations. No new probe or native test was run
while preparing this document.
