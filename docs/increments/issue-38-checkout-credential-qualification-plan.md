# Issue 38: checkout credential qualification implementation plan

> **For agentic workers:** I require `executing-plans` for any separately authorized
> inline implementation. This plan grants no agents, implementation, execution or
> publication. Checkboxes below describe future steps, not completed tests.

Status: **written plan approved; owned harness implementation and pure Python tests authorized**.
I initially recorded **“Plan de credenciales” / “Bundle intacto”** as documentary
permission only. After reviewing the actual written proposal at `3ab6bca8`, the owner
explicitly chose **“AProbar y empezar implementación”**, followed by **“Implementar y
probar”** for exclusively owned pure Python unit tests. I record this before code.
I may create the three owned harness files and execute those pure tests locally;
I may not execute checkout/Node/Git/bubblewrap, controlled runtime fixtures,
namespaces/cgroups, downloads, agents, real credentials, Go, CI or publication.
Independent review and actual runtime-artifact/execution permissions remain absent.

**Goal:** I specify an executable, bounded synthetic-credential experiment that
can distinguish actual main/post residue observations from warnings, exit success,
missing evidence or a guard that simply refuses everything.

**Architecture:** I run the unchanged received bundle in a separately approved
sterile Ubuntu 24.04 amd64 filesystem/network/PID namespace, with Node 24 and real
Git over an owned empty repository. An owned Git wrapper redirects only fetch to
an owned local remote and injects named failures; an optional Node preload records
fixed milestones/injects filesystem failures without inspecting credential values.
An independent observer uses real Git's name-only queries and file presence.

**Tech stack:** Owned Python 3.12+ standard-library supervisor/fixtures/unittest,
owned Node ESM preload, existing approved bubblewrap and delegated cgroup v2.
No npm, compilation, added root dependencies, workflow, Go, real tokens or host
credential inspection. Failure to obtain these exact prerequisites blocks execution;
I do not install tools or alter host security to make the experiment run.

**Spec:** [approved assessment scope](issue-38-checkout-assessment-scope.md),
A06-A14, and [static findings](issue-38-checkout-static-assessment.md), S01-S06.
The proposed root-CI spec/plan at
[`6362a944e0ff6041ac2243de5d92549990c3bc4c`](https://github.com/landroval/PackTrace/tree/6362a944e0ff6041ac2243de5d92549990c3bc4c)
remain unchanged. I test their credential-name classification, not install it.

## Global constraints and permission boundaries

- Candidate stays `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1`.
  I execute neither TypeScript nor reconstructed/transformed bundle modules.
- Runtime copies of `005.data` → `dist/index.js`, `006.data` → `dist/package.json`,
  `007.data` → `dist/problem-matcher.json` must match the fixed hashes in code,
  before and after each experiment. A filename/comment/tag is not build proof.
- Only an approved *sterile* runtime filesystem may be mounted as `/`; never
  `--ro-bind / /`, the host home, actual runner workspace/temp, SSH/GPG agents,
  credentials/config, container sockets, private `.env` or Runner.Listener.
- Normal inputs: persistence/safe.directory/submodules/LFS/tags false, fetch-depth
  1, no SSH key, no privileged/fork event. A persistence-true setup is an explicitly
  labelled synthetic post control, **not acceptance of an expanded CI profile**.
- All environment entries are constructed from literals/owned fixture paths.
  Hyphens are preserved in `INPUT_PERSIST-CREDENTIALS`, not converted to underscores.
  Direct bundle launch has no Runner applying Action metadata defaults; the default
  persistence control therefore explicitly supplies metadata default `true`.
- Token is the literal non-service synthetic string in the owned launcher. It is
  not read from the operator/runner environment or a real Git config. Raw output,
  state/config/token values and even credential-key hashes are never evidence logs.
  Name-only Git output is reduced to fixed booleans. Owned Action state is parsed
  only for the known routing keys/owned paths, with a 64-KiB bound.
- Separate permission must cover creating/using the namespace and new delegated
  child cgroups, running owned harness/tool binaries, acquired bundle main/post,
  synthetic fault/cancellation/deletion cases and owned data writes. No destructive
  host action, network, native malicious target, installation, privilege adjustment,
  runner registration, CI publication or issue closure follows from plan approval.
- Acquisitions stay **39 requests / 1,894,265 payload bytes**. The unallocated request
  is not used. New runtime/package/image acquisition needs its own exact approved
  acquisition manifest and, if necessary, scope revision; this plan has no downloader.

## Review focus

1. Main exit 0 with denied config enumeration/unset/deletion must not certify removal.
2. Failure after token-file rewrite but before first include must remain observable;
   repeated main/post must not erase an orphan's coverage gap.
3. A clean negative observer must enable the owned `wouldEnableGo` boolean, while
   residue/unknown/lifecycle failures must disable it. I never actually invoke Go.
4. Post routing must use actual bounded main state; missing state/config/Git or
   skipped/cancelled post cannot inherit a prior cleanup success.
5. Instrumentation/local fetch differs from actual Runner/network/timing. Even all
   expected-observation cases passing cannot close notice/advisory/platform/adoption.

## Files and exact external input contract

Today I create only **this Markdown document**. Future proposed files, not created:

| Path | Responsibility |
| --- | --- |
| `probes/checkout-credentials/probe.py` | Pure checks, supervisor, seed/observer, cases, fixed receipt |
| `probes/checkout-credentials/git.py` | Real-Git forwarding/local fetch and named fault injection |
| `probes/checkout-credentials/hooks.mjs` | Instrumented milestones/filesystem faults; reject network calls |

The future executable accepts an explicit `--manifest` plus its separately reviewed
`--manifest-sha256`. Those are required actual inputs, not invented runtime identities.
The exact JSON schema is the key set used in `load_manifest` below. Its fields mean:

- `runtimeRoot`: absolute owned sterile Ubuntu 24.04 amd64 filesystem supplied and
  frozen by a separately authorized operator procedure. This plan neither builds
  it nor accepts a host root or a filesystem containing real credentials.
- `runtimeIdentity`: reviewed SHA-256 identity of that external filesystem catalog;
  hashing a label does not authenticate it. Complete tool/shared-library/image
  provenance must accompany the actual manifest at execution approval.
- `bwrap`, `bwrapSHA256`: designated existing host launcher and its actual fingerprint.
- `nodeSHA256`, `gitSHA256`, `pythonSHA256`: actual frozen runtime binary fingerprints,
  at the **fixed** inside paths in code. Node is the externally identified bundled
  Node 24 in `/opt/runner/externals/node24/bin/node`, not PATH discovery or Listener.
- `cgroupRoot`: pre-existing operator-approved delegated subtree, under cgroup v2,
  with memory/pids/cpu enabled and child `cgroup.kill` support. Creating child groups
  here is proposed; enabling delegation/controllers, sudo or security changes is not.
- `rawRoot`: retained frozen three-file corpus directory; missing receipts/files
  do not authorize recollection, reconstruction or changed pins.
- `outputRoot`: absolute **nonexisting** output directory, outside all repositories,
  runtime/input/cgroup trees, approved for private 0700 fixture/receipt retention.

A manifest digest match is not authority: the operator must approve the **actual
manifest/tool/package/catalog/probe hashes and exact command** before any execution.
Missing hosting artifacts leave readiness blocked; executable code does not create
provenance. Trusted, frozen operator-owned inputs are a precondition, not a claim of
hostile-path/device-substitution resistance from `resolve`/`is_file`.

### Budgets and lifecycle

One worker; 30-minute whole experiment; 75 seconds per owned phase including output
EOF and termination; <=120 phases; cgroup memory.max 512 MiB, memory.swap.max 0,
pids.max 64, cpu.max `200000 100000` (two CPU-equivalents). A failed control/readback
or missing cgroup.kill blocks launching. Node old-space 96 MiB is an additional soft
heap setting, not aggregate RAM. OOM/pid-limit/CPU-controller uncertainty is not pass.

Owned supervisor capture of phase stdout/stderr <=1 MiB per phase, 8 MiB cumulatively,
discarded rather than published. Nested owned seed/observer/version commands have a
separate combined 64-KiB/5-second cap per call; SDK-internal buffering is not counted
as supervisor capture and remains subject to the cgroup, not a total I/O-byte claim.
Events <=64 KiB and state/output files <=64 KiB each. Receipt <=64 KiB;
report <=1 MiB. Owned writable retention <=64 MiB / 4,096 entries, checked every 100 ms
and before/after phase: this is a **stop-on-observed-limit, not a hard filesystem quota**;
transient unsampled write overshoot remains a limitation. No host filesystem quota,
CPU/RSS sampling improvement or alternative sandbox is silently introduced.

The writable case/state/events are controlled experimental artifacts, not tamper-proof
receipts against a malicious Action. The probe/observer code is mounted read-only and
uses real Git separately, but this plan does not qualify adversarial evidence hiding
or infer that matching milestones prove a benign candidate. S06 remains open.

Child groups are terminated using cgroup.kill on cancellation/deadline/overflow and
in final cleanup. A normal exit needs EOF, no retained descendant and normal memory/
pid counters **before cleanup**. If kill/reap/group-empty closure fails, retain the
private directory and mark lifecycle unqualified; never launch the next case. Delete
only the now-empty owned child cgroup; do not prune fixture/data trees automatically.

## Expected-observation matrix (future, none executed)

`accept` below means the observed fixture satisfies its stated predicate, not that
Action adoption is acceptable. At least the clean baseline, instrumented clean and
known-residue controls must execute; an always-deny program cannot qualify the guard.
The implementation code contains the exact ordered IDs and expected predicates.

| ID | Kind | Required observation |
| --- | --- | --- |
| C01 | Clean observer | Name-only clean config and no matching file → guard true |
| C02 | Orphan presence observer | Matching empty synthetic file → guard false |
| C03 | Forbidden keys observer | Each include/includeIf/credential/url/sshCommand/http header → false |
| C04 | Invalid/query-failure observer | Invalid UTF-8 and failed query → false, not known absence |
| C05 | Intact unpreloaded main | Main 0; file+include milestones; before-post guard true |
| C06 | Instrumented main | Main 0; `token-written` and include milestones; guard true |
| C07 | First include rejected | Main nonzero; injection reached after file rewrite; guard false |
| C08 | Cleanup enumeration rejected | Main 0; rejection reached; retained file/include; guard false |
| C09 | Cleanup unset rejected | Main 0; rejection reached; retained include; guard false |
| C10 | File deletion rejected | Main 0; deletion reached; retained file; guard false |
| C11 | Additional unlinked file | Main 0; extra-file milestone; guard false |
| C12 | Multiple existing files/includes | Initial guard false; new main 0; guard true |
| C13 | Repeated clean main | Two main 0; independent second cleanup; guard true both |
| C14 | Orphan then repeated main | First nonzero/guard false; second 0/guard false; orphan not rescued |
| C15 | Persistence metadata default | Main 0 with explicit true; guard false/profile false |
| C16 | Actual post control | Persistence-true main leaves residue; state-routed post 0 removes it |
| C17 | Post missing repository state | Setup residue, post 0/early return; guard false |
| C18 | Post missing config | Post 0/early return; required config unavailable → guard false |
| C19 | Post Git unavailable | Post 0/early return; residue retained; guard false |
| C20 | Post cleanup enumeration denied | Post 0/warning path possible; residue retained; false |
| C21 | Auth rewrite cancelled | Milestone reached; kill/EOF/empty group; residue → false |
| C22 | Output overflow | Owned child exceeds cap; killed; no prefix certified |
| C23 | Descendant retains output pipe | Owned parent exits but EOF missing; timeout/kill; no pass |
| C24 | Observer `.git/config` unavailable | No process success substitutes required config; false |
| C25 | Unselected/forbidden profile | SSH/LFS/submodule/unsafe event input rejected before bundle |
| C26 | Git-missing fallback observation | Network-reject marker, nonzero; profile unqualified, no archive |

C03-C04/C25 are owned test families with explicit children in code, not 26 claimed
runtime test passes. C16-C20 use persistence true only to establish positive post
residue controls; they are outside the normal acceptance profile. C26 intentionally
uses unsupported Git as a negative control with no network permission/egress.
S03/S04 arbitrary path/native/global-home races are not executed: those assumptions
remain outside this plan's qualified narrow fixture profile. No invented coverage.

## Task 1: pure guard/coverage tests first

**Files:** future `probes/checkout-credentials/probe.py`.
**Consumes:** explicit bytes/status/phase facts; no host filesystem.
**Produces:** `forbidden_keys`, `guard_decision`, `would_enable` and `ContractTests`.

- [ ] Write the following tests first; missing functions are compilation/API failure,
  not behavioral RED. Confirm the selected family actually ran before reporting RED.
- [ ] Add a temporary always-deny `guard_decision`; C01 must fail. Add the minimum
  functions shown in Task 2, then require all these owned tests to pass.
- [ ] Independently deny-residue, ignore-query-error and permit-incomplete-phase
  counterfactuals must fail their own tests. Restore exact source/hashes before the
  controlled stages. Never mutate the acquired bundle or call warnings cleanup proof.

```python
# Append to probe.py before its final __main__ branch; unittest only when --self-test.
class ContractTests(unittest.TestCase):
    def test_C01_clean_positive(self):
        self.assertTrue(guard_decision(0, b'core.repositoryformatversion\n', 0, True))
    def test_C02_orphan_negative(self):
        self.assertFalse(guard_decision(0, b'', 1, True))
    def test_C03_each_forbidden_key(self):
        for key in [b'include.path', b'includeIf.gitdir:/case/x.path',
                    b'credential.helper', b'url.https://github.com/.insteadof',
                    b'core.sshCommand', b'http.https://github.com/.extraheader']:
            with self.subTest(key=key):
                self.assertFalse(guard_decision(0, key + b'\n', 0, True))
    def test_C04_invalid_or_failed(self):
        for code, data in [(2, b''), (0, b'\xff')]:
            with self.subTest(code=code):
                self.assertFalse(guard_decision(code, data, 0, True))
    def test_C24_missing_required_config(self):
        self.assertFalse(guard_decision(0, b'', 0, False))
    def test_profile_and_lifecycle(self):
        self.assertTrue(would_enable(True, True, True, True))
        for facts in [(False, True, True, True), (True, False, True, True),
                      (True, True, False, True), (True, True, True, False)]:
            self.assertFalse(would_enable(*facts))
    def test_state_missing_not_fabricated(self):
        self.assertEqual(parse_state(b'isPost<<x\ntrue\nx\n'), {'isPost': 'true'})
        with self.assertRaises(Blocked):
            parse_state(b'isPost<<x\ntrue\n')
    def test_C25_each_forbidden_input(self):
        for change in [{'ssh-key': 'synthetic'}, {'lfs': 'true'},
                       {'submodules': 'true'}, {'allow-unsafe-pr-checkout': 'true'}]:
            values = dict(INPUTS); values.update(change)
            self.assertFalse(profile_ok(values, 'push'))
        self.assertFalse(profile_ok(INPUTS, 'pull_request_target'))
        self.assertFalse(profile_ok(INPUTS, 'workflow_run'))
```

## Task 2: complete proposed supervisor, seed, observer and cases

**Files:** future `probes/checkout-credentials/probe.py`.
**Consumes:** frozen manifest/digest and the two owned scripts from Tasks 3/4.
**Produces:** bounded private execution tree and `receipt.json`; stdout only a fixed
summary, no raw output. On failed preflight it creates no bundle child. Executable
parameters are a future actual approved manifest, not permission tokens in code.

- [ ] Implement this complete body, add Task 1's class before the final main branch.
- [ ] Validate the actual future runtime manifest/probe hashes in independent review;
  do not infer the authority to launch from a matching digest or a JSON field.
- [ ] Execute self-tests only with their separate owned-code permission.

```python
import argparse, errno, hashlib, json, os, re, selectors, stat
import platform, subprocess, sys, time, unittest
from pathlib import Path

PIN = '3d3c42e5aac5ba805825da76410c181273ba90b1'
NODE = '/opt/runner/externals/node24/bin/node'
GIT = '/usr/bin/git'
PYTHON = '/usr/bin/python3'
FILES = {
    '005.data': ('index.js', 'b604bf1c08a471aedf51ddddbd3e8d03041683db270692d66cd1b4b097457818'),
    '006.data': ('package.json', '3ca9d4afd21425087cf31893b8f9f63c81b0b8408db5e343ca76e5f8aa26ab9a'),
    '007.data': ('problem-matcher.json', '31430dcd64d833e6baa706d65803cb80ee2fb6ac20a35267b086218bbc210cb7')}
TOKEN = 'packtrace-synthetic-not-a-service-token'
INPUTS = {'repository': '', 'ref': '', 'path': '', 'token': TOKEN,
          'clean': 'true', 'filter': '', 'sparse-checkout': '',
          'sparse-checkout-cone-mode': 'true', 'fetch-depth': '1',
          'fetch-tags': 'false', 'show-progress': 'false', 'lfs': 'false',
          'submodules': 'false', 'ssh-key': '', 'ssh-known-hosts': '',
          'ssh-strict': 'true', 'ssh-user': 'git', 'persist-credentials': 'false',
          'set-safe-directory': 'false', 'github-server-url': 'https://github.com',
          'allow-unsafe-pr-checkout': 'false'}
CASES = [('C05', 'baseline'), ('C06', 'clean'), ('C07', 'first-include'),
         ('C08', 'enumeration'), ('C09', 'unset'), ('C10', 'delete'),
         ('C11', 'extra-file'), ('C12', 'multiple'), ('C13', 'repeat'),
         ('C14', 'orphan-repeat'), ('C15', 'persist'), ('C16', 'post'),
         ('C17', 'post-no-state'), ('C18', 'post-no-config'), ('C19', 'post-no-git'),
         ('C20', 'post-enumeration'), ('C21', 'cancel'), ('C22', 'overflow'),
         ('C23', 'pipe'), ('C24', 'missing-config'), ('C26', 'git-missing')]
UUID1 = '00000000-0000-4000-8000-000000000001'
UUID2 = '00000000-0000-4000-8000-000000000002'
START = time.monotonic()
CAP, TOTAL, RETAIN = 1048576, 8388608, 67108864
used = launches = 0

class Blocked(Exception):
    pass

def bounded(path, cap=65536):
    with open(path, 'rb') as stream:
        data = stream.read(cap + 1)
    if len(data) > cap:
        raise Blocked('file-limit')
    return data

def write_json(path, data):
    raw = json.dumps(data, separators=(',', ':')).encode()
    if len(raw) > 65536:
        raise Blocked('receipt-limit')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(raw)

def forbidden_keys(raw):
    keys = raw.decode('utf-8').lower().splitlines()
    return any(k.startswith(('include.', 'includeif.', 'credential.', 'url.'))
               or k == 'core.sshcommand'
               or (k.startswith('http.') and k.endswith('.extraheader')) for k in keys)

def guard_decision(code, names, residue, config_available):
    try:
        return bool(config_available and code == 0 and residue == 0
                    and not forbidden_keys(names))
    except UnicodeError:
        return False

def would_enable(profile, normal_main, lifecycle, absence):
    return bool(profile and normal_main and lifecycle and absence)

def profile_ok(values, event):
    return (event == 'push' and all(values.get(k) == INPUTS[k] for k in
            ['ssh-key', 'lfs', 'submodules', 'allow-unsafe-pr-checkout',
             'persist-credentials', 'set-safe-directory', 'fetch-depth', 'fetch-tags']))

def parse_state(raw):
    if len(raw) > 65536:
        raise Blocked('state-limit')
    lines = raw.decode('utf-8').splitlines(); out = {}; i = 0
    while i < len(lines):
        key, sep, delim = lines[i].partition('<<'); i += 1
        if (not sep or key not in {'isPost', 'repositoryPath', 'setSafeDirectory'}
                or key in out or not delim or i + 1 >= len(lines)):
            raise Blocked('state-shape')
        value = lines[i]; i += 1
        if lines[i] != delim:
            raise Blocked('state-closure')
        i += 1
        if ((key == 'repositoryPath' and value != '/case/workspace')
                or (key != 'repositoryPath' and value != 'true')):
            raise Blocked('state-value')
        out[key] = value
    return out

def env(inputs=None):
    base = {'PATH': '/case/bin:/usr/bin:/bin', 'HOME': '/case/home',
            'XDG_CONFIG_HOME': '/case/xdg', 'TMPDIR': '/case/temp',
            'RUNNER_TEMP': '/case/temp', 'LANG': 'C.UTF-8',
            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_TERMINAL_PROMPT': '0',
            'GCM_INTERACTIVE': 'Never', 'GITHUB_WORKSPACE': '/case/workspace',
            'GITHUB_REPOSITORY': 'packtrace-fixture/checkout-qualification',
            'GITHUB_REF': 'refs/heads/probe', 'GITHUB_EVENT_NAME': 'push',
            'GITHUB_EVENT_PATH': '/case/event.json', 'GITHUB_SERVER_URL': 'https://github.com',
            'GITHUB_API_URL': 'https://api.github.com', 'GITHUB_RUN_ID': '1',
            'GITHUB_ACTION': 'owned-credential-probe', 'GITHUB_STATE': '/case/state',
            'GITHUB_OUTPUT': '/case/output', 'GITHUB_ENV': '/case/action-env'}
    if inputs is not None:
        base.update({'INPUT_' + k.upper(): v for k, v in inputs.items()})
        base['GITHUB_SHA'] = bounded('/case/commit').decode().strip()
    return base

def small_command(argv, input=None):
    if input is not None and len(input) > 1024:
        raise Blocked('owned-command-input')
    p = subprocess.Popen(argv, env=env(), stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    selector = selectors.DefaultSelector(); data = bytearray(); amount = 0
    end = time.monotonic() + 5
    try:
        if input is not None:
            p.stdin.write(input); p.stdin.close()
        selector.register(p.stdout, selectors.EVENT_READ, 'stdout')
        selector.register(p.stderr, selectors.EVENT_READ, 'stderr')
        while selector.get_map() or p.poll() is None:
            if time.monotonic() >= end:
                raise Blocked('owned-command-deadline')
            for key, _ in selector.select(0.05):
                part = os.read(key.fileobj.fileno(), 4096)
                if not part:
                    selector.unregister(key.fileobj); continue
                amount += len(part)
                if amount > 65536:
                    raise Blocked('owned-command-output')
                if key.data == 'stdout':
                    data.extend(part)
        return p.wait(timeout=1), bytes(data)
    finally:
        selector.close()
        if p.poll() is None:
            p.kill()
        p.wait(timeout=1)
        p.stdout.close(); p.stderr.close()


def git(*args, input=None):
    code, output = small_command([GIT, *args], input)
    if code:
        raise Blocked('seed-or-observer-command')
    return output

def prepare(kind):
    git('init', '--bare', '--initial-branch=probe', '/case/remote')
    git('-C', '/case/remote', 'fast-import', '--quiet', input=(
        b'commit refs/heads/probe\ncommitter Fixture <fixture@example.invalid> 0 +0000\n'
        b'data 7\nfixture\n\n'))
    git('clone', '--local', '--no-hardlinks', '/case/remote', '/case/workspace')
    git('-C', '/case/workspace', 'config', 'remote.origin.url',
        'https://github.com/packtrace-fixture/checkout-qualification')
    Path('/case/commit').write_bytes(git('-C', '/case/workspace', 'rev-parse', 'HEAD'))
    if kind == 'multiple':
        for uuid in [UUID1, UUID2]:
            file = '/case/temp/git-credentials-' + uuid + '.config'
            Path(file).write_text('')
            git('-C', '/case/workspace', 'config', '--add',
                'includeIf.gitdir:/case/workspace/.git.path', file)


def observer():
    count = 0
    with os.scandir('/case/temp') as entries:
        for entry in entries:
            if entry.name.startswith('git-credentials-') and entry.name.endswith('.config'):
                count += 1
    available = Path('/case/workspace/.git/config').is_file()
    okay = available
    query_failed = forbidden = False
    for name in ['/case/workspace/.git/config', '/case/home/.gitconfig',
                 '/case/xdg/git/config', '/etc/gitconfig']:
        path = Path(name)
        if not path.exists():
            continue
        code, names = small_command([GIT, 'config', '--file', name, '--no-includes',
                                     '--name-only', '--list'])
        query_failed |= code != 0
        try:
            bad = forbidden_keys(names)
        except UnicodeError:
            bad = True
        forbidden |= bad
        okay &= guard_decision(code, names, count, available)
    return {'absence': bool(okay and count == 0), 'residueCount': count,
            'configAvailable': available, 'queryFailed': query_failed,
            'forbiddenNamesPresent': forbidden}


def inside(mode):
    if os.geteuid() == 0:
        raise Blocked('root-profile')
    task = json.loads(bounded('/case/task.json'))
    if mode == 'prepare':
        prepare(task['kind'])
    elif mode == 'observe':
        write_json('/case/' + task['label'] + '.json', observer())
    elif mode == 'overflow':
        for _ in range(40):
            os.write(1, b'x' * 65536)
    elif mode == 'pipe':
        subprocess.Popen([PYTHON, '-c', 'import time;time.sleep(120)'], env=env())
    elif mode == 'metadata':
        routes = bounded('/proc/net/route').decode().splitlines()[1:]
        ipv6 = bounded('/proc/net/ipv6_route').decode().splitlines()
        devices = bounded('/proc/net/dev').decode().splitlines()[2:]
        if (any(line.strip() for line in routes) or any(line.split()[-1] != 'lo' for line in ipv6)
                or any(line.split(':', 1)[0].strip() != 'lo' for line in devices)):
            raise Blocked('network-namespace-routes')
        for protected in ['/action/dist/index.js', '/probe/git.py']:
            try:
                fd = os.open(protected, os.O_WRONLY | os.O_APPEND)
            except OSError as error:
                if error.errno != errno.EROFS:
                    raise Blocked('readonly-mount-unqualified')
            else:
                os.close(fd)
                raise Blocked('readonly-mount-writable')
        if sys.version_info < (3, 12) or platform.machine() != 'x86_64' or platform.system() != 'Linux':
            raise Blocked('runtime-platform')
        release = bounded('/etc/os-release').decode()
        if not re.search(r'^ID="?ubuntu"?$', release, re.M) or not re.search(r'^VERSION_ID="?24\.04"?$', release, re.M):
            raise Blocked('ubuntu-24-04-unavailable')
        version_code, node_version = small_command([NODE, '--version'])
        if version_code or not re.fullmatch(rb'v24\.[0-9]+\.[0-9]+\n', node_version):
            raise Blocked('node-24-unavailable')
        git_version = git('--version')
        match = re.fullmatch(rb'git version ([0-9]+)\.([0-9]+)\.([0-9]+)\n', git_version)
        if not match or tuple(map(int, match.groups())) < (2, 43, 0):
            raise Blocked('git-version-profile')
        write_json('/case/metadata.json', {'node': node_version.decode().strip(),
                   'git': git_version.decode().strip(), 'ubuntu': '24.04',
                   'python': platform.python_version(), 'nonroot': True,
                   'externalRoutesAbsent': True, 'mountWriteDenialObserved': True,
                   'netNamespace': os.readlink('/proc/self/ns/net')})
    elif mode == 'action':
        values = dict(INPUTS)
        if task['persist']:
            values['persist-credentials'] = 'true'
        childenv = env(values)
        if task['post']:
            state = parse_state(bounded('/case/state'))
            if task['kind'] == 'post-no-state':
                state.pop('repositoryPath', None)
            if state.get('isPost') != 'true':
                raise Blocked('post-state-unavailable')
            childenv.update({'STATE_' + k: v for k, v in state.items()})
        else:
            Path('/case/state').write_text('')
        args = [NODE, '--max-old-space-size=96']
        if task['kind'] != 'baseline':
            args.extend(['--import', '/probe/hooks.mjs'])
        args.append('/action/dist/index.js')
        return subprocess.call(args, env=childenv, cwd='/case/workspace')
    else:
        raise Blocked('inside-mode')
    return 0


def tree_size(root):
    size = count = 0
    for base, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            count += 1
            st = os.lstat(Path(base) / name)
            if stat.S_ISREG(st.st_mode):
                size += st.st_size
            if count > 4096 or size > RETAIN:
                raise Blocked('retention-limit')
    return size


def fingerprint(path):
    size = 0; digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        while True:
            data = stream.read(1048576)
            if not data:
                break
            size += len(data)
            if size > 134217728:
                raise Blocked('tool-read-limit')
            digest.update(data)
    return digest.hexdigest()


def load_manifest(path, expected):
    raw = bounded(path)
    if not re.fullmatch('[0-9a-f]{64}', expected) or hashlib.sha256(raw).hexdigest() != expected:
        raise Blocked('manifest-identity')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Blocked('duplicate-manifest-key')
            result[key] = value
        return result
    m = json.loads(raw, object_pairs_hook=unique)
    keys = {'runtimeRoot', 'runtimeIdentity', 'bwrap', 'bwrapSHA256', 'nodeSHA256',
            'gitSHA256', 'pythonSHA256', 'cgroupRoot', 'rawRoot', 'outputRoot'}
    if not isinstance(m, dict) or set(m) != keys or not all(isinstance(v, str) for v in m.values()):
        raise Blocked('manifest-shape')
    for key in ['runtimeIdentity', 'bwrapSHA256', 'nodeSHA256', 'gitSHA256', 'pythonSHA256']:
        if not re.fullmatch('[0-9a-f]{64}', m[key]):
            raise Blocked('manifest-digest')
    paths = [Path(m[k]) for k in ['runtimeRoot', 'bwrap', 'cgroupRoot', 'rawRoot', 'outputRoot']]
    if any(not p.is_absolute() or p == Path('/') or '..' in p.parts for p in paths):
        raise Blocked('manifest-path')
    for key in ['runtimeRoot', 'bwrap', 'cgroupRoot', 'rawRoot', 'outputRoot']:
        m[key] = str(Path(m[key]).resolve())
    rt = Path(m['runtimeRoot']); out = Path(m['outputRoot'])
    if os.geteuid() == 0 or platform.system() != 'Linux':
        raise Blocked('host-profile')
    if any((p / '.jj').exists() or (p / '.git').exists() for p in [out.parent, *out.parent.parents]):
        raise Blocked('output-in-repository')
    if out.exists() or not str(Path(m['cgroupRoot'])).startswith('/sys/fs/cgroup/'):
        raise Blocked('manifest-owned-output-or-cgroup')
    for source in [rt, Path(m['rawRoot']), Path(m['cgroupRoot']), Path(__file__).parent]:
        if out == source or out.is_relative_to(source) or source.is_relative_to(out):
            raise Blocked('output-input-overlap')
    for key, tool in [('nodeSHA256', NODE), ('gitSHA256', GIT), ('pythonSHA256', PYTHON)]:
        if fingerprint(rt / tool.lstrip('/')) != m[key]:
            raise Blocked('runtime-tool-identity')
    if fingerprint(m['bwrap']) != m['bwrapSHA256']:
        raise Blocked('launcher-identity')
    m['manifestSHA256'] = expected
    return m


def phase(m, root, case, label, mode, kind, post=False, persist=False):
    global used, launches
    launches += 1
    if launches > 120 or time.monotonic() - START >= 1800:
        raise Blocked('whole-run-budget')
    started = time.monotonic()
    task = case / 'task.json'
    task.write_text(json.dumps({'label': label, 'kind': kind, 'post': post, 'persist': persist}))
    cg = Path(m['cgroupRoot']) / ('packtrace-credential-' + str(os.getpid()) + '-' + str(launches))
    cg.mkdir(mode=0o700)
    process = None; poll = selectors.DefaultSelector(); end = min(START + 1800, time.monotonic() + 75)
    state = 'normal'; amount = 0; closed = False
    try:
        for key, value in [('memory.max', '536870912'), ('memory.swap.max', '0'),
                           ('pids.max', '64'), ('cpu.max', '200000 100000')]:
            (cg / key).write_text(value)
            if (cg / key).read_text().strip() != value:
                raise Blocked('cgroup-control-readback')
        if not (cg / 'cgroup.kill').exists():
            raise Blocked('cgroup-kill-unavailable')
        argv = [m['bwrap'], '--die-with-parent', '--unshare-all',
                '--uid', str(os.getuid()), '--gid', str(os.getgid()),
                '--ro-bind', m['runtimeRoot'], '/', '--proc', '/proc', '--dev', '/dev',
                '--bind', str(case), '/case', '--ro-bind', str(Path(__file__).parent), '/probe',
                '--ro-bind', str(root / 'action'), '/action', '--chdir', '/case', '--clearenv',
                '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'HOME', '/case/home',
                '--', PYTHON, '/probe/probe.py', '--inside', mode]
        def enter_group():
            (cg / 'cgroup.procs').write_text(str(os.getpid()))
        process = subprocess.Popen(argv, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'},
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
                    preexec_fn=enter_group)
        for stream in [process.stdout, process.stderr]:
            poll.register(stream, selectors.EVENT_READ)
        while poll.get_map() or process.poll() is None:
            tree_size(root)
            if time.monotonic() >= end:
                state = 'timed-out'; break
            if mode == 'action' and kind == 'cancel' and (case / 'events').exists() and b'cancel-ready\n' in bounded(case / 'events'):
                state = 'cancelled'; break
            for key, _ in poll.select(0.1):
                data = os.read(key.fileobj.fileno(), 65536)
                if not data:
                    poll.unregister(key.fileobj); continue
                amount += len(data); used += len(data)
                if amount > CAP or used > TOTAL:
                    state = 'overflow'; break
            if state != 'normal':
                break
        if state == 'normal':
            process.wait(timeout=2)
            events = (cg / 'memory.events').read_text() + '\n' + (cg / 'pids.events').read_text()
            if any(int(v) for k, v in (line.split() for line in events.splitlines() if line.strip())
                   if k in {'oom', 'oom_kill', 'max'}):
                state = 'resource-limited'
            closed = 'populated 0' in (cg / 'cgroup.events').read_text()
            if not closed:
                state = 'descendant-retained'
    finally:
        poll.close()
        (cg / 'cgroup.kill').write_text('1')
        if process is not None:
            process.wait(timeout=3)
            process.stdout.close(); process.stderr.close()
        for _ in range(30):
            if 'populated 0' in (cg / 'cgroup.events').read_text():
                closed = True; break
            time.sleep(0.1)
        if not closed:
            raise Blocked('owned-group-not-empty')
        cg.rmdir()
    tree_size(root)
    result = {'state': state, 'exit': process.returncode, 'bytes': amount,
              'lifecycleClosed': closed, 'durationSeconds': time.monotonic() - started}
    write_json(case / (label + '-phase.json'), result)
    return result


def event_set(case):
    if not (case / 'events').exists():
        return set()
    lines = bounded(case / 'events').decode('ascii').splitlines()
    allowed = {'credential-file', 'include', 'first-include-denied', 'enumeration-denied',
               'unset-denied', 'delete-denied', 'extra-file', 'token-written',
               'cancel-ready', 'network-denied', 'git-unavailable', 'fetch-local'}
    if any(line not in allowed for line in lines):
        raise Blocked('event-shape')
    return set(lines)


def experiment(m):
    root = Path(m['outputRoot']); root.mkdir(mode=0o700)
    action = root / 'action/dist'; action.mkdir(parents=True, mode=0o700)
    for source, (dest, expected) in FILES.items():
        data = bounded(Path(m['rawRoot']) / source, 2097152)
        if hashlib.sha256(data).hexdigest() != expected:
            raise Blocked('bundle-identity')
        fd = os.open(action / dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
    rows = []
    def retain(row):
        rows.append(row)
        data = json.dumps(row, separators=(',', ':')).encode() + b'\n'
        ledger = root / 'rows.jsonl'
        if (ledger.stat().st_size if ledger.exists() else 0) + len(data) > 65536:
            raise Blocked('row-ledger-limit')
        with open(ledger, 'ab') as out:
            out.write(data)
    for ident, kind in CASES:
        case = root / ident; case.mkdir(mode=0o700)
        for name in ['home', 'xdg', 'temp', 'bin']:
            (case / name).mkdir(mode=0o700)
        wrapper = case / 'bin/git'
        wrapper.write_text('#!/usr/bin/python3\nimport runpy\nrunpy.run_path("/probe/git.py",run_name="__main__")\n')
        wrapper.chmod(0o700)
        (case / 'event.json').write_text('{"repository":{"private":true,"owner":{"id":1}}}')
        meta = phase(m, root, case, 'metadata', 'metadata', kind)
        if meta['state'] != 'normal' or meta['exit'] != 0:
            raise Blocked('runtime-metadata-unavailable')
        md = json.loads(bounded(case / 'metadata.json'))
        if md['netNamespace'] == os.readlink('/proc/self/ns/net') or not md['nonroot']:
            raise Blocked('namespace-profile')
        prep = phase(m, root, case, 'prepare', 'prepare', kind)
        if prep['state'] != 'normal' or prep['exit'] != 0:
            raise Blocked('fixture-setup')
        def observe(label):
            result = phase(m, root, case, label, 'observe', kind)
            if result['state'] != 'normal' or result['exit'] != 0:
                raise Blocked('observer-unavailable')
            return json.loads(bounded(case / (label + '.json')))
        before = observe('before')
        if kind in {'overflow', 'pipe'}:
            main = phase(m, root, case, 'owned-child', kind, kind)
            accept = main['state'] == ('overflow' if kind == 'overflow' else 'timed-out')
            retain({'id': ident, 'kind': kind, 'accept': accept, 'phase': main}); continue
        if kind == 'missing-config':
            (case / 'workspace/.git/config').rename(case / 'saved-config')
            after = observe('after')
            retain({'id': ident, 'kind': kind, 'accept': not after['absence']
                    and not after['configAvailable'], 'after': after}); continue
        postkind = kind.startswith('post')
        persist = postkind or kind == 'persist'
        setupkind = 'clean' if postkind or kind == 'orphan-repeat' else kind
        if kind == 'orphan-repeat':
            setupkind = 'first-include'
        main = phase(m, root, case, 'main', 'action', setupkind, persist=persist)
        after = observe('after-main'); ev = event_set(case)
        reached = {'first-include': 'first-include-denied', 'enumeration': 'enumeration-denied',
                   'unset': 'unset-denied', 'delete': 'delete-denied', 'extra-file': 'extra-file',
                   'cancel': 'cancel-ready', 'git-missing': 'network-denied'}.get(kind)
        if reached and reached not in ev:
            raise Blocked('injection-not-reached')
        accept = (main['state'] == 'normal' and main['exit'] == 0 and after['absence'])
        if kind in {'first-include', 'orphan-repeat'}:
            accept = (main['state'] == 'normal' and main['exit'] != 0
                      and not after['absence'] and 'token-written' in ev)
        if kind in {'enumeration', 'unset', 'delete', 'extra-file', 'persist'}:
            accept = main['state'] == 'normal' and main['exit'] == 0 and not after['absence']
        if kind == 'cancel':
            accept = main['state'] == 'cancelled' and not after['absence']
        if kind == 'git-missing':
            accept = main['state'] == 'normal' and main['exit'] != 0 and 'network-denied' in ev
        follow = None
        if kind in {'repeat', 'orphan-repeat'}:
            follow = phase(m, root, case, 'second-main', 'action', 'clean')
            second = observe('after-second')
            accept &= follow['state'] == 'normal' and follow['exit'] == 0
            accept &= second['absence'] if kind == 'repeat' else not second['absence']
        if postkind:
            if after['absence']:
                raise Blocked('post-positive-residue-control-missing')
            if kind == 'post-no-config':
                (case / 'workspace/.git/config').rename(case / 'saved-config')
            follow = phase(m, root, case, 'post', 'action', kind, post=True)
            second = observe('after-post')
            accept = follow['state'] == 'normal' and follow['exit'] == 0
            accept &= second['absence'] if kind == 'post' else not second['absence']
            if kind == 'post-enumeration' and 'enumeration-denied' not in event_set(case):
                raise Blocked('post-injection-not-reached')
        if kind in {'baseline', 'clean'}:
            accept &= {'credential-file', 'include', 'fetch-local'} <= ev
            if kind == 'clean':
                accept &= 'token-written' in ev
        if kind == 'multiple':
            accept &= not before['absence']
        if kind == 'orphan-repeat':
            accept &= 'first-include-denied' in ev
        enabled = would_enable(not persist and kind not in {'git-missing'},
                    main['state'] == 'normal' and main['exit'] == 0,
                    main['lifecycleClosed'], after['absence'])
        retain({'id': ident, 'kind': kind, 'accept': bool(accept), 'main': main,
                     'postOrSecond': follow, 'before': before, 'afterMain': after,
                     'wouldEnableGo': enabled, 'fixedEvents': sorted(event_set(case)),
                     'postOrSecondObservation': second if follow else None,
                     'instrumented': kind != 'baseline'})
        for source, (dest, expected) in FILES.items():
            if fingerprint(action / dest) != expected:
                raise Blocked('bundle-changed')
    receipt = {'candidate': PIN, 'fixtureRows': rows, 'expectedObservationsMatched':
               all(row['accept'] for row in rows), 'requestsAcquired': 0,
               'adoption': 'blocked-independent-static-notice-advisory-platform-review',
               'scope': 'owned-local-fetch-and-instrumented-credential-experiment',
               'nodeFromApprovedRuntimeNotObservedWorker': True,
               'filesystemRetention': 'observed-stop-not-hard-quota',
               'noHostCredentialAbsenceClaim': True, 'capturedOutputBytes': used,
               'phases': launches, 'runtimeIdentityClaim': m['runtimeIdentity'],
               'inputManifestSHA256': m['manifestSHA256'], 'toolFingerprints':
               {k: m[k] for k in ['bwrapSHA256', 'nodeSHA256', 'gitSHA256', 'pythonSHA256']},
               'probeFingerprints': {name: fingerprint(Path(__file__).parent / name)
                                    for name in ['probe.py', 'git.py', 'hooks.mjs']},
               'bundleFingerprints': {dest: digest for dest, digest in FILES.values()}}
    write_json(root / 'receipt.json', receipt)
    print(json.dumps({'receiptWritten': True, 'expectedObservationsMatched':
                      receipt['expectedObservationsMatched'], 'adoptionQualified': False}))
    return 0 if receipt['expectedObservationsMatched'] else 1

# Assemble the defined ContractTests class from Task 1 before this branch.
if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('--inside'); parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--manifest'); parser.add_argument('--manifest-sha256')
    args = parser.parse_args()
    try:
        if args.self_test:
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(ContractTests)
            if suite.countTestCases() != 8:
                raise Blocked('contract-test-selection')
            result = unittest.TextTestRunner().run(suite)
            raise SystemExit(0 if result.wasSuccessful() else 1)
        elif args.inside:
            raise SystemExit(inside(args.inside))
        elif args.manifest and args.manifest_sha256:
            raise SystemExit(experiment(load_manifest(args.manifest, args.manifest_sha256)))
        else:
            raise Blocked('explicit-inputs-required')
    except Exception:
        # No exception text: paths/config/output are not disclosure-safe.
        print('{"state":"blocked","qualification":false}', file=sys.stderr)
        raise SystemExit(2)
```

## Task 3: complete proposed Git boundary/fault wrapper

**Files:** future `probes/checkout-credentials/git.py`.
**Consumes:** `/case/task.json` produced by the supervisor, real `/usr/bin/git` and
owned repository. **Produces:** real Git exits/name-only output plus fixed events;
never logs argv/config values or hashes. It rewrites exactly `fetch origin` to the
owned remote; it never starts HTTP/SSH transport. All other commands are real Git
within the sterile namespace/owned repos, not approximate mocked config semantics.

- [ ] Implement this body and ensure baseline and negative selectors are reached.
  Missing selected fault events make observations incomplete; no nominal pass counts.

```python
import json, os, sys
from pathlib import Path

TASK = json.loads(Path('/case/task.json').read_text())
args = sys.argv[1:]
kind = TASK['kind']
post = TASK['post']

def event(name):
    path = Path('/case/events')
    data = (name + '\n').encode('ascii')
    if path.exists() and path.stat().st_size + len(data) > 65536:
        raise SystemExit(125)
    with open(path, 'ab') as out:
        out.write(data)

# The actual candidate fetch includes this exact global -c prefix.
prefix = args[:2] if args[:2] == ['-c', 'protocol.version=2'] else []
operation = args[2:] if prefix else args
if not operation or operation[0] not in {'--version', 'version', 'config', 'rev-parse', 'branch',
        'checkout', 'clean', 'reset', 'log', 'show', 'init', 'remote', 'submodule',
        'sparse-checkout', 'cat-file', 'for-each-ref', 'fetch'}:
    raise SystemExit(125)
lower = [a.lower() for a in operation]
include_write = (operation[0] == 'config' and any(a.startswith('includeif.') for a in lower)
                 and not any(a.startswith('--get') or a.startswith('--unset') for a in lower))
written = Path('/case/includes-written')
linked = written.exists()
if kind == 'git-missing' or (kind == 'post-no-git' and post):
    event('git-unavailable'); raise SystemExit(1)
if include_write:
    if kind == 'first-include' and not linked:
        event('first-include-denied'); raise SystemExit(1)
    event('include')
    written.write_text('true')
if (kind in {'enumeration', 'post-enumeration'} and linked and operation[0] == 'config'
        and '--name-only' in operation and '--get-regexp' in operation and any('includeif' in a for a in lower)):
    event('enumeration-denied'); raise SystemExit(2)
if (kind == 'unset' and linked and operation[0] == 'config'
        and '--unset-all' in operation and any(a.startswith('includeif.') for a in lower)):
    event('unset-denied'); raise SystemExit(5)
if (operation[0] == 'config' and '--file' in operation
        and any('/git-credentials-' in a and a.endswith('.config') for a in operation)
        and not any(a.startswith('--get') or a.startswith('--unset') for a in operation)):
    event('credential-file')
if operation[0] == 'fetch':
    if 'origin' not in operation or any(a.startswith(('http:', 'https:', 'ssh:', 'git@')) for a in operation):
        raise SystemExit(125)
    operation[operation.index('origin')] = '/case/remote'
    event('fetch-local')
# Sterile env/namespace and fixture remote are required: exec is not host authorization.
os.execve('/usr/bin/git', ['/usr/bin/git', *prefix, *operation], dict(os.environ))
```

## Task 4: complete proposed Node preload and isolated controlled run

**Files:** future `probes/checkout-credentials/hooks.mjs`.
**Consumes:** real builtin fs functions and typed task mode. **Produces:** fixed
milestones, synthetic additional file, specific EACCES/cancellation barrier and
network-denied exceptions. I do not inspect writeFile buffers/token/header values.
Even clean preloaded behavior is **instrumented**, not identical timing to production;
C05 is the unpreloaded baseline and local-fetch differences remain explicit.

```javascript
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import tls from 'node:tls';
import http from 'node:http';
import https from 'node:https';
import dgram from 'node:dgram';
import {syncBuiltinESMExports} from 'node:module';

const task = JSON.parse(fs.readFileSync('/case/task.json', 'utf8'));
const append = fs.appendFileSync.bind(fs);
const originalWrite = fs.promises.writeFile.bind(fs.promises);
const originalRm = fs.promises.rm.bind(fs.promises);
function event(name) {
  const file = '/case/events';
  const data = name + '\n';
  const size = fs.existsSync(file) ? fs.statSync(file).size : 0;
  if (size + Buffer.byteLength(data) > 65536) throw new Error('event-limit');
  append(file, data, {mode: 0o600});
}
function credential(file) {
  return typeof file === 'string' && path.dirname(file) === '/case/temp' &&
    /^git-credentials-[0-9a-f-]+\.config$/i.test(path.basename(file));
}
fs.promises.writeFile = async function(file, ...rest) {
  const result = await originalWrite(file, ...rest);
  if (credential(file)) {
    event('token-written');
    if (task.kind === 'extra-file') {
      await originalWrite('/case/temp/git-credentials-00000000-0000-4000-8000-000000000099.config', '', {mode: 0o600});
      event('extra-file');
    }
    if (task.kind === 'cancel') {
      event('cancel-ready');
      await new Promise(() => {setInterval(() => {}, 1000);});
    }
  }
  return result;
};
fs.promises.rm = async function(file, ...rest) {
  if (credential(file) && task.kind === 'delete') {
    event('delete-denied');
    const error = new Error('owned-removal-denied'); error.code = 'EACCES'; throw error;
  }
  return originalRm(file, ...rest);
};
function deny() {event('network-denied'); throw new Error('owned-network-denied');}
net.connect = deny; net.createConnection = deny;
tls.connect = deny;
http.request = deny; http.get = deny;
https.request = deny; https.get = deny;
dgram.createSocket = deny;
globalThis.fetch = deny;
syncBuiltinESMExports();
```

- [ ] Complete Task 1 owned tests and verify all required artifact/tool/namespace/
  cgroup readbacks before authorizing bundle launch. If setup rejects always, report
  blocked readiness; do not count untouched cases as successful observations.
- [ ] Run ordered cases from Task 2 once under the exact approved manifest. Exceptions
  retain prior rows/data as partial; they do not regenerate a complete success report
  from a prefix, authorize retries or run a replacement binary/profile.
- [ ] Inspect C05/C06 transient auth-file/include/fetch milestones and guard true;
  inspect each selected injection milestone and the corresponding guard false.
  Unexpected SDK/Node/Git semantics mean mismatched/incomplete evidence, not permission
  to change the candidate, bypass guard, replace real Git with mocks or invent results.
- [ ] Verify bundle hashes again, exact normal/negative EOF and group closure, total
  resource counters and artifact privacy. Report case rows/families actually executed,
  not documentary A/C IDs or package/compiler passes.

## Task 5: owned commands, receipts, review and adoption disposition

Future Nushell commands, **not run in this preparation**:

```nu
python3 probes/checkout-credentials/probe.py --self-test
```

For controlled execution the operator supplies the actual absolute manifest filename
and its exact SHA-256; no generic example digest is approval. This Nushell definition
spells out the exact invocation without inventing those not-yet-approved identities:

```nu
def run-approved-credential-probe [manifest: path, sha256: string] {
    python3 probes/checkout-credentials/probe.py --manifest $manifest --manifest-sha256 $sha256
}
```

Defining or invoking it remains future work; it never substitutes for authorization.
The plan already defines the complete program/contract;
I stop until those actual artifact identities and effects are separately reviewed and
authorized. I do not use environment secrets to populate either input.

- [ ] Validate the independently reviewed complete probe head, frozen code and input
  manifest/tool/bundle hashes; author review does not satisfy that gate.
- [ ] Record each attempted/completed/not-run case and phase, action exit, before-Go
  and post/second observations, profile/instrumentation and fixed milestones. Include
  independently observed namespace/Node/tool identities and lifecycle/resource limits.
- [ ] Preserve private receipts below 64 KiB. Aggregate stdout byte counts only;
  no raw Git/stdout/state/config values, credentials, private filenames or hashes of
  credential evidence. Runtime/probe/bundle artifact fingerprints are separate.
- [ ] Require both positive and negative controls; future guard mutations above must
  actually fail owned tests and be exactly restored. A failure/injection not reached,
  skipped/unselected case, setup-only failure or compile failure is not behavioral
  credential RED or a qualified negative observation.
- [ ] If expected S01/S02 residue is confirmed, record an observed limitation/blocked
  adoption and required guard/profile disposition; no automatic upstream allegation,
  patch, new SHA or adoption exception. Matching negative-case expectations is not
  cleanliness. If predictions differ, preserve evidence and investigate owned harness
  assumptions before attributing candidate behavior.
- [ ] Seek independent final-head assessment review before any conditional acceptance.
  Actual hosted Worker Node, runner package/image and profile/token absence/privilege
  evidence must be closed externally by separately approved platform work. No Listener
  relaunch/private `.env`/expanded API or account credentials for that purpose.
- [ ] Keep full static/bundle/notices/advisory gates S06 open. C05-C26 cannot qualify
  arbitrary events/native path attacks/submodules/SSH/LFS or host isolation A14.
  Reviewed #23 integration, workflow installation/acquisition/activation permissions,
  final peer review and issue/Project acceptance remain separate #38 gates.

## Preparation checks and handoff

I only parse the authored Python code fragments, inspect JS as text and validate
local links, IDs, sizes, explicit code/parameter definitions and preservation against
a fresh baseline. `ast.parse` proves syntax only: these scripts, tests, hooks, sandbox,
cgroup controls and main/post have **NOT RUN**. I do not claim missing runtimes are
available or the proposed failure predictions have occurred.

I save this one-document proposal with a scoped local `jj` commit/bookmark. Existing
scope/bootstrap/raw/report documents, published PR39/PR37/PR36 local heads, default
unrelated `.pi/todos`, deletion checkpoint and routing remain unchanged. No push,
network, test execution, namespace/cgroup mutation, real credential access or CI.
The owner approved this actual written plan and separately authorized owned-file
implementation/pure Python tests. Independent review, actual artifact/preflight
closure and controlled bundle/tool/native execution still require their distinct
permissions. Approval does not convert authored C01-C26 expectations into observations.
