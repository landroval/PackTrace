# Bounded root-verification CI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans for authorized inline execution, or superpowers:subagent-driven-development only after separately authorized agent orchestration. Steps use checkbox syntax. No execution method, new agent, installation or publication is authorized by this plan.

**Goal:** I install one bounded root-only tests/vet workflow after explicit adoption, execution and publication gates, without treating CI success as complete environment qualification.

**Architecture:** I keep one workflow with pinned checkout and inline standard-library Python control code. It captures finite owned-command evidence and runs official Go in an explicit environment; GitHub platform metadata closes runner-package/image qualification outside the job. I introduce no repository helper, Go change, dependency or artifact/cache Action.

**Tech Stack:** GitHub-hosted Ubuntu 24.04 Linux amd64, qualified pinned checkout/Node 24, official Go 1.27.1, preinstalled Python 3.12+, Bash/Git and Python standard library.

**Spec:** [Approved issue-38 specification](issue-38-root-verification-ci.md), including the user's explicit external-environment-closure adjustment. Status: **local complete-plan draft; not approved for execution**.

## Global constraints

- I own only `.github/workflows/root-verification.yml` in a later executable commit; this preparation owns only the two issue-38 documents.
- I require reviewed #23 integration, approved complete plan, qualified Action security/notices/credential boundary and explicit acquisition/runner permissions before executable implementation.
- I preserve root standard-library-only policy, module/readers/tests, sibling workspaces/bookmarks, original checkout, unrelated local deletion checkpoint, parent/native/shipping gates and global routing.
- PRs targeting/pushes to `development` and manual dispatch select root only; no fuzz control/job, schedules, privileged events, matrix or chaining.
- Exact checkout SHA: `3d3c42e5aac5ba805825da76410c181273ba90b1`; Node 24 and supported runner >=2.327.1. Named-source inspection is not complete bundled/transitive adoption qualification.
- Official `go1.27.1.linux-amd64.tar.gz`: exactly 70,553,950 bytes; SHA-256 `63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445`. These are expected catalog values, not an acquired measured archive.
- Exact HTTPS allowlist: `https://go.dev/dl/go1.27.1.linux-amd64.tar.gz` and `https://dl.google.com/go/go1.27.1.linux-amd64.tar.gz`; no credentials/proxies/retries/mirrors or unlisted redirect.
- Job timeout 15 minutes; root command timeout 10 minutes; setup at most 180 seconds, acquisition inside it at most 120 seconds with at most three redirects/10-second socket operations; vet at most 60 seconds and remaining outer time.
- Trusted verified-toolchain extraction ceiling: 1 GiB summed regular-file bytes, 100,000 members, 64 path components; regular files/directories under `go/` only. Reject links/special files/duplicates/unsafe names; no fallback or target/native-safe-opening claim.
- `GOTOOLCHAIN=local`, `GOPROXY=off`, `GOWORK=off`, `CGO_ENABLED=0`, `GOMAXPROCS=2`, `GOMEMLIMIT=512MiB`; also `GOENV=off`, explicit job-local HOME/TMPDIR/cache and no inherited token/proxy/Node options.
- 16 MiB aggregate owned-command captured stdout/stderr, 64 KiB compact receipt; metadata command capture also has a 64 KiB individual ceiling. Exhaustion/timeout/missing JSON is not a pass.
- Capture ceilings apply to this supervisor's command streams, not service/checkout logs or a hard process/host RSS boundary. Base64 diagnostic representation is bounded by captured bytes plus framing, not misrepresented as a 16 MiB platform-log ceiling.
- I never relaunch Runner.Listener or inspect `.env`/private key/token contents for version evidence. The version command is not side-effect-free: consulted Program loads `.env` and initializes HostContext/diagnostics.
- Node/profile/credential/adoption gates precede Go. Actual runner-package version/image proof comes from selected `Set up job` platform metadata at acceptance; missing/mismatch leaves qualification pending/failed even after successful bounded checks.
- No added API permission, credentials persistence, cache/upload Action, host-global installation/security change, target acquisition/execution, source normalization or automatic closure.

## Review focus

1. A fork/untrusted PR ref must remain data, not shell input; default checkout's tested merge commit must not be attributed to head alone. Task 2's literal-control/identity checks pin this.
2. Credential include-key/residual-file uncertainty must block Go without reading included files or logging values. Task 2's name-only checks and separate privacy fixtures pin this.
3. A socket/read or child process that exceeds bounds must not produce a successful phase from a prefix; an unreturned descendant must not hang capture indefinitely. Task 2's overflow/process-timeout fixtures pin this.
4. Compilation JSON, zero tests, package-only passes and partial framing must not be converted to behavioral success or inflated counts. Task 2's literal independent streams pin this.
5. Missing platform package-version/image proof or a truncated service log must survive nominal job success. Task 3's external acceptance worksheet pins this, without pretending it is an executable hosted test today.

## Preparation evidence and unresolved adoption gates

I consumed 9 public texts/HEAD observations, 137,837 bytes, under the approved
10-document/256 KiB-per-text/2 MiB-total consultation. I acquired no archive body,
Action bundle or executable and ran no Go/test/runner. Go source HEAD returned 302
to the exact allowed dl.google.com URL; its HEAD returned 200 and Content-Length
70553950. These observations do not measure downloaded digest, prove future origin
responses or qualify distribution security/notice obligations.

Runner source consulted at `d7bc179baf11a02110b46cfbbc4040f74ac3f60a`:
[HostContext](https://github.com/actions/runner/blob/d7bc179baf11a02110b46cfbbc4040f74ac3f60a/src/Runner.Common/HostContext.cs),
[Node handler](https://github.com/actions/runner/blob/d7bc179baf11a02110b46cfbbc4040f74ac3f60a/src/Runner.Worker/Handlers/NodeScriptActionHandler.cs),
[StepHost](https://github.com/actions/runner/blob/d7bc179baf11a02110b46cfbbc4040f74ac3f60a/src/Runner.Worker/Handlers/StepHost.cs),
[Program](https://github.com/actions/runner/blob/d7bc179baf11a02110b46cfbbc4040f74ac3f60a/src/Runner.Listener/Program.cs),
[Runner](https://github.com/actions/runner/blob/d7bc179baf11a02110b46cfbbc4040f74ac3f60a/src/Runner.Listener/Runner.cs),
[Node documentation](https://github.com/actions/runner/blob/d7bc179baf11a02110b46cfbbc4040f74ac3f60a/docs/checks/nodejs.md).
The consulted text locates bundled Node below runner root/externals, not PATH;
it does not prove a future hosted worker is built from that source or that its
Linux process layout/installed binaries are qualified. I require authorized actual
profile acceptance, rather than calling a blocked probe successful qualification.

The full pinned Action bundle/transitive security/notice assessment, main/post
credential cleanup qualification, official archive acquisition/extraction and actual
hosted profile remain **NOT RUN / NOT QUALIFIED**. The following complete proposal
is reviewable code, not permission to adopt or execute those distributions.

## Task 1: clear explicit prerequisites, without premature publication

**Files:** Read both issue-38 documents and #23's reviewed integrated contract/plan;
create no executable file during this gate.
**Consumes:** Live exact #23 head/review/integration, current development tree,
operator permissions and independently reviewed adoption evidence.
**Produces:** External dated/head-bound authorization receipt; no public Go API.

- [ ] Read current issue/PR ownership, final-head approvals/threads and development identity; stop on an overlapping owner, changed contract or absent #23 reviewed integration. Do not sync/rebase/rewrite sibling changes without permission.
- [ ] Obtain approval of this actual complete plan, including proposed setup/extraction/capture bounds and external closure. Do not infer it from specification approval.
- [ ] Obtain separate explicit bounded acquisition/security/notice assessment permissions covering the exact checkout source/bundle/dependencies and official archive. No bundle/archive download is permitted through current documentary authority.
- [ ] Require the assessment to enumerate SHA/version/license/notices, bundled/transitive dependencies, executable main/post paths and credential/temp-file cleanup. Read-only named-source inspection/cached licenses alone cannot mark this gate qualified.
- [ ] Obtain permission for future controlled local checks, own-process timeout/kill fixtures, official-Go setup and GitHub-hosted acquisition/execution. Mark missing/failed gate blocked, not successful or silently waived.
- [ ] Record authority before creating YAML. Workflow-bearing push/PR and integration remain separate later permissions because they can trigger acquisition/root jobs.

## Task 2: one independently reviewable workflow, RED then bounded GREEN

**Files:** Create `.github/workflows/root-verification.yml` only; temporary extracted
Python/test scripts outside the repository are future authorized validation evidence.
**Consumes:** Qualified Task 1 gates and actual owned source/job metadata.
**Produces:** Root-check result plus bounded phase evidence; environment qualification
pending external platform closure. No public schema/shared CLI status authority.

- [ ] Extract the proposed `run` Python block into an owned temporary `rootci.py` using indentation, without importing/executing it during documentary preparation. At authorized implementation time write the test block below first; a missing module is compilation/import RED, not behavioral RED.
- [ ] Make the four tested pure helpers return deliberately wrong values while preserving signatures. Run the test block; require actual behavioral failures and nonzero selected tests. Do not count syntax/import failures as behavioral RED.
- [ ] Install the exact proposal below only after Task 1 is satisfied. Restore complete helper logic, run the same tests and retain one actual result stream; no framework installation or target code is needed.

```yaml
name: Root verification
on:
  pull_request:
    branches: [development]
  push:
    branches: [development]
  workflow_dispatch:
permissions:
  contents: read
jobs:
  root:
    name: Root tests and vet
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    steps:
      - name: Start owned budget
        id: init
        shell: bash
        run: |
          python3 - <<'PY'
          import json, os, time
          from pathlib import Path
          root = Path(os.environ['RUNNER_TEMP']) / 'packtrace-root-ci'
          root.mkdir(mode=0o700)
          (root / 'start.json').write_text(json.dumps({'start': time.monotonic()}))
          PY
      - name: Pinned source checkout
        id: checkout
        continue-on-error: true
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
          submodules: false
          lfs: false
          fetch-depth: 1
          fetch-tags: false
          allow-unsafe-pr-checkout: false
          set-safe-directory: false
      - name: Bounded owned root checks
        if: ${{ always() && !cancelled() }}
        shell: bash
        env:
          INIT_OUTCOME: ${{ steps.init.outcome }}
          CHECKOUT_OUTCOME: ${{ steps.checkout.outcome }}
          SOURCE_SHA: ${{ github.sha }}
          PR_HEAD: ${{ github.event.pull_request.head.sha }}
          PR_BASE: ${{ github.event.pull_request.base.sha }}
        run: |
          python3 - <<'PY'
          import base64, hashlib, json, os, platform, re, selectors
          import signal, subprocess, sys, tarfile, time, urllib.error, urllib.request
          from pathlib import Path, PurePosixPath

          CAP = 16 * 1024 * 1024
          RECEIPT_CAP = 64 * 1024
          SIZE = 70553950
          SHA = '63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445'
          SOURCE = 'https://go.dev/dl/go1.27.1.linux-amd64.tar.gz'
          FINAL = 'https://dl.google.com/go/go1.27.1.linux-amd64.tar.gz'
          ROOT = Path(os.environ['RUNNER_TEMP']) / 'packtrace-root-ci'
          WORK = Path(os.environ['GITHUB_WORKSPACE'])
          used = 0
          deadline = time.monotonic()
          result = {'checkout': os.environ['CHECKOUT_OUTCOME'],
                    'setup': 'not-run', 'tests': 'not-run', 'vet': 'not-run',
                    'qualification': 'pending-platform-metadata', 'phases': {},
                    'sourceSHA': os.environ['SOURCE_SHA'],
                    'prHead': os.environ.get('PR_HEAD', ''),
                    'prBase': os.environ.get('PR_BASE', ''),
                    'event': os.environ['GITHUB_EVENT_NAME'],
                    'checkoutAction': 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
                    'commands': {'tests': ['go', 'test', '-count=1', '-json', '-timeout=10m', './...'],
                                 'vet': ['go', 'vet', './...']},
                    'settings': {'GOTOOLCHAIN': 'local', 'GOPROXY': 'off', 'GOWORK': 'off',
                                 'CGO_ENABLED': '0', 'GOENV': 'off', 'GOMAXPROCS': '2',
                                 'GOMEMLIMIT': '512MiB'}}

          class Blocked(Exception):
              pass

          def runner_version(text):
              if len(text) > 32 or not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', text):
                  raise ValueError('invalid-runner-version')
              return tuple(int(p) for p in text.split('.')) >= (2, 327, 1)

          def forbidden_keys(raw):
              keys = raw.decode('utf-8').lower().splitlines()
              return any(k.startswith(('include.', 'includeif.', 'credential.', 'url.'))
                         or k == 'core.sshcommand'
                         or (k.startswith('http.') and k.endswith('.extraheader'))
                         for k in keys)

          def test_counts(raw):
              if not raw or not raw.endswith(b'\n'):
                  raise ValueError('incomplete-json-stream')
              events = [json.loads(line) for line in raw.splitlines()]
              if not all(isinstance(e, dict) for e in events):
                  raise ValueError('invalid-json-event')
              return {'passed': sum(e.get('Action') == 'pass' and bool(e.get('Test')) for e in events),
                      'failed': sum(e.get('Action') == 'fail' and bool(e.get('Test')) for e in events),
                      'failedEvents': sum(e.get('Action') == 'fail' for e in events),
                      'buildFailed': sum(e.get('Action') == 'build-fail' for e in events)}

          def qualified(checks, platform_complete, platform_compatible):
              return bool(checks and platform_complete and platform_compatible)

          def clean_env(home):
              return {'PATH': '/usr/bin:/bin', 'HOME': str(home),
                      'TMPDIR': str(ROOT / 'tmp'), 'LANG': 'C.UTF-8',
                      'GOTOOLCHAIN': 'local', 'GOPROXY': 'off', 'GOWORK': 'off',
                      'CGO_ENABLED': '0', 'GOENV': 'off', 'GOMAXPROCS': '2',
                      'GOMEMLIMIT': '512MiB', 'GOCACHE': str(ROOT / 'gocache'),
                      'GOMODCACHE': str(ROOT / 'gomodcache')}

          def command(label, argv, seconds, env, publish=False, cap=CAP):
              global used
              started = time.monotonic()
              end = min(deadline, started + seconds)
              if time.monotonic() >= end:
                  raise Blocked('no-remaining-time')
              streams = {'stdout': bytearray(), 'stderr': bytearray()}
              state = 'passed'
              process = subprocess.Popen(argv, cwd=WORK, env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          start_new_session=True)
              poll = selectors.DefaultSelector()
              poll.register(process.stdout, selectors.EVENT_READ, 'stdout')
              poll.register(process.stderr, selectors.EVENT_READ, 'stderr')
              try:
                  while poll.get_map():
                      if time.monotonic() >= end:
                          state = 'timed-out'
                          break
                      for key, mask in poll.select(min(0.1, end-time.monotonic())):
                          data = os.read(key.fileobj.fileno(), 65536)
                          if not data:
                              poll.unregister(key.fileobj)
                              continue
                          if used + len(data) > CAP or sum(map(len, streams.values())) + len(data) > cap:
                              state = 'limit-exceeded'
                              break
                          used += len(data)
                          streams[key.data].extend(data)
                      if state != 'passed':
                          break
                  if state != 'passed':
                      try:
                          os.killpg(process.pid, signal.SIGKILL)
                      except ProcessLookupError:
                          pass
                  try:
                      code = process.wait(timeout=max(0.001, end-time.monotonic()))
                  except subprocess.TimeoutExpired:
                      state = 'timed-out'
                      try:
                          os.killpg(process.pid, signal.SIGKILL)
                      except ProcessLookupError:
                          pass
                      code = process.wait(timeout=2)
                  if state == 'passed' and code != 0:
                      state = 'failed'
              finally:
                  poll.close()
                  try:
                      os.killpg(process.pid, signal.SIGKILL)
                  except ProcessLookupError:
                      pass
                  if process.poll() is None:
                      process.wait(timeout=2)
                  process.stdout.close()
                  process.stderr.close()
              record = {'state': state, 'exit': code, 'streams': {},
                        'durationSeconds': max(0, time.monotonic()-started)}
              for name, data in streams.items():
                  record['streams'][name] = {'bytes': len(data)}
                  if not label.startswith('credential-keys-'):
                      record['streams'][name]['sha256'] = hashlib.sha256(data).hexdigest()
                  if publish:
                      for offset in range(0, len(data), 3072):
                          print(json.dumps({'diagnostic': label, 'stream': name, 'offset': offset,
                                'base64': base64.b64encode(data[offset:offset+3072]).decode('ascii')}))
              result['phases'][label] = record
              return state, bytes(streams['stdout'])

          def observed_node():
              pid = os.getppid()
              for _ in range(16):
                  exe = Path(os.readlink('/proc/' + str(pid) + '/exe'))
                  if exe.name == 'Runner.Worker':
                      return exe.parent.parent / 'externals/node24/bin/node'
                  with open('/proc/' + str(pid) + '/stat', 'rb') as f:
                      stat = f.read(4097)
                  if len(stat) > 4096:
                      raise Blocked('process-metadata-limit')
                  pid = int(stat.rsplit(b')', 1)[1].split()[1])
                  if pid <= 0:
                      break
              raise Blocked('node-runtime-unavailable')

          def no_credentials():
              if list(Path(os.environ['RUNNER_TEMP']).glob('git-credentials-*.config')):
                  raise Blocked('credential-residue')
              hosthome = Path(os.environ['HOME'])
              files = [WORK / '.git/config', hosthome / '.gitconfig',
                       hosthome / '.config/git/config', Path('/etc/gitconfig')]
              if not files[0].is_file():
                  raise Blocked('checkout-config-unavailable')
              for i, path in enumerate(files):
                  if not path.exists():
                      continue
                  state, names = command('credential-keys-' + str(i),
                     ['/usr/bin/git', 'config', '--file', str(path), '--no-includes',
                      '--name-only', '--list'], 5, clean_env(ROOT / 'home'), cap=RECEIPT_CAP)
                  if state != 'passed' or forbidden_keys(names):
                      raise Blocked('credential-state-unqualified')

          class NoRedirect(urllib.request.HTTPRedirectHandler):
              def redirect_request(self, *args):
                  return None

          def acquire():
              client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
              url = SOURCE
              seen = set()
              finish = min(deadline, time.monotonic() + 120)
              for _ in range(4):
                  if url not in (SOURCE, FINAL) or url in seen:
                      raise Blocked('unapproved-redirect')
                  seen.add(url)
                  remaining = finish-time.monotonic()
                  if remaining <= 0:
                      raise Blocked('acquisition-timeout')
                  req = urllib.request.Request(url, headers={'User-Agent': 'PackTrace-root-CI'})
                  try:
                      response = client.open(req, timeout=min(10, remaining))
                  except urllib.error.HTTPError as e:
                      response = e
                  with response:
                      if response.status in (301, 302, 303, 307, 308):
                          url = response.headers.get('Location', '')
                          continue
                      if response.status != 200:
                          raise Blocked('acquisition-http-failure')
                      total = 0
                      digest = hashlib.sha256()
                      with (ROOT / 'go.tar.gz').open('xb') as output:
                          while True:
                              if time.monotonic() >= finish:
                                  raise Blocked('acquisition-timeout')
                              data = response.read(min(65536, SIZE-total+1))
                              if not data:
                                  break
                              if total+len(data) > SIZE:
                                  raise Blocked('archive-byte-limit')
                              total += len(data)
                              digest.update(data)
                              output.write(data)
                      if total != SIZE or digest.hexdigest() != SHA:
                          raise Blocked('archive-identity-mismatch')
                      result['archive'] = {'source': SOURCE, 'final': url, 'bytes': total, 'sha256': digest.hexdigest()}
                      return
              raise Blocked('redirect-limit')

          def extract():
              total = 0
              seen = set()
              with tarfile.open(ROOT / 'go.tar.gz', mode='r|gz') as archive:
                  for member in archive:
                      name = member.name.rstrip('/') if member.isdir() else member.name
                      path = PurePosixPath(name)
                      parts = path.parts
                      if (not parts or parts[0] != 'go' or member.name.startswith('/')
                          or '..' in parts or len(parts) > 64 or parts in seen
                          or name != path.as_posix()
                          or not (member.isfile() or member.isdir())):
                          raise Blocked('archive-layout-unqualified')
                      seen.add(parts)
                      if len(seen) > 100000:
                          raise Blocked('archive-member-limit')
                      if member.isfile():
                          total += member.size
                          if total > 1073741824:
                              raise Blocked('archive-expanded-limit')
                      archive.extract(member, ROOT / 'toolchain', filter='data')
              result['archive']['expandedBytes'] = total
              result['archive']['members'] = len(seen)

          def run():
              global deadline
              if os.environ['INIT_OUTCOME'] != 'success' or result['checkout'] != 'success':
                  raise Blocked('checkout-or-initialization-failed')
              deadline = json.loads((ROOT / 'start.json').read_text())['start'] + 900
              if (os.geteuid() == 0 or sys.version_info < (3, 12) or platform.system() != 'Linux'
                  or platform.machine() != 'x86_64' or os.environ.get('RUNNER_ARCH') != 'X64'
                  or os.environ.get('ImageOS') != 'ubuntu24'
                  or not os.environ.get('ImageVersion')):
                  raise Blocked('runner-profile-unqualified')
              result['environment'] = {'imageOS': os.environ['ImageOS'],
                 'imageVersion': os.environ['ImageVersion'], 'kernel': platform.release(),
                 'architecture': platform.machine(), 'reportedLogicalCPU': os.cpu_count(),
                 'availableCPUQuota': 'unmeasured', 'availableRAM': 'unmeasured',
                 'runnerPackageVersion': 'pending-platform-metadata',
                 'aggregatePeakRSS': 'unmeasured'}
              for directory in ('home', 'tmp', 'gocache', 'gomodcache', 'toolchain'):
                  (ROOT / directory).mkdir(mode=0o700)
              env = clean_env(ROOT / 'home')
              state, version = command('node-version', [str(observed_node()), '--version'], 5, env, cap=RECEIPT_CAP)
              if state != 'passed' or not re.fullmatch(rb'v24\.[0-9]+\.[0-9]+\n', version):
                  raise Blocked('node-runtime-unqualified')
              result['environment']['nodeVersion'] = version.decode().strip()
              no_credentials()
              state, identity = command('source-identity', ['/usr/bin/git', 'rev-parse', 'HEAD', 'HEAD^{tree}'], 5, env, cap=RECEIPT_CAP)
              ids = identity.decode('ascii').splitlines()
              if state != 'passed' or len(ids) != 2 or ids[0] != result['sourceSHA'] or not all(re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', x) for x in ids):
                  raise Blocked('source-identity-mismatch')
              result['tree'] = ids[1]
              acquire()
              extract()
              go = str(ROOT / 'toolchain/go/bin/go')
              state, version = command('go-version', [go, 'version'], 5, env, cap=RECEIPT_CAP)
              state2, profile = command('go-profile', [go, 'env', 'GOVERSION', 'GOOS', 'GOARCH'], 5, env, cap=RECEIPT_CAP)
              if state != 'passed' or version != b'go version go1.27.1 linux/amd64\n' or state2 != 'passed' or profile != b'go1.27.1\nlinux\namd64\n':
                  raise Blocked('toolchain-profile-mismatch')
              result['compiler'] = {'version': version.decode().strip(),
                                    'profile': profile.decode().splitlines()}
              result['setup'] = 'passed'
              signal.alarm(0)
              state, raw = command('tests', [go, 'test', '-count=1', '-json', '-timeout=10m', './...'], 600, env, publish=True)
              result['tests'] = state
              if state in ('passed', 'failed'):
                  try:
                      result['testCounts'] = test_counts(raw)
                      counts = result['testCounts']
                      if state == 'passed' and (counts['passed'] == 0 or counts['failedEvents'] or counts['buildFailed']):
                          result['tests'] = 'evidence-invalid'
                  except (ValueError, UnicodeError):
                      result['tests'] = 'evidence-invalid'
              if state in ('passed', 'failed') and time.monotonic() < deadline-1:
                  result['vet'], unused = command('vet', [go, 'vet', './...'], 60, env, publish=True)

          def timeout(signum, frame):
              raise Blocked('setup-timeout')

          try:
              signal.signal(signal.SIGALRM, timeout)
              signal.alarm(180)
              run()
          except (Blocked, OSError, ValueError, tarfile.TarError) as error:
              result['failure'] = str(error) if isinstance(error, Blocked) else 'unqualified-command-or-evidence'
              if result['setup'] != 'passed':
                  result['setup'] = 'blocked'
          finally:
              signal.alarm(0)
          checks = result['setup'] == result['tests'] == result['vet'] == 'passed'
          result['boundedChecksPassed'] = checks
          result['capturedBytes'] = used
          receipt = json.dumps(result, sort_keys=True).encode('utf-8')
          if len(receipt) > RECEIPT_CAP:
              receipt = b'{"boundedChecksPassed":false,"qualification":"pending-platform-metadata","failure":"receipt-limit"}'
              checks = False
          print('ROOTCI_RECEIPT ' + receipt.decode('utf-8'))
          summary = os.environ.get('GITHUB_STEP_SUMMARY')
          if summary:
              with open(summary, 'a', encoding='utf-8') as output:
                  output.write('Root bounded checks: ' + ('passed' if checks else 'not successful') + '\n\n')
                  output.write('Environment qualification: pending external platform metadata.\n')
          sys.exit(0 if checks else 1)
          PY
```

The example is a **proposal** until qualified actual runner acceptance. In particular,
the bounded Linux parent-process metadata lookup must find the actual Worker/bundled
Node on the authorized hosted profile, not succeed by guessing a version directory
or replacing it with PATH Node. Failure/absence is blocked, not an always-deny success.
No Listener/private-config lookup is introduced as a fallback.

- [ ] Pin the setup-only alarm boundary with the fake command callback below; a 180-second setup timer must never cancel the separately bounded ten-minute root command. Retain the corrected proposal's exact code.

Future validation test block (stdlib; no downloads):

```python
import importlib.util, json, pathlib, unittest

# Extract only helper definitions/constants to this owned helper module; do not
# import the executable orchestration or start processes/network during pure tests.
path = pathlib.Path('/tmp/packtrace-rootci-validation/helpers.py')
spec = importlib.util.spec_from_file_location('rootci_helpers', path)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class RootCIContractTests(unittest.TestCase):
    def test_runner_floor_and_malformed(self):
        for text, expected in [('2.327.0', False), ('2.327.1', True), ('2.400.0', True)]:
            with self.subTest(text=text):
                self.assertEqual(m.runner_version(text), expected)
        for text in ['', 'v2.327.1', '2.327', '2.327.1-rc', '02.327.1', '9'*33]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                m.runner_version(text)
    def test_name_only_credentials(self):
        for key in ['include.path', 'includeIf.gitdir:x.path', 'credential.helper',
                    'url.https://example.invalid.insteadOf', 'core.sshCommand',
                    'http.https://github.com/.extraheader']:
            with self.subTest(key=key):
                self.assertTrue(m.forbidden_keys((key+'\n').encode()))
        self.assertFalse(m.forbidden_keys(b'core.bare\nremote.origin.url\n'))
    def test_one_complete_json_stream(self):
        raw = b'{"Action":"pass","Package":"p"}\n{"Action":"pass","Test":"A"}\n{"Action":"pass","Test":"A/leaf"}\n{"Action":"build-fail"}\n'
        self.assertEqual(m.test_counts(raw), {'passed':2, 'failed':0, 'failedEvents':0, 'buildFailed':1})
        self.assertEqual(m.test_counts(b'{"Action":"fail","Test":"B"}\n')['failed'],1)
        self.assertEqual(m.test_counts(b'{"Action":"fail","Package":"p"}\n')['failedEvents'],1)
        for bad in [b'', b'{"Action":"pass"}', b'not-json\n', b'[]\n']:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                m.test_counts(bad)
    def test_external_qualification_not_job_success(self):
        for a in [False, True]:
            for b in [False, True]:
                for c in [False, True]:
                    with self.subTest(checks=a, complete=b, compatible=c):
                        self.assertEqual(m.qualified(a,b,c), a and b and c)

unittest.main()
```

Future authorized extraction (the Python control block is saved as `rootci.py` in this external directory):

```python
import ast, pathlib
root = pathlib.Path('/tmp/packtrace-rootci-validation')
root.mkdir(exist_ok=True)
tree = ast.parse((root / 'rootci.py').read_text())
constants = {'CAP', 'RECEIPT_CAP', 'SIZE', 'SHA', 'SOURCE', 'FINAL'}
retained = []
for node in tree.body:
    if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.ClassDef)):
        retained.append(node)
    elif isinstance(node, ast.Assign) and all(isinstance(n, ast.Name) and n.id in constants for n in node.targets):
        retained.append(node)
(root / 'helpers.py').write_text(ast.unparse(ast.Module(body=retained, type_ignores=[]))+'\n')
```

Only imports, definitions and literal constants survive extraction. No top-level
environment/path read, orchestration invocation, download or receipt writer executes
when these future tests import the resulting module.

Future controlled-fixture block, saved alongside the helper file as `controlled.py`:

```python
import hashlib, importlib.util, io, json, pathlib, signal, sys, tarfile
import tempfile, time, unittest, urllib.error
from unittest.mock import patch

path = pathlib.Path('/tmp/packtrace-rootci-validation/helpers.py')
spec = importlib.util.spec_from_file_location('rootci_controlled_helpers', path)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class Response(io.BytesIO):
    def __init__(self, data=b'', status=200, location=None):
        super().__init__(data)
        self.status = status
        self.headers = {} if location is None else {'Location':location}

class Opener:
    def __init__(self, responses):
        self.responses = list(responses)
    def open(self, request, timeout):
        value = self.responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return value

class ControlledRootCITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='packtrace-rootci-owned-')
        m.ROOT = pathlib.Path(self.temp.name)
        m.WORK = m.ROOT
        m.deadline = time.monotonic()+10
        m.used = 0
        m.result = {'phases':{}, 'archive':{}}
        m.CAP = 65536
    def tearDown(self):
        signal.alarm(0)
        self.temp.cleanup()
    def child(self, text, seconds=1):
        return m.command('owned-fixture', [sys.executable, '-c', text], seconds,
                         m.clean_env(m.ROOT), cap=m.CAP)
    def test_capture_excess_independent_of_timeout(self):
        state, raw = self.child('import os; os.write(1,b"x"*65537)')
        self.assertEqual(state, 'limit-exceeded')
        self.assertLessEqual(m.used,65536)
    def test_timeout_independent_of_bytes(self):
        state, raw = self.child('import time; time.sleep(10)',.1)
        self.assertEqual(state,'timed-out')
    def test_stderr_stays_open_after_stdout_eof(self):
        state, raw = self.child('import os,time; os.close(1); time.sleep(10)',.1)
        self.assertEqual(state,'timed-out')
    def test_parent_exit_does_not_certify_open_descendant_pipes(self):
        code = 'import subprocess,sys; subprocess.Popen([sys.executable,"-c","import time; time.sleep(10)"])'
        state, raw = self.child(code,.1)
        self.assertEqual(state,'timed-out')
    def test_nonzero_and_invalid_stdout_are_distinct(self):
        self.assertEqual(self.child('raise SystemExit(7)')[0],'failed')
        state, raw = self.child('print("not-json")')
        self.assertEqual(state,'passed')
        with self.assertRaises(ValueError):
            m.test_counts(raw)
    def test_acquisition_rejects_each_boundary(self):
        cases = [
          ('short',[Response(b'O')],2,hashlib.sha256(b'OK').hexdigest()),
          ('excess',[Response(b'OK!')],2,hashlib.sha256(b'OK').hexdigest()),
          ('digest',[Response(b'OK')],2,'0'*64),
          ('redirect',[Response(status=302,location='https://evil.invalid/go')],2,'0'*64),
          ('loop',[Response(status=302,location=m.FINAL),Response(status=302,location=m.SOURCE)],2,'0'*64),
          ('http',[Response(status=500)],2,'0'*64),
          ('tls',[urllib.error.URLError('synthetic-tls-failure')],2,'0'*64)]
        for name,responses,size,digest in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory(dir=self.temp.name) as d:
                m.ROOT=pathlib.Path(d)
                m.deadline=time.monotonic()+1
                with patch.object(m,'SIZE',size),patch.object(m,'SHA',digest),patch.object(m.urllib.request,'build_opener',return_value=Opener(responses)):
                    with self.assertRaises((m.Blocked,urllib.error.URLError)):
                        m.acquire()
                self.assertNotIn('final',m.result['archive'])
    def test_valid_acquisition_owns_measured_bytes(self):
        with patch.object(m,'SIZE',2),patch.object(m,'SHA',hashlib.sha256(b'OK').hexdigest()),patch.object(m.urllib.request,'build_opener',return_value=Opener([Response(b'OK')])):
            m.acquire()
        self.assertEqual((m.ROOT/'go.tar.gz').read_bytes(),b'OK')
        self.assertEqual(m.result['archive']['bytes'],2)
    def archive(self,members):
        with tarfile.open(m.ROOT/'go.tar.gz','w:gz') as t:
            for member in members:
                t.addfile(member)
        (m.ROOT/'toolchain').mkdir()
    def test_layout_members_independently_reject(self):
        for name,kind in [('go/../escape',tarfile.DIRTYPE),('/go/x',tarfile.DIRTYPE),
                          ('go//x',tarfile.DIRTYPE),('go/x',tarfile.SYMTYPE),
                          ('go/x',tarfile.CHRTYPE)]:
            with self.subTest(name=name,kind=kind),tempfile.TemporaryDirectory(dir=self.temp.name) as d:
                m.ROOT=pathlib.Path(d)
                member=tarfile.TarInfo(name);member.type=kind
                self.archive([member])
                with self.assertRaises(m.Blocked):m.extract()
    def test_duplicate_members_reject(self):
        member=tarfile.TarInfo('go/x');member.type=tarfile.DIRTYPE
        self.archive([member,member])
        with self.assertRaises(m.Blocked):m.extract()
    def test_declared_expansion_rejects_before_body(self):
        member=tarfile.TarInfo('go/large');member.size=1073741825
        self.archive([member])
        with self.assertRaises(m.Blocked):m.extract()
        self.assertFalse((m.ROOT/'toolchain/go/large').exists())
    def test_member_count_rejects_before_unsafe_write(self):
        def members():
            for i in range(100001):
                member=tarfile.TarInfo('go/d'+str(i));member.type=tarfile.DIRTYPE
                yield member
        self.archive(members())
        with patch.object(m.tarfile.TarFile,'extract') as extract:
            with self.assertRaises(m.Blocked):m.extract()
            self.assertEqual(extract.call_count,100000)
        self.assertFalse((m.ROOT/'toolchain/go/d100000').exists())
    def test_credential_residue_precedes_git_commands(self):
        (m.ROOT/'git-credentials-owned.config').touch()
        with patch.dict(m.os.environ,{'RUNNER_TEMP':str(m.ROOT),'HOME':str(m.ROOT)}),patch.object(m,'command') as command:
            with self.assertRaises(m.Blocked):m.no_credentials()
            command.assert_not_called()
    def test_include_key_never_followed_or_logged(self):
        (m.ROOT/'.git').mkdir();(m.ROOT/'.git/config').touch()
        with patch.dict(m.os.environ,{'RUNNER_TEMP':str(m.ROOT),'HOME':str(m.ROOT)}),patch.object(m,'command',return_value=('passed',b'include.path\n')) as command:
            with self.assertRaises(m.Blocked):m.no_credentials()
            self.assertIn('--no-includes',command.call_args.args[1])
            self.assertFalse(command.call_args.kwargs.get('publish',False))
    def test_setup_alarm_disarmed_before_root_tests(self):
        m.result={'checkout':'success','sourceSHA':'a'*40,'phases':{}}
        (m.ROOT/'start.json').write_text(json.dumps({'start':time.monotonic()}))
        def commands(label,argv,seconds,env,**kwargs):
            replies={'node-version':b'v24.1.0\n','source-identity':('a'*40+'\n'+'b'*40+'\n').encode(),
                     'go-version':b'go version go1.27.1 linux/amd64\n','go-profile':b'go1.27.1\nlinux\namd64\n',
                     'tests':b'{"Action":"pass","Test":"owned"}\n','vet':b''}
            if label=='tests':self.assertEqual(signal.getitimer(signal.ITIMER_REAL)[0],0)
            return 'passed',replies[label]
        env={'INIT_OUTCOME':'success','RUNNER_ARCH':'X64','ImageOS':'ubuntu24','ImageVersion':'owned-fixture'}
        with patch.dict(m.os.environ,env),patch.object(m.os,'geteuid',return_value=1001),patch.object(m.platform,'system',return_value='Linux'),patch.object(m.platform,'machine',return_value='x86_64'),patch.object(m,'observed_node',return_value=m.ROOT/'node'),patch.object(m,'no_credentials'),patch.object(m,'acquire'),patch.object(m,'extract'),patch.object(m,'command',side_effect=commands):
            signal.alarm(180)
            m.run()
        self.assertEqual(m.result['tests'],'passed')
        self.assertEqual(m.result['vet'],'passed')

unittest.main()
```

Future execution commands (Nushell; only after explicit local fixture authority):

```nu
python3 /tmp/packtrace-rootci-validation/extract.py
python3 /tmp/packtrace-rootci-validation/pure.py
python3 /tmp/packtrace-rootci-validation/controlled.py
```

Save the exact extraction/pure/controlled blocks under those filenames and the
proposed inline Python as `rootci.py`; retain nonzero RED and one actual GREEN
stream. No program in these blocks is executed by current plan drafting.
- [ ] Run the controlled-fixture block below under separate local-process execution authority. Its children are owned Python fixtures, never investigated code; its HTTP responses are in-memory stubs with no listener or live request. Root profile/credential gates are mocked, not represented as actual hosting qualification.
- [ ] Independently retain each failing boundary's result, unchanged GREEN code fingerprints and the one actual stdlib test stream. These fixtures do not authorize live downloads or qualify native hostile-archive opening.
- [ ] Parse final YAML only with an already installed explicitly permitted validator; otherwise report that check unavailable, never install a framework. Extract Python and `ast.parse` it; Bash heredocs need `bash -n`, not execution during documentary checks.
- [ ] Verify literal workflow shape: exactly one immutable Action use, contents read, three selected event families, one Ubuntu job/15-minute timeout, no fuzz/privileged/schedule/cache/upload/matrix/secret/OIDC expressions, no PR text in shell.
- [ ] Obtain separately authorized local official-Go root JSON/vet verification if part of execution permission. Count one stream only; local custom-compiler results are not official/hosted qualification.
- [ ] Commit only the owned YAML with `jj commit -m 'ci: verify owned root checks (#38)' .github/workflows/root-verification.yml`, set only `issue-38-root-verification-ci-spec` to that scoped head. Never push yet or include sibling/checkpoint changes.

## Task 3: independently reviewed publication and actual acceptance

**Files:** Update only issue-38 approved evidence documents if separately authorized;
no unrelated gates or source files. Public issue/Project/PR changes need exact scope.
**Consumes:** Final-head peer review, explicit automatic-execution/publication
permissions and complete bounded job/platform evidence.
**Produces:** Accepted installation evidence or precise blocked/failed limitations;
no fuzz/native/scanner/producer/release qualification.

- [ ] Self-review all five focus classes and R01-R20; resolve blocker/important gaps without pretending author review is independent approval. If code/gates materially change, return for contract/plan approval before executing the changed proposal.
- [ ] Obtain explicit workflow-bearing push/PR authority covering actual automatic checkout/official-Go/runner effects. Verify current owner/base/remote exact head and publish only the issue bookmark; use `Refs #38`, not automatic closure. Request `jsustt` review only with permission; changed code needs fresh final-head review.
- [ ] Collect actual authorized PR/manual root evidence and, after separately authorized reviewed integration, the development push evidence. No token/secrets/private inputs are published. An event never run stays NOT RUN; do not synthesize a pass from selection syntax.
- [ ] Reconstruct diagnostic bytes by phase/stream/offset from `diagnostic` JSON lines; require contiguous offsets, the captured byte totals/SHA-256 and complete service log. Decode the one root stdout JSON stream and count nonempty-Test pass events, not package/parallel/focused sums. Missing/truncated platform logs keep qualification incomplete.
- [ ] Record source checkout/tree, PR head/base, event, pinned source/artifact, actual compiler/profile/Node, phase exits/bounds and result limitations. Compare actual platform `Set up job` package version >=2.327.1 and runner image/architecture to the inline receipt. Source strings or a nominal job success do not authenticate missing platform evidence.
- [ ] External acceptance truth table is exactly `checks && platform_complete && platform_compatible`. Missing version/image, contradictory package floor/architecture, partial diagnostic reconstruction or absence of one selected-event proof cannot close qualification/installation. No API/token permission is added merely to automate acceptance.
- [ ] Re-read actual GitHub approvals/threads/head/base before authorized integration; verify integrated bytes and obtain separate integrated root verification/issue-closure authority. Preserve parents #11/#6, #22/native rows and other Project items. Do not change branch-required-check/security settings through workflow installation.

## Contract mapping and preparation handoff

| Spec rows | Owning plan acceptance |
| --- | --- |
| R01-R04 | Task 2 literal event/checkout controls; Task 3 actual three-event source receipts |
| R05-R08 | Task 1 adoption gates; Task 2 observed Node/profile/name-only credential checks; Task 3 external package/image closure |
| R09-R10 | Task 1 permission boundary; Task 2 identity/transport/extraction rejection and bounded setup |
| R11-R17 | Task 2 phase/count/capture/timeout privacy fixtures; Task 3 exact stream/hash/receipt closure |
| R18-R20 | Global constraints and Task 3 unknown/soft-limit/nonqualification/unchanged-protection checks |

I do not mark future task checkboxes performed from documentary review. Plan approval,
complete Action adoption assessment and reviewed #23 integration remain pending.
No actual hosted event, official-Go/archive/Action execution, local subprocess fixture,
Go test/vet, fuzz, agent, push, PR or merge was performed by drafting this artifact.
The plan needs owner review and correction of any proposed code gaps before approval;
no executable delivery is currently authorized.
