"""One pinned macOS feasibility experiment. Import never performs I/O or execution."""
import base64
import gzip
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import selectors
import signal
import stat
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib

CAP = 32 * 1024 * 1024
RECEIPT_CAP = 64 * 1024
MODULE_EXPANDED_CAP = 32 * 1024 * 1024
PREFIX = 'golang.org/x/sys@v0.44.0/'
GO_PIN = {'bytes': 68100347, 'sha256': 'ee215d57e0ec269c60cc9ceca68e6bda321ba9ee5afe24f4b0988703c2d87d12'}
MODULE_PINS = {
    'zip': {'bytes': 2012379, 'sha256': 'f1fa1052808e6bd6eb9c5372c053b2370a582532fac5d6a4600e7a6fab190ff3'},
    'mod': {'bytes': 35, 'sha256': '57f4393ea18d5446a12363b35c23a616d843fa1669c7121a70a2bc3a9677d665'},
    'info': {'bytes': 190, 'sha256': 'db88d97c963506d830212c91e42f4bbd9076c18faccb127b6c096bb86bab0ae6'},
}
MODULE_H1 = 'h1:ildZl3J4uzeKP07r2F++Op7E9B29JRUy+a27EibtBTQ='
MOD_H1 = 'h1:4GL1E5IUh+htKOUEOaiffhrAeqysfVGipDYzABqnCmw='
GO_URL = 'https://dl.google.com/go/go1.27.1.darwin-arm64.tar.gz'
MODULE_URL = 'https://proxy.golang.org/golang.org/x/sys/@v/v0.44.0.'


class Rejected(Exception):
    """Messages are fixed public reason codes, never raw network/process errors."""


def require(condition, reason):
    if not condition:
        raise Rejected(reason)


def clean_env(root):
    return {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(root/'home'),
            'TMPDIR': str(root/'tmp'), 'LANG': 'C', 'LC_ALL': 'C',
            'GOTOOLCHAIN': 'local', 'GOPROXY': 'off', 'GOSUMDB': 'off',
            'GOWORK': 'off', 'CGO_ENABLED': '0', 'GOENV': 'off',
            'GOFLAGS': '-mod=readonly', 'GOTELEMETRY': 'off',
            'GOCACHE': str(root/'gocache'), 'GOMODCACHE': str(root/'gomodcache'),
            'GOMAXPROCS': '2', 'GOMEMLIMIT': '512MiB'}


def strict_json(raw):
    def pairs(items):
        obj = {}
        for key, value in items:
            require(key not in obj, 'duplicate-json-key')
            obj[key] = value
        return obj
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Rejected('nonfinite-json')))
    except (ValueError, UnicodeError, RecursionError):
        raise Rejected('invalid-json') from None


def receipt_fields(obj, fields, reason):
    require(isinstance(obj, dict) and set(obj) == set(fields.split()), reason)


def receipt_integer(value, low, high):
    require(type(value) is int and low <= value <= high, 'probe-integer')


def receipt_case(case, index):
    fields = 'id status reason actualDataEqual distinctDestination cowIndependenceObserved notOriginalBindingObserved atomicCOWClaim'
    receipt_fields({k: v for k, v in case.items() if k != 'observation'}, fields, 'probe-case-fields')
    booleans = fields.split()[3:7]
    require(all(type(case[k]) is bool for k in booleans), 'probe-case-booleans')
    expected = dict(id=case['id'], status='NOT RUN', reason='preflight',
                    actualDataEqual=False, distinctDestination=False,
                    cowIndependenceObserved=False, notOriginalBindingObserved=False, atomicCOWClaim='')
    if 'observation' in case:
        obs = case['observation']
        receipt_fields(obs, 'errno sourceBefore sourceAtCloneSample sourceAfter destination bytes sha256Bytes',
                       'probe-observation-fields')
        receipt_integer(obs['errno'], 0, 2**32-1)
        receipt_integer(obs['bytes'], -2**63, 2**63-1)
        digest = obs['sha256Bytes']
        require(isinstance(digest, list) and len(digest) == 32, 'probe-digest')
        for value in digest: receipt_integer(value, 0, 255)
        samples = [obs[k] for k in ('sourceBefore', 'sourceAtCloneSample', 'sourceAfter', 'destination')]
        for sample in samples:
            receipt_fields(sample, 'device inode ctimeSec ctimeNsec nlink mode size', 'probe-sample-fields')
            for key in ('device', 'inode', 'nlink'): receipt_integer(sample[key], 0, 2**64-1)
            receipt_integer(sample['mode'], 0, 2**32-1)
            receipt_integer(sample['ctimeSec'], -2**63, 2**63-1)
            receipt_integer(sample['ctimeNsec'], 0, 10**9-1)
            receipt_integer(sample['size'], -2**63, 2**63-1)
        before, at, after, dest = samples
        def same(a, b): return (a['device'], a['inode']) == (b['device'], b['inode'])
        def regular(s): return s['mode'] & 0o170000 == 0o100000 and s['nlink'] == 1 and s['size'] == 16
        expected.update(status='FAIL', reason='observation-mismatch')
        errno = obs['errno']
        if errno in (45, 18, 78, 22):
            expected.update(status='BLOCKED', reason='clone-capability-unavailable')
        elif index == 2:
            if errno == 62 and dest['inode'] == 0:
                expected.update(status='PASS', reason='no-follow-refused')
        elif errno:
            expected['reason'] = 'clone-error'
        else:
            expected['atomicCOWClaim'] = 'clonefileat-contract-only'
            expected['actualDataEqual'] = (obs['bytes'] == 16 and bytes(digest) == hashlib.sha256(
                b'owned-literal-B\n' if index == 4 else b'owned-literal-A\n').digest())
            expected['distinctDestination'] = dest['device'] == at['device'] and not same(dest, at) and not same(dest, before)
            if (all(regular(s) for s in samples) and expected['actualDataEqual'] and
                    expected['distinctDestination'] and same(before, after) and
                    (not same(before, at) if index == 4 else same(before, at))):
                reasons = ['owned-clone-data-equal-distinct', 'A-clone-after-trusted-B-overwrite',
                           '', 'known-link-selection-not-production-resolver', 'B-clone-with-restored-A-path-samples']
                expected.update(status='PASS', reason=reasons[index], cowIndependenceObserved=index==1,
                                notOriginalBindingObserved=index==4)
    require({k: v for k, v in case.items() if k != 'observation'} == expected, 'probe-case-observation-mismatch')


def validate_receipt(raw, code):
    require(len(raw) <= RECEIPT_CAP, 'probe-receipt-limit')
    require(raw.startswith(b'{') and raw.endswith(b'}\n'), 'probe-json-framing')
    obj = strict_json(raw)
    fields = {'schema', 'scope', 'qualification', 'sourceObjectBinding', 'status',
              'cases', 'environment', 'cleanup'}
    require(isinstance(obj, dict) and set(obj) == fields, 'probe-fields')
    for key, expected in {'schema': 'packtrace.macos-clone-probe.v1',
                          'scope': 'controlled-fixture-feasibility',
                          'qualification': 'not-qualified',
                          'sourceObjectBinding': 'not-established'}.items():
        require(obj[key] == expected, 'probe-qualification')
    require(isinstance(obj['cases'], list) and len(obj['cases']) == 5 and
            all(isinstance(case, dict) for case in obj['cases']), 'probe-cases')
    require([case.get('id') for case in obj['cases']] ==
            ['regular', 'cow', 'direct-link', 'selected-link', 'swap'], 'probe-case-ids')
    for index, case in enumerate(obj['cases']): receipt_case(case, index)
    env, cleanup = obj['environment'], obj['cleanup']
    receipt_fields(env, 'os arch go cgo osVersion osBuild kernel filesystem mount mountFlags caseSensitive uid api flags reason',
                   'probe-environment-fields')
    for key in ('os', 'arch', 'go', 'cgo', 'osVersion', 'osBuild', 'kernel', 'filesystem', 'mount', 'api', 'reason'):
        require(isinstance(env[key], str) and len(env[key]) <= (1024 if key == 'mount' else 128), 'probe-environment-string')
    receipt_integer(env['mountFlags'], 0, 2**64-1)
    receipt_integer(env['uid'], 0, 2**63-1)
    receipt_integer(env['flags'], -2**63, 2**63-1)
    require(env['caseSensitive'] is None or type(env['caseSensitive']) is bool, 'probe-case-setting')
    require(env['api'] == 'clonefileat' and env['flags'] == 10, 'probe-api')
    fatal_reasons = {'invalid-arguments', 'budget-rejected', 'invalid-evidence-directory', 'fixture-setup-failed',
                     'self-executable-unavailable', 'capability-unavailable', 'capability-pipe-failed',
                     'capability-write-failed', 'observer-protocol-or-supervision-failed'}
    require(env['reason'] in fatal_reasons | {'', 'unsupported-profile', 'nonplain-evidence-directory',
            'filesystem-unavailable', 'unsupported-filesystem', 'controlled-cases-observed'}, 'probe-environment-reason')
    if any('observation' in case for case in obj['cases']):
        require(env['os'] == 'darwin' and env['arch'] == 'arm64' and env['go'] == 'go1.27.1'
                and env['cgo'] == '0' and env['uid'] > 0 and env['osBuild'] and env['kernel']
                and re.fullmatch(r'15\.[0-9]+(?:\.[0-9]+)?', env['osVersion'])
                and all(int(p) <= 65535 for p in env['osVersion'].split('.'))
                and env['filesystem'] == 'apfs' and env['mount'] and env['mountFlags'] & 4096
                and not env['mountFlags'] & 1
                and env['reason'] in ('controlled-cases-observed', 'observer-protocol-or-supervision-failed'),
                'probe-observed-profile')
    receipt_fields(cleanup, 'clean workerReaped residue', 'probe-cleanup-fields')
    require(type(cleanup['clean']) is bool and type(cleanup['workerReaped']) is bool and
            isinstance(cleanup['residue'], list), 'probe-cleanup-types')
    residue_codes = {'unreaped-worker', 'stage-C', 'fixture-artifact', 'unknown-fixture-residue',
                     'unknown-stage-residue', 'owned-directory', 'unknown-root-residue'}
    require(all(isinstance(x, str) and x in residue_codes for x in cleanup['residue']), 'probe-residue')
    require(not cleanup['clean'] or (cleanup['workerReaped'] and not cleanup['residue']), 'probe-cleanup-unconfirmed')
    fatal = env['reason'] in fatal_reasons or not cleanup['clean'] or not cleanup['workerReaped']
    statuses = [case['status'] for case in obj['cases']]
    expected = ('FAIL', 2) if fatal else (('FAIL', 1) if 'FAIL' in statuses else
               (('PASS', 0) if all(s == 'PASS' for s in statuses) else ('BLOCKED', 3)))
    require(type(code) is int and (obj['status'], code) == expected, 'probe-exit-status')
    return obj


def disk_bytes(root, allow_links=False):
    total = 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            entry = Path(directory)/name
            mode = entry.lstat().st_mode
            require(stat.S_ISREG(mode) or stat.S_ISDIR(mode) or
                    (allow_links and stat.S_ISLNK(mode)), 'storage-type')
            total += entry.lstat().st_size
    return total


class Budget:
    """Outer process-group watchdog, independent of the Go supervisor under test."""
    def __init__(self, cap=CAP):
        self.cap, self.used, self.phases = cap, 0, []

    def command(self, label, argv, cwd, env, seconds, stdout_cap=CAP,
                stderr_cap=CAP, storage=lambda: True):
        started = time.monotonic()
        end = started + max(0, seconds)
        out, err = bytearray(), bytearray()
        phase, code, reaped, group_clean = 'exited', None, False, False
        process = None
        try:
            require(seconds > 0, 'phase-deadline')
            process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, start_new_session=True)
            with selectors.DefaultSelector() as selector:
                for stream, target, cap in [(process.stdout, out, stdout_cap), (process.stderr, err, stderr_cap)]:
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, (target, cap))
                while selector.get_map() or process.poll() is None:
                    if time.monotonic() >= end:
                        phase = 'timeout'; break
                    if not storage():
                        phase = 'storage-limit'; break
                    overflow = False
                    for key, _ in selector.select(min(.1, max(0, end-time.monotonic()))):
                        data = os.read(key.fd, 65536)
                        if not data:
                            selector.unregister(key.fileobj); continue
                        target, cap = key.data
                        keep = max(0, min(len(data), cap-len(target), self.cap-self.used))
                        target.extend(data[:keep]); self.used += keep
                        if keep != len(data): overflow = True; break
                    if overflow:
                        phase = 'output-limit'; break
            # Even a normally exited leader must not leave detached work in its group.
            if phase == 'exited':
                process.wait(timeout=1)
                try:
                    os.killpg(process.pid, 0)
                    phase = 'descendant-leak'
                except ProcessLookupError:
                    pass
        except Rejected:
            phase = 'deadline'
        except (OSError, subprocess.TimeoutExpired):
            phase = 'process-error'
        finally:
            if process is not None:
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                try:
                    code = process.wait(timeout=2); reaped = True
                except subprocess.TimeoutExpired:
                    phase = 'unreaped'
                for stream in (process.stdout, process.stderr): stream.close()
                finish = time.monotonic()+.3
                while True:
                    try: os.killpg(process.pid, 0)
                    except ProcessLookupError:
                        group_clean = True; break
                    if time.monotonic() >= finish: break
                    time.sleep(.01)
        result = {'phase': phase, 'exit': code, 'reaped': reaped, 'groupClean': group_clean,
                  'stdout': bytes(out), 'stderr': bytes(err)}
        self.phases.append({'name': label, 'phase': phase, 'exit': code, 'reaped': reaped,
                            'groupClean': group_clean, 'durationSeconds': time.monotonic()-started,
                            'stdoutBytes': len(out), 'stderrBytes': len(err),
                            'stdoutSHA256': hashlib.sha256(out).hexdigest(),
                            'stderrSHA256': hashlib.sha256(err).hexdigest()})
        return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): return None


def allowed_url(url, origin):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == 'https' and parsed.username is None and parsed.password is None
            and parsed.port is None and not parsed.fragment, 'acquisition-url')
    require(not any(x in parsed.path for x in ('..', '\\', '%')), 'acquisition-path')
    if url == origin:
        require((parsed.hostname == 'dl.google.com' and parsed.path.startswith('/go/')) or
                (parsed.hostname == 'proxy.golang.org' and parsed.path.startswith('/golang.org/x/sys/@v/')),
                'acquisition-origin')
    else:
        require(origin.startswith(MODULE_URL.rsplit('.', 1)[0]) and
                parsed.hostname == 'storage.googleapis.com' and
                parsed.path.startswith('/proxy-golang-org-prod/'), 'acquisition-redirect')


def download(url, path, pin, deadline, transport=None):
    origin = url
    if transport is None:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        transport = lambda address, timeout: opener.open(
            urllib.request.Request(address, headers={'Accept-Encoding': 'identity'}), timeout=timeout)
    try:
        for redirects in range(4):
            allowed_url(url, origin)
            remaining = deadline-time.monotonic()
            require(remaining > 0, 'acquisition-timeout')
            try:
                response = transport(url, min(10, remaining))
            except urllib.error.HTTPError as error:
                location = error.headers.get('Location')
                status = error.code
                error.close()
                require(status in (301, 302, 303, 307, 308) and location and redirects < 3,
                        'acquisition-http')
                url = urllib.parse.urljoin(url, location)
                # A same-origin redirect is not an approved alternate endpoint.
                require(url != origin, 'acquisition-redirect')
                continue
            with response:
                require(response.status == 200, 'acquisition-http')
                length = response.headers.get('Content-Length')
                require(length is None or length == str(pin['bytes']), 'acquisition-length')
                require(response.headers.get('Content-Encoding', 'identity') == 'identity', 'acquisition-encoding')
                digest, size = hashlib.sha256(), 0
                with path.open('xb') as output:
                    while True:
                        require(time.monotonic() < deadline, 'acquisition-timeout')
                        data = response.read(min(65536, pin['bytes']-size+1))
                        if not data: break  # Actual full EOF, not just the expected prefix.
                        size += len(data)
                        require(size <= pin['bytes'], 'acquisition-byte-limit')
                        digest.update(data); output.write(data)
                require(size == pin['bytes'] and digest.hexdigest() == pin['sha256'], 'acquisition-identity')
                return {'bytes': size, 'sha256': digest.hexdigest(), 'source': origin,
                        'finalHost': urllib.parse.urlsplit(url).hostname, 'redirects': redirects}
        raise Rejected('acquisition-redirect-limit')
    except (OSError, ValueError, urllib.error.URLError, http.client.HTTPException):
        raise Rejected('acquisition-transport') from None


def safe_name(name, prefix, seen):
    path = PurePosixPath(name)
    require(name and len(name) <= 512 and not name.startswith('/') and '\\' not in name
            and ':' not in name and '\n' not in name and '\r' not in name and '\x00' not in name
            and path.as_posix() == name and len(path.parts) <= 64
            and all(x not in ('', '.', '..') for x in path.parts)
            and (name == prefix.rstrip('/') or name.startswith(prefix)), 'archive-path')
    require(name.casefold() not in seen, 'archive-duplicate')
    seen.add(name.casefold())
    return path


def extract_go(path, dest, max_bytes=1073741824, max_entries=100000):
    dest.mkdir(mode=0o700)
    seen, expanded = set(), 0
    # Decompress through real EOF (including gzip CRC/footer), bounded independently.
    raw = dest/'archive.tar'
    try:
        with gzip.open(path, 'rb') as source, raw.open('xb') as output:
            unpacked = 0
            while True:
                data = source.read(65536)
                if not data: break
                unpacked += len(data)
                require(unpacked <= 1073741824, 'tar-stream-limit')
                output.write(data)
        with tarfile.open(raw, 'r:') as archive:
            for member in archive:
                require(member.isfile() or member.isdir(), 'tar-type')
                name = member.name.rstrip('/') if member.isdir() else member.name
                relative = safe_name(name, 'go/', seen)
                require(len(seen) <= max_entries, 'tar-entries')
                require(member.mode & ~0o777 == 0 and not member.mode & 0o022, 'tar-mode')
                target = dest/relative
                if member.isdir():
                    target.mkdir(mode=0o700, parents=True, exist_ok=True)
                else:
                    expanded += member.size
                    require(0 <= member.size and expanded <= max_bytes, 'tar-expanded')
                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    with archive.extractfile(member) as source, target.open('xb') as output:
                        left = member.size
                        while left:
                            data = source.read(min(65536, left))
                            require(data, 'tar-short-file')
                            output.write(data); left -= len(data)
                    target.chmod(0o755 if member.mode & 0o111 else 0o644)
        raw.unlink()
        return {'entries': len(seen), 'expandedBytes': expanded, 'tarBytes': unpacked}
    except (OSError, EOFError, tarfile.TarError):
        raise Rejected('invalid-tar') from None


def module_sum(data):
    line = hashlib.sha256(data).hexdigest() + '  go.mod\n'
    return 'h1:' + base64.b64encode(hashlib.sha256(line.encode()).digest()).decode()


def extract_module(path, dest, expected):
    seen, hashes, expanded = set(), {}, 0
    dest.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(path) as archive:
            require(len(archive.infolist()) <= 4096, 'zip-entries')
            for member in archive.infolist():
                relative = safe_name(member.filename, PREFIX, seen)
                mode = member.external_attr >> 16
                require(not member.is_dir() and not member.flag_bits & 1 and
                        stat.S_IFMT(mode) in (0, stat.S_IFREG) and mode & 0o7000 == 0,
                        'zip-mode')
                expanded += member.file_size
                require(expanded <= MODULE_EXPANDED_CAP and member.file_size >= 0, 'zip-expanded')
                target = dest/relative
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                digest, size = hashlib.sha256(), 0
                with archive.open(member) as source, target.open('xb') as output:
                    while True:
                        data = source.read(65536)
                        if not data: break  # zipfile checks CRC on complete EOF.
                        size += len(data)
                        require(size <= member.file_size, 'zip-size')
                        digest.update(data); output.write(data)
                require(size == member.file_size, 'zip-size')
                hashes[member.filename] = digest.hexdigest()
                target.chmod(0o444)
        text = ''.join(hashes[name]+'  '+name+'\n' for name in sorted(hashes))
        actual = 'h1:' + base64.b64encode(hashlib.sha256(text.encode()).digest()).decode()
        require(actual == expected, 'module-h1')
        return actual
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError, NotImplementedError, zlib.error):
        raise Rejected('invalid-module-zip') from None


def setup_storage(root):
    return disk_bytes(root/'gocache') <= 2*1024**3 and disk_bytes(root) <= 4*1024**3


def compile_probe(go, module, root, env, budget, deadline):
    commands = [
        ('go-version', ['version'], b'go version go1.27.1 darwin/arm64\n'),
        ('go-profile', ['env', 'GOVERSION', 'GOOS', 'GOARCH', 'CGO_ENABLED'], b'go1.27.1\ndarwin\narm64\n0\n'),
        ('module-verify', ['mod', 'verify'], b'all modules verified\n'),
        ('portable-tests', ['test', '-count=1', '-timeout=60s', './...'], None),
        ('build', ['build', '-o', str(root/'maccloneprobe'), '.'], None),
        ('vet', ['vet', '.'], None),
    ]
    for label, args, expected in commands:
        result = budget.command(label, [str(go)] + args, module, env,
                                min(180, deadline-time.monotonic()), storage=lambda: setup_storage(root))
        require(result['phase'] == 'exited' and result['exit'] == 0 and result['reaped']
                and result['groupClean'], 'setup-command-'+label)
        require(expected is None or result['stdout'] == expected, 'setup-profile-'+label)
    result = budget.command('python-tests', [sys.executable, '-B', '-m', 'unittest', '-v', 'test_ci'],
                            module/'ci', env, min(180, deadline-time.monotonic()),
                            storage=lambda: setup_storage(root))
    require(result['phase'] == 'exited' and result['exit'] == 0 and result['reaped']
            and result['groupClean'], 'setup-command-python-tests')
    return True


def check_module(module):
    expected_mod = r'module\s+packtrace-native-safety-probe\s+go\s+1\.27\.1\s+require\s+golang\.org/x/sys\s+v0\.44\.0\s*'
    require(re.fullmatch(expected_mod, (module/'go.mod').read_text()), 'module-contract')
    sums = (module/'go.sum').read_text().splitlines()
    require(sorted(sums) == sorted([f'golang.org/x/sys v0.44.0 {MODULE_H1}',
                                   f'golang.org/x/sys v0.44.0/go.mod {MOD_H1}']), 'module-sums')
    return True


def seed_module(downloads, cache):
    mod = (downloads/'sys.mod').read_bytes()
    require(module_sum(mod) == MOD_H1, 'module-mod-h1')
    info = strict_json((downloads/'sys.info').read_bytes())
    require(isinstance(info, dict) and info.get('Version') == 'v0.44.0', 'module-info')
    actual = extract_module(downloads/'sys.zip', cache, MODULE_H1)
    require((cache/PREFIX/'go.mod').read_bytes() == mod, 'module-mod-zip-mismatch')
    target = cache/'cache/download/golang.org/x/sys/@v'
    target.mkdir(mode=0o700, parents=True)
    for suffix in ('zip', 'mod', 'info'):
        (downloads/('sys.'+suffix)).rename(target/('v0.44.0.'+suffix))
    (target/'v0.44.0.ziphash').write_text(actual)
    return {'h1': actual, 'goModSum': module_sum(mod)}


def native_once(root, env, budget):
    evidence = root/'evidence'
    mode = evidence.lstat()
    require(stat.S_ISDIR(mode.st_mode) and mode.st_uid == os.geteuid() and
            stat.S_IMODE(mode.st_mode) == 0o700 and not any(evidence.iterdir()), 'evidence-parent')
    result = budget.command('native', [str(root/'maccloneprobe'), '--evidence-dir', str(evidence)],
                            root/'source', env, 895, stdout_cap=48*1024, stderr_cap=64*1024,
                            storage=lambda: disk_bytes(evidence, allow_links=True)+budget.used <= CAP)
    try:
        obj = finish_native(result, evidence)
    except Rejected as error:
        try: error.probe = validate_receipt(result['stdout'], result['exit'])
        except Rejected: pass
        raise
    return result, obj


def preflight(root, budget, env):
    require(platform.system() == 'Darwin' and platform.machine() == 'arm64' and
            platform.mac_ver()[0].split('.')[0] == '15' and os.geteuid() != 0, 'unsupported-profile')
    result = budget.command('os-build', ['/usr/bin/sw_vers', '-buildVersion'], root, env, 5,
                            stdout_cap=4096, stderr_cap=4096)
    require(result['phase'] == 'exited' and result['exit'] == 0, 'os-build-unavailable')
    build = result['stdout'].decode('ascii').strip()
    require(re.fullmatch(r'[0-9A-Za-z.]+', build), 'os-build-invalid')
    fs = os.statvfs(root)
    marker = root/'case-check'
    with marker.open('xb') as output: output.write(b'owned-case-check')
    try: case_sensitive = not (root/'CASE-CHECK').exists()
    finally: marker.unlink()
    return {'uname': platform.uname()._asdict(), 'macOS': platform.mac_ver()[0], 'osBuild': build,
            'uid': os.geteuid(), 'device': root.stat().st_dev, 'caseSensitive': case_sensitive,
            'filesystemType': 'unavailable-in-stdlib; see probe.environment',
            'mount': 'unavailable-in-stdlib; see probe.environment',
            'statvfs': {key: getattr(fs, key) for key in ('f_bsize', 'f_frsize', 'f_blocks', 'f_bfree',
                      'f_bavail', 'f_files', 'f_ffree', 'f_favail', 'f_flag', 'f_namemax')},
            'runner': {key: os.environ.get(key, 'unavailable') for key in
                       ('RUNNER_NAME', 'RUNNER_OS', 'RUNNER_ARCH', 'RUNNER_ENVIRONMENT', 'ImageOS', 'ImageVersion')}}


class setup_timer:
    def __init__(self, deadline): self.deadline = deadline
    def __enter__(self):
        require(self.deadline > time.monotonic(), 'setup-deadline')
        self.previous = signal.signal(signal.SIGALRM, self.expired)
        signal.setitimer(signal.ITIMER_REAL, self.deadline-time.monotonic())
    @staticmethod
    def expired(*args): raise Rejected('setup-timeout')
    def __exit__(self, *args):
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, self.previous)


def prepare(root, module, env, budget, deadline, transport=None):
    check_module(module)
    for name in ('downloads', 'gocache', 'gomodcache'):
        (root/name).mkdir(mode=0o700)
    downloads = root/'downloads'
    archives = {'go': download(GO_URL, downloads/'go.tgz', GO_PIN, deadline, transport)}
    for suffix, pin in MODULE_PINS.items():
        archives['sys.'+suffix] = download(MODULE_URL+suffix, downloads/('sys.'+suffix), pin, deadline, transport)
    archives['go'].update(extract_go(downloads/'go.tgz', root/'toolchain'))
    module_record = seed_module(downloads, root/'gomodcache')
    env['PATH'] = str(root/'toolchain/go/bin')+':/usr/bin:/bin:/usr/sbin:/sbin'
    compile_probe(root/'toolchain/go/bin/go', module, root, env, budget, deadline)
    binary = root/'maccloneprobe'
    require(stat.S_ISREG(binary.lstat().st_mode) and binary.stat().st_size <= 64*1024*1024, 'binary-type-size')
    require(setup_storage(root), 'setup-storage-limit')
    return {'archives': archives, 'module': module_record, 'goVersion': 'go1.27.1',
            'binarySHA256': hashlib.sha256(binary.read_bytes()).hexdigest(),
            'binaryBytes': binary.stat().st_size}


def validate_context(env, helper):
    root = Path(env.get('OWNROOT', ''))
    require(root.is_absolute() and root.resolve() == root, 'owned-root-path')
    mode = root.lstat()
    require(stat.S_ISDIR(mode.st_mode) and stat.S_IMODE(mode.st_mode) == 0o700 and
            mode.st_uid == os.geteuid(), 'owned-root-mode')
    require(helper == root/'source/probes/native-safety/ci/run.py' and helper.resolve() == helper,
            'source-helper-path')
    for key in ('SOURCE_SHA', 'SOURCE_TREE'):
        require(re.fullmatch('[0-9a-f]{40}', env.get(key, '')), 'source-context-identity')
    require(hashlib.sha256(helper.read_bytes()).hexdigest() == env.get('SOURCE_HELPER_SHA256'), 'source-helper-hash')
    deadline = float(env['SETUP_DEADLINE'])
    require(time.monotonic() < deadline <= time.monotonic()+720, 'setup-deadline')
    used = int(env['BOOTSTRAP_OUTPUT_BYTES'])
    require(0 <= used <= 2*1024*1024, 'bootstrap-output-budget')
    raw_phases = env['BOOTSTRAP_PHASES'].encode()
    require(len(raw_phases) <= 8192, 'bootstrap-phases-limit')
    phases = strict_json(raw_phases)
    require(isinstance(phases, list) and len(phases) <= 16, 'bootstrap-phases')
    return {'sha': env['SOURCE_SHA'], 'tree': env['SOURCE_TREE'],
            'helperSHA256': env['SOURCE_HELPER_SHA256'], 'root': root,
            'deadline': deadline, 'used': used, 'bootstrapPhases': phases}


def emit(record):
    encoded = json.dumps(record, separators=(',', ':'), allow_nan=False)
    if len(('NATIVE_PROBE_RECEIPT='+encoded+'\n').encode()) > RECEIPT_CAP:
        record.update(status='FAIL', actualExit=2, reason='outer-receipt-limit', probe=None)
        encoded = json.dumps(record, separators=(',', ':'), allow_nan=False)
    require(len(('NATIVE_PROBE_RECEIPT='+encoded+'\n').encode()) <= RECEIPT_CAP, 'outer-receipt-limit')
    print('NATIVE_PROBE_RECEIPT='+encoded)
    return record['actualExit']


def main(env=None, helper=None):
    env = os.environ if env is None else env
    helper = Path(__file__).absolute() if helper is None else helper
    budget = Budget(CAP-RECEIPT_CAP)
    record = {'schema': 'packtrace.native-probe-ci.v1', 'purpose': 'controlled-fixture-feasibility',
              'qualification': 'not-qualified', 'sourceObjectBinding': 'not-established',
              'status': 'BLOCKED', 'phase': 'context', 'actualExit': 3, 'nativeExit': None,
              'source': {}, 'probe': None, 'environment': {'uname': platform.uname()._asdict()},
              'limits': {'setupSeconds': 720, 'nativeSeconds': 900, 'nativeCommandSeconds': 895,
                         'childSeconds': 10, 'fixtureEntries': 16, 'fixtureBytes': 65536,
                         'aggregateOutputAndEvidenceBytes': CAP, 'receiptBytes': RECEIPT_CAP,
                         'goArchiveBytes': GO_PIN['bytes'], 'goExpandedBytes': 1073741824,
                         'tarStreamBytes': 1073741824, 'tarEntries': 100000,
                         'moduleExpandedBytes': 32*1024*1024, 'moduleEntries': 4096,
                         'buildCacheBytes': 2*1024**3, 'setupStorageBytes': 4*1024**3},
              'networkIsolation': 'not-established; GOPROXY=off is not network isolation',
              'preparationCleanup': 'private ephemeral runner data retained until runner disposal'}
    try:
        context = validate_context(env, helper)
        root = context['root']
        budget.cap -= context['used']
        record['source'] = {key: context[key] for key in ('sha', 'tree', 'helperSHA256')}
        record['bootstrapPhases'] = context['bootstrapPhases']
        record['phase'] = 'preflight'
        child_env = clean_env(root)
        with setup_timer(context['deadline']):
            record['environment'] = preflight(root, budget, child_env)
            record['phase'] = 'setup'
            record['preparation'] = prepare(root, root/'source/probes/native-safety', child_env,
                                            budget, context['deadline'])
        record['phase'] = 'native'
        (root/'evidence').mkdir(mode=0o700)
        result, obj = native_once(root, child_env, budget)
        record.update(probe=obj, nativeExit=result['exit'], status=obj['status'], actualExit=result['exit'], phase='complete')
    except (Rejected, OSError, ValueError, KeyError, UnicodeError) as error:
        record['reason'] = str(error) if isinstance(error, Rejected) else 'controller-error'
        if record['phase'] == 'native':
            record.update(status='FAIL', actualExit=2)
            if budget.phases and budget.phases[-1]['name'] == 'native':
                record['nativeExit'] = budget.phases[-1]['exit']
            if hasattr(error, 'probe'): record['probe'] = error.probe
        elif record['reason'].startswith('setup-command-'):
            record.update(status='FAIL', actualExit=1)
    record['phases'] = budget.phases
    record['capturedOutputBytes'] = budget.used
    return emit(record)


def finish_native(result, evidence):
    require(result['phase'] == 'exited' and result['reaped'] and result.get('groupClean', True), 'native-supervision')
    obj = validate_receipt(result['stdout'], result['exit'])
    require(evidence.is_dir() and not evidence.is_symlink() and not any(evidence.iterdir()), 'native-cleanup-residue')
    return obj


if __name__ == '__main__':
    raise SystemExit(main())
