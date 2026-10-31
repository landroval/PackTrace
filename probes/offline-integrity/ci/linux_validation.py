"""One explicitly dispatched Linux validation; import performs no I/O/execution.

This does not run the unfinished nativequalification-tagged campaign or qualify
all platforms. Reuses the reviewed independent process watchdog from probe CI.
"""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import time

PROFILE = 'linux-scan-amd64-v1'
GO_SIZE = 70553950
GO_SHA256 = '63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445'
PACKAGES = ['./internal/nativefs', './internal/nativeresource', './internal/integrityscan',
            './internal/execution', './cmd/packtrace']
ORIGINAL_PACKAGES = ['./internal/integrityscan', './internal/nativefs', './cmd/packtrace']


def admit(env, system, machine, uid):
    sha = env.get('SOURCE_SHA', '')
    if not (env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
            and env.get('GITHUB_REPOSITORY') == 'landroval/PackTrace'
            and env.get('REPOSITORY_PRIVATE') == 'false'
            and re.fullmatch('[0-9a-f]{40}', sha)
            and env.get('EXPECTED_SHA') == sha
            and env.get('VALIDATION_PROFILE') == PROFILE
            and env.get('OWNED_CONFIRMATION') == 'owned-linux-fixtures-only'
            and env.get('ImageOS') == 'ubuntu24' and env.get('ImageVersion')
            and env.get('RUNNER_ARCH') == 'X64'
            and system == 'Linux' and machine == 'x86_64' and uid > 0):
        raise ValueError('validation-profile-rejected')


def phase_ok(result):
    return (result.get('phase') == 'exited' and result.get('exit') == 0
            and result.get('reaped') is True and result.get('groupClean') is True
            and result.get('groupPermissionDenied') is False)


def test_counts(raw):
    if not raw or not raw.endswith(b'\n'):
        raise ValueError('incomplete-test-stream')
    events = [json.loads(line) for line in raw.splitlines()]
    if not all(isinstance(e, dict) for e in events):
        raise ValueError('invalid-test-stream')
    counts = {'passed': sum(e.get('Action') == 'pass' and bool(e.get('Test')) for e in events),
              'failed': sum(e.get('Action') == 'fail' and bool(e.get('Test')) for e in events),
              'skipped': sum(e.get('Action') == 'skip' and bool(e.get('Test')) for e in events),
              'failedEvents': sum(e.get('Action') in ('fail', 'build-fail') for e in events)}
    if counts['passed'] == 0 or counts['failedEvents']:
        raise ValueError('test-events-failed')
    return counts


def diagnostic(raw):
    truncated = len(raw) > 8192
    bounded = raw[:4096] + raw[-4096:] if truncated else raw
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'base64': base64.b64encode(bounded).decode('ascii'), 'truncated': truncated,
            'scope': 'captured-bytes-only; base64-is-not-redaction'}


def fixture_bytes(root):
    total = 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            info = (Path(directory)/name).lstat()
            if not any(check(info.st_mode) for check in (stat.S_ISREG, stat.S_ISDIR, stat.S_ISLNK,
                                                         stat.S_ISFIFO, stat.S_ISSOCK)):
                raise ValueError('unexpected-fixture-type')
            total += info.st_size
    return total


def helpers(source):
    spec = importlib.util.spec_from_file_location(
        'owned_watchdog', source/'probes/native-safety/ci/run.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def hash_file(path):
    digest = hashlib.sha256()
    size = 0
    with path.open('rb') as stream:
        while data := stream.read(65536):
            size += len(data)
            digest.update(data)
    return size, digest.hexdigest()


def main():
    receipt = {'schema': 'packtrace.linux-validation.v1', 'profile': PROFILE,
               'setup': 'not-run', 'native': 'not-run', 'qualification': 'not-qualified',
               'unresolvedLocalFailure': 'retained; this run cannot erase it',
               'sourceSHA': os.environ.get('SOURCE_SHA', ''), 'cases': [],
               'fixtureScope': 'owned synthetic tests only; no devices, mounts or privilege changes'}
    budget = None
    success = False
    try:
        admit(os.environ, platform.system(), platform.machine(), os.geteuid())
        sys.dont_write_bytecode = True
        source = Path(os.environ['GITHUB_WORKSPACE'])
        root = Path(os.environ['RUNNER_TEMP'])/'packtrace-root-ci'
        # The unchanged preceding root step checked out exactly this SHA and
        # acquired/extracted this pinned archive. Recheck its identity here.
        if hash_file(root/'go.tar.gz') != (GO_SIZE, GO_SHA256):
            raise ValueError('pinned-archive-mismatch')
        h = helpers(source)
        budget = h.Budget(cap=8 << 20)  # existing root capture is separately <=16 MiB
        work = root/'linux-validation'
        work.mkdir(mode=0o700)
        for name in ('home', 'tmp', 'build', 'gomodcache'):
            (work/name).mkdir(mode=0o700)
        env = h.clean_env(root)
        env.update(HOME=str(work/'home'), TMPDIR=str(work/'tmp'), GOTMPDIR=str(work/'build'),
                   GOMODCACHE=str(work/'gomodcache'), PATH=str(root/'toolchain/go/bin')+':/usr/bin:/bin',
                   CC='/usr/bin/gcc', GOTELEMETRY='off')
        go = str(root/'toolchain/go/bin/go')
        # No target/native case starts before this independent environment proof.
        prep_end = time.monotonic()+60
        def command(label, argv, settings, seconds, storage=lambda: True):
            result = budget.command(label, argv, source, settings, seconds,
                                    stdout_cap=4 << 20, stderr_cap=64 << 10, storage=storage)
            if not phase_ok(result):
                publish_failure(label, result)
                raise ValueError('phase-not-successful')
            return result['stdout']
        def publish_failure(label, result):
            receipt['failedPhase'] = label
            receipt['diagnostics'] = {key: diagnostic(result[key]) for key in ('stdout', 'stderr')}
            receipt['captureComplete'] = result['phase'] != 'output-limit'
            # All captured FAIL evidence is retained in Actions logs, not only
            # head/tail hashes. These are bounded owned test fixtures, not targets.
            for stream in ('stdout', 'stderr'):
                raw = result[stream]
                for offset in range(0, len(raw), 3072):
                    print('LINUX_VALIDATION_DIAGNOSTIC '+json.dumps({'phase': label, 'stream': stream,
                          'offset': offset, 'base64': base64.b64encode(raw[offset:offset+3072]).decode('ascii')}), flush=True)
        sha = command('source-identity', ['/usr/bin/git', '-c', 'core.hooksPath='+str(root/'hooks'),
                      'rev-parse', 'HEAD', 'HEAD^{tree}'], env, max(.001, prep_end-time.monotonic()))
        ids = sha.decode('ascii').splitlines()
        if len(ids) != 2 or ids[0] != receipt['sourceSHA'] or not all(re.fullmatch('[0-9a-f]{40}', x) for x in ids):
            raise ValueError('source-identity-mismatch')
        receipt['tree'] = ids[1]
        version = command('go-version', [go, 'version'], env, 5)
        if version != b'go version go1.27.1 linux/amd64\n':
            raise ValueError('compiler-mismatch')
        compiler = command('cc-version', ['/usr/bin/gcc', '-dumpfullversion'], env, 5)
        filesystem = command('filesystem', ['/usr/bin/stat', '-f', '-c', '%T', str(work/'tmp')], env, 5)
        os_release = Path('/etc/os-release').read_bytes()
        if len(os_release) > 4096 or b'ID=ubuntu\n' not in os_release or b'VERSION_ID="24.04"' not in os_release:
            raise ValueError('os-release-mismatch')
        receipt['environment'] = {'os': platform.system(), 'arch': platform.machine(),
            'kernel': platform.release(), 'uid': os.geteuid(), 'imageOS': os.environ['ImageOS'],
            'imageVersion': os.environ['ImageVersion'], 'goVersion': version.decode().strip(),
            'goBinarySHA256': hash_file(Path(go))[1], 'gccVersion': compiler.decode().strip(),
            'filesystem': filesystem.decode().strip(), 'reportedCPU': os.cpu_count(),
            'GOMAXPROCS': env['GOMAXPROCS'], 'aggregatePeakRSS': 'not independently measured by this Python wrapper'}
        receipt['archive'] = {'bytes': GO_SIZE, 'sha256': GO_SHA256}
        receipt['setup'] = 'passed'
        # This budget is independent of every Go supervisor under test.
        end = time.monotonic()+900
        def storage():
            return (h.disk_bytes(root/'gocache')+h.disk_bytes(work/'build') <= 2 << 30
                    and fixture_bytes(work/'tmp') <= 32 << 20)
        phases = [
            ('native-corpus', False, 270, PACKAGES),
            ('race-corpus', True, 360, PACKAGES),
            ('race-original-wider-reproducer', True, 240, ORIGINAL_PACKAGES)]
        receipt['native'] = 'running'
        for name, race, seconds, packages in phases:
            settings = dict(env, CGO_ENABLED='1' if race else '0')
            argv = [go, 'test', '-count=1', '-json', '-timeout='+str(seconds-5)+'s']
            if race:
                argv.append('-race')
            argv.extend(packages)
            limit = min(seconds, end-time.monotonic()-3)  # reserve cleanup inside 15m
            raw = command(name, argv, settings, limit, storage)
            try:
                counts = test_counts(raw)
            except (ValueError, UnicodeError):
                publish_failure(name, {'stdout': raw, 'stderr': b'', 'phase': 'invalid-test-evidence'})
                raise
            receipt['cases'].append({'name': name, 'counts': counts, 'cgo': settings['CGO_ENABLED'],
                                     'command': argv, 'testStreamSHA256': hashlib.sha256(raw).hexdigest()})
        clean = command('source-after', ['/usr/bin/git', 'status', '--porcelain', '--untracked-files=all'],
                        env, min(5, end-time.monotonic()-3))
        if clean:
            raise ValueError('source-was-modified')
        if time.monotonic() > end:
            raise ValueError('native-deadline')
        receipt['native'] = 'passed'
        success = True
    except Exception:
        if receipt['setup'] != 'passed':
            receipt['setup'] = 'failed'
        elif receipt['native'] == 'running':
            receipt['native'] = 'failed'
        receipt.setdefault('failure', 'setup-or-validation-failed; no automatic retry')
    finally:
        if budget is not None:
            receipt['phases'] = budget.phases
            receipt['capturedBytes'] = budget.used
        receipt['validationPassed'] = success
        encoded = json.dumps(receipt, sort_keys=True)
        if len(encoded.encode()) > 64 << 10:
            success = False
            encoded = json.dumps({'schema': receipt['schema'], 'validationPassed': False, 'failure': 'receipt-limit'})
        print('LINUX_VALIDATION_RECEIPT '+encoded, flush=True)
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
