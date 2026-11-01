"""One bounded owned macOS run; import performs no I/O or execution.

The existing reviewed POSIX watchdog and SDK downloader are reused, not the old
clone experiment or its optional module acquisition. No product dependencies.
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

PROFILES = {
    'macos-scan-arm64-v1': ('ARM64', 'arm64', 'arm64', 68100347,
                          'ee215d57e0ec269c60cc9ceca68e6bda321ba9ee5afe24f4b0988703c2d87d12'),
    'macos-scan-amd64-v1': ('X64', 'x86_64', 'amd64', 71621873,
                          '8f8f52c6649542cf027bbc9b9c68d1ec042f9f34808a40413f0b8b3f66f3caa4'),
}
PACKAGES = ['./internal/nativefs', './internal/nativeresource', './internal/integrityscan',
            './internal/execution', './cmd/packtrace']


def admit(env, system, machine, version, uid):
    row = PROFILES.get(env.get('VALIDATION_PROFILE'))
    sha = env.get('SOURCE_SHA', '')
    if not (row and env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
            and env.get('GITHUB_REPOSITORY') == 'landroval/PackTrace'
            and env.get('REPOSITORY_PRIVATE') == 'false'
            and re.fullmatch('[0-9a-f]{40}', sha) and env.get('EXPECTED_SHA') == sha
            and env.get('OWNED_CONFIRMATION') == 'owned-native-fixtures-only'
            and env.get('ImageOS') == 'macos15' and env.get('ImageVersion')
            and env.get('RUNNER_ARCH') == row[0] and system == 'Darwin'
            and machine == row[1] and re.fullmatch(r'15(?:\.[0-9]+){1,2}', version) and uid > 0):
        raise ValueError('native-profile-rejected')
    return row[2:]


def events(raw):
    if not raw or not raw.endswith(b'\n'):
        raise ValueError('incomplete-test-stream')
    result = [json.loads(line) for line in raw.splitlines()]
    if not all(isinstance(e, dict) for e in result):
        raise ValueError('invalid-test-event')
    return result


def negative_control(raw, code, test, marker):
    rows = events(raw)
    fails = [e.get('Test') for e in rows if e.get('Action') == 'fail' and e.get('Test')]
    output = ''.join(e.get('Output', '') for e in rows if e.get('Test') == test)
    if code != 1 or fails != [test] or marker not in output or any(e.get('Action') == 'build-fail' for e in rows):
        raise ValueError('negative-control-not-demonstrated')
    return True


def counts(raw):
    rows = events(raw)
    c = {'passed': sum(e.get('Action') == 'pass' and bool(e.get('Test')) for e in rows),
         'skipped': sum(e.get('Action') == 'skip' and bool(e.get('Test')) for e in rows),
         'failedEvents': sum(e.get('Action') in ('fail', 'build-fail') for e in rows)}
    if c['passed'] == 0 or c['failedEvents']:
        raise ValueError('test-stream-failed')
    return c


def load_helpers(source):
    spec = importlib.util.spec_from_file_location('owned_watchdog', source/'probes/native-safety/ci/run.py')
    h = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(h)
    return h


def file_hash(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def publish(label, result):
    for stream in ('stdout', 'stderr'):
        raw = result[stream]
        for offset in range(0, len(raw), 3072):
            print('MACOS_NATIVE_DIAGNOSTIC '+json.dumps({'phase': label, 'stream': stream, 'offset': offset,
                  'base64': base64.b64encode(raw[offset:offset+3072]).decode('ascii')}), flush=True)


def main():
    receipt = {'schema': 'packtrace.macos-native.v1', 'setup': 'not-run', 'native': 'not-run',
               'sourceSHA': os.environ.get('SOURCE_SHA', ''), 'qualification': 'not-qualified',
               'validationPassed': False, 'cases': [], 'negativeControls': [], 'boundSeconds': 900,
               'scope': 'owned fixtures; no devices, mounts, privileges, target code or new dependencies'}
    budget = None
    receipt_path = None
    success = False
    try:
        receipt['activePhase'] = 'profile-admission'
        arch, size, sha = admit(os.environ, platform.system(), platform.machine(), platform.mac_ver()[0], os.geteuid())
        sys.dont_write_bytecode = True
        source = Path(os.environ['MAC_NATIVE_SOURCE'])
        root = Path(os.environ['MAC_NATIVE_ROOT'])
        info = root.lstat()
        if (not root.is_absolute() or root.resolve() != root or not stat.S_ISDIR(info.st_mode)
                or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.geteuid()
                or source != root/'source' or source.resolve() != source):
            raise ValueError('owned-root-or-source-context')
        receipt_path = root/'receipt.json'
        started = json.loads((root/'start.json').read_text())['start']
        if not isinstance(started, (int, float)) or not 0 <= time.monotonic()-started < 900:
            raise ValueError('owned-start-context')
        end = started+900
        h = load_helpers(source)
        budget = h.Budget(cap=8 << 20)
        for name in ('home', 'tmp', 'build', 'gocache', 'gomodcache', 'mutants'):
            (root/name).mkdir(mode=0o700)
        env = h.clean_env(root)
        env.update(CGO_ENABLED='1', CC='/usr/bin/clang', GOOS='darwin', GOARCH=arch,
                   GOTMPDIR=str(root/'build'), MACOSX_DEPLOYMENT_TARGET='15.0')

        # Reuse the exercised nonfollowing scratch accountant. Import once,
        # never on each watchdog tick; this does not admit a Linux native row.
        spec = importlib.util.spec_from_file_location('owned_storage', source/'probes/offline-integrity/ci/linux_validation.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        def storage():
            try:
                return (module.fixture_bytes(root/'gocache')+module.fixture_bytes(root/'build') <= 2 << 30
                        and module.fixture_bytes(root/'tmp') <= 32 << 20)
            except (OSError, ValueError):
                receipt['storageFailure'] = 'owned-storage-observation-failed'
                raise

        def command(label, argv, seconds, expected_failure=False):
            receipt['activePhase'] = label
            result = budget.command(label, argv, source, env, min(seconds, end-time.monotonic()-10),
                                    stdout_cap=4 << 20, stderr_cap=64 << 10, storage=storage)
            budget.phases[-1]['captureComplete'] = result.get('captureComplete', False)
            operational = (result['phase'] == 'exited' and result['reaped'] is True
                           and result['groupClean'] is True and result['groupPermissionDenied'] is False
                           and result.get('captureComplete') is True)
            if not operational or (result['exit'] != 0 and not expected_failure):
                receipt['failedPhase'] = label
                publish(label, result)
                raise ValueError('command-not-successful')
            return result

        with h.setup_timer(end):
            result = command('source', ['/usr/bin/git', 'rev-parse', 'HEAD', 'HEAD^{tree}'], 10)
            ids = result['stdout'].decode('ascii').splitlines()
            if len(ids) != 2 or ids[0] != receipt['sourceSHA'] or not all(re.fullmatch('[0-9a-f]{40}', x) for x in ids):
                raise ValueError('source-identity')
            receipt['tree'] = ids[1]
            receipt['activePhase'] = 'pinned-sdk-acquisition'
            archive = root/'go.tar.gz'
            receipt['archive'] = h.download('https://dl.google.com/go/go1.27.1.darwin-'+arch+'.tar.gz',
                                           archive, {'bytes': size, 'sha256': sha}, min(end, time.monotonic()+120))
            receipt['archive'].update(h.extract_go(archive, root/'toolchain'))
            go = str(root/'toolchain/go/bin/go')
            env.update(PATH=str(root/'toolchain/go/bin')+':/usr/bin:/bin:/usr/sbin:/sbin',
                       GOROOT=str(root/'toolchain/go'))
            version = command('go-version', [go, 'version'], 10)['stdout'].decode().strip()
            if version != 'go version go1.27.1 darwin/'+arch:
                raise ValueError('sdk-version')
            sdk = command('sdk-path', ['/usr/bin/xcrun', '--show-sdk-path'], 10)['stdout'].decode().strip()
            if not sdk.startswith('/Applications/') or '\n' in sdk or len(sdk) > 4096:
                raise ValueError('installed-sdk-path')
            env['SDKROOT'] = sdk
            sdk_version = command('sdk-version', ['/usr/bin/xcrun', '--show-sdk-version'], 10)['stdout'].decode().strip()
            if not re.fullmatch(r'[0-9]+(?:\.[0-9]+){1,2}', sdk_version):
                raise ValueError('installed-sdk-version')
            compiler = command('clang-version', ['/usr/bin/clang', '--version'], 10)['stdout'].decode().splitlines()[0]
            build = command('os-build', ['/usr/bin/sw_vers', '-buildVersion'], 5)['stdout'].decode().strip()
            receipt['environment'] = {'os': 'darwin', 'arch': arch, 'machine': platform.machine(),
                'macOS': platform.mac_ver()[0], 'kernel': platform.release(), 'osBuild': build,
                'uid': os.geteuid(), 'imageOS': os.environ['ImageOS'], 'imageVersion': os.environ['ImageVersion'],
                'goVersion': version, 'goBinarySHA256': file_hash(Path(go)), 'compiler': compiler,
                'sdkRoot': sdk, 'sdkVersion': sdk_version, 'reportedCPU': os.cpu_count(), 'GOMAXPROCS': '2',
                'aggregatePeakRSS': 'not independently measured by Python; production native sampling is tested'}
            receipt['setup'] = 'passed'
            receipt['native'] = 'running'
            # Frozen overlays, never a modification to source or a production
            # fallback. The type-guard negative opens only an owned inert FIFO
            # with O_NONBLOCK, not a device, project or dependency executable.
            guard = source/'internal/nativefs/backend_darwin.go'
            original = guard.read_text()
            mutant, n = re.subn(r'const char \*profile =.*?;',
                                'const char *profile = "(version 1)(allow default)";', original, count=1, flags=re.S)
            if n != 1 or mutant == original:
                raise ValueError('guard-negative-source-mismatch')
            resident = source/'internal/nativeresource/child_darwin.go'
            resident_original = resident.read_text()
            needle = 'return 0, true, &darwinResourceFailure{"mach-task-basic-info", int(code)}'
            if resident_original.count(needle) != 1:
                raise ValueError('resident-negative-source-mismatch')
            for label, path, text, package, test, marker in [
                ('negative-preopen-type', guard, mutant, './internal/nativefs',
                 'TestDarwinPreparedGuardRefusesOwnedFIFOOpen', 'owned special-node open was not denied'),
                ('negative-live-zero', resident, resident_original.replace(needle, 'return 0, true, nil'),
                 './internal/nativeresource', 'TestDarwinRetainedChildMemoryIdentityExitAndQueryFailure',
                 'live failed Mach query became success')]:
                replacement = root/'mutants'/(label+'.go')
                replacement.write_text(text)
                overlay = root/'mutants'/(label+'.json')
                overlay.write_text(json.dumps({'Replace': {str(path): str(replacement)}}))
                r = command(label, [go, 'test', '-count=1', '-json', '-timeout=115s', '-overlay='+str(overlay),
                                    '-run=^'+test+'$', package], 120, expected_failure=True)
                publish(label, r)
                negative_control(r['stdout'], r['exit'], test, marker)
                receipt['negativeControls'].append({'name': label, 'expectedNamedFailure': test,
                                                    'demonstrated': True, 'mutantSHA256': file_hash(replacement)})
            for label, race, seconds, packages in [
                ('root-corpus', False, 300, ['./...']), ('race-corpus', True, 300, PACKAGES),
                ('race-original-wider-reproducer', True, 180,
                 ['./internal/integrityscan', './internal/nativefs', './cmd/packtrace'])]:
                argv = [go, 'test', '-count=1', '-json', '-timeout='+str(seconds-5)+'s']
                if race:
                    argv.append('-race')
                result = command(label, argv+packages, seconds)
                receipt['cases'].append({'name': label, 'counts': counts(result['stdout']),
                                         'testStreamSHA256': hashlib.sha256(result['stdout']).hexdigest()})
            command('vet', [go, 'vet', './...'], 30)
            changed = command('source-clean', ['/usr/bin/git', 'status', '--porcelain', '--untracked-files=all'], 5)
            if changed['stdout']:
                raise ValueError('source-mutated')
            receipt['native'] = 'passed'
            success = True
    except Exception as error:
        known = isinstance(error, ValueError) or ('h' in locals() and isinstance(error, h.Rejected))
        receipt['failure'] = str(error) if known else 'setup-or-native-error'
        # Preserve the reused helper's fixed rejection codes, not raw OS text.
        receipt.setdefault('failedPhase', receipt.get('activePhase', 'uninitialized'))
        if receipt['setup'] != 'passed':
            receipt['setup'] = 'failed'
        elif receipt['native'] == 'running':
            receipt['native'] = 'failed'
    finally:
        if budget is not None:
            receipt['phases'] = budget.phases
            receipt['capturedBytes'] = budget.used
        receipt['validationPassed'] = success
        encoded = json.dumps(receipt, sort_keys=True)
        if len(encoded.encode()) > 64 << 10:
            success = False
            encoded = json.dumps({'schema': receipt['schema'], 'validationPassed': False, 'failure': 'receipt-limit'})
        if receipt_path is not None:
            try:
                with receipt_path.open('x') as output:
                    output.write(encoded)
            except OSError:
                success = False
                receipt['validationPassed'] = False
                receipt['failure'] = 'receipt-publication-failed'
                encoded = json.dumps(receipt, sort_keys=True)
                if len(encoded.encode()) > 64 << 10:
                    encoded = json.dumps({'schema': receipt['schema'], 'validationPassed': False, 'failure': 'receipt-limit'})
        print('MACOS_NATIVE_RECEIPT '+encoded, flush=True)
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
