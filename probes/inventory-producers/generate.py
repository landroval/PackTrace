#!/usr/bin/env python3
"""Generate only owned inert fixtures in a rootless, private bwrap namespace."""
import argparse
import base64
from dataclasses import dataclass, field
import errno
import gzip
import hashlib
import http.server
import io
import json
import os
import re
from pathlib import Path
import selectors
import signal
import socket
import stat
import subprocess
import tarfile
import threading
import time

from prepare import Rejected, check_source, require

MAX_OUTPUT = 8 << 20
MAX_REPLAY = 16 << 20
REGISTRY = 'http://127.0.0.1:41769'


@dataclass
class RunBudget:
    calls: int = 0
    limit: int = 6
    output: int = 0
    deadline: float = field(default_factory=lambda: time.monotonic() + 600)
    receipts: list = field(default_factory=list)


def run_owned(argv, cwd, env, budget):
    require(budget.calls < budget.limit and time.monotonic() < budget.deadline, 'invocation-limit')
    budget.calls += 1
    deadline = min(budget.deadline, time.monotonic() + 120)
    receipt = {'argv': argv, 'status': 'exit', 'reaped': False, 'groupClean': False}
    p = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    selector = selectors.DefaultSelector(); selector.register(p.stdout, selectors.EVENT_READ)
    chunks, failed = [], None
    try:
        while True:
            if time.monotonic() >= deadline:
                raise Rejected('deadline')
            for key, _ in selector.select(0.05):
                data = os.read(key.fileobj.fileno(), 65536)
                if not data:
                    selector.unregister(key.fileobj); key.fileobj.close()
                else:
                    budget.output += len(data)
                    require(budget.output <= MAX_OUTPUT, 'output-limit')
                    chunks.append(data)
            # Retain the original unreaped direct-child PID until group cleanup.
            exited = os.waitid(os.P_PID, p.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if exited is not None and not selector.get_map():
                break
    except Rejected as e:
        failed = e; receipt['status'] = str(e)
    finally:
        selector.close()
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            failed = Rejected('cleanup-unconfirmed'); receipt['status'] = str(failed)
        try:
            p.wait(timeout=5); receipt['reaped'] = True
        except subprocess.TimeoutExpired:
            failed = Rejected('cleanup-unconfirmed'); receipt['status'] = str(failed)
        if p.stdout is not None:
            p.stdout.close()
        until = time.monotonic() + 1
        while time.monotonic() < until:
            try:
                os.killpg(p.pid, 0)
            except ProcessLookupError:
                receipt['groupClean'] = True; break
            except PermissionError:
                break
            time.sleep(0.01)
        raw = b''.join(chunks)
        receipt.update(exit=p.returncode, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), output=raw.decode('utf-8', errors='replace'))
        budget.receipts.append(receipt)
    if failed is not None:
        raise failed
    require(receipt['reaped'] and receipt['groupClean'] and p.returncode == 0, 'producer-failed')
    return raw


def install_arguments(kind, version, registry, layout, backend):
    require(registry == REGISTRY, 'registry-not-owned')
    require(kind in ('npm', 'bun') and layout in ('hoisted', 'isolated') and backend in ('copyfile', 'hardlink'), 'producer-options')
    if kind == 'npm':
        return ['/usr/bin/node', '/tools/package/bin/npm-cli.js', 'install', '--ignore-scripts', '--no-audit', '--no-fund', '--install-links', '--registry', registry, '--userconfig', '/work/config/user', '--globalconfig', '/work/config/global', '--cache', '/work/cache/npm']
    return ['/tools/bun-linux-x64/bun', 'install', '--ignore-scripts', '--no-progress', '--linker', layout, '--backend', backend, '--registry', registry]


def package_archive(manifest, extra=None):
    files = {'package/package.json': json.dumps(manifest, sort_keys=True).encode() + b'\n', 'package/index.js': b'// PackTrace owned inert fixture; never executed.\n'}
    for name, data in (extra or {}).items():
        files['package/' + name] = data if isinstance(data, bytes) else data.encode()
    tar_bytes = io.BytesIO()
    with tarfile.open(fileobj=tar_bytes, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, data in sorted(files.items()):
            item = tarfile.TarInfo(name); item.size = len(data); item.mode = 0o644; item.mtime = 0
            archive.addfile(item, io.BytesIO(data))
    result = io.BytesIO()
    with gzip.GzipFile(fileobj=result, mode='wb', mtime=0) as gz:
        gz.write(tar_bytes.getvalue())
    return result.getvalue()


def case_expectations():
    return {
        'single': {'versions': {'fixture-common': ['1.0.0', '2.0.0'], 'fixture-parent': ['1.0.0'], 'fixture-bundle': ['1.0.0'], 'fixture-peer': ['1.0.0']}, 'optionalAbsent': ['fixture-platform'], 'minimumCommonOneCopies': 2, 'scopes': 1},
        'workspaces': {'versions': {'fixture-common': ['1.0.0', '2.0.0']}, 'scopes': 2, 'workspaceManifest': 'packages/member/package.json'},
        'sources': {'declaredKeys': ['fixture-file', 'fixture-tarball', 'fixture-url', 'fixture-git'], 'sourceClaimsRemainUnqualified': True, 'scopes': 1},
    }


def source_manifest(commit, include_git=True):
    require(re.fullmatch('[0-9a-f]{40}', commit), 'owned-git-commit')
    dependencies = {'fixture-file': 'file:../../local-fixture', 'fixture-tarball': 'file:../../fixture-tarball.tgz', 'fixture-url': REGISTRY + '/files/fixture-url-1.0.0.tgz'}
    if include_git:
        dependencies['fixture-git'] = 'git+file:///work/git-fixture#' + commit
    return {'name': 'owned-sources', 'version': '1.0.0', 'private': True, 'dependencies': dependencies}


def selected_cases(kind, requested=None):
    defaults = ['single', 'workspaces', 'sources'] + (['hardlink'] if kind == 'bun' else [])
    allowed = defaults + (['isolated-single'] if kind == 'bun' else [])
    cases = defaults if requested is None else requested
    require(cases and len(cases) == len(set(cases)) and all(case in allowed for case in cases), 'case-selection')
    return cases


def call_allowance(kind, cases):
    return 1 + len(cases) + (1 if kind == 'npm' and 'single' in cases else 0)


def capture(root):
    entries, content_bytes, names, identities = [], 0, 0, {}
    stack = [root]
    while stack:
        directory = stack.pop()
        for item in sorted(os.scandir(directory), key=lambda x: x.name):
            name = Path(item.path).relative_to(root).as_posix()
            names += len(name.encode()); require(names <= 16 << 20 and len(entries) < 100000 and len(Path(name).parts) <= 64, 'capture-limit')
            s = item.stat(follow_symlinks=False)
            record = {'path': name}
            if stat.S_ISLNK(s.st_mode):
                record.update(kind='link', target=os.readlink(item.path))
                require(len(record['target'].encode()) <= 4096, 'capture-link-limit')
            elif stat.S_ISDIR(s.st_mode):
                record['kind'] = 'directory'; stack.append(Path(item.path))
            else:
                require(stat.S_ISREG(s.st_mode), 'capture-type')
                key = (s.st_dev, s.st_ino)
                if key not in identities:
                    identities[key] = len(identities) + 1
                record.update(kind='file', size=s.st_size, links=s.st_nlink, object=identities[key])
                if Path(name).name == 'package.json' or name in ('package-lock.json', 'npm-shrinkwrap.json', 'bun.lock'):
                    require(0 <= s.st_size <= 64 << 20, 'capture-file-limit')
                    data = Path(item.path).read_bytes(); content_bytes += len(data)
                    require(content_bytes <= MAX_REPLAY, 'capture-data-limit')
                    record.update(data=data.decode('utf-8'), sha256=hashlib.sha256(data).hexdigest())
            entries.append(record)
    return {'entries': sorted(entries, key=lambda x: x['path']), 'contentBytes': content_bytes}


def sandbox_arguments(tool, control, script):
    return ['bwrap', '--unshare-all', '--die-with-parent', '--new-session',
            '--size', str(512 << 20), '--tmpfs', '/work', '--ro-bind', '/usr', '/usr',
            '--tmpfs', '/usr/local', '--remount-ro', '/usr/local',
            '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib', '/lib64',
            '--proc', '/proc', '--remount-ro', '/proc', '--dev', '/dev', '--remount-ro', '/dev',
            '--symlink', '/work/tmp', '/tmp', '--ro-bind', str(tool), '/tools',
            '--ro-bind', str(control), '/control', '--ro-bind', str(script.parent), '/runner',
            '--remount-ro', '/', '--chdir', '/work', '--clearenv', '--setenv', 'PATH', '/usr/bin',
            '--setenv', 'HOME', '/work/home', '--setenv', 'TMPDIR', '/work/tmp',
            '--setenv', 'PYTHONDONTWRITEBYTECODE', '1', '/usr/bin/python3', '-B', '/runner/generate.py', '--inside']


def isolation_controls(control):
    require(os.readlink('/proc/self/ns/net') != control['hostNet'] and {name for _, name in socket.if_nameindex()} == {'lo'}, 'network-namespace')
    require(os.statvfs('/work').f_blocks * os.statvfs('/work').f_frsize <= 512 << 20, 'scratch-ceiling')
    require(os.statvfs('/').f_flag & os.ST_RDONLY, 'root-not-readonly')
    Path('/work/positive').write_text('owned'); require(Path('/work/positive').read_text() == 'owned', 'scratch-positive')
    for mode in ('rb', 'wb'):
        try:
            with Path(control['outsideCanary']).open(mode):
                pass
        except FileNotFoundError:
            pass
        else:
            raise Rejected('outside-canary-accessible')
    server = socket.socket(); server.settimeout(1); server.bind(('127.0.0.1', 0)); server.listen(1)
    client = socket.socket(); client.settimeout(1); client.connect(server.getsockname()); peer, _ = server.accept()
    client.sendall(b'owned'); require(peer.recv(5) == b'owned', 'loopback-positive')
    client.close(); peer.close(); server.close()
    external = socket.socket(); external.settimeout(1)
    try:
        external.connect(('198.18.0.1', 80))
    except OSError as e:
        require(e.errno == errno.ENETUNREACH, 'external-observation')
    else:
        raise Rejected('external-accessible')
    finally:
        external.close()
    return {'privateNetwork': True, 'loopbackPositive': True, 'outsideReadWriteDenied': True, 'externalENETUNREACH': True, 'scratchKernelCeiling': 512 << 20, 'rootReadonly': True}


def fixture_registry():
    packages, files = {}, {}
    def add(name, version, **fields):
        manifest = dict(name=name, version=version, **fields)
        extra = None
        if name == 'fixture-parent':
            extra = {'node_modules/fixture-bundle/package.json': json.dumps({'name': 'fixture-bundle', 'version': '1.0.0'}), 'node_modules/fixture-bundle/index.js': '// owned inert bundled fixture\n'}
        data = package_archive(manifest, extra)
        url = f'{REGISTRY}/files/{name}-{version}.tgz'
        files[f'/files/{name}-{version}.tgz'] = data
        row = dict(manifest, dist={'tarball': url, 'integrity': 'sha512-' + base64.b64encode(hashlib.sha512(data).digest()).decode(), 'shasum': hashlib.sha1(data).hexdigest()})
        packages.setdefault(name, {})[version] = row
        return data
    for version in ('1.0.0', '2.0.0'):
        add('fixture-common', version)
    add('fixture-peer', '1.0.0')
    add('fixture-bundle', '1.0.0')
    add('fixture-parent', '1.0.0', dependencies={'fixture-common': '1.0.0', 'fixture-bundle': '1.0.0'}, bundleDependencies=['fixture-bundle'], peerDependencies={'fixture-peer': '*'}, scripts={'postinstall': 'echo unexpected > /work/LIFECYCLE_EXECUTED'})
    add('fixture-platform', '1.0.0', os=['darwin'], cpu=['arm64'])
    local_tar = add('fixture-tarball', '1.0.0')
    add('fixture-url', '1.0.0')
    for name, versions in packages.items():
        files['/' + name] = json.dumps({'name': name, 'dist-tags': {'latest': sorted(versions)[-1]}, 'versions': versions}).encode()
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = files.get(self.path)
            if body is None:
                self.send_error(404); return
            self.send_response(200); self.send_header('Content-Length', str(len(body)))
            self.send_header('Content-Type', 'application/octet-stream' if self.path.endswith('.tgz') else 'application/json'); self.end_headers(); self.wfile.write(body)
        def log_message(self, *args):
            pass
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 41769), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    return server, thread, local_tar


def inside():
    control = json.loads(Path('/control/prepared.json').read_text())
    source = control['source']; planned = selected_cases(source['kind'], control.get('cases')); budget = RunBudget(limit=call_allowance(source['kind'], planned)); result = {'producer': source['kind'] + '@' + source['version'], 'status': 'failed', 'captures': []}
    server, thread = None, None
    try:
        for name in ('home', 'tmp', 'cache', 'config', 'projects'):
            Path('/work', name).mkdir(mode=0o700)
        for name in ('user', 'global'):
            Path('/work/config', name).write_text('')
        result['isolation'] = isolation_controls(control)
        executable = Path('/tools/package/bin/npm-cli.js' if source['kind'] == 'npm' else '/tools/bun-linux-x64/bun')
        with executable.open('rb') as f:
            require(hashlib.file_digest(f, 'sha256').hexdigest() == control['executableSHA256'], 'executable-changed')
        with Path('/usr/bin/node').open('rb') as f:
            require(hashlib.file_digest(f, 'sha256').hexdigest() == source['runtime']['sha256'], 'runtime-changed')
        env = dict(os.environ, DO_NOT_TRACK='1', CI='1', NPM_CONFIG_IGNORE_SCRIPTS='true', NPM_CONFIG_AUDIT='false', NPM_CONFIG_FUND='false', BUN_INSTALL_CACHE_DIR='/work/cache/bun', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_SYSTEM='/dev/null', GIT_AUTHOR_NAME='Owned Fixture', GIT_COMMITTER_NAME='Owned Fixture', GIT_AUTHOR_EMAIL='fixture@example.invalid', GIT_COMMITTER_EMAIL='fixture@example.invalid', GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='protocol.file.allow', GIT_CONFIG_VALUE_0='always')
        version_argv = ['/usr/bin/node', str(executable), '--version'] if source['kind'] == 'npm' else [str(executable), '--version']
        actual_version = run_owned(version_argv, Path('/work'), env, budget).decode().strip()
        require(actual_version == source['version'], 'producer-version-mismatch')
        result['actualVersion'] = actual_version
        server, thread, local_tar = fixture_registry()
        Path('/work/fixture-tarball.tgz').write_bytes(local_tar)
        local = Path('/work/local-fixture'); local.mkdir(); (local / 'package.json').write_text(json.dumps({'name': 'fixture-file', 'version': '1.0.0'}))
        git = Path('/work/git-fixture'); git.mkdir(); (git / 'package.json').write_text(json.dumps({'name': 'fixture-git', 'version': '1.0.0'})); (git / 'index.js').write_text('// owned inert; never executed\n')
        helpers = RunBudget(deadline=budget.deadline)
        for args in (['init', '-q'], ['add', 'package.json', 'index.js'], ['-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'owned inert fixture']):
            run_owned(['/usr/bin/git'] + args, git, env, helpers)
        git_commit = run_owned(['/usr/bin/git', 'rev-parse', 'HEAD'], git, env, helpers).decode().strip()
        result['helperReceipts'] = helpers.receipts
        expectations = case_expectations()
        cases = selected_cases(source['kind'], control.get('cases'))
        omit_git_file = source['kind'] == 'bun' and source['version'] == '1.3.2'
        if omit_git_file:
            result['unqualifiedProducerCases'] = [{'case': 'sources/git+file', 'qualified': False, 'reason': 'prior actual Bun 1.3.2 requests failed both HEAD and explicit commit; not retried or inferred'}]
            expectations['sources']['declaredKeys'].remove('fixture-git')
        for case in cases:
            project = Path('/work/projects', case); project.mkdir()
            if case in ('single', 'hardlink', 'isolated-single'):
                manifest = {'name': 'owned-root', 'version': '1.0.0', 'private': True, 'dependencies': {'fixture-parent': '1.0.0', 'fixture-common': '2.0.0', 'fixture-alias': 'npm:fixture-common@1.0.0', 'fixture-peer': '1.0.0'}, 'optionalDependencies': {'fixture-platform': '1.0.0'}}
            elif case == 'workspaces':
                manifest = {'name': 'owned-root', 'version': '1.0.0', 'private': True, 'workspaces': ['packages/*'], 'dependencies': {'fixture-common': '2.0.0'}}
                member = project / 'packages/member'; member.mkdir(parents=True); (member / 'package.json').write_text(json.dumps({'name': 'fixture-member', 'version': '1.0.0', 'dependencies': {'fixture-common': '1.0.0'}}))
            else:
                manifest = source_manifest(git_commit, include_git=not omit_git_file)
            (project / 'package.json').write_text(json.dumps(manifest, sort_keys=True))
            layout = 'isolated' if source['kind'] == 'bun' and case in ('workspaces','isolated-single') else 'hoisted'
            backend = 'hardlink' if case == 'hardlink' else 'copyfile'
            args = install_arguments(source['kind'], source['version'], REGISTRY, layout, backend)
            run_owned(args, project, env, budget)
            require(not Path('/work/LIFECYCLE_EXECUTED').exists(), 'lifecycle-executed')
            captured = capture(project); captured.update(case=case, layout=layout, backend=backend, expected=expectations.get(case, expectations['single']))
            result['captures'].append(captured)
            if case == 'single' and source['kind'] == 'npm':
                run_owned(['/usr/bin/node', '/tools/package/bin/npm-cli.js', 'shrinkwrap', '--ignore-scripts'], project, env, budget)
                shrink = capture(project); shrink.update(case='shrinkwrap', layout=layout, backend=backend, expected=expectations['single']); result['captures'].append(shrink)
        result['status'] = 'passed'
    except (Rejected, OSError, ValueError) as e:
        result['reason'] = str(e) if isinstance(e, Rejected) else 'setup-unavailable'
    finally:
        if server is not None:
            server.shutdown(); server.server_close(); thread.join(timeout=2)
        result['invocations'] = budget.calls; result['receipts'] = budget.receipts
    raw = json.dumps(result, separators=(',', ':')).encode()
    require(budget.output + len(raw) <= MAX_OUTPUT, 'batch-output-limit')
    os.write(1, raw + b'\n')
    return 0 if result['status'] == 'passed' else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--cases', nargs='+', choices=['single', 'workspaces', 'sources', 'hardlink', 'isolated-single'])
    parser.add_argument('prepared', nargs='?', type=Path); parser.add_argument('output', nargs='?', type=Path)
    args = parser.parse_args()
    if args.inside:
        return inside()
    require(args.prepared is not None and args.output is not None, 'arguments')
    prepared = json.loads(args.prepared.read_text()); source = prepared['source']; check_source(source)
    tool = args.prepared.parent / 'tool'
    executable = tool / ('package/bin/npm-cli.js' if source['kind'] == 'npm' else 'bun-linux-x64/bun')
    with executable.open('rb') as f:
        require(hashlib.file_digest(f, 'sha256').hexdigest() == prepared['executableSHA256'], 'prepared-tool-changed')
    cases = selected_cases(source['kind'], args.cases)
    allowance = call_allowance(source['kind'], cases)
    budget_file = args.prepared.parent / 'generation-budget.json'
    if budget_file.exists():
        accounting = json.loads(budget_file.read_text())
    else:
        accounting = {'reservedCalls': 0, 'batches': []}
    require(accounting['reservedCalls'] + allowance <= 12, 'producer-budget-exhausted')
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    accounting['reservedCalls'] += allowance
    accounting['batches'].append({'directory': str(args.output), 'reservedCalls': allowance, 'state': 'intent-before-spawn'})
    with budget_file.open('w') as f:
        json.dump(accounting, f, indent=2); f.flush(); os.fsync(f.fileno())
    canary = args.output / 'owned-outside-canary'; canary.write_text('owned inaccessible canary')
    digest = hashlib.sha256(canary.read_bytes()).hexdigest()
    control = args.output / 'control'; control.mkdir(mode=0o700)
    data = {'source': source, 'executableSHA256': prepared['executableSHA256'], 'hostNet': os.readlink('/proc/self/ns/net'), 'outsideCanary': str(canary), 'cases': cases}
    (control / 'prepared.json').write_text(json.dumps(data))
    intent = {'sourceSHA256': hashlib.sha256(args.prepared.read_bytes()).hexdigest(), 'generatorSHA256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'reservedProducerCalls': allowance, 'scope': 'owned fixtures only; no native qualification dispatch'}
    (args.output / 'intent.json').write_text(json.dumps(intent, indent=2) + '\n')
    outer = RunBudget(deadline=time.monotonic() + 600)
    try:
        raw = run_owned(sandbox_arguments(tool, control, Path(__file__).resolve()), args.output, {'PATH': '/usr/bin', 'PYTHONDONTWRITEBYTECODE': '1'}, outer)
        result = json.loads(raw)
        require(result['status'] == 'passed' and result['invocations'] <= allowance, 'producer-batch-failed')
        (args.output / 'result.json').write_bytes(raw)
        accounting['batches'][-1].update(state='completed', observedCalls=result['invocations'])
    finally:
        require(hashlib.sha256(canary.read_bytes()).hexdigest() == digest, 'host-canary-mutated')
        (args.output / 'outer-receipts.json').write_text(json.dumps(outer.receipts, indent=2) + '\n')
        budget_file.write_text(json.dumps(accounting, indent=2) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
