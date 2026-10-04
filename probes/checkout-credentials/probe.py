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
