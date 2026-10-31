"""Controlled fixtures only; no downloads or native probe execution."""
import ast
import base64
import copy
import hashlib
import http.server
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import zipfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('probe_ci', HERE / 'run.py')
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)


def h1(files):
    lines = ''.join(hashlib.sha256(data).hexdigest() + '  ' + name + '\n'
                    for name, data in sorted(files.items()))
    return 'h1:' + base64.b64encode(hashlib.sha256(lines.encode()).digest()).decode()


def receipt(status='PASS'):
    # Complete hand-specified protocol fixtures; these are NOT native observations.
    def sample(inode):
        return dict(device=1, inode=inode, ctimeSec=0, ctimeNsec=0, nlink=1, mode=0o100600, size=16)
    zero = dict(device=0, inode=0, ctimeSec=0, ctimeNsec=0, nlink=0, mode=0, size=0)
    env = dict(os='darwin', arch='arm64', go='go1.27.1', cgo='0', osVersion='15.7.1',
               osBuild='24G90', kernel='24.6.0', filesystem='apfs', mount='/owned', mountFlags=4096,
               caseSensitive=None, uid=501, api='clonefileat', flags=10, reason='controlled-cases-observed')
    cases = []
    reasons = ['owned-clone-data-equal-distinct', 'A-clone-after-trusted-B-overwrite',
               'no-follow-refused', 'known-link-selection-not-production-resolver',
               'B-clone-with-restored-A-path-samples']
    for i, name in enumerate(('regular', 'cow', 'direct-link', 'selected-link', 'swap')):
        obs = dict(errno=0, sourceBefore=sample(10), sourceAtCloneSample=sample(12 if i==4 else 10),
                   sourceAfter=sample(10), destination=sample(11), bytes=16,
                   sha256Bytes=list(hashlib.sha256(b'owned-literal-B\n' if i==4 else b'owned-literal-A\n').digest()))
        if i==2:
            obs = dict(errno=62, sourceBefore=zero.copy(), sourceAtCloneSample=zero.copy(),
                       sourceAfter=zero.copy(), destination=zero.copy(), bytes=0, sha256Bytes=[0]*32)
        cases.append(dict(id=name, status='PASS', reason=reasons[i], observation=obs,
                          actualDataEqual=i!=2, distinctDestination=i!=2,
                          cowIndependenceObserved=i==1, notOriginalBindingObserved=i==4,
                          atomicCOWClaim='' if i==2 else 'clonefileat-contract-only'))
    if status == 'FAIL':
        cases[0].update(status='FAIL', reason='clone-error', actualDataEqual=False,
                        distinctDestination=False, atomicCOWClaim='')
        cases[0]['observation'].update(errno=13)
    elif status in ('BLOCKED', 'FATAL'):
        for case in cases:
            case.pop('observation')
            case.update(status='NOT RUN', reason='preflight', actualDataEqual=False,
                        distinctDestination=False, cowIndependenceObserved=False,
                        notOriginalBindingObserved=False, atomicCOWClaim='')
        env.update(os='linux', arch='amd64', go='go1.27.3', osVersion='', osBuild='', kernel='',
                   filesystem='', mount='', mountFlags=0,
                   reason='invalid-arguments' if status=='FATAL' else 'unsupported-profile')
    return dict(schema='packtrace.macos-clone-probe.v1', scope='controlled-fixture-feasibility',
                qualification='not-qualified', sourceObjectBinding='not-established',
                status='FAIL' if status=='FATAL' else status, cases=cases, environment=env,
                cleanup={'clean': True, 'workerReaped': True, 'residue': []})


def portable_python_fixture(module):
    directory = module/'ci'; directory.mkdir()
    (directory/'test_ci.py').write_text('''import os,unittest
from pathlib import Path
class Offline(unittest.TestCase):
 def test_offline(self):
  self.assertEqual(os.environ['GOPROXY'], 'off')
  self.assertNotIn('GITHUB_TOKEN', os.environ)
  Path('python-tested').write_text('once')
  self.assertFalse(Path('fail-python').exists())
''')


class Recovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.compiled = Path(cls.tmp.name)
        env = ci.clean_env(cls.compiled)
        for name in ('home', 'tmp'): (cls.compiled/name).mkdir()
        for name in ('PATH', 'GOCACHE', 'GOMODCACHE'):
            if name in os.environ: env[name] = os.environ[name]
        go = shutil.which('go')
        if go is None: raise AssertionError('offline cached Go required for compiled contract checks')
        for args in (['build', '-o', str(cls.compiled/'probe'), '.'],
                     ['test', '-c', '-o', str(cls.compiled/'tests')]):
            result = subprocess.run([go]+args, cwd=HERE.parent, env=env, capture_output=True, timeout=180)
            if result.returncode: raise AssertionError(result.stderr.decode())

    def setUp(self):
        self.tmpcase = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpcase.cleanup)
        self.root = Path(self.tmpcase.name)

    def actual(self, binary, args, extra=None):
        env = ci.clean_env(self.root); env.update(extra or {})
        result = ci.Budget().command('compiled-control', [str(binary)]+args, HERE.parent, env, 5)
        self.assertEqual(result['phase'], 'exited')
        self.assertTrue(result['reaped'] and result['groupClean'])
        return result

    def test_real_fatal_exit_two_retained_by_outer_controller_once(self):
        import contextlib
        from unittest.mock import patch
        root = self.root
        helper = root/'source/probes/native-safety/ci/run.py'
        helper.parent.mkdir(parents=True); helper.write_bytes(b'controller-boundary-only')
        env = dict(OWNROOT=str(root), SOURCE_SHA='a'*40, SOURCE_TREE='b'*40,
                   SOURCE_HELPER_SHA256=hashlib.sha256(helper.read_bytes()).hexdigest(),
                   SETUP_DEADLINE=str(time.monotonic()+20), BOOTSTRAP_OUTPUT_BYTES='0', BOOTSTRAP_PHASES='[]')
        # Actual compiled Go invalid-argument protocol path, never the native adapter.
        binary = root/'maccloneprobe'
        binary.write_text(f'#!{sys.executable}\nimport os\nfrom pathlib import Path\n'
                          'Path("fatal-called").write_text("once")\n'
                          f'os.execv({str(self.compiled/"probe")!r}, ["probe", "--invalid"])\n')
        binary.chmod(0o700)
        out = io.StringIO()
        with patch.object(ci, 'preflight', return_value={}), patch.object(ci, 'prepare', return_value={}), \
             contextlib.redirect_stdout(out):
            code = ci.main(env, helper)
        record = json.loads(out.getvalue().split('=',1)[1])
        self.assertEqual((code, record['nativeExit'], record['status']), (2, 2, 'FAIL'))
        self.assertIsNotNone(record['probe'], 'legitimate exit-2 receipt was discarded')
        self.assertEqual(record['probe']['environment']['reason'], 'invalid-arguments')
        self.assertEqual(len([p for p in record['phases'] if p['name']=='native']), 1)
        self.assertEqual(len(list(root.rglob('fatal-called'))), 1)

    def test_real_go_guard_accepts_actual_ci_launch_layout(self):
        root = self.root; (root/'evidence').mkdir(mode=0o700)
        (root/'source/probes/native-safety').mkdir(parents=True)
        binary = root/'maccloneprobe'
        binary.write_text(f'#!{sys.executable}\nimport os,sys\n'
                          'os.environ["PROBE_CI_LAYOUT_WORKER"]="1"\n'
                          f'os.execv({str(self.compiled/"tests")!r}, ["tests", "-test.run=^TestCILayoutWorker$", "--"]+sys.argv[1:])\n')
        binary.chmod(0o700)
        budget = ci.Budget()
        try:
            result, obj = ci.native_once(root, ci.clean_env(root), budget)
        except ci.Rejected as error:
            self.fail('CI launch did not satisfy the compiled directory/receipt contract: '+str(error))
        self.assertEqual((result['exit'], obj['environment']['reason']), (2, 'invalid-arguments'))
        self.assertEqual(list((root/'evidence').iterdir()), [])

    def test_complete_compiled_go_receipt_and_label_only_forgery(self):
        good = self.actual(self.compiled/'tests', ['-test.run=^TestCIReceiptWorker$'],
                           {'PROBE_CI_RECEIPT_WORKER': '1'})
        obj = ci.validate_receipt(good['stdout'], good['exit'])
        self.assertEqual(obj['status'], 'PASS')
        fatal = self.actual(self.compiled/'probe', ['--invalid'])
        # Start with actual Go output, change only status labels as in the review repro.
        forged = json.loads(fatal['stdout']); forged['status'] = 'PASS'
        for case in forged['cases']: case['status'] = 'PASS'
        with self.assertRaises(ci.Rejected): ci.validate_receipt(json.dumps(forged).encode()+b'\n', 0)

    def test_receipt_schema_observations_and_aggregation_fail_closed(self):
        changes = [
            ('linux-pass', lambda r: r['environment'].update(os='linux')),
            ('missing-profile', lambda r: r['environment'].update(osBuild='')),
            ('filesystem', lambda r: r['environment'].update(filesystem='other')),
            ('missing-observation', lambda r: r['cases'][0].pop('observation')),
            ('bad-digest', lambda r: r['cases'][0]['observation'].update(sha256Bytes=[0]*32)),
            ('same-inode', lambda r: r['cases'][0]['observation']['destination'].update(inode=10)),
            ('bad-no-follow', lambda r: r['cases'][2]['observation'].update(errno=40)),
            ('cow-label', lambda r: r['cases'][1].update(cowIndependenceObserved=False)),
            ('swap-label', lambda r: r['cases'][4].update(notOriginalBindingObserved=False)),
            ('claim-enum', lambda r: r['cases'][0].update(atomicCOWClaim='atomic')),
            ('reason-enum', lambda r: r['cases'][0].update(reason='invented')),
            ('boolean-type', lambda r: r['cases'][0].update(actualDataEqual=1)),
            ('integer-type', lambda r: r['cases'][0]['observation'].update(bytes=True)),
            ('digest-range', lambda r: r['cases'][0]['observation'].update(sha256Bytes=[256]*32)),
            ('sample-fields', lambda r: r['cases'][0]['observation']['destination'].update(other=1)),
            ('negative-unsigned', lambda r: r['cases'][0]['observation']['destination'].update(inode=-1)),
            ('timestamp-range', lambda r: r['cases'][0]['observation']['destination'].update(ctimeNsec=10**9)),
            ('env-type', lambda r: r['environment'].update(uid='501')),
            ('api-flags', lambda r: r['environment'].update(flags=0)),
            ('cleanup-enum', lambda r: r['cleanup'].update(residue=['invented'])),
        ]
        for label, change in changes:
            with self.subTest(label=label):
                obj = receipt(); change(obj)
                with self.assertRaises(ci.Rejected): ci.validate_receipt(json.dumps(obj).encode()+b'\n', 0)
        obj = receipt('FAIL'); obj['status'] = 'BLOCKED'
        with self.assertRaises(ci.Rejected): ci.validate_receipt(json.dumps(obj).encode()+b'\n', 3)
        obj = receipt('FAIL'); obj['cleanup'].update(clean=False, residue=['unknown-root-residue'])
        with self.assertRaises(ci.Rejected): ci.validate_receipt(json.dumps(obj).encode()+b'\n', 1)
        self.assertEqual(ci.validate_receipt(json.dumps(obj).encode()+b'\n', 2)['status'], 'FAIL')
        obj = receipt('FATAL')
        self.assertEqual(ci.validate_receipt(json.dumps(obj).encode()+b'\n', 2)['status'], 'FAIL')
        with self.assertRaises(ci.Rejected): ci.validate_receipt(json.dumps(obj).encode()+b'\n', 1)

    def test_prepared_python_tests_execute_offline_and_fail_setup(self):
        module = self.root/'module'; module.mkdir(); portable_python_fixture(module)
        tool = self.root/'go'
        tool.write_text(f'#!{sys.executable}\nimport sys\na=sys.argv[1:]\n'
                        "if a==['version']: print('go version go1.27.1 darwin/arm64')\n"
                        "elif a[0]=='env': print('go1.27.1\\ndarwin\\narm64\\n0')\n"
                        "elif a==['mod','verify']: print('all modules verified')\n")
        tool.chmod(0o700)
        budget = ci.Budget()
        ci.compile_probe(tool, module, self.root, ci.clean_env(self.root), budget, time.monotonic()+5)
        self.assertTrue((module/'ci/python-tested').exists(), 'prepared CI skipped Python tests')
        self.assertEqual([p['exit'] for p in budget.phases if p['name']=='python-tests'], [0])
        (module/'ci/fail-python').write_text('x')
        with self.assertRaisesRegex(ci.Rejected, 'setup-command-python-tests'):
            ci.compile_probe(tool, module, self.root, ci.clean_env(self.root), ci.Budget(), time.monotonic()+5)


class Checks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
    def tearDown(self):
        self.tmp.cleanup()

    def test_receipt_actual_status_and_forgery(self):
        for status, code in [('PASS', 0), ('FAIL', 1), ('BLOCKED', 3)]:
            raw = json.dumps(receipt(status)).encode() + b'\n'
            self.assertEqual(ci.validate_receipt(raw, code)['status'], status)
            with self.assertRaises(ci.Rejected):
                ci.validate_receipt(raw, 2)
        for key, value in [('qualification', 'qualified'), ('sourceObjectBinding', 'established'),
                           ('schema', 'other'), ('cases', {}), ('environment', []), ('cleanup', []),
                           ('status', 'NOT RUN')]:
            forged = receipt(); forged[key] = value
            with self.assertRaises(ci.Rejected):
                ci.validate_receipt(json.dumps(forged).encode()+b'\n', 0)
        for raw in [b'{}{}', json.dumps(receipt()).encode() + b'\n{}',
                    json.dumps(receipt()).encode().replace(b'"status": "PASS"', b'"status": "PASS", "status": "PASS"', 1)+b'\n',
                    json.dumps(receipt()).encode().replace(b'"uid": 501', b'"uid": NaN')+b'\n',
                    b'x' * 65537]:
            with self.assertRaises(ci.Rejected):
                ci.validate_receipt(raw, 0)

    def test_pass_requires_confirmed_module_cleanup_and_lf(self):
        for cleanup in [{}, {'clean': False, 'workerReaped': True},
                        {'clean': True, 'workerReaped': False}, {'clean': 1, 'workerReaped': True}]:
            obj = receipt(); obj['cleanup'] = cleanup
            with self.assertRaises(ci.Rejected):
                ci.validate_receipt(json.dumps(obj).encode()+b'\n', 0)
        with self.assertRaises(ci.Rejected):
            ci.validate_receipt(json.dumps(receipt()).encode(), 0)

    def test_pass_cannot_hide_missing_or_failed_required_cases(self):
        for cases in [[], [{'id': 'other', 'status': 'PASS'}],
                      [{**case, 'status': 'BLOCKED'} for case in receipt()['cases']]]:
            obj = receipt(); obj['cases'] = cases
            with self.assertRaises(ci.Rejected): ci.validate_receipt(json.dumps(obj).encode()+b'\n', 0)
        obj = receipt(); obj['cleanup']['residue'] = ['unknown']
        with self.assertRaises(ci.Rejected): ci.validate_receipt(json.dumps(obj).encode()+b'\n', 0)

    def test_emit_preserves_failure_and_caps_oversize_receipt(self):
        import contextlib
        record = {'status': 'PASS', 'actualExit': 0, 'nativeExit': 0, 'probe': {'x': 'a'*65536}}
        output = io.StringIO()
        with contextlib.redirect_stdout(output): code = ci.emit(record)
        obj = json.loads(output.getvalue().split('=', 1)[1])
        self.assertEqual((code, obj['status'], obj['nativeExit']), (2, 'FAIL', 0))
        self.assertIsNone(obj['probe'])
        self.assertLessEqual(len(output.getvalue().encode()), ci.RECEIPT_CAP)

    def test_clean_environment_drops_credentials(self):
        os.environ['GITHUB_TOKEN'] = 'never-forward'
        os.environ['HTTPS_PROXY'] = 'never-forward'
        try:
            env = ci.clean_env(self.root)
            self.assertNotIn('GITHUB_TOKEN', env)
            self.assertNotIn('HTTPS_PROXY', env)
            for key, val in {'GOTOOLCHAIN': 'local', 'GOPROXY': 'off', 'GOSUMDB': 'off',
                             'GOWORK': 'off', 'CGO_ENABLED': '0', 'GOENV': 'off'}.items():
                self.assertEqual(env.get(key), val)
        finally:
            del os.environ['GITHUB_TOKEN']; del os.environ['HTTPS_PROXY']

    def test_process_real_exit_stderr_and_aggregate_budget(self):
        budget = ci.Budget(4096)
        result = budget.command('fixture', [sys.executable, '-c',
            'import sys; print("yes"); sys.stderr.write("no"); sys.exit(3)'],
            self.root, ci.clean_env(self.root), 2)
        self.assertEqual((result['exit'], result['stdout'], result['stderr']), (3, b'yes\n', b'no'))
        self.assertEqual(result['phase'], 'exited')
        for code, kwargs in [('import sys; sys.stderr.write("x"*2048)', {'stderr_cap': 128}),
                             ('print("x"*8192)', {})]:
            result = budget.command('fixture', [sys.executable, '-c', code],
                                     self.root, ci.clean_env(self.root), 2, **kwargs)
            self.assertEqual(result['phase'], 'output-limit')
            self.assertTrue(result['reaped'])
        self.assertLessEqual(budget.used, 4096)

    def test_timeout_kills_and_reaps_group_including_inherited_pipes(self):
        pidfile = self.root / 'pid'
        code = ('import os,signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); '
                'p=os.fork(); '
                f'open({str(pidfile)!r},"w").write(str(os.getpid())) if p==0 else None; '
                'time.sleep(30)')
        start = time.monotonic()
        result = ci.Budget(4096).command('fixture', [sys.executable, '-c', code],
                                       self.root, ci.clean_env(self.root), .2)
        self.assertEqual(result['phase'], 'timeout')
        self.assertTrue(result['reaped'])
        self.assertLess(time.monotonic() - start, 3)
        # A killed orphan can briefly be a zombie under Linux container PID 1.
        if pidfile.exists():
            pid = int(pidfile.read_text())
            try:
                stat = Path(f'/proc/{pid}/stat').read_text()
                self.assertEqual(stat.split()[2], 'Z')
            except FileNotFoundError:
                pass

    def test_disk_budget_and_lingering_descendant_are_not_success(self):
        result = ci.Budget(4096).command('fixture', [sys.executable, '-c',
                 'import time; time.sleep(5)'], self.root, ci.clean_env(self.root), 2,
                 storage=lambda: False)
        self.assertEqual(result['phase'], 'storage-limit')
        self.assertTrue(result['reaped'])
        result = ci.Budget(4096).command('fixture', [sys.executable, '-c',
                 'import os,time; p=os.fork(); time.sleep(5) if p==0 else None'],
                 self.root, ci.clean_env(self.root), .2)
        self.assertEqual(result['phase'], 'timeout')

    def test_download_real_http_eof_hash_and_limit(self):
        data = b'controlled archive bytes'
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200); self.end_headers()
                self.wfile.write(data if self.path != '/short' else data[:-1])
            def log_message(self, *_): pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        import urllib.request
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        # Boundary transport maps approved HTTPS to an inert local HTTP fixture.
        def transport(url, timeout):
            tail = '/short' if 'short' in url else '/ok'
            return opener.open(f'http://127.0.0.1:{server.server_port}{tail}', timeout=timeout)
        pin = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        try:
            p = self.root / 'ok'
            ci.download('https://dl.google.com/go/fixture', p, pin, time.monotonic()+3, transport)
            self.assertTrue(p.is_file(), 'download must produce the checked bytes')
            self.assertEqual(p.read_bytes(), data)
            for name, changed in [('short', pin), ('wrong', {**pin, 'sha256': '0'*64}),
                                  ('long', {**pin, 'bytes': len(data)-1})]:
                with self.assertRaises(ci.Rejected):
                    ci.download('https://dl.google.com/go/'+name, self.root/name, changed,
                                time.monotonic()+3, transport)
        finally:
            server.shutdown(); server.server_close(); thread.join()

    def test_download_full_eof_and_malformed_transfer_are_rejected(self):
        import http.client
        pin = {'bytes': 1, 'sha256': hashlib.sha256(b'x').hexdigest()}
        class Chunked(io.BytesIO):
            status = 200; headers = {}
            def read(self, n=-1): return super().read(min(n, 1))
        with self.assertRaises(ci.Rejected):
            ci.download(ci.GO_URL, self.root/'trailing', pin, time.monotonic()+2,
                        lambda *a: Chunked(b'xy'))
        def broken(*args): raise http.client.IncompleteRead(b'x', 2)
        try:
            ci.download(ci.GO_URL, self.root/'broken', pin, time.monotonic()+2, broken)
        except ci.Rejected:
            rejected = True
        except http.client.HTTPException:
            rejected = False
        else:
            rejected = False
        self.assertTrue(rejected, 'malformed transfer needs a controlled rejection receipt')
        class Length(io.BytesIO):
            status = 200; headers = {'Content-Length': '2'}
        with self.assertRaises(ci.Rejected):
            ci.download(ci.GO_URL, self.root/'length', pin, time.monotonic()+2,
                        lambda *a: Length(b'x'))
        class Encoded(io.BytesIO):
            status = 200; headers = {'Content-Encoding': 'gzip'}
        with self.assertRaises(ci.Rejected):
            ci.download(ci.GO_URL, self.root/'encoding', pin, time.monotonic()+2,
                        lambda *a: Encoded(b'x'))

    def test_redirect_validation_and_timeout(self):
        import urllib.error
        payload = b'x'
        pin = {'bytes': 1, 'sha256': hashlib.sha256(payload).hexdigest()}
        origin = 'https://proxy.golang.org/golang.org/x/sys/@v/v0.44.0.zip'
        calls = []
        class Response(io.BytesIO):
            status = 200
            headers = {}
        def transport(url, timeout):
            calls.append(url)
            if len(calls) == 1:
                raise urllib.error.HTTPError(url, 302, '', {'Location':
                    'https://storage.googleapis.com/proxy-golang-org-prod/fixture?opaque=yes'}, None)
            return Response(payload)
        ci.download(origin, self.root/'redirect', pin, time.monotonic()+2, transport)
        self.assertEqual(len(calls), 2)
        for destination in ['http://storage.googleapis.com/proxy-golang-org-prod/x',
                            'https://user:secret@storage.googleapis.com/proxy-golang-org-prod/x',
                            'https://evil.invalid/x', 'https://storage.googleapis.com/other/x',
                            'https://storage.googleapis.com/proxy-golang-org-prod/../other']:
            def bad(url, timeout):
                raise urllib.error.HTTPError(url, 302, '', {'Location': destination}, None)
            with self.assertRaises(ci.Rejected):
                ci.download(origin, self.root/'bad', pin, time.monotonic()+2, bad)
        def loop(url, timeout):
            raise urllib.error.HTTPError(url, 302, '', {'Location': origin}, None)
        with self.assertRaises(ci.Rejected):
            ci.download(origin, self.root/'loop', pin, time.monotonic()+2, loop)
        with self.assertRaises(ci.Rejected):
            ci.download(origin, self.root/'late', pin, time.monotonic()-1, transport)

    def tar(self, members):
        p = self.root/'archive.tgz'
        with tarfile.open(p, 'w:gz') as out:
            for name, kind, mode, data in members:
                info = tarfile.TarInfo(name); info.mode = mode; info.type = kind
                if kind == tarfile.REGTYPE:
                    info.size = len(data); out.addfile(info, io.BytesIO(data))
                else:
                    info.linkname = '../../escape'; out.addfile(info)
        return p

    def test_tar_extraction_paths_modes_full_eof_and_expansion(self):
        p = self.tar([('go/bin/go', tarfile.REGTYPE, 0o755, b'fixture')])
        ci.extract_go(p, self.root/'good', max_bytes=128, max_entries=3)
        self.assertTrue((self.root/'good/go/bin/go').is_file(), 'extractor must produce checked file')
        self.assertEqual((self.root/'good/go/bin/go').read_bytes(), b'fixture')
        self.assertEqual((self.root/'good/go/bin/go').stat().st_mode & 0o777, 0o755)
        for members in [[('../escape', tarfile.REGTYPE, 0o644, b'x')],
                        [('go/x', tarfile.SYMTYPE, 0o777, b'')],
                        [('go/x', tarfile.LNKTYPE, 0o644, b'')],
                        [('go/x', tarfile.FIFOTYPE, 0o644, b'')],
                        [('go/x', tarfile.REGTYPE, 0o4755, b'x')],
                        [('go/x', tarfile.REGTYPE, 0o644, b'x')]*2,
                        [('go/x', tarfile.REGTYPE, 0o644, b'x'*129)]]:
            with self.assertRaises(ci.Rejected):
                ci.extract_go(self.tar(members), self.root/('bad'+str(time.monotonic_ns())),
                              max_bytes=128, max_entries=3)
        p = self.tar([('go/x', tarfile.REGTYPE, 0o644, b'x')])
        p.write_bytes(p.read_bytes()[:-6])
        with self.assertRaises(ci.Rejected):
            ci.extract_go(p, self.root/'truncated', max_bytes=128, max_entries=3)

    def test_archive_entry_count_zip_mode_crc_and_expansion(self):
        p = self.tar([('go/x', tarfile.REGTYPE, 0o644, b'x')])
        with self.assertRaises(ci.Rejected):
            ci.extract_go(p, self.root/'entries', max_entries=0)
        p = self.root/'module.zip'
        for mode in (stat.S_IFLNK | 0o777, stat.S_IFIFO | 0o644, stat.S_IFREG | 0o4755):
            with zipfile.ZipFile(p, 'w') as z:
                info = zipfile.ZipInfo(ci.PREFIX+'x'); info.create_system = 3
                info.external_attr = mode << 16; z.writestr(info, b'controlled data')
            with self.assertRaises(ci.Rejected):
                ci.extract_module(p, self.root/str(mode), h1({ci.PREFIX+'x': b'controlled data'}))
        with zipfile.ZipFile(p, 'w') as z: z.writestr(ci.PREFIX+'x', b'controlled data')
        p.write_bytes(p.read_bytes().replace(b'controlled data', b'corrupted bytes'))
        with self.assertRaises(ci.Rejected): ci.extract_module(p, self.root/'crc', 'h1:bad')
        with zipfile.ZipFile(p, 'w') as z: z.writestr(ci.PREFIX+'x', b'x'*129)
        from unittest.mock import patch
        with patch.object(ci, 'MODULE_EXPANDED_CAP', 128):
            with self.assertRaises(ci.Rejected): ci.extract_module(p, self.root/'expanded', h1({ci.PREFIX+'x': b'x'*129}))

    def test_module_h1_zip_paths_and_cache_seed(self):
        prefix = 'golang.org/x/sys@v0.44.0/'
        files = {prefix+'go.mod': b'module golang.org/x/sys\n\ngo 1.25.0\n', prefix+'unix/x.go': b'package unix\n'}
        def archive(mapping, name='module.zip'):
            path = self.root/name
            with zipfile.ZipFile(path, 'w') as z:
                for key, value in mapping.items(): z.writestr(key, value)
            return path
        p = archive(files)
        expected = h1(files)
        self.assertEqual(ci.extract_module(p, self.root/'cache', expected), expected)
        self.assertEqual((self.root/'cache'/prefix/'unix/x.go').read_bytes(), b'package unix\n')
        for mapping, digest in [({prefix+'../bad': b'x'}, h1({prefix+'../bad': b'x'})), (files, 'h1:forged'),
                                ({prefix+'x': b'x', prefix+'X': b'y'}, h1({prefix+'x': b'x', prefix+'X': b'y'})),
                                ({'other/x': b'x'}, h1({'other/x': b'x'}))]:
            with self.assertRaises(ci.Rejected):
                ci.extract_module(archive(mapping), self.root/str(time.monotonic_ns()), digest)
        self.assertEqual(ci.module_sum(b'module x\n'), h1({'go.mod': b'module x\n'}))

    def test_module_contract_and_seed_reject_wrong_mod_sum(self):
        module = self.root/'module'; module.mkdir()
        (module/'go.mod').write_text('module packtrace-native-safety-probe\n\ngo 1.27.1\n\nrequire golang.org/x/sys v0.44.0\n')
        sums = f'golang.org/x/sys v0.44.0 {ci.MODULE_H1}\ngolang.org/x/sys v0.44.0/go.mod {ci.MOD_H1}\n'
        (module/'go.sum').write_text(sums)
        self.assertTrue(ci.check_module(module))
        for name, value in [('go.mod', 'module other\ngo 1.27.1\n'),
                            ('go.sum', sums+'other v1.0.0 h1:bad\n')]:
            old = (module/name).read_text(); (module/name).write_text(value)
            with self.assertRaises(ci.Rejected): ci.check_module(module)
            (module/name).write_text(old)
        downloads = self.root/'downloads'; downloads.mkdir()
        (downloads/'sys.mod').write_bytes(b'wrong')
        with self.assertRaises(ci.Rejected): ci.seed_module(downloads, self.root/'cache')

    def test_prepare_build_vet_and_native_exactly_once_with_controlled_executable(self):
        # This is controller-only behavioral coverage, NOT Darwin API coverage.
        for status, code in [('PASS', 0), ('FAIL', 1), ('BLOCKED', 3)]:
            root = self.root/status; root.mkdir(); (root/'source').mkdir()
            evidence = root/'evidence'; evidence.mkdir(mode=0o700)
            binary = root/'maccloneprobe'
            marker = root/'calls'
            script = (f'#!{sys.executable}\nimport sys\nfrom pathlib import Path\n'
                      f'p=Path({str(marker)!r}); p.write_text(p.read_text()+"x" if p.exists() else "x")\n'
                      f'print({json.dumps(receipt(status))!r})\nsys.exit({code})\n')
            binary.write_text(script); binary.chmod(0o700)
            budget = ci.Budget()
            result, obj = ci.native_once(root, ci.clean_env(root), budget)
            self.assertEqual((result['exit'], obj['status']), (code, status))
            self.assertEqual(marker.read_text(), 'x')
            self.assertEqual([p['name'] for p in budget.phases], ['native'])

    def test_compile_offline_controlled_tool_behavior_and_failure(self):
        module = self.root/'module'; module.mkdir(); portable_python_fixture(module)
        tool = self.root/'go'
        events = self.root/'events'
        tool.write_text(f'#!{sys.executable}\n' + '''import json,os,sys
from pathlib import Path
p=Path('''+repr(str(events))+''')
a=sys.argv[1:]
with p.open('a') as f: f.write(json.dumps(a)+'\\n')
assert os.environ['GOPROXY']=='off' and os.environ['GOSUMDB']=='off'
assert 'GITHUB_TOKEN' not in os.environ
if a==['version']: print('go version go1.27.1 darwin/arm64')
elif a==['env','GOVERSION','GOOS','GOARCH','CGO_ENABLED']: print('go1.27.1\\ndarwin\\narm64\\n0')
elif a==['mod','verify']: print('all modules verified')
elif a==['build','-o','''+repr(str(self.root/'maccloneprobe'))+''','.' ]:
 Path(a[2]).write_bytes(b'controlled binary, not native')
elif a==['vet','.']: sys.exit(1 if Path('fail-vet').exists() else 0)
elif a==['test','-count=1','-timeout=60s','./...']: sys.exit(1 if Path('fail-test').exists() else 0)
else: sys.exit(9)
''')
        tool.chmod(0o700)
        self.assertTrue(ci.compile_probe(tool, module, self.root, ci.clean_env(self.root),
                                       ci.Budget(), time.monotonic()+5))
        calls = [json.loads(x) for x in events.read_text().splitlines()]
        self.assertIn(['test', '-count=1', '-timeout=60s', './...'], calls)
        self.assertEqual(calls[-2:], [['build', '-o', str(self.root/'maccloneprobe'), '.'], ['vet', '.']])
        (module/'fail-test').write_text('x')
        with self.assertRaisesRegex(ci.Rejected, 'setup-command-portable-tests'):
            ci.compile_probe(tool, module, self.root, ci.clean_env(self.root), ci.Budget(), time.monotonic()+5)
        (module/'fail-test').unlink()
        (module/'fail-vet').write_text('x')
        with self.assertRaises(ci.Rejected):
            ci.compile_probe(tool, module, self.root, ci.clean_env(self.root),
                             ci.Budget(), time.monotonic()+5)
        with self.assertRaises(ci.Rejected):
            ci.compile_probe(tool, module, self.root, ci.clean_env(self.root),
                             ci.Budget(), time.monotonic()-1)

    def test_setup_clock_and_preflight_do_not_create_native_fixtures(self):
        from unittest.mock import patch
        with patch.object(ci.platform, 'system', return_value='Linux'), self.assertRaises(ci.Rejected):
            ci.preflight(self.root, ci.Budget(), ci.clean_env(self.root))
        self.assertFalse((self.root/'evidence').exists())
        with self.assertRaises(ci.Rejected):
            with ci.setup_timer(time.monotonic()+.03): time.sleep(1)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL)[0], 0)

    def test_source_context_and_actual_linux_entrypoint_block_without_download(self):
        root = self.root/'owned'; root.mkdir(mode=0o700)
        helper = root/'source/probes/native-safety/ci/run.py'
        helper.parent.mkdir(parents=True); helper.write_bytes(b'controlled checked source')
        env = {'OWNROOT': str(root), 'SOURCE_SHA': 'a'*40, 'SOURCE_TREE': 'b'*40,
               'SOURCE_HELPER_SHA256': hashlib.sha256(helper.read_bytes()).hexdigest(),
               'SETUP_DEADLINE': str(time.monotonic()+10), 'BOOTSTRAP_OUTPUT_BYTES': '0',
               'BOOTSTRAP_PHASES': '[]'}
        self.assertEqual(ci.validate_context(env, helper)['sha'], 'a'*40)
        for key, value in [('SOURCE_SHA', 'bad'), ('SOURCE_TREE', 'bad'),
                           ('SOURCE_HELPER_SHA256', '0'*64), ('SETUP_DEADLINE', 'nan'),
                           ('BOOTSTRAP_OUTPUT_BYTES', '999999999')]:
            with self.assertRaises(ci.Rejected): ci.validate_context({**env, key: value}, helper)
        import contextlib
        output = io.StringIO()
        from unittest.mock import patch
        with patch.object(ci.platform, 'system', return_value='Linux'), contextlib.redirect_stdout(output):
            code = ci.main(env, helper)
        self.assertEqual(code, 3)
        line = output.getvalue()
        self.assertTrue(line.startswith('NATIVE_PROBE_RECEIPT='))
        obj = json.loads(line.split('=', 1)[1])
        self.assertEqual((obj['status'], obj['phase']), ('BLOCKED', 'preflight'))
        self.assertIsNone(obj['nativeExit'])
        self.assertFalse((root/'downloads').exists())
        self.assertFalse((root/'evidence').exists())
        self.assertLessEqual(len(line.encode()), ci.RECEIPT_CAP)

    def test_main_controller_receipts_with_real_process_protocol_fixtures(self):
        # These subprocesses test CI protocol/controller behavior, NOT native clone APIs.
        import contextlib
        from unittest.mock import patch
        for label, status, exitcode, residue, expected in [
            ('pass', 'PASS', 0, False, 0), ('fail', 'FAIL', 1, False, 1),
            ('blocked', 'BLOCKED', 3, False, 3), ('residue', 'PASS', 0, True, 2),
            ('invalid', 'invalid JSON', 2, False, 2)]:
            root = self.root/label; root.mkdir(mode=0o700)
            helper = root/'source/probes/native-safety/ci/run.py'
            helper.parent.mkdir(parents=True); helper.write_bytes(b'checked fixture')
            env = {'OWNROOT': str(root), 'SOURCE_SHA': 'a'*40, 'SOURCE_TREE': 'b'*40,
                   'SOURCE_HELPER_SHA256': hashlib.sha256(helper.read_bytes()).hexdigest(),
                   'SETUP_DEADLINE': str(time.monotonic()+10), 'BOOTSTRAP_OUTPUT_BYTES': '0', 'BOOTSTRAP_PHASES': '[]'}
            marker = root/'called'
            binary = root/'maccloneprobe'
            raw = json.dumps(receipt(status)) if status != 'invalid JSON' else status
            binary.write_text(f'#!{sys.executable}\nfrom pathlib import Path\nimport sys\n'
                              f'Path({str(marker)!r}).write_text("once")\n'
                              +(f'Path(sys.argv[2],"residue").write_text("x")\n' if residue else '')
                              +f'print({raw!r})\nsys.exit({exitcode})\n')
            binary.chmod(0o700)
            out = io.StringIO()
            with patch.object(ci, 'preflight', return_value={'testBoundary': 'controller-only'}), \
                 patch.object(ci, 'prepare', return_value={'testBoundary': 'controller-only'}), \
                 contextlib.redirect_stdout(out):
                code = ci.main(env, helper)
            record = json.loads(out.getvalue().split('=', 1)[1])
            self.assertEqual(code, expected)
            self.assertEqual(record['nativeExit'], exitcode)
            self.assertEqual(record['qualification'], 'not-qualified')
            self.assertEqual(marker.read_text(), 'once')
            self.assertEqual(len([p for p in record['phases'] if p['name']=='native']), 1)
            if residue:
                self.assertEqual(record['probe']['status'], 'PASS')
                self.assertEqual(record['status'], 'FAIL')
            elif status != 'invalid JSON':
                self.assertEqual(record['status'], status)
            else:
                self.assertEqual(record['status'], 'FAIL')
        for reason, expected in [('setup-command-vet', 1), ('acquisition-identity', 3)]:
            out = io.StringIO()
            with patch.object(ci, 'preflight', return_value={}), \
                 patch.object(ci, 'prepare', side_effect=ci.Rejected(reason)), contextlib.redirect_stdout(out):
                code = ci.main(env, helper)
            record = json.loads(out.getvalue().split('=', 1)[1])
            self.assertEqual(code, expected)
            self.assertIsNone(record['nativeExit'])
            self.assertEqual(record['phase'], 'setup')

    def test_seed_positive_checks_zip_mod_info_and_exact_single_cache(self):
        from unittest.mock import patch
        downloads = self.root/'downloads'; downloads.mkdir()
        mod = b'module golang.org/x/sys\\n'
        files = {ci.PREFIX+'go.mod': mod, ci.PREFIX+'unix/x.go': b'package unix\\n'}
        with zipfile.ZipFile(downloads/'sys.zip', 'w') as z:
            for name, data in files.items(): z.writestr(name, data)
        (downloads/'sys.mod').write_bytes(mod)
        (downloads/'sys.info').write_text('{"Version":"v0.44.0"}')
        with patch.object(ci, 'MODULE_H1', h1(files)), patch.object(ci, 'MOD_H1', h1({'go.mod': mod})):
            obj = ci.seed_module(downloads, self.root/'cache')
        self.assertEqual(obj['h1'], h1(files))
        cached = self.root/'cache/cache/download/golang.org/x/sys/@v'
        self.assertEqual({x.name for x in cached.iterdir()},
                         {'v0.44.0.zip', 'v0.44.0.mod', 'v0.44.0.info', 'v0.44.0.ziphash'})
        self.assertEqual((cached/'v0.44.0.ziphash').read_text(), h1(files))

    def test_prepare_actual_acquire_extract_seed_compile_pipeline(self):
        from unittest.mock import patch
        root = self.root/'pipeline'; root.mkdir(mode=0o700)
        module = root/'source/probes/native-safety'; module.mkdir(parents=True); portable_python_fixture(module)
        for name in ('home', 'tmp'): (root/name).mkdir()
        mod = b'module golang.org/x/sys\\n'
        files = {ci.PREFIX+'go.mod': mod, ci.PREFIX+'unix/x.go': b'package unix\\n'}
        (module/'go.mod').write_text('module packtrace-native-safety-probe\n\ngo 1.27.1\n\nrequire golang.org/x/sys v0.44.0\n')
        (module/'go.sum').write_text(f'golang.org/x/sys v0.44.0 {h1(files)}\ngolang.org/x/sys v0.44.0/go.mod {h1({"go.mod": mod})}\n')
        fake_go = (f'#!{sys.executable}\nimport sys\nfrom pathlib import Path\na=sys.argv[1:]\n'
                   "if a==['version']: print('go version go1.27.1 darwin/arm64')\n"
                   "elif a[0]=='env': print('go1.27.1\\ndarwin\\narm64\\n0')\n"
                   "elif a==['mod','verify']: print('all modules verified')\n"
                   "elif a[0]=='build': Path(a[2]).write_bytes(b'controller-only fixture binary')\n"
                   "elif a not in (['vet','.'], ['test','-count=1','-timeout=60s','./...']): sys.exit(8)\n").encode()
        go_tar = self.tar([('go/bin/go', tarfile.REGTYPE, 0o755, fake_go)]).read_bytes()
        zipout = io.BytesIO()
        with zipfile.ZipFile(zipout, 'w') as z:
            for name, data in files.items(): z.writestr(name, data)
        data = {'zip': zipout.getvalue(), 'mod': mod, 'info': b'{"Version":"v0.44.0"}'}
        pin = lambda value: {'bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest()}
        requested = []
        class Response(io.BytesIO):
            status = 200; headers = {}
        def transport(url, timeout):
            requested.append(url)
            return Response(go_tar if url == ci.GO_URL else data[url.rsplit('.', 1)[1]])
        with patch.object(ci, 'GO_PIN', pin(go_tar)), patch.object(ci, 'MODULE_PINS', {k: pin(v) for k,v in data.items()}), \
             patch.object(ci, 'MODULE_H1', h1(files)), patch.object(ci, 'MOD_H1', h1({'go.mod': mod})):
            result = ci.prepare(root, module, ci.clean_env(root), ci.Budget(), time.monotonic()+5, transport)
        self.assertEqual(result.get('binarySHA256'), hashlib.sha256(b'controller-only fixture binary').hexdigest())
        self.assertEqual(len(requested), 4)
        self.assertFalse((root/'evidence').exists())
        self.assertEqual(set(result.get('module', {})), {'h1', 'goModSum'})

    def test_final_receipt_requires_actual_cleanup_exit_and_limits(self):
        evidence = self.root/'evidence'; evidence.mkdir(mode=0o700)
        result = {'phase': 'exited', 'exit': 0, 'reaped': True,
                  'stdout': json.dumps(receipt()).encode()+b'\n', 'stderr': b'', 'groupClean': True}
        obj = ci.finish_native(result, evidence)
        self.assertEqual(obj['status'], 'PASS')
        (evidence/'unknown').write_text('x')
        with self.assertRaises(ci.Rejected): ci.finish_native(result, evidence)
        (evidence/'unknown').unlink()
        for key, value in [('phase', 'timeout'), ('reaped', False), ('groupClean', False), ('exit', 3)]:
            with self.assertRaises(ci.Rejected): ci.finish_native({**result, key: value}, evidence)
        for status, code in [('FAIL', 1), ('BLOCKED', 3)]:
            obj = ci.finish_native({**result, 'stdout': json.dumps(receipt(status)).encode()+b'\n', 'exit': code}, evidence)
            self.assertEqual(obj['status'], status)


class PreparationDiagnostics(unittest.TestCase):
    """Real main/prepare/compile/watchdog; acquisition and host are inert boundaries.

    Catches discarded failures, unbounded excerpts, unsafe decoding, broadened
    stream retention, changed exits, and retries/native entry after setup failure.
    """
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.outputs = []

    def outer(self, label='python-tests', stdout=b'', stderr=b'', bootstrap=False, cap=32*1024*1024):
        import contextlib
        from unittest.mock import patch
        root = self.root/str(len(self.outputs)); root.mkdir(mode=0o700)
        helper = root/'source/probes/native-safety/ci/run.py'
        helper.parent.mkdir(parents=True); helper.write_bytes(Path(ci.__file__).read_bytes())
        module = helper.parent.parent
        (module/'go.mod').write_text('module packtrace-native-safety-probe\n\ngo 1.27.1\n\nrequire golang.org/x/sys v0.44.0\n')
        (module/'go.sum').write_text(f'golang.org/x/sys v0.44.0 {ci.MODULE_H1}\ngolang.org/x/sys v0.44.0/go.mod {ci.MOD_H1}\n')
        # This real failing unittest emits its own traceback to actual stderr.
        (helper.parent/'test_ci.py').write_text('''import os,sys,unittest
from pathlib import Path
class Controlled(unittest.TestCase):
 def test_diagnostic(self):
  for key in ('GITHUB_TOKEN','HTTPS_PROXY','AWS_SECRET_ACCESS_KEY'):
   self.assertNotIn(key, os.environ)
  p=Path('python-calls'); p.write_text(p.read_text()+'x' if p.exists() else 'x')
  sys.stdout.buffer.write(Path('stdout').read_bytes()); sys.stdout.buffer.flush()
  sys.stderr.buffer.write(Path('stderr').read_bytes()); sys.stderr.buffer.flush()
  self.assertFalse(Path('fail').exists(), 'controlled-preparation-failure')
''')
        for stream, data in [('stdout', stdout), ('stderr', stderr)]:
            (module/stream).write_bytes(data); (helper.parent/stream).write_bytes(data)
        if label == 'python-tests': (helper.parent/'fail').touch()
        tool = root/'toolchain/go/bin/go'; tool.parent.mkdir(parents=True)
        tool.write_text(f'#!{sys.executable}\n'+'''import os,sys
from pathlib import Path
for key in ('GITHUB_TOKEN','HTTPS_PROXY','AWS_SECRET_ACCESS_KEY'):
 assert key not in os.environ
assert os.environ['GOPROXY']=='off' and os.environ['GOSUMDB']=='off'
a=sys.argv[1:]
label=('go-version' if a==['version'] else 'go-profile' if a[0]=='env' else
       'module-verify' if a[0]=='mod' else 'portable-tests' if a[0]=='test' else a[0])
with Path('calls').open('a') as f: f.write(label+'\\n')
if label=='''+repr(label)+''':
 sys.stdout.buffer.write(Path('stdout').read_bytes())
 sys.stderr.buffer.write(Path('stderr').read_bytes())
 sys.exit(7)
if label=='go-version': print('go version go1.27.1 darwin/arm64')
elif label=='go-profile': print('go1.27.1\\ndarwin\\narm64\\n0')
elif label=='module-verify': print('all modules verified')
# Deliberately no binary: successful tests still cannot enter native execution.
''')
        tool.chmod(0o700)
        env = dict(OWNROOT=str(root), SOURCE_SHA='a'*40, SOURCE_TREE='b'*40,
                   SOURCE_HELPER_SHA256=hashlib.sha256(helper.read_bytes()).hexdigest(),
                   SETUP_DEADLINE=str(time.monotonic()+20), BOOTSTRAP_OUTPUT_BYTES='0',
                   BOOTSTRAP_PHASES=json.dumps([{'fixture': 'b'*8100}]) if bootstrap else '[]')
        out = io.StringIO()
        def forbidden(*args, **kwargs):
            raise AssertionError('native entry forbidden in preparation diagnostic tests')
        # No transport, archive acquisition or native code is executed. Keep the
        # actual prepare failure propagation and final main/emit path intact.
        with patch.object(ci, 'CAP', cap), \
             patch.object(ci, 'preflight', return_value={'fixture': 'not-a-native-host'}), \
             patch.object(ci, 'download', return_value={'fixture': 'no-acquisition'}), \
             patch.object(ci, 'extract_go', return_value={}), \
             patch.object(ci, 'seed_module', return_value={}), \
             patch.object(ci, 'native_once', side_effect=forbidden), \
             patch.dict(os.environ, {'GITHUB_TOKEN': 'ambient-token-never-retain',
                        'HTTPS_PROXY': 'https://signed.invalid/?credential=never-retain',
                        'AWS_SECRET_ACCESS_KEY': 'ambient-key-never-retain'}), \
             contextlib.redirect_stdout(out):
            code = ci.main(env, helper)
        text = out.getvalue(); self.outputs.append(text)
        self.assertTrue(text.startswith('NATIVE_PROBE_RECEIPT='))
        self.assertEqual(text.count('\n'), 1)
        record = json.loads(text.split('=', 1)[1])
        self.assertEqual(code, record['actualExit'])
        self.assertEqual(record['phase'], 'setup')
        self.assertIsNone(record['nativeExit']); self.assertIsNone(record['probe'])
        self.assertEqual(record['qualification'], 'not-qualified')
        self.assertEqual(record['sourceObjectBinding'], 'not-established')
        self.assertEqual(record['source']['helperSHA256'], env['SOURCE_HELPER_SHA256'])
        self.assertFalse((root/'evidence').exists())
        names = [p['name'] for p in record['phases']]
        calls = (module/'calls').read_text().splitlines()
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(names[:len(calls)], calls)
        self.assertNotIn('native', names)
        self.assertEqual(record['capturedOutputBytes'], sum(p['stdoutBytes']+p['stderrBytes'] for p in record['phases']))
        self.assertLessEqual(record['capturedOutputBytes']+len(text.encode()), 32*1024*1024)
        self.assertLessEqual(len(text.encode()), 64*1024)
        for secret in ('ambient-token-never-retain', 'ambient-key-never-retain', 'signed.invalid'):
            self.assertNotIn(secret, text)
        if label in ('python-tests', 'portable-tests', 'vet', 'go-version'):
            self.assertEqual((code, record['status'], record['reason']),
                             (1, 'FAIL', 'setup-command-'+label))
            self.assertEqual(names[-1], label)
        return record, module

    def stream(self, phase, name, expected=None):
        diagnostic = phase.get('diagnostics')
        self.assertIsNotNone(diagnostic, 'failed preparation test output lost from actual outer receipt')
        self.assertEqual(diagnostic['encoding'], 'base64')
        excerpt = diagnostic[name]
        head = base64.b64decode(excerpt['head'], validate=True)
        tail = base64.b64decode(excerpt['tail'], validate=True)
        self.assertEqual(excerpt['retainedBytes'], len(head)+len(tail))
        self.assertLessEqual(len(head)+len(tail), 8192)
        if expected is not None:
            self.assertEqual(phase[name+'Bytes'], len(expected))
            self.assertEqual(phase[name+'SHA256'], hashlib.sha256(expected).hexdigest())
            self.assertEqual(head+tail, expected if len(expected)<=8192 else expected[:4096]+expected[-4096:])
            self.assertEqual(excerpt['truncated'], len(expected)>8192)
        return head+tail

    def test_actual_failing_unittest_stderr_survives_outer_receipt(self):
        record, module = self.outer(stdout=b'controlled stdout\n', stderr=b'controlled stderr\n')
        phase = record['phases'][-1]
        self.assertEqual((phase['phase'], phase['exit'], phase['reaped'], phase['groupClean']), ('exited', 1, True, True))
        self.assertTrue(phase.get('diagnostics', {}).get('captureComplete'))
        self.stream(phase, 'stdout', b'controlled stdout\n')
        stderr = self.stream(phase, 'stderr')
        self.assertIn(b'FAIL: test_diagnostic', stderr)
        self.assertIn(b'AssertionError', stderr)
        self.assertIn(b'controlled-preparation-failure', stderr)
        self.assertEqual(phase['stderrBytes'], len(stderr))
        self.assertEqual(phase['stderrSHA256'], hashlib.sha256(stderr).hexdigest())
        self.assertFalse(phase['diagnostics']['stderr']['truncated'])
        self.assertEqual((module/'ci/python-calls').read_text(), 'x')
        self.assertTrue(all('diagnostics' not in p for p in record['phases'][:-1]))

    def test_head_tail_encoding_caps_empty_and_invalid_bytes_in_outer_receipt(self):
        for data in (b'', b'\x00\xff\xfe\x1b\n', b'x'*8192,
                     b'head'+bytes(range(256))*1024+b'tail'):
            with self.subTest(size=len(data)):
                record, _ = self.outer('portable-tests', data, data[::-1], bootstrap=True)
                phase = record['phases'][-1]
                self.assertEqual((phase['exit'], phase['phase'], phase['reaped'], phase['groupClean']), (7, 'exited', True, True))
                self.assertTrue(phase.get('diagnostics', {}).get('captureComplete'))
                self.stream(phase, 'stdout', data); self.stream(phase, 'stderr', data[::-1])

    def test_output_limit_is_not_claimed_as_complete_capture(self):
        data = b'prefix'+b'x'*262144+b'uncaptured-tail'
        record, _ = self.outer('portable-tests', data, cap=128*1024)
        phase = record['phases'][-1]
        self.assertEqual(phase['phase'], 'output-limit')
        self.assertTrue(phase['reaped'] and phase['groupClean'])
        diagnostic = phase.get('diagnostics')
        self.assertIsNotNone(diagnostic)
        self.assertFalse(diagnostic['captureComplete'])
        self.assertLessEqual(record['capturedOutputBytes'], 64*1024)
        captured = data[:phase['stdoutBytes']]
        self.stream(phase, 'stdout', captured)
        self.stream(phase, 'stderr', b'')
        self.assertNotIn(b'uncaptured-tail', self.stream(phase, 'stdout'))
        self.assertEqual(record['actualExit'], 1)

    def test_watchdog_does_not_retain_arbitrary_or_native_labeled_output(self):
        for label in ('native', 'acquisition', 'python-tests'):
            budget = ci.Budget()
            result = budget.command(label, [sys.executable, '-B', '-c',
                'import sys; print("private-arbitrary-output"); sys.stderr.write("private-stderr"); sys.exit(4)'],
                self.root, ci.clean_env(self.root), 2)
            self.assertEqual(result['exit'], 4)
            self.assertNotIn('diagnostics', budget.phases[-1])
            self.assertNotIn('private-arbitrary-output', json.dumps(budget.phases))
            self.assertNotIn('private-stderr', json.dumps(budget.phases))

    def test_success_and_non_test_failures_do_not_retain_streams(self):
        for label in ('success', 'vet', 'go-version'):
            with self.subTest(label=label):
                record, module = self.outer(label, b'not-test-payload', b'not-test-stderr')
                self.assertTrue(all('diagnostics' not in p for p in record['phases']))
                self.assertNotIn('not-test-payload', json.dumps(record))
                self.assertNotIn('not-test-stderr', json.dumps(record))
                if label == 'success':
                    self.assertEqual(record['reason'], 'controller-error')  # absent inert binary
                    self.assertEqual(record['actualExit'], 3)
                    self.assertEqual(record['phases'][-1]['exit'], 0)
                    self.assertEqual((module/'ci/python-calls').read_text(), 'x')


class Bootstrap(unittest.TestCase):
    def setUp(self):
        try:
            import yaml  # Only an already-installed parser; no installation/network.
        except ImportError:
            self.skipTest('installed YAML parser unavailable; parsed-workflow check NOT RUN')
        workflow = HERE.parents[2]/'.github/workflows/macos-clone-feasibility.yml'
        self.workflow = yaml.safe_load(workflow.read_text())
        step = self.workflow['jobs']['probe']['steps'][0]
        body = step['run'].split("python3 -B - <<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        self.ns = {'__name__': 'controlled_bootstrap'}
        exec(compile(body, str(workflow), 'exec'), self.ns)
        self.env = {'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REPOSITORY': 'landroval/PackTrace',
                    'GITHUB_SHA': 'a'*40, 'EXPECTED_SOURCE_SHA': 'a'*40,
                    'FIXTURE_CONFIRMATION': 'owned-fixtures-only'}

    def test_parsed_job_has_only_manual_fixed_free_row(self):
        self.assertEqual(set(self.workflow['on']), {'workflow_dispatch'})
        self.assertEqual(self.workflow['permissions'], {})
        jobs = self.workflow['jobs']; self.assertEqual(set(jobs), {'probe'})
        job = jobs['probe']; self.assertEqual(job['runs-on'], 'macos-15')
        self.assertLessEqual(job['timeout-minutes'], 30)
        self.assertEqual(job['permissions'], {})
        inputs = self.workflow['on']['workflow_dispatch']['inputs']
        self.assertEqual(set(inputs), {'expected_source_sha', 'confirmation'})
        self.assertTrue(all(x['required'] is True for x in inputs.values()))
        self.assertEqual(inputs['confirmation']['options'], ['owned-fixtures-only'])
        self.assertEqual(len(job['steps']), 1)
        self.assertNotIn('uses', job['steps'][0])

    def test_job_visibility_gate_before_allocation(self):
        # Parse the job expression (not step text) and evaluate documented event data.
        # GitHub property lookup of missing fields is empty; no !private coercion.
        guard = self.workflow['jobs']['probe'].get('if')
        self.assertIsInstance(guard, str, 'no job-level gate before runner allocation')
        expression = guard.strip()
        if expression.startswith('${{') and expression.endswith('}}'):
            expression = expression[3:-2].strip()
        tree = ast.parse(expression, mode='eval').body
        def evaluate(node, context):
            if isinstance(node, ast.Constant): return node.value
            if isinstance(node, ast.Name): return context.get(node.id, '')
            if isinstance(node, ast.Attribute):
                parent = evaluate(node.value, context)
                return parent.get(node.attr, '') if isinstance(parent, dict) else ''
            if isinstance(node, ast.Compare) and len(node.ops)==1 and isinstance(node.ops[0], ast.Eq):
                a, b = evaluate(node.left, context), evaluate(node.comparators[0], context)
                # Actions string equality is case-insensitive; event visibility is a documented enum.
                return isinstance(a, str) and isinstance(b, str) and a.casefold()==b.casefold()
            self.fail('unsupported job expression; extend semantic evaluator, never grep')
        for value, want in [('public', True), ('private', False), ('internal', False),
                            ('', False), (None, False), (False, False), (True, False), (0, False)]:
            with self.subTest(visibility=value):
                context = {'github': {'event': {'repository': {'visibility': value}}}}
                self.assertIs(evaluate(tree, context), want)
        for context in [{}, {'github': {}}, {'github': {'event': {}}},
                        {'github': {'event': {'repository': {}}}},
                        {'github': {'event': {'repository': {'private': False}}}}]:
            self.assertIs(evaluate(tree, context), False)

    def test_bootstrap_rejects_request_before_source_execution(self):
        validate = self.ns['validate_request']
        self.assertEqual(validate(self.env), 'a'*40)
        for key, value in [('GITHUB_EVENT_NAME', 'push'), ('GITHUB_REPOSITORY', 'other/PackTrace'),
                           ('EXPECTED_SOURCE_SHA', 'b'*40), ('GITHUB_SHA', 'a'*39),
                           ('FIXTURE_CONFIRMATION', 'yes'), ('EXPECTED_SOURCE_SHA', 'a'*40+';echo x')]:
            with self.assertRaises(self.ns['Rejected']): validate({**self.env, key: value})

    def test_bootstrap_tree_validation_types_paths_bounds(self):
        blob = 'b'*40
        def row(path, mode='100644', size='12'):
            return f'{mode} blob {blob} {size}\t{path}\0'.encode()
        tree = self.ns['validate_tree'](row('probes/native-safety/ci/run.py'))
        self.assertIn('probes/native-safety/ci/run.py', tree)
        for raw in [row('../escape'), row('.git/config'), row('x', '120000'),
                    row('x', '160000'), row('x', size='999999999'),
                    row('x')+row('X'), row('x')+row('x'), b'bad',
                    row('a/../x'), row('a\\x')]:
            with self.assertRaises(self.ns['Rejected']):
                self.ns['validate_tree'](row('probes/native-safety/ci/run.py')+raw)

    def test_bootstrap_actual_process_budget_rejects_timeout_output_and_storage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = self.ns['clean_env'](root)
            command = self.ns['command']
            raw = command([sys.executable, '-c', 'print("fixture")'], root, root, env, time.monotonic()+2)
            self.assertEqual(raw, b'fixture\n')
            for code, seconds in [('import time; time.sleep(20)', .1),
                                  ('import sys; sys.stderr.write("x"*2200000)', 2)]:
                self.ns['USED'] = 0
                with self.assertRaises(self.ns['Rejected']):
                    command([sys.executable, '-c', code], root, root, env, time.monotonic()+seconds)
            self.assertNotEqual(self.ns['PHASES'][-1]['phase'], 'exited')
            (root/'link').symlink_to('missing')
            with self.assertRaises(self.ns['Rejected']): self.ns['storage'](root)

    def test_entire_parsed_bootstrap_invocation_is_blocked_before_git(self):
        step = self.workflow['jobs']['probe']['steps'][0]
        body = step['run'].split("python3 -B - <<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        result = subprocess.run([sys.executable, '-B', '-c', body], env={'PATH': '/usr/bin:/bin'},
                                capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 3)
        obj = json.loads(result.stdout.decode().split('=', 1)[1])
        self.assertEqual((obj['status'], obj['phase']), ('BLOCKED', 'bootstrap'))
        self.assertEqual(obj['phases'], [])

    def test_actual_bootstrap_controlled_git_checks_tree_before_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ('home', 'tmp', 'hooks', 'templates'): (root/name).mkdir(mode=0o700)
            helper = b'# controlled source fixture; never executed\n'
            sha = hashlib.sha1(b'blob '+str(len(helper)).encode()+b'\0'+helper).hexdigest()
            git = root/'fixture-git'
            calls = root/'calls'
            git.write_text(f'#!{sys.executable}\n' + '''import json,os,sys
from pathlib import Path
a=sys.argv[1:]
assert 'GITHUB_TOKEN' not in os.environ and 'HTTPS_PROXY' not in os.environ
assert os.environ['GIT_ALLOW_PROTOCOL']=='https'
assert 'protocol.allow=never' in a and 'credential.helper=' in a
while a and a[0]=='-c': a=a[2:]
p=Path('''+repr(str(calls))+''')
with p.open('a') as f: f.write(json.dumps(a)+'\\n')
if a[0]=='init': Path('.git').mkdir()
elif a[0]=='rev-parse': print('''+repr('a'*40+'\n'+'c'*40)+''')
elif a[0]=='ls-tree':
 sys.stdout.buffer.write('''+repr(f'100644 blob {sha} {len(helper)}\tprobes/native-safety/ci/run.py\0'.encode())+''')
elif a[0]=='checkout':
 p=Path('probes/native-safety/ci/run.py'); p.parent.mkdir(parents=True); p.write_bytes('''+repr(helper)+''')
elif a[0]=='config': print('core.bare\\ncore.repositoryformatversion')
''')
            git.chmod(0o700)
            self.ns['GIT'] = str(git)
            checked = self.ns['checkout'](root, {}, 'a'*40, time.monotonic()+5)
            self.assertEqual(checked.get('tree'), 'c'*40)
            self.assertEqual(checked.get('helperSHA256'), hashlib.sha256(helper).hexdigest())
            commands = [json.loads(line) for line in calls.read_text().splitlines()]
            names = [x[0] for x in commands]
            self.assertLess(names.index('ls-tree'), names.index('checkout'))
            self.assertIn(['fetch', '--depth=1', '--no-tags', '--recurse-submodules=no',
                           'https://github.com/landroval/PackTrace.git', 'a'*40], commands)


if __name__ == '__main__':
    unittest.main()
