import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('validation', Path(__file__).with_name('linux_validation.py'))
validation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validation)


class Validation(unittest.TestCase):
    def test_failed_or_incomplete_stream_cannot_pass(self):
        good = b'{"Action":"pass","Test":"owned"}\n'
        self.assertEqual(validation.test_counts(good)['passed'], 1)
        for raw in (b'', good[:-1], b'{}\n', good + b'{"Action":"fail","Package":"owned"}\n',
                    b'{"Action":"build-fail","Package":"owned"}\n',
                    good + b'{"Action":"build-fail","Package":"owned"}\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                validation.test_counts(raw)

    def test_control_entry_skip_is_not_a_native_qualification_claim(self):
        raw = b'{"Action":"pass","Test":"owned"}\n{"Action":"skip","Test":"private-entry"}\n'
        self.assertEqual(validation.test_counts(raw), {'passed': 1, 'failed': 0, 'skipped': 1, 'failedEvents': 0})

    def test_reap_and_group_uncertainty_prevent_success(self):
        good = dict(phase='exited', exit=0, reaped=True, groupClean=True, groupPermissionDenied=False)
        self.assertTrue(validation.phase_ok(good))
        for key, bad in [('phase', 'timeout'), ('exit', 2), ('reaped', False),
                         ('groupClean', False), ('groupPermissionDenied', True)]:
            with self.subTest(key=key):
                self.assertFalse(validation.phase_ok(dict(good, **{key: bad})))

    def test_exact_public_manual_profile_before_any_command(self):
        env = dict(GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_REPOSITORY='landroval/PackTrace',
                   REPOSITORY_PRIVATE='false', SOURCE_SHA='a' * 40, EXPECTED_SHA='a' * 40,
                   VALIDATION_PROFILE='linux-scan-amd64-v1', OWNED_CONFIRMATION='owned-linux-fixtures-only',
                   ImageOS='ubuntu24', ImageVersion='owned-image', RUNNER_ARCH='X64')
        validation.admit(env, 'Linux', 'x86_64', 1001)
        for key, bad in [('GITHUB_EVENT_NAME', 'push'), ('REPOSITORY_PRIVATE', 'true'),
                         ('GITHUB_REPOSITORY', 'other/repo'), ('SOURCE_SHA', 'b' * 40),
                         ('EXPECTED_SHA', ''), ('VALIDATION_PROFILE', 'other'),
                         ('OWNED_CONFIRMATION', ''), ('RUNNER_ARCH', 'ARM64'), ('ImageOS', 'ubuntu22')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                validation.admit(dict(env, **{key: bad}), 'Linux', 'x86_64', 1001)
        with self.assertRaises(ValueError):
            validation.admit(env, 'Linux', 'x86_64', 0)

    def test_fixture_budget_accepts_owned_fifo_socket_and_does_not_follow_links(self):
        import os
        import socket
        import tempfile
        with tempfile.TemporaryDirectory(prefix='ptv-') as directory:
            root = Path(directory)/'fixtures'
            root.mkdir()
            outside = Path(directory)/'outside'
            outside.write_bytes(b'x' * 1024)
            (root/'regular').write_bytes(b'abc')
            (root/'alias').symlink_to(outside)
            os.mkfifo(root/'fifo')
            with socket.socket(socket.AF_UNIX) as server:
                server.bind(str(root/'socket'))
                self.assertEqual(validation.fixture_bytes(root), 3 + len(str(outside)))

    def test_mutable_fixture_and_build_entries_can_disappear(self):
        import tempfile
        from unittest.mock import patch
        helpers = validation.helpers(Path(__file__).resolve().parents[3])
        with tempfile.TemporaryDirectory(prefix='pt-gone-') as directory:
            with patch.object(validation.os, 'walk', return_value=[(directory, [], ['gone'])]):
                self.assertEqual(validation.fixture_bytes(Path(directory)), 0)
                self.assertEqual(helpers.disk_bytes(Path(directory)), 0)
            with patch.object(Path, 'lstat', side_effect=PermissionError('owned-test')):
                with patch.object(validation.os, 'walk', return_value=[(directory, [], ['denied'])]):
                    with self.assertRaises(PermissionError):
                        validation.fixture_bytes(Path(directory))
                    with self.assertRaises(PermissionError):
                        helpers.disk_bytes(Path(directory))

    def test_actual_storage_callback_accepts_owned_build_ipc_without_following_links(self):
        import ast
        import inspect
        import os
        import socket
        import tempfile
        # Execute the production callback with real owned trees, without faking
        # Ubuntu/Go provenance or running any hosted/native row.
        tree = ast.parse(inspect.getsource(validation.main))
        callback = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == 'storage')
        helpers = validation.helpers(Path(__file__).resolve().parents[3])
        for area in ('gocache', 'build'):
            with self.subTest(area=area), tempfile.TemporaryDirectory(prefix='pt-build-') as directory:
                root = Path(directory)
                work = root/'work'
                for path in (root/'gocache', work/'build', work/'tmp'):
                    path.mkdir(parents=True)
                selected = root/'gocache' if area == 'gocache' else work/'build'
                (selected/'regular').write_bytes(b'owned')
                (selected/'alias').symlink_to(selected/'regular')
                os.mkfifo(selected/'fifo')
                with socket.socket(socket.AF_UNIX) as server:
                    server.bind(str(selected/'socket'))
                    namespace = dict(h=helpers, root=root, work=work, receipt={},
                                     fixture_bytes=validation.fixture_bytes, ValidationRejected=validation.ValidationRejected)
                    exec(compile(ast.Module(body=[callback], type_ignores=[]), '<actual-storage-callback>', 'exec'), namespace)
                    try:
                        admitted = namespace['storage']()
                    except Exception as error:
                        self.fail('owned build IPC rejected: '+str(error))
                    self.assertTrue(admitted)

    def test_pending_failure_capture_and_callback_exception_keep_receipts(self):
        import os
        import sys
        import tempfile
        import time
        helpers = validation.helpers(Path(__file__).resolve().parents[3])
        for mode in ('storage-stop', 'storage-exception', 'capture-limit'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix='pt-drain-') as directory:
                ready = Path(directory)/'ready'
                marker = b'OWNED PENDING FAILURE DIAGNOSTIC\\n'
                child = ('import os,time; from pathlib import Path; os.write(2,'+repr(marker)+
                         '); Path('+repr(str(ready))+').write_text("ready"); time.sleep(5)')
                def storage():
                    end = time.monotonic()+2
                    while not ready.exists() and time.monotonic() < end:
                        time.sleep(.001)
                    self.assertTrue(ready.exists())
                    if mode == 'storage-exception':
                        raise validation.ValidationRejected('unexpected-fixture-type')
                    return False
                budget = helpers.Budget()
                result = budget.command('owned-pending', [sys.executable, '-c', child],
                                        Path(directory), dict(os.environ), 3,
                                        stderr_cap=4 if mode == 'capture-limit' else 1024, storage=storage)
                self.assertTrue(result['reaped'] and result['groupClean'])
                self.assertEqual(len(budget.phases), 1)
                self.assertEqual(result['phase'], 'process-error' if mode == 'storage-exception' else 'storage-limit')
                self.assertEqual(result['stderr'], marker[:4] if mode == 'capture-limit' else marker)
                self.assertEqual(result['captureComplete'], mode != 'capture-limit')

    def test_diagnostics_are_bounded_and_not_reported_complete_when_truncated(self):
        raw = b'a' * 10000
        diagnostic = validation.diagnostic(raw)
        self.assertEqual(diagnostic['bytes'], 10000)
        self.assertTrue(diagnostic['truncated'])
        import base64
        self.assertEqual(len(base64.b64decode(diagnostic['base64'])), 8192)
        self.assertFalse(validation.diagnostic(b'owned')['truncated'])


if __name__ == '__main__':
    unittest.main()
