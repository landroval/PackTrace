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
                    b'{"Action":"build-fail","Package":"owned"}\n'):
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
