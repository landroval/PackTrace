import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('mac_validation', Path(__file__).with_name('macos_validation.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class MacNativeValidation(unittest.TestCase):
    def environment(self, arch):
        return dict(GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_REPOSITORY='landroval/PackTrace',
                    REPOSITORY_PRIVATE='false', SOURCE_SHA='a'*40, EXPECTED_SHA='a'*40,
                    VALIDATION_PROFILE='macos-scan-'+arch+'-v1',
                    OWNED_CONFIRMATION='owned-native-fixtures-only', ImageVersion='owned-image',
                    ImageOS='macos15', RUNNER_ARCH='ARM64' if arch == 'arm64' else 'X64')

    def test_public_manual_rows_bind_sdk_os_arch_and_source(self):
        for arch, machine, size, sha in [
            ('arm64', 'arm64', 68100347, 'ee215d57e0ec269c60cc9ceca68e6bda321ba9ee5afe24f4b0988703c2d87d12'),
            ('amd64', 'x86_64', 71621873, '8f8f52c6649542cf027bbc9b9c68d1ec042f9f34808a40413f0b8b3f66f3caa4')]:
            with self.subTest(arch=arch):
                env = self.environment(arch)
                self.assertEqual(m.admit(env, 'Darwin', machine, '15.8.2', 501), (arch, size, sha))
                for key, value in [('GITHUB_EVENT_NAME', 'push'), ('REPOSITORY_PRIVATE', 'true'),
                                   ('GITHUB_REPOSITORY', 'elsewhere/repo'), ('EXPECTED_SHA', 'b'*40),
                                   ('SOURCE_SHA', 'bad'), ('VALIDATION_PROFILE', 'macos-scan-other-v1'),
                                   ('OWNED_CONFIRMATION', ''), ('RUNNER_ARCH', 'ARM64' if arch == 'amd64' else 'X64'),
                                   ('ImageOS', 'macos14'), ('ImageVersion', '')]:
                    with self.subTest(key=key), self.assertRaises(ValueError):
                        m.admit(dict(env, **{key: value}), 'Darwin', machine, '15.8.2', 501)
                for system, other, version, uid in [('Linux', machine, '15.8.2', 501),
                                                    ('Darwin', 'x86_64' if arch == 'arm64' else 'arm64', '15.8.2', 501),
                                                    ('Darwin', machine, '16.0', 501), ('Darwin', machine, '15.8.2', 0)]:
                    with self.subTest(system=system, machine=other, version=version, uid=uid), self.assertRaises(ValueError):
                        m.admit(env, system, other, version, uid)

    def test_negative_control_requires_actual_named_assertion_failure(self):
        test='TestOwnedControl'
        expected=b'{"Action":"output","Test":"TestOwnedControl","Output":"expected-marker"}\n{"Action":"fail","Test":"TestOwnedControl"}\n{"Action":"fail","Package":"owned"}\n'
        self.assertTrue(m.negative_control(expected, 1, test, 'expected-marker'))
        for raw, code in [(expected,0), (expected[:-1],1), (b'',1),
                          (b'{"Action":"build-fail"}\n',1),
                          (expected.replace(b'expected-marker',b'other-fault'),1),
                          (expected+b'{"Action":"fail","Test":"Unrelated"}\n',1)]:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                m.negative_control(raw, code, test, 'expected-marker')


if __name__ == '__main__':
    unittest.main()
