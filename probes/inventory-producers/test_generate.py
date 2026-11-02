import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import time
import unittest

import generate


class GenerationTests(unittest.TestCase):
    def test_arguments_disable_scripts_and_only_use_owned_registry(self):
        for kind, version in [('npm', '8.19.4'), ('npm', '10.9.4'), ('npm', '11.6.2'), ('bun', '1.3.2'), ('bun', '1.4.2')]:
            args = generate.install_arguments(kind, version, 'http://127.0.0.1:41769', 'hoisted', 'copyfile')
            self.assertIn('--ignore-scripts', args)
            self.assertIn('http://127.0.0.1:41769', args)
            self.assertNotIn('latest', ' '.join(args))
            self.assertNotIn('--allow-scripts', args)
        with self.assertRaises(generate.Rejected):
            generate.install_arguments('npm', '10.9.4', 'https://registry.npmjs.org', 'hoisted', 'copyfile')

    def test_owned_pack_has_only_inert_fixture_data(self):
        manifest = {'name': 'fixture-owned', 'version': '1.0.0'}
        data = generate.package_archive(manifest)
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            self.assertEqual({x.name for x in archive}, {'package/package.json', 'package/index.js'})
        self.assertIn('single', generate.case_expectations())
        self.assertIn('workspaces', generate.case_expectations())
        self.assertIn('sources', generate.case_expectations())

    def test_git_fixture_request_has_a_concrete_owned_commit(self):
        with self.assertRaises(generate.Rejected):
            generate.source_manifest('')
        manifest = generate.source_manifest('a' * 40)
        self.assertEqual(manifest['dependencies']['fixture-git'], 'git+file:///work/git-fixture#' + 'a' * 40)
        unsupported = generate.source_manifest('a' * 40, include_git=False)
        self.assertNotIn('fixture-git', unsupported['dependencies'])
        self.assertEqual(len(unsupported['dependencies']), 3)

    def test_partial_batch_uses_only_its_remaining_call_allowance(self):
        self.assertEqual(generate.selected_cases('bun', ['sources', 'hardlink']), ['sources', 'hardlink'])
        self.assertEqual(generate.call_allowance('bun', ['sources', 'hardlink']), 3)
        self.assertEqual(generate.selected_cases('bun', ['isolated-single']), ['isolated-single'])
        with self.assertRaises(generate.Rejected):
            generate.selected_cases('npm', ['sources', 'sources'])
        with self.assertRaises(generate.Rejected):
            generate.selected_cases('npm', ['hardlink'])

    def test_invocation_budget_refuses_before_spawning(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); marker = root / 'must-not-exist'
            budget = generate.RunBudget(calls=6)
            with self.assertRaises(generate.Rejected):
                generate.run_owned([sys.executable, '-c', f'open({str(marker)!r},"w").write("no")'], root, {}, budget)
            self.assertFalse(marker.exists())

    def test_owned_process_deadline_is_reaped(self):
        with tempfile.TemporaryDirectory() as tmp:
            budget = generate.RunBudget(deadline=time.monotonic() + 0.1)
            with self.assertRaises(generate.Rejected):
                generate.run_owned([sys.executable, '-c', 'import time; time.sleep(20)'], Path(tmp), {}, budget)
            self.assertEqual(budget.calls, 1)
            self.assertTrue(budget.receipts[-1]['reaped'])
            self.assertEqual(budget.receipts[-1]['status'], 'deadline')

    def test_capture_preserves_link_and_outside_hardlink_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'root'; root.mkdir()
            manifest = root / 'package.json'; manifest.write_text('{"name":"fixture-owned"}')
            outside = Path(tmp) / 'owned-outside-alias'
            outside.hardlink_to(manifest)
            (root / 'alias').symlink_to('package.json')
            captured = generate.capture(root)
            files = {x['path']: x for x in captured['entries']}
            self.assertEqual(files['package.json']['links'], 2)
            self.assertEqual(files['alias']['target'], 'package.json')
            self.assertEqual(hashlib.sha256(files['package.json']['data'].encode()).hexdigest(), files['package.json']['sha256'])
            self.assertNotIn(str(Path(tmp)), json.dumps(captured))

    def test_sandbox_only_has_one_capped_writable_scratch(self):
        args = generate.sandbox_arguments(Path('/owned/tool'), Path('/owned/control'), Path('/owned/generate.py'))
        self.assertIn('--unshare-all', args)
        self.assertIn('--clearenv', args)
        self.assertIn('--remount-ro', args)
        index = args.index('--size')
        self.assertEqual(args[index + 1:index + 4], [str(512 << 20), '--tmpfs', '/work'])
        self.assertIn(['--symlink', 'usr/bin', '/bin'], [args[i:i+3] for i in range(len(args)-2)])
        self.assertNotIn('--bind', args)
        self.assertNotIn('--not-a-security-boundary', args)


if __name__ == '__main__':
    unittest.main()
