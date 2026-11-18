"""Stdlib-only checks; no scanner, producers, network or full-size writes."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import prepare_corpus as corpus


class PreparationTests(unittest.TestCase):
    def test_reference_projection_without_io(self):
        with patch('builtins.open', side_effect=AssertionError('I/O')), \
                patch.object(Path, 'open', side_effect=AssertionError('I/O')), \
                patch('os.scandir', side_effect=AssertionError('I/O')):
            first = corpus.project()
            self.assertEqual(first, corpus.project())
        self.assertEqual(first['dimensions'], dict(instances=1000, files=50000, targetBytes=1073741824))
        self.assertEqual(first['counts']['payloadFiles'], 48998)
        self.assertEqual(first['counts']['lockPackageEntries'], 1001)
        self.assertEqual(first['counts']['expectedFileRecords'], 50000)
        self.assertFalse(first['expectedWork']['preparedAuthenticatedReferences'])
        self.assertIsNone(first['expectedWork']['advisoryDecisions'])
        self.assertEqual(first['bytes'], dict(
            target=1073741824, metadata=168229, payload=1073573595,
            rootManifest=25080, installedManifests=44000, lockfile=99149,
            rawManifestAndLockReceipts=168229, base64ManifestAndLockData=225640))
        self.assertEqual(first['contract']['recordsSHA256'],
                         'fe63530a278af53fc2f78ffac2d056522d585d95bbde4cabdbe0c7370b51b3a8')
        self.assertEqual(first['bytes']['metadata'] + first['bytes']['payload'], 1 << 30)

    def test_miniature_independent_walk_and_reproduction(self):
        with tempfile.TemporaryDirectory(prefix='packtrace-b6-owned-') as parent:
            roots = [Path(parent) / name for name in ('one', 'two')]
            results = [corpus.write_owned(root, 2, 12, 8192) for root in roots]
            self.assertEqual(results[0], results[1])
            inventories = []
            for root in roots:
                observed, directories = {}, 1
                for directory, dirs, files in os.walk(root, followlinks=False):
                    directories += len(dirs)
                    for name in dirs + files:
                        info = (Path(directory) / name).lstat()
                        self.assertTrue(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                        if stat.S_ISREG(info.st_mode):
                            self.assertEqual(info.st_nlink, 1)
                    for name in files:
                        path = Path(directory) / name
                        data = path.read_bytes()
                        self.assertEqual(len(data), path.stat().st_size)
                        relative = path.relative_to(root).as_posix()
                        kind = 'metadata' if name in ('package.json', 'package-lock.json') else 'payload'
                        observed[relative] = dict(path=relative, kind=kind, bytes=len(data),
                                                  sha256=hashlib.sha256(data).hexdigest())
                        if kind == 'payload':
                            # Independent expected byte construction, not generator helpers.
                            pattern = b'PackTrace owned inert B6 fixture; never execute.\n'
                            self.assertEqual(data, (pattern * (len(data) // len(pattern) + 1))[:len(data)])
                self.assertEqual(len(observed), 12)
                self.assertEqual(directories, 4)
                self.assertEqual(sum(r['bytes'] for r in observed.values()), 8192)
                metadata = sorted(p for p, r in observed.items() if r['kind'] == 'metadata')
                payload = sorted(p for p, r in observed.items() if r['kind'] == 'payload')
                self.assertEqual(len(metadata), 4)
                self.assertEqual(len(payload), 8)
                digest = hashlib.sha256()
                for path in metadata + payload:
                    digest.update((json.dumps(observed[path], sort_keys=True, separators=(',', ':')) + '\n').encode('ascii'))
                self.assertEqual(digest.hexdigest(), results[0]['contract']['recordsSHA256'])
                self.assertEqual(sum(observed[p]['bytes'] for p in metadata), results[0]['bytes']['metadata'])
                self.assertEqual(sum(observed[p]['bytes'] for p in payload), results[0]['bytes']['payload'])
                root_manifest = json.loads((root / 'package.json').read_bytes())
                lock = json.loads((root / 'package-lock.json').read_bytes())
                self.assertEqual(root_manifest['dependencies'], {'fixture-000000': '1.0.0', 'fixture-000001': '1.0.0'})
                self.assertEqual(set(lock['packages']), {'', 'node_modules/fixture-000000', 'node_modules/fixture-000001'})
                for name in root_manifest['dependencies']:
                    self.assertEqual(json.loads((root / 'node_modules' / name / 'package.json').read_bytes()),
                                     {'name': name, 'version': '1.0.0'})
                inventories.append(observed)
            self.assertEqual(inventories[0], inventories[1])
            with self.assertRaises(FileExistsError):
                corpus.write_owned(roots[0], 2, 12, 8192)
            self.assertEqual(len(list(roots[0].rglob('*.txt'))), 8)

    def test_cli_refuses_reference_size_write(self):
        with tempfile.TemporaryDirectory(prefix='packtrace-b6-owned-') as parent:
            destination = Path(parent) / 'absent'
            with patch('sys.argv', ['prepare_corpus.py', '--write-owned', str(destination)]), \
                    contextlib.redirect_stderr(io.StringIO()) as error, \
                    self.assertRaises(SystemExit) as rejected:
                corpus.main()
            self.assertEqual(rejected.exception.code, 1)
            self.assertIn('miniature-only', error.getvalue())
            self.assertFalse(destination.exists())

    def test_rejected_dimensions_do_not_create_destination(self):
        with tempfile.TemporaryDirectory(prefix='packtrace-b6-owned-') as parent:
            destination = Path(parent) / 'absent'
            for dimensions in ((0, 12, 8192), (2, 5, 8192), (2, 12, 1),
                               (1001, 50000, 1 << 30), (2, 50001, 8192),
                               (2, 12, (1 << 30) + 1), (True, 12, 8192)):
                with self.subTest(dimensions=dimensions), self.assertRaises(ValueError):
                    corpus.write_owned(destination, *dimensions)
                self.assertFalse(destination.exists())


if __name__ == '__main__':
    unittest.main()
