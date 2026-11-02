import base64
import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

import prepare


class PreparationTests(unittest.TestCase):
    def source(self, data, kind='npm'):
        version = '10.9.4' if kind == 'npm' else '1.4.2'
        return dict(kind=kind, version=version,
                    url=(f'https://registry.npmjs.org/npm/-/npm-{version}.tgz' if kind == 'npm' else f'https://github.com/oven-sh/bun/releases/download/bun-v{version}/bun-linux-x64.zip'),
                    size=len(data), algorithm='sha512' if kind == 'npm' else 'sha256',
                    digest=hashlib.new('sha512' if kind == 'npm' else 'sha256', data).hexdigest(),
                    license='Artistic-2.0' if kind == 'npm' else 'MIT',
                    runtime={'version': 'v26.12.1', 'sha256': 'a' * 64})

    def tar(self, entries):
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode='w:gz', format=tarfile.USTAR_FORMAT) as archive:
            for name, kind, body in entries:
                item = tarfile.TarInfo(name)
                item.type = kind
                item.size = len(body) if kind == tarfile.REGTYPE else 0
                item.linkname = body.decode() if kind == tarfile.SYMTYPE else ''
                archive.addfile(item, io.BytesIO(body) if item.isfile() else None)
        return out.getvalue()

    def test_source_and_redirects_remain_official_and_pinned(self):
        s = self.source(b'owned')
        prepare.check_source(s)
        for key, value in [('url', 'https://example.invalid/tool'), ('version', 'latest'), ('digest', ''), ('license', ''), ('runtime', None)]:
            bad = dict(s); bad[key] = value
            with self.subTest(key=key), self.assertRaises(prepare.Rejected):
                prepare.check_source(bad)
        self.assertTrue(prepare.allowed_redirect('bun', 'https://release-assets.githubusercontent.com/owned'))
        self.assertFalse(prepare.allowed_redirect('bun', 'http://release-assets.githubusercontent.com/owned'))
        self.assertFalse(prepare.allowed_redirect('bun', 'https://evil.invalid/tool'))
        self.assertFalse(prepare.allowed_redirect('npm', 'https://github.com/owned'))

    def test_bytes_and_digest_must_match_before_extraction(self):
        data = self.tar([('package/LICENSE', tarfile.REGTYPE, b'The Artistic License 2.0')])
        source = self.source(data)
        prepare.verify_bytes(data, source)
        for altered in [data[:-1], data + b'extra', b'X' + data[1:]]:
            with self.assertRaises(prepare.Rejected):
                prepare.verify_bytes(altered, source)

    def test_unsafe_type_path_and_case_collision_refused(self):
        for entries in [
            [('package/../escape', tarfile.REGTYPE, b'owned')],
            [('package/link', tarfile.SYMTYPE, b'../../owned')],
            [('package/A', tarfile.REGTYPE, b'a'), ('package/a', tarfile.REGTYPE, b'b')],
            [('package/A/one', tarfile.REGTYPE, b'a'), ('package/a/two', tarfile.REGTYPE, b'b')],
        ]:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); data = self.tar(entries); archive = root / 'tool.tgz'; archive.write_bytes(data)
                with self.assertRaises(prepare.Rejected):
                    prepare.extract(archive, root / 'out', self.source(data), prepare.Budget())
                self.assertFalse((root / 'escape').exists())

    def test_extraction_and_global_allowances_are_not_reset(self):
        data = self.tar([('package/LICENSE', tarfile.REGTYPE, b'The Artistic License 2.0')])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); archive = root / 'tool.tgz'; archive.write_bytes(data)
            budget = prepare.Budget(extracted=prepare.MAX_EXTRACTED - 1)
            with self.assertRaises(prepare.Rejected):
                prepare.extract(archive, root / 'out', self.source(data), budget)
        budget = prepare.Budget(compressed=prepare.MAX_COMPRESSED)
        with self.assertRaises(prepare.Rejected):
            budget.reserve_compressed(1)

    def test_positive_owned_extract_requires_actual_license(self):
        data = self.tar([('package/LICENSE', tarfile.REGTYPE, b'The Artistic License 2.0'), ('package/bin/npm-cli.js', tarfile.REGTYPE, b'owned inert')])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); archive = root / 'tool.tgz'; archive.write_bytes(data)
            prepare.extract(archive, root / 'out', self.source(data), prepare.Budget())
            self.assertEqual((root / 'out/package/bin/npm-cli.js').read_bytes(), b'owned inert')
            receipt = prepare.license_receipt(root / 'out', self.source(data))
            self.assertEqual(receipt['spdx'], 'Artistic-2.0')
            (root / 'out/package/LICENSE').unlink()
            with self.assertRaises(prepare.Rejected):
                prepare.license_receipt(root / 'out', self.source(data))

    def test_bun_notice_keeps_its_linked_library_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); notice = root / 'LICENSE.md'
            data = b'Bun itself is MIT-licensed.\nJavaScriptCore is LGPL-2 licensed.\nLinked libraries have additional licenses.\n'
            notice.write_bytes(data)
            source = self.source(b'owned zip', 'bun')
            source.update(licensePath=str(notice), licenseSHA256=hashlib.sha256(data).hexdigest())
            receipt = prepare.license_receipt(root, source)
            self.assertEqual(receipt['scope'], 'Bun itself; linked-library notices retained separately')

    def test_zip_case_and_size_bounds(self):
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w') as archive:
            archive.writestr('bun-linux-x64/bun', b'owned inert')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); archive = root / 'tool.zip'; archive.write_bytes(out.getvalue())
            source = self.source(out.getvalue(), 'bun')
            prepare.extract(archive, root / 'out', source, prepare.Budget())
            self.assertEqual((root / 'out/bun-linux-x64/bun').read_bytes(), b'owned inert')


if __name__ == '__main__':
    unittest.main()
