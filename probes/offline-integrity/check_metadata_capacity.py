#!/usr/bin/env python3
"""Owned offline capacity fixture; no full payload, producer or network.
Run from repository root with one NEW destination under a trusted owned parent.
"""
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
from prepare_corpus import metadata, encoded


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(data)


def author(base, count, references):
    base.mkdir()
    rows = dict(metadata(count))  # exact frozen B6 source originals
    lock = json.loads(rows['package-lock.json'])
    refs = []
    for i in range(count):
        name = f'fixture-{i:06d}'
        location = 'node_modules/' + name
        if references:
            # Actual miniature package archive, including original installed manifest.
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode='w', format=tarfile.USTAR_FORMAT) as tar:
                data = rows[location + '/package.json']
                info = tarfile.TarInfo('package/package.json')
                info.size, info.mode = len(data), 0o600
                tar.addfile(info, io.BytesIO(data))
            # Product's strict USTAR profile requires exactly two terminal zero
            # blocks, not tarfile's optional 10-KiB record padding. No entry
            # or content is omitted: one header + padded body + two blocks.
            tar_bytes = buf.getvalue()[:512 + ((len(data) + 511) // 512) * 512 + 1024]
            archive = gzip.compress(tar_bytes, mtime=0)
            sri = 'sha512-' + base64.b64encode(hashlib.sha512(archive).digest()).decode()
            origin = f'https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz'
            lock['packages'][location].update(resolved=origin, integrity=sri)
            filename = name + '.tgz'
            write(base / 'prepared' / filename, archive)
            refs.append(dict(location=location, lockKey=location, name=name,
                             version='1.0.0', origin=origin, classification='unknown',
                             expectedSRI=sri, archive=filename, context='none'))
    if references:
        rows['package-lock.json'] = encoded(lock)
    for path, data in rows.items():
        write(base / 'target' / path, data)
    policy = dict(version=1, designation='user-designated', reason='owned offline capacity check',
                  provenance='authored miniature archives; actual lock SRI; no publisher authenticity claim',
                  manager='npm@10.9.4', requiredChecks=['integrity'], failOn=['integrity'],
                  requireHardMemoryLimit=False, minimumAssurance='independently-anchored', references=refs)
    write(base / 'prepared' / 'policy.json', encoded(policy))


def main():
    base = Path(sys.argv[1])
    base.mkdir(exist_ok=False)
    for name, n, refs in [('b6-original-1000', 1000, False), ('checked-2', 2, True), ('checked-1000', 1000, True)]:
        author(base / name, n, refs)
    manifest = []
    for path in sorted(base.rglob('*')):
        if path.is_file():
            data = path.read_bytes()
            manifest.append(dict(path=str(path.relative_to(base)), bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
    write(base / 'manifest.json', encoded(manifest))


if __name__ == '__main__':
    main()
