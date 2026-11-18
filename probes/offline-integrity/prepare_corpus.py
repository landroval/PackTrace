#!/usr/bin/env python3
"""Deterministic inert B6 target preparation, not a scan or qualification runner.

Import/project perform no filesystem I/O. Only write_owned creates files, in a
new caller-owned destination; CLI materialization is miniature-only (32 MiB).
"""
import argparse
import hashlib
import json
from pathlib import Path

SCHEMA = 'packtrace.b6-offline-corpus.v1'
BLOCK = b'PackTrace owned inert B6 fixture; never execute.\n'
REFERENCE = (1000, 50000, 1 << 30)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')


def identity(index):
    return f'fixture-{index:06d}'


def metadata(instances):
    dependencies = {identity(i): '1.0.0' for i in range(instances)}
    root = dict(name='packtrace-b6-owned', version='1.0.0', private=True,
                dependencies=dependencies)
    packages = {'': dict(name=root['name'], version='1.0.0', dependencies=dependencies)}
    rows = [('package.json', encoded(root))]
    for i in range(instances):
        name = identity(i)
        package = dict(name=name, version='1.0.0')
        # No fake archive digest, registry authentication or producer provenance.
        packages['node_modules/' + name] = package
        rows.append((f'node_modules/{name}/package.json', encoded(package)))
    rows.append(('package-lock.json', encoded(dict(name=root['name'], version='1.0.0',
                                                 lockfileVersion=3, packages=packages))))
    return sorted(rows)


def layout(instances, files, target_bytes):
    if any(type(n) is not int or n <= 0 for n in (instances, files, target_bytes)):
        raise ValueError('positive integer dimensions required')
    if instances > 1000 or files > 50000 or target_bytes > 1 << 30:
        raise ValueError('dimensions exceed the fixed reference envelope')
    payload_files = files - instances - 2
    if payload_files < instances:
        raise ValueError('at least one payload file per instance required')
    rows = metadata(instances)
    metadata_bytes = sum(len(data) for _, data in rows)
    payload_bytes = target_bytes - metadata_bytes
    if payload_bytes < payload_files:
        raise ValueError('target bytes must cover metadata and nonempty payloads')
    return rows, payload_files, payload_bytes


def payload_paths(instances, payload_files):
    per_instance, extra = divmod(payload_files, instances)
    for i in range(instances):
        for j in range(per_instance + (i < extra)):
            yield f'node_modules/{identity(i)}/file-{j:06d}.txt'


def payload_chunks(size):
    """Bounded, deterministic bytes; no size-proportional allocation."""
    chunk = BLOCK * (65536 // len(BLOCK))
    while size:
        data = chunk[:min(size, len(chunk))]
        yield data
        size -= len(data)


def records(instances, files, target_bytes):
    rows, payload_files, payload_bytes = layout(instances, files, target_bytes)
    for path, data in rows:
        yield dict(path=path, kind='metadata', bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
    size, extra = divmod(payload_bytes, payload_files)
    digests = {}
    for ordinal, path in enumerate(payload_paths(instances, payload_files)):
        length = size + (ordinal < extra)
        if length not in digests:
            digest = hashlib.sha256()
            for chunk in payload_chunks(length):
                digest.update(chunk)
            digests[length] = digest.hexdigest()
        yield dict(path=path, kind='payload', bytes=length, sha256=digests[length])


def project(instances=1000, files=50000, target_bytes=1 << 30):
    """No-I/O projection: hashes at most two distinct small payload sizes at B6."""
    rows, payload_files, payload_bytes = layout(instances, files, target_bytes)
    sizes = {path: len(data) for path, data in rows}
    digest = hashlib.sha256()
    for row in records(instances, files, target_bytes):
        digest.update(encoded(row))
    manifest_bytes = sum(n for path, n in sizes.items() if path != 'package-lock.json')
    lock_bytes = sizes['package-lock.json']
    return dict(
        schema=SCHEMA, qualification='not-qualified; target-preparation-only',
        dimensions=dict(instances=instances, files=files, targetBytes=target_bytes),
        counts=dict(rootManifests=1, installedManifests=instances, lockfiles=1,
                    lockPackageEntries=instances + 1, lockedInstances=instances,
                    installedInstances=instances, identities=instances,
                    payloadFiles=payload_files, expectedFileRecords=files,
                    directories=instances + 2),
        bytes=dict(target=target_bytes, metadata=target_bytes - payload_bytes,
                   payload=payload_bytes, rootManifest=sizes['package.json'],
                   installedManifests=manifest_bytes - sizes['package.json'],
                   lockfile=lock_bytes, rawManifestAndLockReceipts=manifest_bytes + lock_bytes,
                   base64ManifestAndLockData=sum(4 * ((n + 2) // 3) for n in sizes.values())),
        payload=dict(patternASCII=BLOCK.decode('ascii'),
                     smallFileBytes=payload_bytes // payload_files,
                     largeFileCount=payload_bytes % payload_files),
        expectedWork=dict(inventoryInstalledObservations=instances,
                          inventoryLockedObservations=instances,
                          candidateIntegrityFileComparisons=files - 2,
                          candidateIntegrityBytes=target_bytes - sizes['package.json'] - lock_bytes,
                          advisoryDecisions=None, referenceArchives=None,
                          preparedIntelligence=False, preparedAuthenticatedReferences=False),
        contract=dict(recordEncoding='ASCII sorted-key compact JSON plus LF',
                      recordOrder='metadata paths sorted, then payload instance/file numeric order',
                      recordFields=['bytes', 'kind', 'path', 'sha256'],
                      recordsSHA256=digest.hexdigest(),
                      scope='regular target file paths, logical sizes and content hashes only; not filesystem metadata or authenticity'))


def write_owned(destination, instances, files, target_bytes):
    """New trusted owned path only; not an untrusted-path containment API.

    Never merges, follows existing corpus entries, cleans up, or emits a report
    inside the target. Failure leaves an explicitly partial directory for review.
    """
    result = project(instances, files, target_bytes)  # validate before mutation
    destination = Path(destination)
    destination.mkdir(exist_ok=False)
    rows, payload_files, payload_bytes = layout(instances, files, target_bytes)
    for path, data in rows:
        output = destination / path
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open('xb') as stream:
            stream.write(data)
    size, extra = divmod(payload_bytes, payload_files)
    for ordinal, path in enumerate(payload_paths(instances, payload_files)):
        with (destination / path).open('xb') as stream:
            for chunk in payload_chunks(size + (ordinal < extra)):
                stream.write(chunk)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--instances', type=int, default=REFERENCE[0])
    parser.add_argument('--files', type=int, default=REFERENCE[1])
    parser.add_argument('--target-bytes', type=int, default=REFERENCE[2])
    parser.add_argument('--write-owned', type=Path,
                        help='new destination under a trusted owned parent; miniature only')
    args = parser.parse_args()
    try:
        if args.write_owned is not None:
            if args.target_bytes > 32 << 20:
                raise ValueError('CLI writes are miniature-only, at most 32 MiB; full B6 preparation needs separate authority')
            result = write_owned(args.write_owned, args.instances, args.files, args.target_bytes)
        else:
            result = project(args.instances, args.files, args.target_bytes)
    except (ValueError, OSError) as error:
        parser.exit(1, f'preparation failed (any created tree is partial): {error}\n')
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
