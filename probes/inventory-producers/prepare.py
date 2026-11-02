#!/usr/bin/env python3
"""Acquire pinned official fixture producers as data; never executes a producer."""
import argparse
from dataclasses import asdict, dataclass
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import time
import urllib.parse
import urllib.request
import zipfile

MAX_COMPRESSED = 512 << 20
MAX_EXTRACTED = 2 << 30
VERSIONS = {'npm': {'8.19.4', '10.9.4', '11.6.2'}, 'bun': {'1.3.2', '1.4.2'}}


class Rejected(Exception):
    pass


def require(value, code):
    if not value:
        raise Rejected(code)


@dataclass
class Budget:
    compressed: int = 0
    extracted: int = 0

    def reserve_compressed(self, count):
        require(0 <= count <= MAX_COMPRESSED - self.compressed, 'compressed-limit')
        self.compressed += count

    def reserve_extracted(self, count):
        require(0 <= count <= MAX_EXTRACTED - self.extracted, 'expanded-limit')
        self.extracted += count


def check_source(s):
    kind, version = s.get('kind'), s.get('version')
    require(kind in VERSIONS and version in VERSIONS[kind], 'producer-version')
    url = (f'https://registry.npmjs.org/npm/-/npm-{version}.tgz' if kind == 'npm' else
           f'https://github.com/oven-sh/bun/releases/download/bun-v{version}/bun-linux-x64.zip')
    algorithm = 'sha512' if kind == 'npm' else 'sha256'
    require(s.get('url') == url and s.get('algorithm') == algorithm, 'producer-origin')
    require(isinstance(s.get('size'), int) and 0 < s['size'] <= (16 << 20 if kind == 'npm' else 192 << 20), 'producer-size')
    require(isinstance(s.get('digest'), str) and re.fullmatch('[0-9a-f]{' + str(hashlib.new(algorithm).digest_size * 2) + '}', s['digest']), 'producer-digest')
    require(s.get('license') == ('Artistic-2.0' if kind == 'npm' else 'MIT'), 'producer-license')
    runtime = s.get('runtime')
    require(isinstance(runtime, dict) and re.fullmatch(r'v\d+\.\d+\.\d+', runtime.get('version', '')) and
            re.fullmatch('[0-9a-f]{64}', runtime.get('sha256', '')), 'runtime-missing')
    major, minor, _ = map(int, runtime['version'][1:].split('.'))
    minimum = {'8.19.4': (16, 0), '10.9.4': (20, 5), '11.6.2': (22, 9)}
    if kind == 'npm':
        require((major, minor) >= minimum[version], 'runtime-unqualified')


def allowed_redirect(kind, url):
    p = urllib.parse.urlsplit(url)
    hosts = {'registry.npmjs.org'} if kind == 'npm' else {'github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'}
    return p.scheme == 'https' and p.hostname in hosts and p.port in (None, 443) and p.username is None and p.password is None


class RedirectGuard(urllib.request.HTTPRedirectHandler):
    def __init__(self, kind):
        self.kind, self.count = kind, 0

    def redirect_request(self, request, fp, code, message, headers, newurl):
        self.count += 1
        require(self.count <= 3 and allowed_redirect(self.kind, newurl), 'producer-redirect')
        return super().redirect_request(request, fp, code, message, headers, newurl)


def verify_bytes(data, source):
    require(len(data) == source['size'] and hashlib.new(source['algorithm'], data).hexdigest() == source['digest'], 'producer-bytes-digest')


def download(source, target, budget):
    check_source(source)
    budget.reserve_compressed(source['size'] + 1)  # Includes the overlength sentinel.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), RedirectGuard(source['kind']))
    request = urllib.request.Request(source['url'], headers={'User-Agent': 'PackTrace-owned-inventory-fixtures/1', 'Accept-Encoding': 'identity'})
    h, count, deadline = hashlib.new(source['algorithm']), 0, time.monotonic() + 120
    with opener.open(request, timeout=30) as response, target.open('xb') as output:
        require(response.status == 200 and allowed_redirect(source['kind'], response.url), 'producer-response')
        while True:
            require(time.monotonic() < deadline, 'producer-deadline')
            chunk = response.read(min(131072, source['size'] - count + 1))
            if not chunk:
                break
            count += len(chunk)
            require(count <= source['size'], 'producer-size')
            h.update(chunk); output.write(chunk)
    require(count == source['size'] and h.hexdigest() == source['digest'], 'producer-bytes-digest')


class BoundedReader:
    def __init__(self, raw, allowance):
        self.raw, self.left = raw, allowance

    def read(self, size):
        require(0 <= size <= self.left, 'archive-envelope-limit')
        # Reserve before native decompression, including a failing read.
        self.left -= size
        return self.raw.read(size)


def member_path(name, prefix):
    require(isinstance(name, str) and 0 < len(name.encode('utf-8')) <= 4096 and not any(c in name for c in '\\:\x00'), 'archive-path')
    name = name.rstrip('/')
    parts = name.split('/')
    require(parts[0] == prefix and len(parts) <= 64 and all(p and p not in ('.', '..') for p in parts), 'archive-path')
    return PurePosixPath(*parts)


def extract(archive, destination, source, budget):
    check_source(source)
    destination.mkdir(mode=0o700, exist_ok=False)
    prefix = 'package' if source['kind'] == 'npm' else 'bun-linux-x64'
    seen, prefixes, count = set(), {}, 0

    def publish(name, directory, mode, size, reader):
        nonlocal count
        relative = member_path(name, prefix)
        folded = str(relative).casefold()
        count += 1
        require(count <= 100000 and folded not in seen, 'archive-collision-limit')
        seen.add(folded)
        for i in range(1, len(relative.parts) + 1):
            part = '/'.join(relative.parts[:i]); key = part.casefold()
            require(key not in prefixes or prefixes[key] == part, 'archive-ancestor-collision')
            prefixes[key] = part
        target = destination.joinpath(*relative.parts)
        if directory:
            target.mkdir(mode=0o700, parents=True, exist_ok=True)
            return
        require(0 <= size <= MAX_EXTRACTED, 'archive-file-size')
        budget.reserve_extracted(size)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(target, flags, 0o700 if mode & 0o111 else 0o600)
        with os.fdopen(fd, 'wb') as output:
            left = size
            while left:
                chunk = reader.read(min(left, 131072))
                require(chunk and len(chunk) <= left, 'archive-short-read')
                output.write(chunk); left -= len(chunk)
            require(not reader.read(1), 'archive-extra-data')

    try:
        if source['kind'] == 'npm':
            with archive.open('rb') as raw, gzip.GzipFile(fileobj=raw) as gz:
                with tarfile.open(fileobj=BoundedReader(gz, MAX_EXTRACTED), mode='r|') as tar:
                    for item in tar:
                        require(item.isdir() or item.isfile(), 'archive-type')
                        publish(item.name, item.isdir(), item.mode, item.size, None if item.isdir() else tar.extractfile(item))
        else:
            with zipfile.ZipFile(archive) as zipped:
                require(len(zipped.infolist()) <= 100000, 'archive-entry-limit')
                for item in zipped.infolist():
                    mode = item.external_attr >> 16
                    require(stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR) and not item.flag_bits & 1, 'archive-type')
                    if item.is_dir():
                        publish(item.filename, True, mode, 0, None)
                    else:
                        with zipped.open(item) as reader:
                            publish(item.filename, False, mode, item.file_size, reader)
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as e:
        raise Rejected('archive-unavailable') from e
    return {'entries': count}


def license_receipt(root, source):
    if source['kind'] == 'npm':
        path = root / 'package/LICENSE'
    else:
        require(source.get('licensePath') and re.fullmatch('[0-9a-f]{64}', source.get('licenseSHA256', '')), 'license-missing')
        path = Path(source['licensePath'])
    try:
        with path.open('rb') as stream:
            data = stream.read((512 << 10) + 1)
    except OSError as e:
        raise Rejected('license-missing') from e
    require(0 < len(data) <= 512 << 10, 'license-size')
    digest = hashlib.sha256(data).hexdigest()
    if source['kind'] == 'npm':
        require(b'artistic license 2.0' in data.lower(), 'license-unqualified')
    else:
        require(digest == source['licenseSHA256'] and b'bun itself is mit-licensed.' in data.lower() and b'javascriptcore' in data.lower() and b'lgpl' in data.lower(), 'license-unqualified')
    scope = 'npm package' if source['kind'] == 'npm' else 'Bun itself; linked-library notices retained separately'
    return {'spdx': source['license'], 'sha256': digest, 'bytes': len(data), 'scope': scope}


def prepare_one(source, root, budget):
    check_source(source)
    node = Path('/usr/bin/node')
    with node.open('rb') as runtime_file:
        require(hashlib.file_digest(runtime_file, 'sha256').hexdigest() == source['runtime']['sha256'], 'runtime-changed')
    root.mkdir(mode=0o700, exist_ok=False)
    archive = root / ('archive.tgz' if source['kind'] == 'npm' else 'archive.zip')
    download(source, archive, budget)
    extracted = root / 'tool'
    detail = extract(archive, extracted, source, budget)
    license_info = license_receipt(extracted, source)
    executable = extracted / ('package/bin/npm-cli.js' if source['kind'] == 'npm' else 'bun-linux-x64/bun')
    require(executable.is_file() and not executable.is_symlink(), 'producer-executable')
    with executable.open('rb') as f:
        executable_hash = hashlib.file_digest(f, 'sha256').hexdigest()
    receipt = dict(source=source, executable=str(executable), executableSHA256=executable_hash, license=license_info, extraction=detail, budget=asdict(budget), executed=False)
    (root / 'prepared.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sources', type=Path); parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    sources = json.loads(args.sources.read_text())
    require(isinstance(sources, list) and len(sources) == 5 and {(s.get('kind'), s.get('version')) for s in sources} == {(k, v) for k, vs in VERSIONS.items() for v in vs}, 'source-set')
    args.destination.mkdir(mode=0o700, exist_ok=False)
    budget = Budget()
    for source in sources:
        prepare_one(source, args.destination / (source['kind'] + '-' + source['version']), budget)


if __name__ == '__main__':
    main()
