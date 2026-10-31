"""Owned Windows preparation for the explicitly authorized manual profile only."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import subprocess
import sys
import urllib.request
import zipfile

SIZE = 78931360
SHA = 'a3911b5e0e1b1053f25ed0675f4c1c6aad1e2bfcf253df2b9be4caabd2edd95d'
URL = 'https://go.dev/dl/go1.27.1.windows-amd64.zip'
FINAL = 'https://dl.google.com/go/go1.27.1.windows-amd64.zip'


def archive_name(name):
    p = PurePosixPath(name)
    if (not name or '\\' in name or '\x00' in name or ':' in name or
            p.is_absolute() or not p.parts or p.parts[0] != 'go' or
            any(x in ('', '.', '..') for x in name.rstrip('/').split('/')) or
            len(p.parts) > 128 or len(name) > 4096):
        raise ValueError('sdk-member-path')
    for part in p.parts:
        base = part.split('.', 1)[0].rstrip(' ').upper()
        if (part.endswith(('.', ' ')) or any(c in part for c in '<>"|?*') or
                base in ('CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$') or
                re.fullmatch(r'(COM|LPT)[1-9]', base)):
            raise ValueError('sdk-member-alias')
    return p.parts


def extract(archive, destination):
    total = 0
    with zipfile.ZipFile(archive) as z:
        members = z.infolist()
        if len(members) > 25000:
            raise ValueError('sdk-member-limit')
        seen = set()
        for member in members:
            parts = archive_name(member.filename)
            key = '/'.join(parts).casefold()
            if key in seen:
                raise ValueError('sdk-collision')
            seen.add(key)
            total += member.file_size
            if total > 512 << 20 or member.file_size > 128 << 20:
                raise ValueError('sdk-expansion-limit')
            mode = member.external_attr >> 16
            if mode & 0o170000 not in (0, 0o100000, 0o040000):
                raise ValueError('sdk-member-type')
            target = destination.joinpath(*parts)
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(member) as source, target.open('xb') as output:
                remaining = member.file_size
                while remaining:
                    b = source.read(min(65536, remaining))
                    if not b:
                        raise ValueError('sdk-short-member')
                    output.write(b)
                    remaining -= len(b)
                if source.read(1):
                    raise ValueError('sdk-long-member')
    return total


class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        if newurl != FINAL:
            raise ValueError('sdk-redirect')
        return super().redirect_request(request, fp, code, message, headers, newurl)


def main():
    if (len(sys.argv) != 2 or sys.platform != 'win32' or platform.machine().lower() not in ('amd64', 'x86_64') or
            os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch' or
            os.environ.get('GITHUB_REPOSITORY') != 'landroval/PackTrace' or
            os.environ.get('ImageOS') != 'win22' or
            not re.fullmatch('[0-9a-f]{40}', os.environ.get('SOURCE_SHA', '')) or
            os.environ['SOURCE_SHA'] != os.environ.get('EXPECTED_SHA')):
        raise ValueError('environment-outside-profile')
    root = Path(sys.argv[1])
    archive = root/'go.zip'
    digest = hashlib.sha256()
    used = 0
    opener = urllib.request.build_opener(Redirect())
    with opener.open(URL, timeout=30) as response, archive.open('xb') as output:
        if response.geturl() not in (URL, FINAL):
            raise ValueError('sdk-final-url')
        while True:
            b = response.read(min(65536, SIZE + 1 - used))
            if not b:
                break
            used += len(b)
            if used > SIZE:
                raise ValueError('sdk-byte-limit')
            digest.update(b)
            output.write(b)
    if used != SIZE or digest.hexdigest() != SHA:
        raise ValueError('sdk-identity')
    toolchain = root/'toolchain'
    toolchain.mkdir()
    expanded = extract(archive, toolchain)
    go = toolchain/'go/bin/go.exe'
    env = dict(os.environ, GOTOOLCHAIN='local', GOPROXY='off', GOSUMDB='off', GOWORK='off', GOENV='off',
               GOMAXPROCS='2', GOMEMLIMIT='512MiB', CGO_ENABLED='0', GOCACHE=str(root/'cache'), GOTMPDIR=str(root/'build'))
    cc = shutil.which('gcc')
    if not cc:
        cc = next((p for p in (r'C:\msys64\mingw64\bin\gcc.exe', r'C:\mingw64\bin\gcc.exe',
                              r'C:\msys64\ucrt64\bin\gcc.exe') if Path(p).is_file()), None)
    if not cc:
        raise ValueError('preinstalled-c-compiler-unavailable')
    env.update(GOROOT=str(toolchain/'go'), GOOS='windows', GOARCH='amd64', GOFLAGS='', GOEXPERIMENT='', GODEBUG='', GORACE='')
    env['PATH'] = str(Path(cc).parent) + os.pathsep + env['PATH']
    env['CC'] = str(cc)
    version = subprocess.run([str(go), 'version'], env=env, capture_output=True, check=True, timeout=15).stdout.decode().strip()
    if version != 'go version go1.27.1 windows/amd64':
        raise ValueError('sdk-version')
    runner = root/'controller.exe'
    subprocess.run([str(go), 'build', '-o', str(runner), './probes/offline-integrity/ci/windowsrunner'],
                   cwd=root/'source', env=env, check=True, timeout=240)
    (root/'prepared.json').write_text(json.dumps({'go': str(go), 'runner': str(runner), 'source': str(root/'source'),
                                                'root': str(root), 'cc': str(cc), 'sdkSHA256': SHA,
                                                'sdkBytes': SIZE, 'expandedBytes': expanded, 'version': version}))
    with open(os.environ['GITHUB_PATH'], 'a', encoding='utf-8') as f:
        f.write(str(Path(cc).parent)+'\n')
    print('WINDOWS_NATIVE_SETUP '+json.dumps({'sourceSHA': os.environ['SOURCE_SHA'], 'sdkSHA256': SHA,
                                            'sdkBytes': SIZE, 'expandedBytes': expanded, 'goVersion': version,
                                            'compiler': str(cc), 'os': platform.platform(),
                                            'imageOS': os.environ.get('ImageOS'), 'imageVersion': os.environ.get('ImageVersion')}))


if __name__ == '__main__':
    main()
