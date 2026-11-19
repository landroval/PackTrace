#!/usr/bin/env python3
"""Replay ONLY a retained public pilot copy; no producer, network, or pin creation.

Usage: python3 replay_public_pilot.py OLD_EVIDENCE EXACT_BINARY NEW_EVIDENCE
OLD_EVIDENCE must contain owned-case, owned.baseline.json and policy.pin from the
160-reference pilot. This tests consistency, not independent policy/publisher trust.
NEW_EVIDENCE must not exist. Source files are never changed. All controls restore
our copy, retain real process statuses and verify before/after input snapshots.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(root):
    result = {}
    for p in sorted(root.rglob('*')):
        mode = p.lstat().st_mode
        name = str(p.relative_to(root))
        if stat.S_ISREG(mode):
            result[name] = digest(p)
        elif stat.S_ISLNK(mode):
            result[name] = {'symlink': os.readlink(p)}
        elif not stat.S_ISDIR(mode):
            raise RuntimeError(f'nonordinary input: {p}')
    return result


def save(root, name, value):
    (root / name).write_text(json.dumps(value, indent=2) + '\n')


def replay(source, executable, out):
    source, executable, out = source.resolve(), executable.resolve(), out.absolute()
    if out == source or source in out.parents or out == executable or executable in out.parents:
        raise ValueError('evidence output must be separate from source and executable')
    baseline = json.loads((source / 'owned.baseline.json').read_text())
    original = {d: snapshot(source / 'owned-case' / d) for d in ('target', 'references')}
    if original != baseline:
        raise ValueError('retained pilot is not restored')
    if any(not isinstance(v, str) for files in original.values() for v in files.values()):
        raise ValueError('retained pilot must contain ordinary files only')
    pin = (source / 'policy.pin').read_text().strip()
    raw = (source / 'owned-case/references/policy.json').read_bytes()
    # Check the EXISTING pin. Never create or substitute a policy trust anchor.
    alg, encoded = pin.split('-', 1)
    if base64.b64encode(hashlib.new(alg, raw).digest()).decode() != encoded:
        raise ValueError('existing pin does not match retained policy')
    refs = json.loads(raw)['references']
    if len(refs) != 160:
        raise ValueError('expected the existing 160-reference public pilot')
    sri_rows = []
    for i, ref in enumerate(refs, 1):
        archive = ref['archive']
        if Path(archive).is_absolute() or '..' in Path(archive).parts:
            raise ValueError('archive escapes retained reference root')
        data = (source / 'owned-case/references' / archive).read_bytes()
        tokens = ref['expectedSRI'].split()
        matches = [token for token in tokens if token.split('-', 1)[0] in ('sha256', 'sha384', 'sha512')
                   and base64.b64encode(hashlib.new(token.split('-', 1)[0], data).digest()).decode() == token.split('-', 1)[1]]
        if len(matches) != len(tokens) or not matches:
            raise ValueError(f'original archive SRI mismatch: {i}')
        sri_rows.append({'instance': i, 'archive': archive, 'verifiedSRI': matches})
    out.mkdir(mode=0o700)  # Refuse overwrite/reuse of previous evidence.
    case = out / 'owned-case'
    shutil.copytree(source / 'owned-case', case)
    binary = out / 'packtrace'
    binary_hash = digest(executable)
    shutil.copy2(executable, binary)
    if digest(binary) != binary_hash:
        raise RuntimeError('exact executable changed during copying')
    (out / 'binary.sha256').write_text(binary_hash + '  packtrace\n')
    (out / 'policy.pin').write_text(pin + '\n')
    save(out, 'all-160-sri.json', sri_rows)
    target, references = case / 'target', case / 'references'

    def inputs():
        return {d: snapshot(case / d) for d in ('target', 'references')}

    def run(label, expected, drift, modify=None):
        if inputs() != baseline or digest(binary) != binary_hash:
            raise RuntimeError('copy or executable changed before control')
        restore = []

        def change(path, body):
            old = path.read_bytes()
            restore.append(lambda: path.write_bytes(old))
            path.write_bytes(body)

        def absent(path):
            held = out / 'held-reference'
            if held.exists():
                raise RuntimeError('held reference already exists')
            path.rename(held)
            restore.append(lambda: held.rename(path))

        try:
            if modify:
                modify(change, absent)
            before = inputs()
            save(out, label + '.before.json', before)
            argv = [str(binary), 'verify-integrity', '--policy', str(references / 'policy.json'),
                    '--trusted-policy-digest', pin, str(target)]
            save(out, label + '.argv.json', argv)
            start = time.monotonic()
            with (out / (label + '.stdout')).open('wb') as stdout, (out / (label + '.stderr')).open('wb') as stderr:
                process = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, timeout=155)
            after = inputs()
            (out / (label + '.status')).write_text(str(process.returncode) + '\n')
            save(out, label + '.after.json', after)
            row = {'label': label, 'actualExit': process.returncode, 'expectedExit': expected,
                   'inputsUnchanged': before == after, 'binarySHA256': binary_hash,
                   'seconds': time.monotonic() - start}
            save(out, label + '.result.json', row)
            text = (out / (label + '.stdout')).read_text()
            if process.returncode != expected or before != after or f'drift findings: {drift}\n' not in text:
                raise RuntimeError(f'control failed: {row}; stdout={text!r}')
            if 'comparison: incomplete;' not in text:
                raise RuntimeError('ambiguous resolve ownership must remain incomplete')
            print(json.dumps(row), flush=True)
        finally:
            for undo in reversed(restore):
                undo()
            if inputs() != baseline or digest(binary) != binary_hash:
                raise RuntimeError('control did not restore our copy')

    express = target / 'node_modules/express/index.js'
    missing = references / refs[-1]['archive']
    mutate_express = lambda change, absent: change(express, b'/* inert offline drift control */\n')
    run('01-intact', 3, 0)
    run('02-express', 3, 1, mutate_express)
    run('03-missing', 3, 0, lambda change, absent: absent(missing))
    run('04-mixed', 3, 1, lambda change, absent: (absent(missing), mutate_express(change, absent)))
    run('05-restored', 3, 0)
    paths = {3: 'index.d.ts', 4: 'index.d.ts', 5: 'index.d.ts', 6: 'assert.d.ts',
             7: 'index.d.ts', 40: 'lib/ejs.js', 49: 'index.js', 97: 'lib/jake.js', 99: 'src/index.js'}
    for i, relative in paths.items():
        path = target / refs[i - 1]['location'] / relative
        run(f'archive-{i:03}', 3, 1, lambda change, absent, p=path: change(p, p.read_bytes() + b'\n/* inert control */\n'))
    util = target / 'node_modules/resolve/test/shadowed_core/node_modules/util/index.js'
    # Original identical manifestless subtree: the intact control already proves
    # equality cannot close ownership. Changing it must not invent a comparison.
    run('ownership-modified', 3, 0, lambda change, absent: change(util, b'/* inert ambiguous bytes */\n'))
    run('ownership-missing', 3, 0, lambda change, absent: absent(util))
    run('99-final-intact', 3, 0)
    if original != {d: snapshot(source / 'owned-case' / d) for d in ('target', 'references')}:
        raise RuntimeError('original retained pilot changed')
    save(out, 'replay-summary.json', {'controls': 17, 'references': 160, 'sourceUnchanged': True,
                                    'copyRestored': True, 'binarySHA256': binary_hash,
                                    'remainingConstraint': 'resolve manifestless package-shaped ownership is ambiguous',
                                    'trust': 'retained experimental pin; not independent publisher or installation evidence'})


if __name__ == '__main__':
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    replay(*(Path(arg) for arg in sys.argv[1:]))
