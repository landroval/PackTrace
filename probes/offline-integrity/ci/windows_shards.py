"""Offline preparation/verification only; never dispatches or acquires an SDK."""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat

SHARDS = ('0', '1', '2')
CAP = 4 << 20
COMPATIBILITY = 'windows11-x64-compat-arm64-v1'
PACKAGE = re.compile(r'packtrace(?:/[A-Za-z0-9_.-]+)*\Z')
NAME = re.compile(r'(Test|Example|Fuzz)\w*\Z')


def select_shard(env):
    value = env.get('CORPUS_SHARD', '')
    if value in ('', 'unsharded'):
        return None
    if env.get('VALIDATION_PROFILE') == COMPATIBILITY and value in SHARDS:
        return int(value)
    raise ValueError('unsupported-corpus-shard')


def shard_index(name):
    # Match the Go controller: duplicate names in different packages stay together.
    return int.from_bytes(hashlib.sha256(name.encode('utf-8')).digest()[:8], 'big') % 3


def _json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate-shard-json-field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def _events(raw):
    if not raw or len(raw) > CAP or not raw.endswith(b'\n'):
        raise ValueError('incomplete-corpus-stream')
    events = []
    for line in raw.splitlines():
        if len(line) > 1 << 20:
            raise ValueError('corpus-event-limit')
        event = _json(line)
        if not isinstance(event, dict) or event.get('Action') in ('fail', 'build-fail'):
            raise ValueError('failed-corpus-stream')
        events.append(event)
    return events


def _packages(events):
    packages = {}
    for event in events:
        action, package = event.get('Action'), event.get('Package', '')
        if action == 'build-output':
            continue
        if (not isinstance(package, str) or len(package) > 512 or not PACKAGE.fullmatch(package)
                or any(part in ('.', '..') for part in package.split('/'))):
            raise ValueError('invalid-corpus-package')
        if action == 'start':
            if package in packages or event.get('Test'):
                raise ValueError('duplicate-corpus-package')
            packages[package] = False
        elif action in ('pass', 'skip') and not event.get('Test'):
            if package not in packages or packages[package]:
                raise ValueError('duplicate-corpus-package-terminal')
            packages[package] = True
        elif action in ('run', 'pass', 'skip', 'output', 'pause', 'cont'):
            if package not in packages or packages[package]:
                raise ValueError('event-outside-corpus-package')
        else:
            raise ValueError('invalid-corpus-action')
    if not packages or not all(packages.values()):
        raise ValueError('incomplete-corpus-packages')
    return packages


def inventory(raw):
    events = _events(raw)
    _packages(events)
    tests = set()
    for event in events:
        if event.get('Test'):
            raise ValueError('inventory-ran-a-test')
        if event.get('Action') != 'output':
            continue
        output = event.get('Output', '')
        if not isinstance(output, str):
            raise ValueError('invalid-inventory-output')
        for name in output.splitlines():
            if not name.startswith(('Test', 'Example', 'Fuzz')):
                continue
            key = event['Package']+'#'+name
            if not NAME.fullmatch(name) or len(name.encode('utf-8')) > 256 or key in tests or len(tests) >= 10000:
                raise ValueError('invalid-or-duplicate-test-inventory')
            tests.add(key)
    if not tests:
        raise ValueError('empty-test-inventory')
    return sorted(tests)


def inventory_digest(tests):
    return hashlib.sha256(('\n'.join(tests)+'\n').encode('utf-8')).hexdigest()


def verify_coverage(tests, raw, index, required):
    if index not in range(3) or len(tests) != len(set(tests)) or not set(required) <= set(tests):
        raise ValueError('invalid-shard-inventory-or-required-cases')
    selected = sorted(key for key in tests if shard_index(key.split('#')[1]) == index)
    if not selected:
        raise ValueError('empty-shard')
    events = _events(raw)
    packages = _packages(events)
    if not {key.split('#')[0] for key in tests} <= set(packages):
        raise ValueError('omitted-corpus-package')
    runs, terminal = set(), {}
    for event in events:
        name = event.get('Test', '')
        if not name:
            continue
        if not isinstance(name, str) or len(name.encode('utf-8')) > 4096:
            raise ValueError('invalid-shard-test-name')
        key = event['Package']+'#'+name
        top = event['Package']+'#'+name.split('/')[0]
        if top not in selected:
            raise ValueError('unexpected-or-overlapping-shard-test')
        if event['Action'] == 'run':
            if key in runs:
                raise ValueError('duplicate-shard-test')
            runs.add(key)
        elif event['Action'] in ('pass', 'skip'):
            if key not in runs or key in terminal:
                raise ValueError('invalid-shard-terminal')
            terminal[key] = event['Action']
    if runs != set(terminal) or not set(selected) <= set(terminal):
        raise ValueError('missing-shard-test-or-terminal')
    expected = sorted(set(selected) & set(required))
    if any(terminal[key] != 'pass' for key in expected) or not any(value == 'pass' for value in terminal.values()):
        raise ValueError('required-shard-case-not-passed')
    return dict(selected=selected, skipped=sorted(key for key in selected if terminal[key] == 'skip'),
                requiredPassed=expected, counts=dict(passed=sum(value == 'pass' for value in terminal.values()),
                                                   skipped=sum(value == 'skip' for value in terminal.values())))


def aggregate(parts, expected_head, expected_tree, required):
    # Acquisition/dispatch is deliberately absent. Caller independently pins the
    # expected source; matching receipts never authenticate a publisher/host.
    from windows_setup import SIZE, SHA
    if (not re.fullmatch('[0-9a-f]{40}', expected_head) or not re.fullmatch('[0-9a-f]{40}', expected_tree)
            or len(parts) != 3 or not required or len(required) != len(set(required))):
        raise ValueError('incomplete-or-unpinned-corpus-shards')
    common, observed, seen, results = None, set(), set(), []
    try:
        for part in parts:
            setup, receipt = part['setup'], part['receipt']
            value = receipt['CorpusShard']
            if value not in SHARDS or value in seen:
                raise ValueError('missing-or-duplicate-corpus-shard')
            seen.add(value)
            index = int(value)
            facts = setup['windowsFacts']
            if (setup['sourceSHA'] != expected_head or setup['sdkBytes'] != SIZE or setup['sdkSHA256'] != SHA
                    or setup['goVersion'] != 'go version go1.27.1 windows/amd64'
                    or setup['compatibilityOnly'] is not True or setup['corpusShard'] != value
                    or facts['major'] != 10 or facts['build'] < 22000 or facts['product_type'] != 1
                    or facts['native_machine'] != 0xaa64):
                raise ValueError('unqualified-shard-setup')
            if (receipt['Schema'] != 'packtrace.windows-native.v1' or receipt['SourceSHA'] != expected_head
                    or receipt['Tree'] != expected_tree or receipt['GoVersion'] != setup['goVersion']
                    or receipt['Setup'] != 'passed' or receipt.get('Failure')
                    or receipt['Native'] != 'emulated-shard-commands-passed-not-full-compatibility'
                    or receipt['Qualification'] != 'not-qualified-native-windows11-x64'
                    or receipt['CorpusShardCommandsPassed'] is not True
                    or receipt['ValidationPassed'] is not False or receipt.get('CompatibilityPassed', False) is not False
                    or receipt['HostArchitectureQuerySucceeded'] is not True
                    or receipt['ProcessArchitecture'] != 'amd64' or receipt['HostMachine'] != 0xaa64
                    or receipt['BoundSeconds'] != 900 or receipt['CommitLimitBytes'] != 2 << 30):
                raise ValueError('unqualified-shard-receipt')
            phases = receipt['Phases']
            names = ['source', 'go-version', 'harness-self-check', 'corpus-inventory', 'root-corpus', 'vet', 'source-clean']
            if [phase['Name'] for phase in phases] != names:
                raise ValueError('missing-duplicate-or-unexpected-shard-phase')
            for phase in phases:
                if (phase['State'] != 'exited' or phase['Exit'] != 0 or phase['Reaped'] is not True
                        or phase['GroupClean'] is not True or phase['CaptureComplete'] is not True
                        or type(phase['Seconds']) not in (int, float)
                        or not math.isfinite(phase['Seconds']) or not 0 <= phase['Seconds'] <= 900):
                    raise ValueError('incomplete-shard-original-process-or-capture')
            if (sum(phase['Seconds'] for phase in phases) > 890
                    or phases[3]['Seconds'] + phases[4]['Seconds'] > 700 or phases[-1]['StdoutBytes'] != 0):
                raise ValueError('shard-budget-or-clean-source-unconfirmed')
            for phase, raw in ((phases[3], part['inventory']), (phases[4], part['tests'])):
                if len(raw) != phase['StdoutBytes'] or hashlib.sha256(raw).hexdigest() != phase['StdoutSHA256']:
                    raise ValueError('shard-captured-stream-mismatch')
            tests = inventory(part['inventory'])
            if (receipt['CorpusInventorySHA256'] != inventory_digest(tests)
                    or receipt['CorpusInventoryCount'] != len(tests) or common is not None and tests != common):
                raise ValueError('mismatched-shard-inventories')
            common = tests
            result = verify_coverage(tests, part['tests'], index, required)
            pattern = '^('+'|'.join(sorted({key.split('#')[1] for key in result['selected']}))+')$'
            if receipt['CorpusShardPattern'] != pattern or len(pattern.encode('utf-8')) > 16 << 10:
                raise ValueError('shard-selector-mismatch')
            counts = phases[4]['Counts']
            cases = phases[4]['IntelligenceCases']
            if (counts != dict(Passed=result['counts']['passed'], Skipped=result['counts']['skipped'], Failed=0, BuildFailed=0)
                    or len(cases) != len(set(cases)) or sorted(cases) != result['requiredPassed']):
                raise ValueError('shard-terminal-or-required-case-mismatch')
            if observed & set(result['selected']):
                raise ValueError('overlapping-corpus-shards')
            observed.update(result['selected'])
            results.append(dict(shard=value, topLevelTests=len(result['selected']), skipped=result['skipped'],
                                counts=result['counts'], requiredPassed=result['requiredPassed']))
    except (KeyError, TypeError, AttributeError, UnicodeError, OverflowError) as error:
        raise ValueError('invalid-corpus-shard-evidence') from error
    if seen != set(SHARDS) or observed != set(common):
        raise ValueError('incomplete-corpus-shard-union')
    return dict(schema='packtrace.windows-corpus-shards.v1', sourceSHA=expected_head, tree=expected_tree,
                corpusPassed=True, compatibilityOnly=True, validationPassed=False,
                qualification='emulated-full-corpus-not-native-x64', topLevelTests=len(common),
                inventorySHA256=inventory_digest(common), requiredCases=sorted(required),
                shards=sorted(results, key=lambda result: result['shard']))


def _read(path, cap):
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    with os.fdopen(os.open(path, flags), 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > cap:
            raise ValueError('shard-artifact-type-or-limit')
        raw = source.read(cap+1)
    if len(raw) > cap:
        raise ValueError('shard-artifact-limit')
    return raw


def required_cases():
    source = _read(Path(__file__).with_name('windowsrunner')/'stream.go', 64 << 10).decode('utf-8')
    match = re.search(r'var requiredIntelligenceCases = \[\]string\{(.*?)\n\}', source, re.S)
    if not match:
        raise ValueError('required-case-declaration-missing')
    cases = re.findall(r'"([^"\n]+)"', match.group(1))
    if not cases or len(cases) != len(set(cases)):
        raise ValueError('invalid-required-case-declaration')
    return cases


def main(argv=None):
    # Run from the independently pinned source checkout. No GitHub/network,
    # credential access, acquisition or dispatch exists in this verifier.
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--expected-tree', required=True)
    parser.add_argument('directories', type=Path, nargs=3)
    args = parser.parse_args(argv)
    try:
        parts = [dict(setup=_json(_read(path/'windows_native_setup.json', 64 << 10)),
                      receipt=_json(_read(path/'windows_native_receipt.json', 64 << 10)),
                      inventory=_read(path/'corpus-inventory-stdout.jsonl', CAP),
                      tests=_read(path/'root-corpus-stdout.jsonl', CAP)) for path in args.directories]
        result = aggregate(parts, args.expected_head, args.expected_tree, required_cases())
    except (OSError, ValueError, UnicodeError):
        print(json.dumps(dict(corpusPassed=False, validationPassed=False, failure='unqualified-corpus-shards')))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
