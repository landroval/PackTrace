import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import windows_shards as shards


def encode(events):
    return b''.join(json.dumps(event, ensure_ascii=False).encode()+b'\n' for event in events)


def listing(names):
    return encode([dict(Action='start', Package='packtrace/owned')]+
                  [dict(Action='output', Package='packtrace/owned', Output=name+'\n') for name in names]+
                  [dict(Action='pass', Package='packtrace/owned')])


def execution(tests, index):
    selected = [key for key in tests if shards.shard_index(key.split('#')[1]) == index]
    rows = [dict(Action='start', Package='packtrace/owned')]
    for key in selected:
        package, name = key.split('#')
        rows += [dict(Action='run', Package=package, Test=name), dict(Action='pass', Package=package, Test=name)]
    rows.append(dict(Action='pass', Package='packtrace/owned'))
    return encode(rows)


class CompleteShards(unittest.TestCase):
    def setUp(self):
        self.names = ['TestOwned'+str(i) for i in range(60)]+['Example', 'FuzzOwned', 'TestÑame']
        self.raw = listing(self.names)

    def parts(self):
        import windows_setup as setup
        tests = shards.inventory(self.raw)
        result = []
        for index in range(3):
            raw = execution(tests, index)
            coverage = shards.verify_coverage(tests, raw, index, tests)
            phases = []
            for name in ('source', 'go-version', 'harness-self-check', 'corpus-inventory', 'root-corpus', 'vet', 'source-clean'):
                data = self.raw if name == 'corpus-inventory' else raw if name == 'root-corpus' else b''
                phase = dict(Name=name, State='exited', Exit=0, Seconds=1, Reaped=True, GroupClean=True, CaptureComplete=True,
                             StdoutBytes=len(data), StdoutSHA256=hashlib.sha256(data).hexdigest(), StderrBytes=0,
                             StderrSHA256=hashlib.sha256(b'').hexdigest())
                if name == 'root-corpus':
                    phase['Counts'] = dict(Passed=coverage['counts']['passed'], Failed=0, Skipped=0, BuildFailed=0)
                    phase['IntelligenceCases'] = coverage['requiredPassed']
                phases.append(phase)
            receipt = dict(Schema='packtrace.windows-native.v1', SourceSHA='a'*40, Tree='b'*40,
                           GoVersion='go version go1.27.1 windows/amd64', Setup='passed',
                           Native='emulated-shard-commands-passed-not-full-compatibility',
                           Qualification='not-qualified-native-windows11-x64', ValidationPassed=False, CompatibilityPassed=False,
                           CorpusShardCommandsPassed=True, CorpusShard=str(index), CorpusInventoryCount=len(tests),
                           CorpusShardPattern='^('+'|'.join(sorted({key.split('#')[1] for key in coverage['selected']}))+')$',
                           CorpusInventorySHA256=shards.inventory_digest(tests), HostArchitectureQuerySucceeded=True,
                           ProcessArchitecture='amd64', HostMachine=0xaa64, BoundSeconds=900, CommitLimitBytes=2<<30,
                           Phases=phases)
            result.append(dict(setup=dict(sourceSHA='a'*40, sdkBytes=setup.SIZE, sdkSHA256=setup.SHA,
                                          goVersion=receipt['GoVersion'], compatibilityOnly=True, corpusShard=str(index),
                                          windowsFacts=dict(major=10, build=26200, product_type=1, native_machine=0xaa64)),
                               receipt=receipt, inventory=self.raw, tests=raw))
        return result

    def test_only_complete_matching_three_shards_can_aggregate(self):
        tests = shards.inventory(self.raw)
        parts = self.parts()
        result = shards.aggregate(parts, 'a'*40, 'b'*40, tests)
        self.assertTrue(result['corpusPassed'])
        self.assertFalse(result['validationPassed'])
        self.assertEqual(result['topLevelTests'], len(tests))
        for bad in (parts[:1], parts[:2], [parts[0], parts[0], parts[2]]):
            with self.assertRaises(ValueError):
                shards.aggregate(bad, 'a'*40, 'b'*40, tests)
        mutations = [('receipt', 'Tree', 'c'*40), ('receipt', 'CorpusInventorySHA256', '0'*64),
                     ('receipt', 'CorpusInventoryCount', 1), ('receipt', 'CorpusShardCommandsPassed', False),
                     ('receipt', 'CompatibilityPassed', True), ('receipt', 'ValidationPassed', True),
                     ('receipt', 'HostMachine', 0x8664), ('receipt', 'BoundSeconds', 901),
                     ('setup', 'sdkSHA256', '0'*64), ('setup', 'sourceSHA', 'c'*40)]
        for section, key, value in mutations:
            bad = copy.deepcopy(parts)
            bad[0][section][key] = value
            with self.subTest(section=section, key=key), self.assertRaises(ValueError):
                shards.aggregate(bad, 'a'*40, 'b'*40, tests)
        for key in ('Reaped', 'GroupClean', 'CaptureComplete'):
            bad = copy.deepcopy(parts)
            bad[0]['receipt']['Phases'][4][key] = False
            with self.subTest(key=key), self.assertRaises(ValueError):
                shards.aggregate(bad, 'a'*40, 'b'*40, tests)
        for inventory_seconds, run_seconds in ((100, 601), (1, float('nan')), (1, True)):
            bad = copy.deepcopy(parts)
            bad[0]['receipt']['Phases'][3]['Seconds'] = inventory_seconds
            bad[0]['receipt']['Phases'][4]['Seconds'] = run_seconds
            with self.assertRaises(ValueError):
                shards.aggregate(bad, 'a'*40, 'b'*40, tests)
        with self.assertRaises(ValueError):
            shards.aggregate(parts, 'a'*40, 'b'*40, [])
        bad = copy.deepcopy(parts)
        bad[0]['tests'] = bad[0]['tests'][:-1]
        with self.assertRaises(ValueError):
            shards.aggregate(bad, 'a'*40, 'b'*40, tests)

    def test_nested_terminals_are_required_and_skips_remain_visible(self):
        tests = shards.inventory(self.raw)
        rows = [json.loads(line) for line in execution(tests, 0).splitlines()]
        first = next(i for i, event in enumerate(rows) if event['Action'] == 'run')
        child = dict(rows[first], Test=rows[first]['Test']+'/owned-child')
        with_child = rows[:first+1]+[child, dict(child, Action='skip')]+rows[first+1:]
        result = shards.verify_coverage(tests, encode(with_child), 0, tests)
        self.assertEqual(result['counts']['skipped'], 1)
        with self.assertRaises(ValueError):
            shards.verify_coverage(tests, encode(rows[:first+1]+[child]+rows[first+1:]), 0, tests)
        with self.assertRaises(ValueError):
            shards._json(b'{"Action":"pass","Action":"skip"}')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'owned.jsonl'
            path.write_bytes(self.raw)
            self.assertEqual(shards._read(path, len(self.raw)), self.raw)
            with self.assertRaises(ValueError):
                shards._read(path, len(self.raw)-1)
        self.assertEqual(len(shards.required_cases()), 16)

    def test_closed_selection_keeps_native_profiles_unsharded(self):
        for value in ('', 'unsharded'):
            self.assertIsNone(shards.select_shard(dict(VALIDATION_PROFILE='windows-scan-amd64-v1', CORPUS_SHARD=value)))
        for value in shards.SHARDS:
            self.assertEqual(shards.select_shard(dict(VALIDATION_PROFILE='windows11-x64-compat-arm64-v1', CORPUS_SHARD=value)), int(value))
        for value in ('3', '01', '-1', '0|1', '0/.*'):
            with self.assertRaises(ValueError):
                shards.select_shard(dict(VALIDATION_PROFILE='windows11-x64-compat-arm64-v1', CORPUS_SHARD=value))
        with self.assertRaises(ValueError):
            shards.select_shard(dict(VALIDATION_PROFILE='windows-scan-amd64-v1', CORPUS_SHARD='0'))

    def test_inventory_and_partitions_are_complete_and_disjoint(self):
        tests = shards.inventory(self.raw)
        self.assertEqual(len(tests), 63)
        pieces = [{key for key in tests if shards.shard_index(key.split('#')[1]) == index} for index in range(3)]
        self.assertEqual(set.union(*pieces), set(tests))
        self.assertTrue(all(pieces))
        self.assertFalse(pieces[0] & pieces[1] or pieces[0] & pieces[2] or pieces[1] & pieces[2])
        for name in self.names:
            self.assertEqual(shards.shard_index(name), int.from_bytes(hashlib.sha256(name.encode()).digest()[:8], 'big') % 3)
        for bad in (b'', self.raw[:-1], self.raw+b'{"Action":"fail","Package":"packtrace/owned"}\n', listing(['TestOwned0', 'TestOwned0']), listing(['Test../bad'])):
            with self.assertRaises(ValueError):
                shards.inventory(bad)

    def test_coverage_rejects_missing_duplicate_unassigned_and_skipped_required(self):
        tests = shards.inventory(self.raw)
        required = tests
        for index in range(3):
            raw = execution(tests, index)
            result = shards.verify_coverage(tests, raw, index, required)
            expected = [key for key in tests if shards.shard_index(key.split('#')[1]) == index]
            self.assertEqual(result['selected'], expected)
            rows = [json.loads(line) for line in raw.splitlines()]
            terminal = next(i for i, event in enumerate(rows) if event.get('Test') and event['Action'] == 'pass')
            for changed in (rows[:terminal]+rows[terminal+1:], rows[:terminal]+[rows[terminal]]+rows[terminal:], rows[:terminal]+[dict(rows[terminal], Action='skip')]+rows[terminal+1:]):
                with self.assertRaises(ValueError):
                    shards.verify_coverage(tests, encode(changed), index, required)
            alien = next(key for key in tests if key not in expected).split('#')[1]
            changed = rows[:-1]+[dict(Action='run', Package='packtrace/owned', Test=alien), dict(Action='pass', Package='packtrace/owned', Test=alien)]+rows[-1:]
            with self.assertRaises(ValueError):
                shards.verify_coverage(tests, encode(changed), index, required)
            with self.assertRaises(ValueError):
                shards.verify_coverage(tests, raw[:-1], index, required)


if __name__ == '__main__':
    unittest.main()
