"""Check that authored fixtures actually exercise their named boundary."""
import json
from pathlib import Path
import unittest


class FixtureContract(unittest.TestCase):
    def test_selection_paths(self):
        cases = {c["id"]: c for c in json.loads((Path(__file__).parent / "testdata/cases.json").read_text())}
        intended = {
            "a18-pnpm": "pnpm-lock.yaml",
            "a18-yarn": "yarn.lock",
            "a18-bun-binary": "bun.lockb",
            "a18-hidden-npm": "node_modules/.package-lock.json",
            "a18-nested-npm": "node_modules/a/package-lock.json",
            "a18-mixed-root": "package-lock.json",
        }
        for case_id, path in intended.items():
            with self.subTest(case_id=case_id):
                self.assertEqual(cases[case_id]["path"], path)

    def test_budgets(self):
        p = Path(__file__).parent / "testdata/cases.json"
        cases = json.loads(p.read_text())
        self.assertLessEqual(len(cases), 80)
        self.assertEqual(len({c["id"] for c in cases}), len(cases))
        self.assertLessEqual(p.stat().st_size, 64 * 1024**2)
        self.assertEqual({c["group"] for c in cases}, {f"A{i:02d}" for i in range(1,19)})
        for c in cases:
            self.assertLessEqual(len(c["content"].encode()), 2 * 1024**2)
            self.assertLessEqual(len(c.get("files", {})), 256)
            for path in [c["path"], *c.get("files", {})]:
                self.assertLessEqual(len(Path(path).parts), 32)


if __name__ == "__main__":
    unittest.main()
