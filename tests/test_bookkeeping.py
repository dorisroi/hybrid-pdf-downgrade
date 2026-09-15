import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('comparator_under_test', ROOT/'compare_runs.py')
cmp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cmp)


class BookkeepingTest(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT/'results/canonical/20260915_162034_799680/run1/numbers.json').read_text())

    def compare(self, a, b):
        with contextlib.redirect_stdout(io.StringIO()):
            return cmp.compare(a, b)

    def test_known_equal_version_and_all_389_fields_pass(self):
        self.assertEqual(len(cmp.invariants(self.data)), 389)
        self.assertTrue(self.compare(self.data, self.data))

    def test_unknown_missing_and_invalid_versions_fail_even_when_equal(self):
        for value in ['unknown', '', None, '0x37', True]:
            with self.subTest(value=value):
                d = copy.deepcopy(self.data)
                d['meta']['pyhanko'] = value
                self.assertFalse(self.compare(d, d))
        d = copy.deepcopy(self.data)
        del d['meta']['pyhanko']
        self.assertFalse(self.compare(d, d))

    def test_version_change_fails(self):
        d = copy.deepcopy(self.data)
        d['meta']['pyhanko'] = '0.38.0'
        self.assertFalse(self.compare(self.data, d))

    def test_each_e6_e9_verdict_change_fails(self):
        for exp, rows, key in [('E6','variants','rule_accepts'), ('E7','cases','refined_accepts'), ('E8','cases','accepts'), ('E9','rows','e7')]:
            with self.subTest(exp=exp):
                d = copy.deepcopy(self.data)
                d[exp][rows][0][key] = not d[exp][rows][0][key]
                self.assertFalse(self.compare(self.data, d))


if __name__ == '__main__':
    unittest.main()
