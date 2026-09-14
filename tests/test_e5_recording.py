"""Recording-only regression checks; no signing or historical result writes."""
import ast
import json
from pathlib import Path
import random
import statistics
import types
import unittest


def load_analysis():
    source = Path(__file__).resolve().parents[1] / "src/experiments/e5_cost.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    wanted = {"_bootstrap_median_diff", "_stats", "run"}
    nodes = [
        n for n in tree.body
        if isinstance(n, ast.Assign)
        or isinstance(n, ast.FunctionDef) and n.name in wanted
    ]
    ns = {"random": random, "statistics": statistics}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec"), ns)
    return ns


class E5RecordingTest(unittest.TestCase):
    def setUp(self):
        self.ns = load_analysis()
        self.a = [1.0, 2.0, 100.0, 101.0]
        self.b = [3.0, 10.0, 11.0, 200.0]
        self.calls = []
        counts = {"A": 0, "B": 0}

        def one(first, second, first_field, second_field, tag):
            i = counts[tag]
            counts[tag] += 1
            self.calls.append(tag)
            return (self.a if tag == "A" else self.b)[i], 1000 + i

        self.ns["_one"] = one
        self.ns["pki"] = types.SimpleNamespace(selfsigned=lambda *args: args[0])
        self.result = self.ns["run"](reps=4, verbose=False)

    def test_execution_order_unchanged(self):
        self.assertEqual(self.calls, ["A", "B"] * 4)

    def test_difference_of_medians_not_paired_median(self):
        self.assertEqual(self.result["time_delta_ms"], -40.5)
        paired = statistics.median(b-a for a, b in zip(self.a, self.b))
        self.assertNotEqual(self.result["time_delta_ms"], paired)

    def test_raw_observations_and_summaries(self):
        rows = self.result["observations"]
        self.assertEqual([r["block_index"] for r in rows], [1, 2, 3, 4])
        for order, expected in (("A", self.a), ("B", self.b)):
            raw = [r[order]["time_ms"] for r in rows]
            self.assertEqual(raw, expected)
            self.assertEqual(self.result["time_ms"][order], self.ns["_stats"](raw))
        self.assertEqual(json.loads(json.dumps(self.result)), self.result)

    def test_metadata_replays_original_independent_bootstrap(self):
        meta = self.result["analysis"]
        self.assertFalse(meta["paired_analysis"])
        self.assertFalse(meta["randomised"])
        self.assertFalse(meta["counterbalanced"])
        boot = meta["bootstrap"]
        self.assertEqual((boot["resamples"], boot["seed"]), (10000, 12345))
        rng = random.Random(boot["seed"])
        diffs = []
        for _ in range(boot["resamples"]):
            a = statistics.median(rng.choices(self.a, k=len(self.a)))
            b = statistics.median(rng.choices(self.b, k=len(self.b)))
            diffs.append(b-a)
        diffs.sort()
        lo, hi = boot["sorted_zero_based_endpoint_indices"]
        self.assertEqual(self.result["time_delta_ci95"], [diffs[lo], diffs[hi]])


if __name__ == "__main__":
    unittest.main()
