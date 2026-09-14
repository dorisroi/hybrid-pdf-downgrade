"""Read-only verification of the frozen canonical pair; no signing or rendering."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
RECORD = ROOT/'results/canonical/20260915_052647_101641'
sys.path.insert(0, str(ROOT/'src'))
from experiments import e5_cost
from pyhanko.pdf_utils.reader import PdfFileReader
import compare_runs


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    data = {tag: read(RECORD/tag/'numbers.json') for tag in ['run1', 'run2']}
    require(compare_runs.compare(data['run1'], data['run2']), 'Invariant comparison failed')
    for tag, d in data.items():
        artifacts = RECORD/tag/'artifacts'
        rows = d['E5']['observations']
        require(len(rows) == d['E5']['reps'], tag + ': sample count')
        for order in ['A', 'B']:
            times = [r[order]['time_ms'] for r in rows]
            sizes = [r[order]['size_bytes'] for r in rows]
            require(e5_cost._stats(times) == d['E5']['time_ms'][order], tag + ': timing statistics')
            require(e5_cost._stats(sizes) == d['E5']['size_bytes'][order], tag + ': size statistics')
        a = [r['A']['time_ms'] for r in rows]
        b = [r['B']['time_ms'] for r in rows]
        require(list(e5_cost._bootstrap_median_diff(a, b)) == d['E5']['time_delta_ci95'], tag + ': bootstrap')
        require(d['E5']['analysis']['bootstrap']['seed'] == e5_cost.BOOTSTRAP_SEED, tag + ': seed')
        require(d['E5']['analysis']['bootstrap']['resamples'] == e5_cost.BOOTSTRAP_RESAMPLES, tag + ': resamples')
        require(all(r['execution_order'] == ['A','B'] for r in rows), tag + ': execution order')
        for exp in ['E1','E2','C1']:
            for order, result in d[exp]['orders'].items():
                full = (artifacts/(f'_c1_{order}_2.pdf' if exp == 'C1' else result['hybrid_path'])).read_bytes()
                inner = (artifacts/(f'_c1_{order}_1.pdf' if exp == 'C1' else result['inner_path'])).read_bytes()
                cuts = [c for c in result['cuts'] if c.get('identical_to_inner')]
                require(cuts and all(full[:c['offset']] == inner for c in cuts), tag + ': prefix identity')
                if exp != 'C1':
                    require(hashlib.sha256(full).hexdigest() == result['hybrid_sha256'], tag + ': full hash')
                    require(hashlib.sha256(inner).hexdigest() == result['inner_sha256'], tag + ': inner hash')
        with (artifacts/d['E1']['orders']['A']['hybrid_path']).open('rb') as stream:
            sigs = {s.field_name:s for s in PdfFileReader(stream).embedded_signatures}
            pq = sigs['PQLayer'].signer_info
            require(pq['signature_algorithm']['algorithm'].dotted == d['AUDIT']['pq_oid'], tag + ': PQ OID')
            require(len(pq['signature'].native) == d['AUDIT']['pq_sig_len'], tag + ': PQ length')
        print(tag + ': raw statistics, bootstrap, prefix identities and CMS identifiers PASS')
    print('Canonical verification PASS. This is not a fresh signing or DSS run.')


if __name__ == '__main__':
    main()
