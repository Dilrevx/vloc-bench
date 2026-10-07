import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('owned_normalization', ROOT / 'tools/normalize_vloc_v1.py')
normalizer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(normalizer)


class NormalizationTests(unittest.TestCase):
    def test_generated_files_exactly_rebuild_from_pinned_originals(self):
        blobs = {p: subprocess.check_output(['git', '-C', str(ROOT), 'show', normalizer.COMMIT + ':' + p])
                 for p in normalizer.PROVENANCE}
        for name, body in normalizer.build(blobs).items():
            self.assertEqual((ROOT / 'datasets/vloc' / name).read_bytes(), body)

    def test_native_manifest_counts_and_missing_revision_retained(self):
        cases = normalizer.normalize(normalizer.read_rows((ROOT / normalizer.RAW).read_bytes()))
        counts = normalizer.counts(cases)
        self.assertEqual(counts['tasks'], 500)
        self.assertEqual(counts['nonempty_advisories'], 411)
        self.assertEqual(counts['fully_revision_pinned_tasks'], 499)
        self.assertEqual(counts['native_ground_truth_file_labels'], 2618)
        missing = [c for c in cases if c['source']['vulnerable_commit'] is None]
        self.assertEqual([c['case_id'] for c in missing], ['vloc-wyfFZf7k'])

    def test_upstream_tree_is_byte_for_byte_unchanged(self):
        changed = subprocess.check_output(['git', '-C', str(ROOT), 'diff', '--name-only', '--diff-filter=DMRTUXB', normalizer.COMMIT], text=True)
        self.assertEqual(changed, '')
        paths = subprocess.check_output(['git', '-C', str(ROOT), 'ls-tree', '-r', '--name-only', normalizer.COMMIT], text=True).splitlines()
        for path in paths:
            original = subprocess.check_output(['git', '-C', str(ROOT), 'show', normalizer.COMMIT + ':' + path])
            self.assertEqual((ROOT / path).read_bytes(), original, path)

    def test_cli_refuses_existing_output_without_touching_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(['python3', str(ROOT / 'tools/normalize_vloc_v1.py'), '--output-dir', tmp], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list(Path(tmp).iterdir()), [])


if __name__ == '__main__':
    unittest.main()
