"""Lock pruning cannot introduce versions, sources, checksums or dependency edges."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('isolation', 'scripts/prepare-authz-workspace.py')
isolation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(isolation)


class IsolatedLock(unittest.TestCase):
    def test_cargo_unused_patch_metadata_requires_exact_reviewed_identity(self):
        text = 'version = 4\n\n[[package]]\nname = "root"\nversion = "1.0.0"\n\n[[patch.unused]]\nname = "driver"\nversion = "1.0.0"\nsource = "git+reviewed"\n'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'Cargo.lock';path.write_text(text)
            isolated = isolation.read_lock(path)
        self.assertEqual(len(isolated['package']), 1)
        original = {'package': [{'name':'root','version':'1.0.0'},
                    {'name':'driver','version':'1.0.0','source':'git+reviewed'}]}
        isolation.verify_subset(original, isolated)
        for field,value in [('version','2.0.0'),('source','git+unreviewed'),('dependencies',['root'])]:
            changed = copy.deepcopy(isolated);changed['unused_patches'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                isolation.verify_subset(original, changed)

    def test_project_lock_is_a_valid_reviewed_subset(self):
        # The project lock is also a valid identity subset of itself.
        lock = isolation.read_lock(Path('Cargo.lock'))
        isolation.verify_subset(lock, lock)

    def test_only_removing_packages_and_edges_is_allowed(self):
        original = {'package': [{'name':'root','version':'1.0.0','dependencies':['dep','unused']},
                    {'name':'dep','version':'1.0.0','checksum':'reviewed'},
                    {'name':'unused','version':'1.0.0'}]}
        pruned = copy.deepcopy(original)
        pruned['package'].pop(); pruned['package'][0]['dependencies'] = ['dep']
        isolation.verify_subset(original, pruned)
        for field, value in [('version','2.0.0'),('source','git+new-source'),('checksum','changed')]:
            changed = copy.deepcopy(pruned); changed['package'][1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                isolation.verify_subset(original, changed)
        changed = copy.deepcopy(pruned);changed['package'][1]['dependencies'] = ['root']
        with self.assertRaises(ValueError): isolation.verify_subset(original, changed)
