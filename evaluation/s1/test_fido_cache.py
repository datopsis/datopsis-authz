"""Cache identity and unconditional verifier wiring; no network or real feed."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'fido_preflight', Path(__file__).resolve().parents[2]/'scripts/check-fixture-inputs.py')
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


class FidoCache(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root/'verifier'
        (self.source/'artifacts/locks').mkdir(parents=True)
        self.digest = 'a'*64
        self.lock('amd64', self.digest)
        self.lock('arm64', self.digest)

    def lock(self, arch, digest):
        (self.source/f'artifacts/locks/{arch}.json').write_text(
            json.dumps({'downloads': {'fido-mds': {'sha256': digest}}}))

    def test_exact_portable_digest_key(self):
        self.assertEqual(preflight.locked_key(self.source), f'fido-mds-{self.digest}')

    def test_different_architecture_or_malformed_digest_blocks(self):
        self.lock('arm64', 'b'*64)
        with self.assertRaises(ValueError):
            preflight.locked_key(self.source)
        self.lock('amd64', 'bad')
        self.lock('arm64', 'bad')
        with self.assertRaises(ValueError):
            preflight.locked_key(self.source)

    def test_each_restored_cache_hit_invokes_full_owner_verifier(self):
        revision = 'c'*40
        inputs = self.root/'evaluation/s1'
        inputs.mkdir(parents=True)
        (inputs/'inputs.json').write_text(json.dumps({'rauthy-ubi': {'revision': revision}}))
        cache = self.root/'cache'
        cache.mkdir()
        (cache/'fido-mds.jwt').write_bytes(b'cached bytes are not a verification verdict')
        with patch.object(preflight, 'ROOT', self.root), \
             patch.object(preflight, 'SOURCE', self.source), \
             patch.object(preflight, 'CACHE', cache), \
             patch('sys.argv', ['check-fixture-inputs.py']), \
             patch.object(preflight.subprocess, 'check_output', side_effect=[revision, '', revision, '']), \
             patch.object(preflight.subprocess, 'run') as run:
            preflight.main()
            preflight.main()
        self.assertEqual(run.call_count, 2)
        for call in run.call_args_list:
            self.assertEqual(call.args[0][1:4], ['scripts/artifacts.py', 'acquire-fido',
                                               'artifacts/locks/amd64.json'])
            self.assertTrue(call.kwargs['check'])
            self.assertEqual(call.kwargs['env']['FIDO_MDS_CACHE_DIR'], str(cache))
