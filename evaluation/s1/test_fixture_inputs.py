"""Lightweight transport checks: no network, containers or real feed acquisition."""
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock
from urllib.error import HTTPError
from fixture_inputs import download_locked, seed_rauthy_feed


class FixtureInputs(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cache = self.root/'cache.jwt'
        self.data = b'publisher fixture bytes'
        self.item = {'url':'https://publisher.test/', 'filename':'feed.jwt',
                     'sha256':hashlib.sha256(self.data).hexdigest()}

    def limited(self, delay='60'):
        return HTTPError(self.item['url'],429,'rate limited',{'Retry-After':delay},None)

    def test_retry_then_reuse_without_second_network_request(self):
        open_url = Mock(side_effect=[self.limited(),io.BytesIO(self.data)])
        sleep = Mock()
        download_locked(self.item,self.cache,open_url=open_url,sleep=sleep)
        self.assertEqual(self.cache.read_bytes(),self.data)
        sleep.assert_called_once_with(60)
        open_url.reset_mock()
        download_locked(self.item,self.cache,open_url=open_url,sleep=sleep)
        open_url.assert_not_called()

    def test_repeated_429_is_bounded_and_never_creates_cache(self):
        open_url = Mock(side_effect=self.limited())
        sleep = Mock()
        with self.assertRaises(HTTPError):
            download_locked(self.item,self.cache,open_url=open_url,sleep=sleep)
        self.assertEqual(open_url.call_count,4)
        self.assertEqual(sleep.call_count,3)
        self.assertFalse(self.cache.exists())

    def test_long_retry_after_is_not_shortened(self):
        sleep = Mock()
        with self.assertRaises(HTTPError):
            download_locked(self.item,self.cache,open_url=Mock(side_effect=self.limited('600')),sleep=sleep)
        sleep.assert_not_called()

    def test_404_is_not_retried(self):
        open_url = Mock(side_effect=HTTPError(self.item['url'],404,'missing',{},None))
        sleep = Mock()
        with self.assertRaises(HTTPError):
            download_locked(self.item,self.cache,open_url=open_url,sleep=sleep)
        open_url.assert_called_once()
        sleep.assert_not_called()

    def test_wrong_hash_never_becomes_a_cached_input(self):
        with self.assertRaises(ValueError):
            download_locked(self.item,self.cache,open_url=Mock(return_value=io.BytesIO(b'changed feed')))
        self.assertFalse(self.cache.exists())

    def test_owner_lock_revalidates_cached_bytes(self):
        source = self.root/'owner'
        locks = source/'artifacts/locks'
        locks.mkdir(parents=True)
        (locks/'amd64.json').write_text(json.dumps({'downloads':{'fido-mds':self.item}}))
        self.cache.write_bytes(self.data)
        seed_rauthy_feed(source,self.cache,'amd64')
        self.assertEqual((source/'.artifact-bundle/feed.jwt').read_bytes(),self.data)
        self.cache.write_bytes(b'corrupt cache')
        with self.assertRaises(ValueError):
            seed_rauthy_feed(source,self.cache,'amd64')
        with self.assertRaises(ValueError):
            download_locked(self.item,self.cache,open_url=Mock())
