"""Grant API caller contracts; no network, credentials or runtime fixture."""
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
from catalog_grants import grant


class CatalogGrants(unittest.TestCase):
    def catalog(self, expected, remove=False):
        http = Mock()
        http.json.return_value = [] if remove else [expected]
        return SimpleNamespace(base='https://catalog.test', http=http,
                               provider=SimpleNamespace(token=Mock(return_value='fixture-operator')))

    def test_single_table_grant_uses_table_api_kind(self):
        expected = {'subject':{'kind':'User','id':'oidc~alice'},
                    'resource':{'kind':'Table','id':'one'},'access':'select'}
        catalog = self.catalog(expected)
        grant(catalog,'unused','user:oidc~alice','select','lakekeeper_table:warehouse/one')
        self.assertEqual(catalog.http.request.call_args.args[:2],
                         ('POST','https://catalog.test/management/v1/permissions/table/one/grants'))
        self.assertEqual(catalog.http.json.call_args.args[:2],
                         ('GET','https://catalog.test/management/v1/permissions/table/one/grants'))
        self.assertEqual(catalog.http.request.call_args.kwargs['json']['subject'],expected['subject'])

    def test_namespace_group_removal_preserves_identity_and_ack_before_readback(self):
        expected = {'subject':{'kind':'Group','id':'readers:team'},
                    'resource':{'kind':'Namespace','id':'ns'},'access':'select'}
        catalog = self.catalog(expected,remove=True)
        readback = Mock(return_value=[])
        with patch('catalog_grants.time.monotonic', return_value=12.5) as clock:
            def get(*args, **kwargs):
                clock.assert_called_once()
                return readback(*args, **kwargs)
            catalog.http.json.side_effect = get
            acknowledged = grant(catalog,'unused','group:readers:team','select','namespace:ns',True)
        self.assertEqual(acknowledged,12.5)
        self.assertEqual(catalog.http.request.call_args.args[:2],
                         ('POST','https://catalog.test/management/v1/permissions/namespace/ns/grants'))
        self.assertEqual(catalog.http.request.call_args.kwargs['json'],
                         {'subject':expected['subject'],'access':'select','remove':True})

    def test_readback_does_not_hide_a_rejected_write(self):
        catalog = self.catalog({})
        catalog.http.request.return_value.raise_for_status.side_effect = RuntimeError('write rejected')
        with self.assertRaisesRegex(RuntimeError,'write rejected'):
            grant(catalog,'unused','user:oidc~alice','select','namespace:ns')
        catalog.http.json.assert_not_called()
