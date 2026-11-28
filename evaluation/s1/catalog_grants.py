"""Catalog-native grant transport, isolated from container provisioning."""
import time


def grant(catalog, key, user, relation, obj, delete=False):
    assert relation == 'select'
    subject_kind, subject_id = user.split(':', 1)
    kinds = {'namespace': 'Namespace', 'lakekeeper_table': 'Table'}
    kind, identifier = obj.split(':', 1)
    resource = {'kind': kinds[kind], 'id': identifier.split('/')[-1]}
    endpoint = catalog.base + '/management/v1/permissions/' + resource['kind'].lower() + '/' + resource['id'] + '/grants'
    response = catalog.http.request('POST', endpoint,
        headers={'Authorization':'Bearer '+catalog.provider.token('operator')},
        json={'subject':{'kind':{'user':'User','group':'Group'}[subject_kind], 'id':subject_id},'access':relation,'remove':delete})
    response.raise_for_status()
    acknowledged = time.monotonic()
    listed = catalog.http.json('GET', endpoint,
        headers={'Authorization':'Bearer '+catalog.provider.token('operator')})
    expected = {'subject':{'kind':{'user':'User','group':'Group'}[subject_kind], 'id':subject_id}, 'resource':resource, 'access':relation}
    assert (expected in listed) is not delete, listed
    return acknowledged
