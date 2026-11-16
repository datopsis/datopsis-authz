"""Compose pinned fixture helpers without editing their source checkout."""
import json
import os
from pathlib import Path

import fixture as upstream
from common import HTTPS, WORK, host, pki, run, secret, wait, write
from fixture import BACKEND_NETWORK, Storage, backend_address, container, database, leaf, transport
from rauthy import Rauthy as PinnedRauthy

class Rauthy(PinnedRauthy):
    def config_rauthy(self):
        result = super().config_rauthy()
        path = self.path / 'bootstrap/api_keys.json'
        keys = json.loads(path.read_text())
        keys[0]['access'] += [{'group':'Clients','access_rights':['read','update']}]
        write(path, keys)
        return result



def snapshot(catalog, key):
    return catalog.http.json('POST', 'https://cedar:8443/snapshot', headers={'Authorization': 'Bearer '+key}, json={})


def restore(catalog, key, state):
    """Reset fixture between destructive cases; never used inside an assertion."""
    headers = {'Authorization': 'Bearer '+key}
    current = snapshot(catalog,key)
    for old_grant in current['grants']:
        if old_grant not in state['grants']:
            catalog.http.request('POST','https://cedar:8443/mutate',headers=headers,json={'op':'grant','grant':old_grant,'remove':True}).raise_for_status()
    for name, (resource, _) in current['parents'].items():
        if name not in state['parents']:
            catalog.http.request('POST','https://cedar:8443/mutate',headers=headers,json={'op':'delete','resource':resource}).raise_for_status()
    for resource, parent in state['parents'].values():
        catalog.http.request('POST','https://cedar:8443/mutate',headers=headers,json={'op':'put','resource':resource,'parent':parent,'owner':None}).raise_for_status()
    for grant in state['grants']:
        catalog.http.request('POST','https://cedar:8443/mutate',headers=headers,json={'op':'grant','grant':grant,'remove':False}).raise_for_status()
    for principal, epoch in state.get("epochs", {}).items():
        catalog.http.request("POST", "https://cedar:8443/mutate", headers=headers, json={"op":"revoke_before", "principal":principal,"epoch":epoch}).raise_for_status()
    assert snapshot(catalog,key) == state


def grant(catalog, key, user, relation, obj, delete=False):
    assert relation == 'select'
    subject_kind, subject_id = user.split(':', 1)
    kinds = {'namespace': 'Namespace', 'lakekeeper_table': 'Table'}
    kind, identifier = obj.split(':', 1)
    resource = {'kind': kinds[kind], 'id': identifier.split('/')[-1]}
    catalog.http.request('POST', 'https://cedar:8443/mutate', headers={'Authorization': 'Bearer '+key}, json={'op':'grant','grant':{'subject':{'kind':{'user':'User','group':'Group'}[subject_kind], 'id':subject_id}, 'resource':resource, 'access':relation},'remove':delete}).raise_for_status()


def migrate(catalog):
    run('docker', 'run', '--rm', '--label', 'datopsis.idp-bakeoff=true', '--network', 'container:'+catalog.proxy, '--env-file', catalog.env, '-v', f'{catalog.provider.ca}:/ca/ca.pem:ro', 'localhost/lakekeeper-datopsis:s1', 'migrate')
    # In-memory backend has no migration; validate its schema twice instead.
    run('docker', 'run', '--rm', 'localhost/authz-serve:s1', 'policy')


class CedarCatalog(upstream.AuthCatalog):
    def start_backend(self, audience='lakekeeper,operator,expiry'):
        # Substitute only the image and adapter-specific mounts. All OIDC/TLS
        # arguments remain the pinned Catalog.start_backend implementation.
        from catalog import Catalog
        obj = json.loads(run('docker','inspect',self.proxy))[0]
        if BACKEND_NETWORK not in obj['NetworkSettings']['Networks']:
            run('docker','network','connect',BACKEND_NETWORK,self.proxy)
        migrate(self)
        import catalog as module
        original = module.run
        def invoke(*args, **kwargs):
            args = list(args)
            if 'localhost/lakekeeper-ubi:integration' in args:
                index = args.index('localhost/lakekeeper-ubi:integration')
                args[index:index+1] = ['-v', f'{WORK / "cedar-key"}:/run/cedar-key:ro', 'localhost/lakekeeper-datopsis:s1']
            return original(*args, **kwargs)
        module.run = invoke
        try:
            return Catalog.start_backend(self,audience)
        finally:
            module.run = original


def setup(arch, record):
    ca = pki()
    os.environ['AWS_CA_BUNDLE'] = str(ca)
    run('docker','network','create','--internal',upstream.NETWORK)
    run('docker','network','create','--internal',BACKEND_NETWORK)
    original_container = upstream.container
    def with_backend_alias(name, *args, **kwargs):
        if name == 'fga-postgres':
            kwargs['extra'] = [*kwargs.get('extra', []), '--network-alias', 'cedar']
        return original_container(name, *args, **kwargs)
    upstream.container = with_backend_alias
    try:
        env, _unused_fga_db = database(ca)
    finally:
        upstream.container = original_container
    # Reuse the fixture's private PostgreSQL network namespace as stable backend
    # endpoint. It keeps the interface present during a decision-service outage.
    provider = Rauthy('rauthy',ca)
    record('rauthy',lambda:provider.start(arch),required=True)
    key = secret()
    write(WORK/'cedar-key',key)
    run('sudo','chown','root:root',WORK/'cedar-key')
    run('sudo','chmod','0440',WORK/'cedar-key')
    # Outbound admin lookup uses a separate IDP-only attachment. Clients cannot
    # reach the private decision API through the normal client network.
    run('docker','network','create','--internal','s4-idp')
    run('docker','network','connect','--alias',provider.hostname,'s4-idp',provider.container)
    run('docker','network','connect','s4-idp','fga-postgres')
    write(WORK/'rauthy-admin',provider.admin['Authorization'])
    run('sudo','chown','root:root',WORK/'rauthy-admin')
    run('sudo','chmod','0440',WORK/'rauthy-admin')
    tls = leaf('cedar')
    container('cedar','localhost/authz-serve:s1',['serve'],env={'AUTHZ_TLS_CERT':'/tls/cert.pem','AUTHZ_TLS_KEY':'/tls/key.pem','AUTHZ_KEY_FILE':'/run/cedar-key','AUTHZ_RAUTHY_USERS_URL':provider.base+'/auth/v1/users','AUTHZ_RAUTHY_CA_FILE':'/ca/ca.pem','AUTHZ_RAUTHY_KEY_FILE':'/run/rauthy-admin'},mounts=[(tls,'/tls'),(WORK/'cedar-key','/run/cedar-key'),(WORK/'rauthy-admin','/run/rauthy-admin'),(ca,'/ca/ca.pem')],network='container:fga-postgres')
    address = backend_address()
    run('sudo','tee','/etc/hosts',input=Path('/etc/hosts').read_text()+f'{address} cedar # idp-bakeoff\n')
    http = HTTPS(ca)
    wait(lambda:http.request('POST','https://cedar:8443/decide',headers={'Authorization':'Bearer '+key},json=[]).status_code==200)
    record('cedar_tls',lambda:transport('cedar',8443,ca),required=True)
    env.update({'AUTHZ_ENDPOINT':'https://cedar:8443','AUTHZ_CA_FILE':'/ca/ca.pem','AUTHZ_KEY_FILE':'/run/cedar-key','LAKEKEEPER__AUTHZ_BACKEND':'datopsis','LAKEKEEPER__DEFAULT_PROJECT_ID':'00000000-0000-0000-0000-000000000000'})
    storage = Storage(ca)
    record('storage_tls',storage.start,required=True)
    catalog = CedarCatalog(provider,env,storage)
    record('lakekeeper_tls',catalog.start,required=True)
    operator = provider.token('operator')
    record('seed',lambda:catalog.seed(operator),required=True)
    return catalog,operator,key
