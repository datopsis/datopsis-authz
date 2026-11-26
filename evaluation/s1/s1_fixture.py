"""Compose pinned fixture helpers without editing their source checkout."""
import json
import os
import time
from pathlib import Path

import fixture as upstream
from common import HTTPS, WORK, host, pki, run, secret, wait, write
from fixture import BACKEND_NETWORK, Storage, backend_address, container, database, leaf, transport
from rauthy import Rauthy as PinnedRauthy

class Rauthy(PinnedRauthy):
    def config_rauthy(self):
        result = super().config_rauthy()
        reader_secret = secret()
        self.reader_key = 'API-Key authz-reader$' + reader_secret
        path = self.path / 'bootstrap/api_keys.json'
        keys = json.loads(path.read_text())
        # Use the exact bootstrap shape provided by the pinned Rauthy helper.
        reader = dict(keys[0])
        reader.update({'name':'authz-reader','secret':{'Plain':reader_secret},
                       'access':[{'group':'Users','access_rights':['read']}]})
        keys.append(reader)
        write(path, keys)
        return result

    def start(self, arch):
        from unittest.mock import patch
        import rauthy
        original = rauthy.write
        def write_clients(path, value):
            if str(path).endswith('/bootstrap/clients.json'):
                for client in value:
                    if client['id'] != 'expiry':
                        client['access_token_lifetime'] = 900
            return original(path, value)
        with patch.object(rauthy, 'write', write_clients):
            return super().start(arch)



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
    assert snapshot(catalog,key) == state


from catalog_grants import grant


def migrate(catalog):
    run('docker', 'run', '--rm', '--label', 'datopsis.idp-bakeoff=true', '--network', 'container:'+catalog.proxy, '--env-file', catalog.env, '-v', f'{catalog.provider.ca}:/ca/ca.pem:ro', 'localhost/lakekeeper-datopsis:s1', 'migrate')
    run('docker', 'run', '--rm', '--network', 'container:fga-postgres',
        '--env-file', WORK/'cedar.env', '-v', f'{WORK/"cedar-db-url"}:/run/cedar-db-url:ro',
        '-v', f'{catalog.provider.ca}:/ca/ca.pem:ro', 'localhost/authz-serve:s1', 'migrate')


class CedarCatalog(upstream.AuthCatalog):
    authz_audiences = 'lakekeeper,operator,expiry'

    def start_backend(self, audience=None):
        if audience is None:
            audience = self.authz_audiences
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


def setup(arch, record, machine_principals=(), extra_catalog_audiences=()):
    ca = pki()
    os.environ['AWS_CA_BUNDLE'] = str(ca)
    run('docker','network','create','--internal',upstream.NETWORK)
    run('docker','network','create','--internal',BACKEND_NETWORK)
    original_container = upstream.container
    def with_backend_alias(name, *args, **kwargs):
        if name == 'fga-postgres':
            kwargs['extra'] = [*kwargs.get('extra', []), '--network-alias', 'cedar']
            args = ('localhost/postgresql-ubi:integration', *args[1:])
        return original_container(name, *args, **kwargs)
    upstream.container = with_backend_alias
    try:
        env, authz_db = database(ca)
    finally:
        upstream.container = original_container
    # Reuse the fixture's private PostgreSQL network namespace as stable backend
    # endpoint. It keeps the interface present during a decision-service outage.
    provider = Rauthy('rauthy',ca)
    record('rauthy',lambda:provider.start(arch),required=True)
    key = secret()
    write(WORK/'cedar-key',key)
    write(WORK/'trino-key',secret())
    run('sudo','chown','root:root',WORK/'trino-key')
    run('sudo','chmod','0440',WORK/'trino-key')
    run('sudo','chown','root:root',WORK/'cedar-key')
    run('sudo','chmod','0440',WORK/'cedar-key')
    run('docker','network','create','--internal','slice1-idp')
    run('docker','network','connect','--alias',provider.hostname,'slice1-idp',provider.container)
    run('docker','network','connect','slice1-idp','fga-postgres')
    # The service receives Users/read only; fixture mutation uses its separate admin key.
    write(WORK/'rauthy-reader', provider.reader_key)
    write(WORK/'cedar-db-url',authz_db)
    run('sudo','chown','root:root',WORK/'rauthy-reader',WORK/'cedar-db-url')
    run('sudo','chmod','0440',WORK/'rauthy-reader',WORK/'cedar-db-url')
    tls = leaf('cedar')
    container('cedar','localhost/authz-serve:s1',['serve'],env={
        'AUTHZ_TLS_CERT':'/tls/cert.pem','AUTHZ_TLS_KEY':'/tls/key.pem','AUTHZ_KEY_FILE':'/run/cedar-key',
        'AUTHZ_TRINO_KEY_FILE':'/run/trino-key','AUTHZ_DATABASE_URL_FILE':'/run/cedar-db-url','AUTHZ_DATABASE_CA_FILE':'/ca/ca.pem',
        'AUTHZ_RAUTHY_USERS_URL':provider.base+'/auth/v1/users','AUTHZ_RAUTHY_CA_FILE':'/ca/ca.pem',
        'AUTHZ_RAUTHY_KEY_FILE':'/run/rauthy-reader','AUTHZ_MACHINE_PRINCIPALS':','.join(('oidc~operator','oidc~lakekeeper','oidc~expiry', *machine_principals))},
        mounts=[(WORK/'trino-key','/run/trino-key'),(tls,'/tls'),(WORK/'cedar-key','/run/cedar-key'),(WORK/'rauthy-reader','/run/rauthy-reader'),
                (WORK/'cedar-db-url','/run/cedar-db-url'),(ca,'/ca/ca.pem')],network='container:fga-postgres')
    address = backend_address()
    run('sudo','tee','/etc/hosts',input=Path('/etc/hosts').read_text()+f'{address} cedar # idp-bakeoff\n')
    http = HTTPS(ca)
    wait(lambda:http.request('POST','https://cedar:8443/decide',headers={'Authorization':'Bearer '+key},json=[]).status_code==200)
    record('cedar_tls',lambda:transport('cedar',8443,ca),required=True)
    env.update({'AUTHZ_ENDPOINT':'https://cedar:8443','AUTHZ_CA_FILE':'/ca/ca.pem','AUTHZ_KEY_FILE':'/run/cedar-key','LAKEKEEPER__AUTHZ_BACKEND':'datopsis','LAKEKEEPER__DEFAULT_PROJECT_ID':'00000000-0000-0000-0000-000000000000'})
    storage = Storage(ca)
    record('storage_tls',storage.start,required=True)
    catalog = CedarCatalog(provider,env,storage)
    catalog.authz_audiences = ",".join((catalog.authz_audiences, *extra_catalog_audiences))
    record('lakekeeper_tls',catalog.start,required=True)
    operator = provider.token('operator')
    record('seed',lambda:catalog.seed(operator),required=True)
    return catalog,operator,key
