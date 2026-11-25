"""S2 evidence, separate from the unchanged mandatory C1-C8 suite."""
import json
import os
import platform
import subprocess
import sys
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / '.sources/lakehouse-integration'
PIN = 'e8379a528bf413c05aad49e56bc8cd507b5e077a'
assert subprocess.check_output(['git','-C',str(SOURCE),'rev-parse','HEAD'],text=True).strip() == PIN
sys.path.extend([str(ROOT/'evaluation/s1'), str(SOURCE/'evaluation/authz'), str(SOURCE/'evaluation/idp')])
import common
common.OUT = ROOT/'reports/s2'
from common import WORK, decode, run, save, secret
from s1_fixture import setup, grant
from trino import start
# Same coordinator-approved immutable inputs as slice 1.
import rauthy
INPUTS = json.loads((ROOT/'evaluation/s1/inputs.json').read_text())
rauthy.REVISION = INPUTS['rauthy-ubi']['revision']

CASES = ('S2.1', 'S2.2', 'S2.3', 'S2.4', 'S2.5', 'S2.single', 'S2.groups', 'S2.audit', 'S2.durable', 'S2.credentials')
results = {'run': {'architecture':os.environ['INTEGRATION_ARCH'], 'uname':platform.machine(), 'url':os.environ['RUN_URL'],
    'source':os.environ.get('GITHUB_SHA'), 'fixture':PIN, 'trino_ubi':'685ff5bca0037d38e3c2e2ed47a60f2540dad7c2'}}
results.update({case:{'status':'blocked','reason':'Fixture prerequisites have not completed'} for case in CASES})

def record(name, fn, required=False):
    try:
        results[name] = {'status':'pass', 'value':fn()}
    except Exception as exc:
        results[name] = {'status':'fail', 'error':str(exc), 'traceback':traceback.format_exc()}
    save('results.json', results)
    print(name+': '+results[name]['status'], flush=True)
    if required:
        assert results[name]['status'] == 'pass', name
    return results[name]


def evaluate():
    import pyarrow as pa
    catalog, operator, key = setup(os.environ['INTEGRATION_ARCH'], record)
    human = catalog.provider.human()['access_token']
    user = 'oidc~' + decode(human)[1]['sub']
    privileged = 'oidc~operator'
    users = {user:secret(), privileged:secret(), 'oidc~unknown':secret()}
    trino_key = run('sudo','cat',WORK/'trino-key').strip()
    headers = {'Authorization':'Bearer '+key}
    def mutation(value):
        catalog.http.request('POST','https://cedar:8443/mutate',headers=headers,json=value).raise_for_status()
    for name, region in ((user, "eu"), (privileged, 'us'), ('oidc~unknown','eu')):
        mutation({'op':'set_region','principal':name,'region':region})
    admin = catalog.pyiceberg(operator)
    admin.create_namespace('s2')
    ids = {}
    for name in ('allowed','denied'):
        table = admin.create_table('s2.'+name, schema=pa.schema([
            pa.field('id',pa.int64()),pa.field('region',pa.string()),pa.field('sensitive',pa.string())]))
        table.append(pa.Table.from_pylist([{'id':1,'region':'eu','sensitive':'secret-eu'}, {'id':2,'region':'us','sensitive':'secret-us'}, {'id':3,'region':'eu','sensitive':'secret-eu-2'}]))
        ids[name] = str(table.metadata.table_uuid)
        mutation({'op':'bind_trino','name':['iceberg','s2',name], 'binding':{'resource':{'kind':'Table','id':ids[name]},'region_column':'region','sensitive_column':'sensitive'}})
    # Connector machine credential can load both tables: only OPA can hide denied.
    ns = 'namespace:'+admin.load_namespace_properties('s2')['namespace_id']
    grant(catalog,key,'user:oidc~lakekeeper','select',ns)
    grant(catalog,key,'user:'+user,'select','lakekeeper_table:'+catalog.warehouse_id+'/'+ids['allowed'])
    sql, tls = start(catalog,trino_key,users,'batch')
    record('trino_tls',lambda:tls)
    def rows(who, query, expected):
        actual = sql(who,query)
        assert actual == {'rows':expected}, actual
        return actual
    def deny(who, query):
        actual = sql(who,query)
        assert actual.get('error',{}).get('errorName') == 'PERMISSION_DENIED', actual
        assert actual['error']['errorType'] == 'USER_ERROR', actual
        return {'errorName':actual['error']['errorName'],'message':actual['error']['message']}
    def table_checks():
        return {
            'show':rows(user,'SHOW TABLES FROM iceberg.s2',[['allowed']]),
            'metadata':rows(user,"SELECT table_name FROM iceberg.information_schema.tables WHERE table_schema = 's2' ORDER BY table_name",[['allowed']]),
            'allowed':rows(user,'SELECT id FROM iceberg.s2.allowed ORDER BY id',[[1],[3]]),
            'denied':deny(user,'SELECT * FROM iceberg.s2.denied'),
            'write_denied':deny(user,"INSERT INTO iceberg.s2.allowed VALUES (4, 'eu', 'bad')"),
        }
    record('S2.1',table_checks)
    record('S2.2',lambda:rows(user,'SELECT id, region FROM iceberg.s2.allowed ORDER BY id',[[1,'eu'],[3,'eu']]))
    record('S2.3',lambda:{'masked':rows(user,'SELECT id, sensitive FROM iceberg.s2.allowed ORDER BY id',[[1,None],[3,None]]),
        'privileged':rows(privileged,'SELECT id, sensitive FROM iceberg.s2.allowed ORDER BY id',[[1,'secret-eu'],[2,'secret-us'],[3,'secret-eu-2']]),
        'columns':rows(user,'SHOW COLUMNS FROM iceberg.s2.allowed', [['id','bigint','',''],['region','varchar','',''],['sensitive','varchar','','']])})
    def parity():
        evidence = []
        for name in ('allowed','denied'):
            url = catalog.base+f'/catalog/v1/{catalog.warehouse_id}/namespaces/s2/tables/{name}'
            response = catalog.http.request('GET',url,headers={'Authorization':'Bearer '+human})
            expected = name == 'allowed'
            assert response.status_code == 200 if expected else response.status_code in (403,404), response.text
            query = {'input':{'context':{'identity':{'user':user,'groups':decode(human)[1]['groups']},'properties':{'serviceKey':trino_key}},'action':{'operation':'SelectFromColumns','resource':{'table':{'catalogName':'iceberg','schemaName':'s2','tableName':name,'columns':['id']}}}}}
            decision = catalog.http.json('POST','https://cedar:8443/opa/allow',json=query)
            assert decision == {'result':expected}, decision
            evidence.append({'principal':user,'table_uuid':ids[name],'catalog_status':response.status_code,'opa':decision})
        # Revoke the exact shared grant and require both enforcement points to deny.
        obj = 'lakekeeper_table:'+catalog.warehouse_id+'/'+ids['allowed']
        before = time.monotonic()
        grant(catalog,key,'user:'+user,'select',obj,True)
        try:
            query['input']['action']['resource']['table']['tableName'] = 'allowed'
            decision = catalog.http.json('POST','https://cedar:8443/opa/allow',json=query)
            assert decision == {'result':False}, decision
            actual = sql(user,'SELECT * FROM iceberg.s2.allowed')
            error = actual.get('error',{})
            # Removing the last visible binding can hide the whole catalog.
            if error.get('errorName') == 'CATALOG_NOT_FOUND':
                assert error['errorCode'] == 44 and error['errorType'] == 'USER_ERROR', actual
                assert error['message'] == "line 1:15: Catalog 'iceberg' not found", actual
            else:
                assert error.get('errorName') == 'PERMISSION_DENIED' and error['errorType'] == 'USER_ERROR', actual
            denied = {'errorName':error['errorName'],'message':error['message']}
            response = catalog.http.request('GET',catalog.base+f'/catalog/v1/{catalog.warehouse_id}/namespaces/s2/tables/allowed',headers={'Authorization':'Bearer '+human})
            assert response.status_code in (403,404), response.status_code
            elapsed = time.monotonic()-before
            assert elapsed < 5, elapsed
            evidence.append({'seconds':elapsed,'after_revoke_catalog':response.status_code,'after_revoke_opa':decision,'after_revoke_trino':denied})
        finally:
            grant(catalog,key,'user:'+user,'select',obj)
            rows(user,'SELECT id FROM iceberg.s2.allowed ORDER BY id',[[1],[3]])
        return evidence
    record('S2.4',parity)
    def groups():
        obj = 'lakekeeper_table:'+catalog.warehouse_id+'/'+ids['allowed']
        grant(catalog,key,'user:'+user,'select',obj,True)
        grant(catalog,key,'group:lake-readers','select',obj)
        subject = decode(human)[1]['sub']
        user_url = catalog.provider.base+'/auth/v1/users/'+subject
        before_user = catalog.http.json('GET',user_url,headers=catalog.provider.admin)
        try:
            rows(user,'SELECT id FROM iceberg.s2.allowed ORDER BY id',[[1],[3]])
            before = time.monotonic()
            removed = catalog.provider.remove_group(subject)
            assert 'lake-readers' not in (removed.get('groups') or [])
            time.sleep(0.3)  # Deliberately past the bounded live-membership cache.
            actual = sql(user,'SELECT id FROM iceberg.s2.allowed ORDER BY id')
            error = actual.get('error',{})
            assert error.get('errorName') == 'PERMISSION_DENIED' and error.get('errorType') == 'USER_ERROR', actual
            response = catalog.http.request('GET',catalog.base+f'/catalog/v1/{catalog.warehouse_id}/namespaces/s2/tables/allowed',headers={'Authorization':'Bearer '+human})
            assert response.status_code in (403,404), response.status_code
            elapsed = time.monotonic()-before
            assert elapsed < 5, elapsed
            return {'seconds':elapsed,'trino':error['errorName'],'catalog_status':response.status_code,'old_token':True}
        finally:
            catalog.http.json('PUT',user_url,headers=catalog.provider.admin,json=before_user)
            grant(catalog,key,'group:lake-readers','select',obj,True)
            grant(catalog,key,'user:'+user,'select',obj)
            time.sleep(0.3)
            rows(user,'SELECT id FROM iceberg.s2.allowed ORDER BY id',[[1],[3]])
    record('S2.groups',groups)
    def credentials():
        query = {'input':{'context':{'identity':{'user':user,'groups':[]},'properties':{'serviceKey':key}},'action':{'operation':'ExecuteQuery'}}}
        assert catalog.http.request('POST','https://cedar:8443/opa/allow',json=query).status_code == 401
        assert catalog.http.request('POST','https://cedar:8443/mutate',headers={'Authorization':'Bearer '+trino_key},json={'op':'set_region','principal':user,'region':'us'}).status_code == 401
        return {'native_key_rejected_by_opa':True,'opa_key_cannot_mutate':True}
    record('S2.credentials',credentials)
    def durable():
        from s1_fixture import snapshot, migrate
        before = snapshot(catalog,key)
        run('docker','restart','cedar')
        from common import wait
        wait(lambda:catalog.http.request('POST','https://cedar:8443/decide',headers=headers,json=[]).status_code==200)
        migrate(catalog); migrate(catalog)
        assert snapshot(catalog,key) == before
        rows(user,'SELECT id, sensitive FROM iceberg.s2.allowed ORDER BY id',[[1,None],[3,None]])
        return {'bindings_regions_grants_survive':True,'repeated_migrations':2}
    record('S2.durable',durable)

    def outage():
        rows(user,'SELECT id FROM iceberg.s2.allowed ORDER BY id',[[1],[3]])
        # Leave Cedar/Lakekeeper alive. Disconnect only Trino from its private endpoint.
        run('docker','network','disconnect','authz-backend','trino')
        try:
            before = time.monotonic()
            actual = sql(user,'SELECT id FROM iceberg.s2.allowed ORDER BY id')
            assert 'rows' not in actual and 'error' in actual, actual
            error = actual['error']
            assert 'io.trino.plugin.opa.OpaQueryException' in json.dumps(error), error
            assert 'OPA' in json.dumps(error), error
            return {'seconds':time.monotonic()-before,'errorName':error['errorName'],'failure_type':error.get('failureInfo',{}).get('type'),'no_rows':True}
        finally:
            run('docker','network','connect','authz-backend','trino')
            rows(user,'SELECT id FROM iceberg.s2.allowed ORDER BY id',[[1],[3]])
    record('S2.5',outage)
    save('trino-batch.log.json', {'log':run('docker','logs','trino')})
    run('docker','rm','-f','trino')
    sql, tls = start(catalog,trino_key,users,'single')
    record('S2.single',lambda:{'tables':rows(user,'SHOW TABLES FROM iceberg.s2',[['allowed']]),
        'mask_rows':rows(user,'SELECT id, sensitive FROM iceberg.s2.allowed ORDER BY id',[[1,None],[3,None]]),
        'denied':deny(user,'SELECT * FROM iceberg.s2.denied')})
    def audit():
        query = "SELECT json_build_object('wire',count(*) FILTER (WHERE action LIKE 'trino:%'), 'cedar',count(*) FILTER (WHERE reason LIKE 'trino_cedar_%'), 'denied',count(*) FILTER (WHERE NOT decision AND action LIKE 'trino:%'), 'missing_results',count(*) FILTER (WHERE action LIKE 'trino:%' AND result IS NULL), 'routes',array_agg(DISTINCT split_part(action, ':', 2)) FILTER (WHERE action LIKE 'trino:%')) FROM authz_audit"
        command = 'export PGSSLROOTCERT=/ca/ca.pem; psql "$(cat /run/cedar-db-url)" -At -c "'+query+'"'
        data = json.loads(run('docker','run','--rm','--network','container:fga-postgres','-v',f'{WORK/"cedar-db-url"}:/run/cedar-db-url:ro','-v',f'{catalog.provider.ca}:/ca/ca.pem:ro','localhost/postgresql-ubi:integration','bash','-c',command))
        assert data['wire'] > 0 and data['cedar'] > 0 and data['denied'] > 0, data
        assert data['missing_results'] == 0, data
        assert sorted(data['routes']) == ['allow','batch','batch_masks','mask','rows'], data
        return data
    record('S2.audit',audit)
    assert all(results[case]['status']=='pass' for case in CASES), 'S2 incomplete; see results.json'


if __name__ == '__main__':
    if sys.argv[1:] == ['initialize']:
        save('results.json',results)
    elif sys.argv[1:] == ['cleanup']:
        common.cleanup()
        for network in common.run('docker','network','ls','-q','--filter','name=^(authz-backend|slice1-idp)$').split():
            run('docker','network','rm',network)
    else:
        save('results.json',results)
        try:
            evaluate()
        finally:
            common.cleanup()
            for network in common.run('docker','network','ls','-q','--filter','name=^(authz-backend|slice1-idp)$').split():
                run('docker','network','rm',network)
            run('sudo','rm','-rf',WORK)
