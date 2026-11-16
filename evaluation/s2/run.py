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

CASES = ('S2.1', 'S2.2', 'S2.3', 'S2.4', 'S2.5', 'S2.single')
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
    users = {user:secret(), privileged:secret(), 'bob':secret()}
    headers = {'Authorization':'Bearer '+key}
    def mutation(value):
        catalog.http.request('POST','https://cedar:8443/mutate',headers=headers,json=value).raise_for_status()
    for name, region in ((user, "eu"), (privileged, 'us'), ('bob','eu')):
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
    sql, tls = start(catalog,key,users,'batch')
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
            query = {'input':{'context':{'identity':{'user':user,'groups':decode(human)[1]['groups']},'properties':{'serviceKey':key}},'action':{'operation':'SelectFromColumns','resource':{'table':{'catalogName':'iceberg','schemaName':'s2','tableName':name,'columns':['id']}}}}}
            decision = catalog.http.json('POST','https://cedar:8443/opa/allow',json=query)
            assert decision == {'result':expected}, decision
            evidence.append({'principal':user,'table_uuid':ids[name],'catalog_status':response.status_code,'opa':decision})
        # Revoke the exact shared grant and require both enforcement points to deny.
        obj = 'lakekeeper_table:'+catalog.warehouse_id+'/'+ids['allowed']
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
            evidence.append({'after_revoke_catalog':response.status_code,'after_revoke_opa':decision,'after_revoke_trino':denied})
        finally:
            grant(catalog,key,'user:'+user,'select',obj)
            rows(user,'SELECT id FROM iceberg.s2.allowed ORDER BY id',[[1],[3]])
        return evidence
    record('S2.4',parity)
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
    sql, tls = start(catalog,key,users,'single')
    record('S2.single',lambda:{'tables':rows(user,'SHOW TABLES FROM iceberg.s2',[['allowed']]),
        'mask_rows':rows(user,'SELECT id, sensitive FROM iceberg.s2.allowed ORDER BY id',[[1,None],[3,None]]),
        'denied':deny(user,'SELECT * FROM iceberg.s2.denied')})
    assert all(results[case]['status']=='pass' for case in CASES), 'S2 incomplete; see results.json'


if __name__ == '__main__':
    save('results.json',results)
    if sys.argv[1:] == ['initialize']:
        pass
    elif sys.argv[1:] == ['cleanup']:
        common.cleanup()
        for network in common.run('docker','network','ls','-q','--filter','name=^authz-backend$').split():
            run('docker','network','rm',network)
    else:
        try:
            evaluate()
        finally:
            common.cleanup()
            for network in common.run('docker','network','ls','-q','--filter','name=^authz-backend$').split():
                run('docker','network','rm',network)
            run('sudo','rm','-rf',WORK)
