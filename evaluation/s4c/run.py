"""Slice 4c adversarial runtime review on the unchanged S2 fixture (CI only).

Each case asserts the REQUIRED secure behaviour end to end: Rauthy, Lakekeeper
with the Cedar adapter, serve, PostgreSQL and stock Trino 484 with OPA. A FAIL
is a finding for owner triage. All cases run; any FAIL fails this step only.
"""
import json
import os
import platform
import subprocess
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT/'.sources/lakehouse-integration'
PIN = 'e8379a528bf413c05aad49e56bc8cd507b5e077a'
assert subprocess.check_output(['git','-C',str(SOURCE),'rev-parse','HEAD'],text=True).strip() == PIN
sys.path.extend([str(ROOT/'evaluation/s1'),str(ROOT/'evaluation/s2'),str(SOURCE/'evaluation/authz'),str(SOURCE/'evaluation/idp')])
import common
common.OUT = ROOT/'reports/s4c'
from common import HTTPS, WORK, decode, run, save, secret, write
from s1_fixture import setup, grant
from trino import start
import rauthy
INPUTS = json.loads((ROOT/'evaluation/s1/inputs.json').read_text())
rauthy.REVISION = INPUTS['rauthy-ubi']['revision']

CASES = ('control','rename_in_place_stale_binding','drop_and_recreate_same_name','hidden_metadata_tables',
         'information_schema_and_system_metadata','show_stats_and_describe','mask_and_row_filter_oracles',
         'writes_and_ddl','impersonation','identifier_case','audit_owner_separation')
RESULTS = {'run':{'architecture':os.environ.get('INTEGRATION_ARCH'),'uname':platform.machine(),
                  'url':os.environ.get('RUN_URL'),'source':os.environ.get('GITHUB_SHA'),'fixture':PIN,
                  'trino_ubi':INPUTS['trino-ubi']['revision']},
           'cases':{c:{'status':'BLOCKED','reason':'Fixture prerequisites have not completed'} for c in CASES}}


def record(name, fn, required=False):
    try:
        RESULTS['cases'][name] = {'status':'PASS','evidence':fn()}
    except Exception as exc:
        RESULTS['cases'][name] = {'status':'FAIL','error':str(exc),'traceback':traceback.format_exc()}
    save('runtime.json',RESULTS)
    print(name+': '+RESULTS['cases'][name]['status']+('' if RESULTS['cases'][name]['status']=='PASS' else ' - '+RESULTS['cases'][name]['error'][:500]),flush=True)
    if required:
        assert RESULTS['cases'][name]['status']=='PASS', name
    return RESULTS['cases'][name]


def evaluate():
    import pyarrow as pa
    arch = os.environ['INTEGRATION_ARCH']
    fixture_cases = {}
    def fixture_record(name, fn, required=False):
        try:
            fixture_cases[name] = {'status':'pass','value':fn()}
        except Exception as exc:
            fixture_cases[name] = {'status':'fail','error':str(exc)}
            if required:
                raise
        return fixture_cases[name]
    catalog, operator, key = setup(arch, fixture_record)
    RESULTS['fixture'] = {k:v['status'] for k,v in fixture_cases.items()}
    human = catalog.provider.human()['access_token']
    user = 'oidc~'+decode(human)[1]['sub']
    privileged = 'oidc~operator'
    users = {user:secret(), privileged:secret()}
    trino_key = run('sudo','cat',WORK/'trino-key').strip()
    headers = {'Authorization':'Bearer '+key}
    def mutation(value):
        catalog.http.request('POST','https://cedar:8443/mutate',headers=headers,json=value).raise_for_status()
    mutation({'op':'set_region','principal':user,'region':'eu'})
    admin = catalog.pyiceberg(operator)
    admin.create_namespace('s4c')
    ns = 'namespace:'+admin.load_namespace_properties('s4c')['namespace_id']
    # The connector machine identity can load every s4c table; only OPA decides.
    grant(catalog,key,'user:oidc~lakekeeper','select',ns)
    schema = pa.schema([pa.field('id',pa.int64()),pa.field('region',pa.string()),pa.field('sensitive',pa.string())])
    def create(name, rows, bind=True, alice=True, region=None, sensitive=None):
        table = admin.create_table('s4c.'+name, schema=schema)
        table.append(pa.Table.from_pylist(rows, schema=schema))
        uuid = str(table.metadata.table_uuid)
        if bind:
            mutation({'op':'bind_trino','name':['iceberg','s4c',name],'binding':{'resource':{'kind':'Table','id':uuid},
                      'region_column':region,'sensitive_column':sensitive}})
        if alice:
            grant(catalog,key,'user:'+user,'select','lakekeeper_table:'+catalog.warehouse_id+'/'+uuid)
        return uuid
    rows = [{'id':1,'region':'eu','sensitive':'secret-eu'},{'id':2,'region':'us','sensitive':'secret-us'}]
    ids = {'visible':create('visible',rows,region='region',sensitive='sensitive'),
           'private':create('private',[{'id':9,'region':'eu','sensitive':'private-secret'}],alice=False),
           'shared':create('shared',[{'id':1,'region':'eu','sensitive':'alice-may-read'}]),
           'dropme':create('dropme',[{'id':1,'region':'eu','sensitive':'alice-may-read'}])}
    sql, tls = start(catalog,trino_key,users,'batch')
    http = HTTPS(catalog.provider.ca)
    def raw(auth_user, header_user, statement):
        auth = (auth_user, users[auth_user])
        page = http.json('POST','https://trino:8443/v1/statement',data=statement,headers={'X-Trino-User':header_user},auth=auth)
        data = []
        while True:
            if 'error' in page:
                return {'error':page['error'],'rows':data}
            data.extend(page.get('data',[]))
            if 'nextUri' not in page:
                return {'rows':data}
            page = http.json('GET',page['nextUri'],headers={'X-Trino-User':header_user},auth=auth)
    def rows_of(who, statement):
        result = sql(who, statement)
        assert 'rows' in result, result
        return result['rows']
    def refused(who, statement):
        result = sql(who, statement)
        assert 'error' in result and not result.get('rows'), f'{statement!r} returned {result}'
        return {'errorName':result['error'].get('errorName'),'message':result['error'].get('message','')[:300]}
    def control():
        assert rows_of(user,'SELECT id, sensitive FROM iceberg.s4c.visible ORDER BY id') == [[1,None]]
        assert rows_of(user,'SELECT id, sensitive FROM iceberg.s4c.shared') == [[1,'alice-may-read']]
        assert refused(user,'SELECT * FROM iceberg.s4c.private')['errorName'] == 'PERMISSION_DENIED'
        assert rows_of(privileged,'SELECT id FROM iceberg.s4c.private') == [[9]]
        return {'trino':tls['version'],'masked_and_filtered':True,'private_denied':True}
    record('control',control,required=True)

    def rename_in_place():
        # Lakekeeper only calls the authorizer's detach/attach hooks when a rename
        # changes namespace. Renaming within s4c keeps iceberg.s4c.shared bound
        # to the moved UUID; a NEW table created under the old name must not be
        # readable through that stale binding.
        admin.rename_table('s4c.shared','s4c.shared_moved')
        replacement = create('shared',[{'id':7,'region':'eu','sensitive':'operator-only-secret'}],bind=False,alice=False)
        result = sql(user,'SELECT id, sensitive FROM iceberg.s4c.shared')
        evidence = {'replacement_uuid':replacement,'original_uuid':ids['shared'],'alice_result':result}
        assert 'error' in result and not result.get('rows'), \
            f'stale SQL-name binding served a different table to the old grantee: {evidence}'
        return evidence
    record('rename_in_place_stale_binding',rename_in_place)

    def drop_recreate():
        admin.drop_table('s4c.dropme')
        replacement = create('dropme',[{'id':8,'region':'eu','sensitive':'operator-only-secret'}],bind=False,alice=False)
        result = sql(user,'SELECT id, sensitive FROM iceberg.s4c.dropme')
        evidence = {'replacement_uuid':replacement,'original_uuid':ids['dropme'],'alice_result':result}
        assert 'error' in result and not result.get('rows'), \
            f'binding survived DROP and served the recreated table: {evidence}'
        return evidence
    record('drop_and_recreate_same_name',drop_recreate)

    def hidden():
        evidence = {}
        for suffix in ('files','snapshots','partitions','manifests','history','properties','refs','entries'):
            statement = f'SELECT * FROM iceberg.s4c."visible${suffix}"'
            result = sql(user,statement)
            text = json.dumps(result)
            assert 'secret-eu' not in text and 'secret-us' not in text, f'{suffix} leaked masked values'
            assert 'error' in result and not result.get('rows'), f'{statement} readable: {result}'
            evidence[suffix] = result['error'].get('errorName')
        return evidence
    record('hidden_metadata_tables',hidden)

    def metadata():
        tables = rows_of(user,"SELECT table_name FROM iceberg.information_schema.tables WHERE table_schema='s4c' ORDER BY 1")
        columns = rows_of(user,"SELECT DISTINCT table_name FROM iceberg.information_schema.columns WHERE table_schema='s4c' ORDER BY 1")
        evidence = {'tables':tables,'columns':columns}
        for statement in ("SELECT table_name FROM system.jdbc.tables WHERE table_cat='iceberg' AND table_schem='s4c'",
                          "SELECT table_name FROM system.jdbc.columns WHERE table_cat='iceberg' AND table_schem='s4c'",
                          "SELECT table_name FROM system.metadata.table_comments WHERE catalog_name='iceberg' AND schema_name='s4c'",
                          "SELECT table_name FROM iceberg.information_schema.table_privileges WHERE table_schema='s4c'"):
            result = sql(user,statement)
            evidence[statement] = result.get('rows', result.get('error',{}).get('errorName'))
            assert 'private' not in json.dumps(result.get('rows',[])), f'{statement} listed private: {result}'
        assert ['private'] not in tables and ['private'] not in columns, evidence
        return evidence
    record('information_schema_and_system_metadata',metadata)

    def stats():
        evidence = {}
        for statement in ('SHOW STATS FOR iceberg.s4c.visible','SHOW STATS FOR (SELECT * FROM iceberg.s4c.visible)',
                          'SHOW STATS FOR iceberg.s4c.private','DESCRIBE iceberg.s4c.private','SHOW CREATE TABLE iceberg.s4c.private',
                          'SHOW CREATE TABLE iceberg.s4c.visible','EXPLAIN SELECT * FROM iceberg.s4c.private'):
            result = sql(user,statement)
            text = json.dumps(result)
            evidence[statement] = result.get('error',{}).get('errorName','rows')
            for leak in ('secret-eu','secret-us','private-secret'):
                assert leak not in text, f'{statement} leaked {leak}'
            if 'private' in statement:
                assert 'error' in result and not result.get('rows'), f'{statement} answered: {result}'
        return evidence
    record('show_stats_and_describe',stats)

    def oracles():
        checks = {
            "SELECT id FROM iceberg.s4c.visible WHERE sensitive = 'secret-eu'":[],
            "SELECT count(*) FROM iceberg.s4c.visible WHERE sensitive LIKE 'secret%'":[[0]],
            "SELECT count(*) FROM iceberg.s4c.visible":[[1]],
            "SELECT count(*) FROM iceberg.s4c.visible WHERE region = 'us'":[[0]],
            "SELECT max(length(sensitive)) FROM iceberg.s4c.visible":[[None]],
        }
        evidence = {}
        for statement, expected in checks.items():
            actual = rows_of(user,statement)
            evidence[statement] = actual
            assert actual == expected, f'{statement}: {actual} != {expected}'
        return evidence
    record('mask_and_row_filter_oracles',oracles)

    def writes():
        evidence = {}
        before = rows_of(privileged,'SELECT id, region, sensitive FROM iceberg.s4c.visible ORDER BY id')
        for statement in ("INSERT INTO iceberg.s4c.visible VALUES (3,'eu','x')", 'DELETE FROM iceberg.s4c.visible',
                          "UPDATE iceberg.s4c.visible SET sensitive = 'x'", 'ALTER TABLE iceberg.s4c.visible ADD COLUMN c bigint',
                          'ALTER TABLE iceberg.s4c.visible RENAME TO iceberg.s4c.stolen', 'DROP TABLE iceberg.s4c.visible',
                          "COMMENT ON TABLE iceberg.s4c.visible IS 'x'", 'CREATE TABLE iceberg.s4c.copy AS SELECT * FROM iceberg.s4c.visible',
                          'CREATE VIEW iceberg.s4c.v AS SELECT * FROM iceberg.s4c.private', 'CREATE SCHEMA iceberg.s4c_evil',
                          'ALTER TABLE iceberg.s4c.visible EXECUTE optimize', "ALTER TABLE iceberg.s4c.visible EXECUTE expire_snapshots(retention_threshold => '0d')",
                          'TRUNCATE TABLE iceberg.s4c.visible', "CALL iceberg.system.register_table('s4c','reg','s3://x/y')"):
            evidence[statement] = refused(user,statement)['errorName']
        after = rows_of(privileged,'SELECT id, region, sensitive FROM iceberg.s4c.visible ORDER BY id')
        assert before == after, 'table changed through a refused statement'
        names = sorted(t[1] for t in admin.list_tables('s4c'))
        assert not {'copy','v','stolen','reg'} & set(names), names
        return evidence
    record('writes_and_ddl',writes)

    def impersonation():
        result = raw(user, privileged, 'SELECT id FROM iceberg.s4c.private')
        assert 'error' in result and not result['rows'], f'impersonated the operator: {result}'
        result2 = raw(user, privileged, 'SELECT 1')
        assert 'error' in result2, f'impersonation accepted: {result2}'
        return {'private':result['error'].get('errorName'),'select_1':result2['error'].get('errorName')}
    record('impersonation',impersonation)

    def case():
        evidence = {}
        for statement in ('SELECT * FROM iceberg."S4C"."PRIVATE"','SELECT * FROM ICEBERG.S4C.PRIVATE','SELECT * FROM iceberg.s4c."Private"'):
            evidence[statement] = refused(user,statement)['errorName']
        return evidence
    record('identifier_case',case)

    def audit_owner():
        from urllib.parse import urlsplit, unquote
        database = urlsplit(run('sudo','cat',WORK/'cedar-db-url').strip())
        values = dict(PGHOST=database.hostname,PGPORT=str(database.port or 5432),PGDATABASE=unquote(database.path.lstrip('/')),
            PGUSER=unquote(database.username),PGPASSWORD=unquote(database.password),PGSSLMODE='verify-full',PGSSLROOTCERT='/ca/ca.pem')
        write(WORK/'s4c-audit.env','\n'.join(k+'='+v for k,v in values.items())+'\n')
        query = ("SELECT json_build_object('service_role',current_user,'owner',(SELECT tableowner FROM pg_tables WHERE tablename='authz_audit'),"
                 "'superuser',(SELECT rolsuper FROM pg_roles WHERE rolname=current_user),"
                 "'can_delete',has_table_privilege('authz_audit','DELETE'),'can_truncate',has_table_privilege('authz_audit','TRUNCATE'));")
        data = json.loads(run('docker','run','--rm','-i','--network','container:fga-postgres','--env-file',WORK/'s4c-audit.env',
            '-v',f'{catalog.provider.ca}:/ca/ca.pem:ro','localhost/postgresql-ubi:integration','psql','-XAt','-f','-',input=query))
        # Read-only evidence: the credential serve uses must not own (and so be
        # able to disable the append-only trigger on) its own audit table.
        assert data['owner'] != data['service_role'] and not data['superuser'], f'serve credential owns its audit table: {data}'
        assert not data['can_delete'] and not data['can_truncate'], data
        return data
    record('audit_owner_separation',audit_owner)
    failed = [c for c in CASES if RESULTS['cases'][c]['status'] != 'PASS']
    assert not failed, f'slice 4c adversarial runtime findings: {failed}; see reports/s4c/runtime.json'


def cleanup():
    common.cleanup()
    for network in run('docker','network','ls','-q','--filter','name=^(authz-backend|slice1-idp)$').split():
        run('docker','network','rm',network)
    run('sudo','rm','-rf',WORK)


if __name__ == '__main__':
    if sys.argv[1:] == ['initialize']:
        save('runtime.json',RESULTS)
    elif sys.argv[1:] == ['cleanup']:
        cleanup()
    else:
        save('runtime.json',RESULTS)
        # S1 leaves its fixture work directory behind; start from S2's clean state.
        cleanup()
        try:
            evaluate()
        finally:
            cleanup()
