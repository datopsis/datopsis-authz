"""S4 measured experiments. Credentials stay in the existing per-run fixture."""
import statistics
import time

from common import decode, run, save, secret, WORK


def membership_cases(catalog, key, human, namespace, tuples, denial):
    provider, http = catalog.provider, catalog.http
    claims = decode(human)[1]
    principal = 'oidc~' + claims['sub']
    human_id = 'user:' + principal
    headers = {'Authorization': 'Bearer '+key}
    user_url = provider.base + '/auth/v1/users/' + claims['sub']
    original = http.json('GET', user_url, headers=provider.admin)
    evidence = {}

    def configure(ttl):
        http.request('POST', 'https://cedar:8443/membership', headers=headers,
                     json={'principal': principal, 'cache_ms': ttl}).raise_for_status()

    def restore():
        http.json('PUT', user_url, headers=provider.admin, json=original)

    def load(token):
        return http.request('GET', catalog.base + f'/catalog/v1/{catalog.warehouse_id}/namespaces/bakeoff/tables/sample',
                            headers={'Authorization': 'Bearer '+token})

    try:
        tuples(human_id, 'select', namespace, True)
        for mode in ('C-live', 'C-cache-250ms', 'B-poll-1s'):
            restore()
            configure(0 if mode == 'C-live' else 250 if mode.startswith('C-') else None)
            negative = denial(lambda: catalog.read(catalog.pyiceberg(human)))
            tuples('group:lake-readers', 'select', namespace)
            allowed = catalog.read(catalog.pyiceberg(human))
            tuples('group:lake-readers', 'select', namespace, True)
            unmapped = denial(lambda: catalog.read(catalog.pyiceberg(human)))
            tuples('group:lake-readers', 'select', namespace)
            # Warm the cache immediately before removal, exercising its exposure bound.
            assert load(human).status_code == 200
            before = time.monotonic()
            removed = provider.remove_group(claims['sub'])
            acknowledged = time.monotonic()
            assert 'lake-readers' not in (removed.get('groups') or [])
            poll_requests = 0
            epoch = None
            if mode.startswith('B-'):
                # One complete poll cycle after acknowledged removal. The baseline
                # above is authoritative. Persist the cutoff BEFORE acknowledging sync.
                time.sleep(1)
                current = http.json('GET', user_url, headers=provider.admin)
                poll_requests += 1
                assert set(original['groups']) - set(current.get('groups') or [])
                epoch = int(time.time()) + 1  # reject every token issued in this second
                http.request('POST', 'https://cedar:8443/mutate', headers=headers,
                             json={'op':'revoke_before','principal':principal,'epoch':epoch}).raise_for_status()
            samples = []
            while time.monotonic() - acknowledged < 30:
                response = load(human)
                samples.append({'seconds_since_ack':time.monotonic()-acknowledged,'status':response.status_code})
                assert response.status_code in (200,403,404), response.status_code
                if response.status_code in (403,404):
                    break
                time.sleep(.025)
            assert samples[-1]['status'] in (403,404), samples
            assert decode(human)[1]['exp'] > time.time(), 'C3 requires an unexpired old token'
            old_denied = denial(lambda: catalog.read(catalog.pyiceberg(human)))
            evidence[mode] = {'unmapped':negative,'mapped_exact_rows':allowed,'mapping_removal':unmapped,
                'IdP_removal_old_unexpired_token':old_denied, 'removal_request_seconds':acknowledged-before,
                'first_denial_seconds':samples[-1]['seconds_since_ack'],'samples':samples,
                'poll_requests':poll_requests}
            save('S4-membership.json', evidence)
            if mode.startswith('C-'):
                # Measure a repeatable mix of 20 fresh catalog requests and service
                # lookups, then force an outage past the positive-cache TTL.
                restore()
                configure(0 if mode == 'C-live' else 250)
                before_lookups = lookup_samples()
                durations = []
                for _ in range(20):
                    start = time.monotonic()
                    assert load(human).status_code == 200
                    durations.append((time.monotonic()-start)*1000)
                run('docker','stop',provider.container)
                try:
                    time.sleep(.3)
                    start = time.monotonic()
                    outage = load(human)
                    assert outage.status_code in (403,500,503), outage.status_code
                    body = outage.json()
                    assert body.get('error',{}).get('type'), body
                    assert not any(k in body for k in ('metadata','config','storage-credentials'))
                    evidence[mode].update({'catalog_latency_ms':durations,'median_ms':statistics.median(durations),
                        'membership_lookup_ms':lookup_samples()[len(before_lookups):],
                        'catalog_load_requests':20,
                        'outage_status':outage.status_code,'outage_error_type':body['error']['type'],
                        'outage_seconds':time.monotonic()-start})
                finally:
                    run('docker','start',provider.container)
                    from common import wait
                    wait(lambda:http.request('GET',provider.base+'/auth/v1/health').status_code==200,180)
                configure(None)
            else:
                restore()
                while time.time() < epoch:
                    time.sleep(.05)
                human = provider.human()['access_token']
                assert decode(human)[1]['iat'] >= epoch
                assert load(human).status_code == 200, 'Fresh token must recover after epoch'
                # Epoch rollback is forbidden and missing iat fails closed.
                check = {'principal':principal,'groups':['lake-readers'],'action':'read_data',
                         'resource':{'kind':'Namespace','id':namespace.split(':',1)[1]}}
                response = http.json('POST','https://cedar:8443/decide',headers=headers,json=[check])
                assert response[0]['allowed'] is False
                evidence[mode]['missing_iat_denied'] = True
            tuples('group:lake-readers','select',namespace,True)
            save('S4-membership.json', evidence)
        return evidence, human
    finally:
        configure(None)
        restore()
        tuples('group:lake-readers','select',namespace,True)
        tuples(human_id,'select',namespace)


def short_tokens(catalog, namespace, tuples):
    """Configure the real IdP; measure expiry exposure and token endpoint cost.

    Existing Trino and Sail containers are reused. Queries force fresh metadata.
    Requests per client are measured by sanitized IdP TokenIssued event counts
    where available; do not infer renewal behavior from arithmetic.
    """
    provider, http = catalog.provider, catalog.http
    url = provider.base+'/auth/v1/clients/lakekeeper'
    original = http.json('GET',url,headers=provider.admin)
    updated = {**original,'access_token_lifetime':30}
    evidence = {'configured_lifetime_seconds':30, 'clients':{}}
    user_url = None
    original_user = None
    human_id = None
    try:
        http.json('PUT',url,headers=provider.admin,json=updated)
        # Restart Sail with a genuine 30-second file token. Trino is already
        # running from C5; subsequent statements reuse its OAuth session.
        from common import write
        run('docker','restart','trino')
        from common import wait
        wait(lambda:http.json('GET','https://trino:8443/v1/info').get('starting') is False,180)
        evidence['trino_short_token_initial'] = trino_query(http)
        short_file_token = provider.token()
        # Write through the existing bind-mounted inode rather than replacing it.
        run('sudo','tee',WORK/'sail-authz/token',input=short_file_token)
        run('docker','restart','sail-backend')
        token = provider.human()['access_token']
        claims = decode(token)[1]
        human_id = 'user:oidc~'+claims['sub']
        user_url = provider.base+'/auth/v1/users/'+claims['sub']
        original_user = http.json('GET',user_url,headers=provider.admin)
        assert 'lake-readers' in claims['groups']
        tuples(human_id,'select',namespace,True)
        tuples('group:lake-readers','select',namespace)
        assert claims['exp'] - claims['iat'] == 30
        path = catalog.base+f'/catalog/v1/{catalog.warehouse_id}/namespaces/bakeoff/tables/sample'
        assert http.request('GET',path,headers={'Authorization':'Bearer '+token}).status_code==200
        removed=provider.remove_group(claims['sub'])
        assert 'lake-readers' not in (removed.get('groups') or [])
        start = time.monotonic()
        samples=[]
        while time.monotonic()-start < 100:
            r=http.request('GET',path,headers={'Authorization':'Bearer '+token})
            samples.append({'seconds':time.monotonic()-start,'status':r.status_code})
            assert r.status_code in (200,401), r.status_code
            if r.status_code == 401:
                break
            time.sleep(1)
        assert samples[-1]['status'] == 401
        evidence['C3_old_unexpired_token'] = 'FAIL: allowed until authentication expiry; 401 is not authorization denial'
        evidence['trino_after_expiry'] = trino_query(http)
        evidence['sail_stale_file'] = sail_query(provider)
        assert evidence['sail_stale_file']['returncode'] != 0, 'Expired Sail file unexpectedly read successfully'
        fresh_file_token = provider.token()
        run('sudo','tee',WORK/'sail-authz/token',input=fresh_file_token)
        evidence['sail_rewritten_file'] = sail_query(provider)
        evidence.update({'old_token_exposure_seconds' :samples[-1]['seconds'], 'samples':samples,
                         'claim_lifetime_seconds':claims['exp']-claims['iat'],
                         'clock_allowance_seconds':60})
        for client in ('Trino','PyIceberg','Sail-token-file'):
            timings=[]
            for _ in range(5):
                tick=time.monotonic()
                fresh=provider.token()
                timings.append((time.monotonic()-tick)*1000)
                assert http.request('GET',path,headers={'Authorization':'Bearer '+fresh}).status_code==200
            evidence['clients'][client]={'explicit_client_credentials_requests':5,'latency_ms':timings,
                'projected_requests_per_minute_at_20s_renewal':3,
                'scope':'Token endpoint microbenchmark; native client renewal measured separately'}
        # Isolate each workload so persisted TokenIssued events measure native
        # token acquisition, not an estimate or a relabeled microbenchmark.
        client=catalog.pyiceberg()
        workloads = {
            'Trino': lambda: trino_query(http),
            'PyIceberg': lambda: catalog.read(client),
            'Sail-token-file': lambda: sail_query(provider),
        }
        for name, workload in workloads.items():
            before_ids = token_event_ids(provider)
            tick = time.monotonic()
            outcomes = []
            acquisitions = 0
            for i in range(4):
                if i:
                    time.sleep(max(0, tick+i*20-time.monotonic()))
                if name == 'Sail-token-file':
                    fresh = provider.token()
                    acquisitions += 1
                    run('sudo','tee',WORK/'sail-authz/token',input=fresh)
                try:
                    value = workload()
                    outcomes.append({'seconds':time.monotonic()-tick,'value':value})
                except Exception as exc:
                    outcomes.append({'seconds':time.monotonic()-tick,'error_type':type(exc).__name__})
            after_ids = token_event_ids(provider)
            evidence['clients'][name]['native_workload'] = {
                'seconds':time.monotonic()-tick, 'requests':4, 'token_issued_events':len(after_ids-before_ids),
                'external_file_acquisitions':acquisitions, 'outcomes':outcomes,
                'scope':'Isolated 0/20/40/60s fresh queries; Sail uses explicit external file renewal every 20s',
            }
            save('S4-short-tokens.json',evidence)
            if name == 'Trino':
                run('docker','stop','trino')
        save('S4-short-tokens.json',evidence)
        return evidence
    finally:
        http.json('PUT',url,headers=provider.admin,json=original)
        if original_user is not None:
            http.json('PUT',user_url,headers=provider.admin,json=original_user)
            tuples('group:lake-readers','select',namespace,True)
            tuples(human_id,'select',namespace)
        save('S4-short-tokens.json',evidence)


def trino_query(http):
    page = http.json('POST','https://trino:8443/v1/statement',
                     data='SELECT * FROM iceberg.bakeoff.sample ORDER BY id',headers={'X-Trino-User':'evaluation'})
    rows=[]
    while True:
        assert 'error' not in page, page.get('error',{}).get('errorName')
        rows.extend(page.get('data',[]))
        if 'nextUri' not in page:
            break
        page=http.json('GET',page['nextUri'])
    assert rows == [[1,'alpha'],[2,'beta']], rows
    return {'rows':rows,'scope':'Long-running Trino process, fresh SQL after short-token expiry; token request count not instrumented'}


def sail_query(provider):
    import os
    import subprocess
    from common import ROOT
    result=subprocess.run([str(ROOT/'.sources/sail-venv/bin/python'), str(ROOT/'evaluation/authz/sail_client.py')],
        env=dict(os.environ,GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=str(provider.ca)),capture_output=True,text=True,timeout=180)
    # Only retain status: exception text can contain remote request details.
    return {'returncode':result.returncode,'scope':'Full pinned Sail exact-row and typed-denial client'}


def token_event_ids(provider):
    time.sleep(.3)  # let asynchronous event persistence settle
    events = provider.http.json('POST',provider.base+'/auth/v1/events',headers=provider.admin,
                               json={'from':1719784800,'until':int(time.time())+2,'level':'info','typ':'TokenIssued'})
    # IDs only; never retain event bodies or token values.
    return {event['id'] for event in events if (event.get('text') or '').startswith('lakekeeper (')}


def lookup_samples():
    import json
    logs = run('docker','logs','cedar')
    result=[]
    for line in logs.splitlines():
        try:
            entry=json.loads(line)
            if 'membership_lookup_ms' in entry:
                result.append(entry['membership_lookup_ms'])
        except ValueError:
            pass
    return result
