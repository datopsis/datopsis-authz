"""Independent native Sail costs when the pinned IdP cannot be acquired.

This never passes an authenticated-user, gateway, or Lakekeeper assertion.
"""
import concurrent.futures
import json
import os
import statistics
import socket
import subprocess
import time
from pathlib import Path

import run as s5

s5.WORK = s5.ROOT/'.runtime/s5-engine'
s5.RUNTIME = s5.WORK/'instances'
s5.common.WORK = s5.WORK
s5.WORK.mkdir(parents=True, exist_ok=True)
os.environ.update(S5_RUNTIME=str(s5.RUNTIME), S5_CONFIG=str(s5.WORK/'supervisor.json'))
config = dict(image='localhost/sail-ubi:integration', network='none',
    ca='/etc/ssl/certs/ca-certificates.crt', memory='512m', cpus='1',env={'TOKIO_WORKER_THREADS':'2'})
s5.write(s5.WORK/'supervisor.json', config)
s5.run('sudo','chown','root:root',s5.WORK/'supervisor.json')
result = dict(architecture=s5.ARCH,machine=s5.RESULTS['machine'],source=s5.RESULTS['source'],
    run=s5.RESULTS['run'],host=s5.RESULTS['host'],sail=s5.RESULTS['sail'],
    scope='Engine only: no JWT authentication, gateway routing or Lakekeeper grant assertions',cases={})
image=json.loads(s5.run('docker','image','inspect',config['image']))[0]
assert image['Architecture']==s5.ARCH
assert image['Config']['Labels']['org.opencontainers.image.revision']==s5.RESULTS['sail']
result['image']=dict(id=image['Id'],labels=image['Config']['Labels'])


def record(name, fn):
    try:
        result['cases'][name]=dict(status='PASS',evidence=fn())
    except Exception as exc:
        result['cases'][name]=dict(status='FAIL',error=str(exc))
    s5.save('engine-only.json',result)
    print(json.dumps(dict(case=name,**result['cases'][name])),flush=True)


try:
    record('single',lambda:s5.single('engine-only-no-catalog'))
    s5.stop_all()
    for n in (1,5,20):
        def scale(n=n):
            def start(_):
                started=time.monotonic()
                try:
                    value=s5.lifecycle(dict(op='ensure',token='engine-only-no-catalog'))
                    return dict(status='READY',**value,total_seconds=time.monotonic()-started)
                except Exception as exc:
                    return dict(status='FAIL',error=str(exc),total_seconds=time.monotonic()-started)
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
                values=list(pool.map(start,range(n)))
            ready_memory=s5.memory()
            tunnels=[]
            try:
                jobs=[]
                for index,instance in enumerate(values):
                    if instance['status']!='READY': continue
                    port=50100+index
                    proc=subprocess.Popen(['sudo','-E','socat',
                        f'TCP4-LISTEN:{port},bind=127.0.0.1,reuseaddr,fork',
                        'EXEC:'+str(s5.HELPER)+' relay '+instance['name']],
                        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                    tunnels.append(proc)
                    def ready(port=port):
                        with socket.create_connection(('127.0.0.1',port),timeout=1): return True
                    s5.wait(ready,10)
                    jobs.append(dict(token='',sql='SELECT sum(id) AS total, count(DISTINCT id) AS distinct_ids FROM range(1000000)',
                        endpoint=f'127.0.0.1:{port}',tls=False,expected=[{'total':499999500000,'distinct_ids':1000000}]))
                queries=json.loads(s5.run(s5.PYTHON,s5.ROOT/'evaluation/s5/client.py',input=json.dumps(dict(jobs=jobs))))
                memory=s5.memory()
            finally:
                for proc in tunnels:
                    s5.run('sudo','kill','-TERM',str(proc.pid))
                    proc.wait(timeout=10)
            times=sorted(v['total_seconds'] for v in values)
            value=dict(n=n,instances=values,ready_memory=ready_memory,memory=memory,queries=queries,
                query_failures=sum(q['status']!='OK' for q in queries),
                aggregate_cgroup_peak_bytes=sum(v['cgroup_peak_bytes'] for v in memory['instances']),cold_to_ready_seconds=times,
                min_seconds=min(times),median_seconds=statistics.median(times),max_seconds=max(times),
                failures=sum(v['status']!='READY' for v in values))
            s5.save(f'engine-scale-{n}.json',value)
            assert value['failures']==value['query_failures']==0 and len(memory['instances'])==len(queries)==n,value
            return value
        record(f'instances_{n}',scale)
        s5.stop_all()
    record('resource_limits',lambda:s5.limits(config,'engine-only-no-catalog'))
finally:
    s5.stop_all()
    remaining=s5.names()
    s5.run('sudo','rm','-rf',s5.WORK)
    result['cleanup']=dict(runtime_removed=not s5.WORK.exists(),instances_remaining=len(remaining))
    s5.save('engine-only.json',result)
assert all(v['status']=='PASS' for v in result['cases'].values()),'Engine-only measurement failure'
