"""Blocking S3 slow-reader oracle, retained without relaxing any assertion."""
import json
import os
import subprocess
import sys
from pathlib import Path
import common
from common import run, save, wait
ROOT = Path(__file__).resolve().parents[2]
SAIL = ROOT/'.sources/lakehouse-integration/.sources/sail-ubi'
PYTHON = ROOT/'.sources/lakehouse-integration/.sources/sail-venv/bin/python'
def stream(ca, path):
    # Unmodified owner-paced client and passive control-frame observer.
    obj = json.loads(run('docker', 'inspect', 'sail-a'))[0]
    trace = common.OUT/'paced-h2.jsonl'
    with trace.open('w') as output:
        observer = subprocess.Popen(['sudo', 'nsenter', '-t', str(obj['State']['Pid']), '-n',
                                     '/usr/bin/python3', '-u', str(SAIL/'tests/h2_trace.py')], stdout=output, stderr=subprocess.STDOUT)
        pid = None
        try:
            def ready():
                nonlocal pid
                lines = trace.read_text().splitlines()
                if lines:
                    event = json.loads(lines[0]); assert event['event'] == 'ready'
                    pid = event['pid']; return True
            wait(ready, 10)
            result = subprocess.run([str(PYTHON), str(SAIL/'tests/stream_probe.py'),
                                     'sc://sail:50051/;use_ssl=true;token='+path.read_text().strip(),
                                     '1000000', '5', '16', 'none'], capture_output=True, text=True, timeout=240,
                                    env=dict(os.environ, GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=str(ca)))
            events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
            save('paced-client.json', dict(returncode=result.returncode, events=events,
                                           log=result.stdout+result.stderr))
        finally:
            if pid: run('sudo', 'kill', '-TERM', str(pid))
            assert observer.wait(timeout=10) == 0, 'Invalid packet capture'
    frames = [json.loads(line) for line in trace.read_text().splitlines()]
    logs = run('docker', 'logs', 'gateway')
    stalls = [json.loads(line) for line in logs.splitlines() if line.startswith('{') and 'downstream_backpressure' in line]
    save('paced-backpressure.json', stalls)
    capture = next(e for e in frames if e['event'] == 'capture_summary')
    assert capture['drops'] == 0
    result_flow = max((f for f in capture['flows'] if f['ports'][0] == 50052), key=lambda f: f['data_bytes'])
    assert result_flow['data_bytes'] > 0
    connected = next(e['seconds'] for e in frames if e['event'] == 'tcp_syn' and e['ports'] == result_flow['ports'])
    pairs = []
    for ping in frames:
        if (ping.get('frame') == 'PING' and not ping['ack'] and ping['ports'] == result_flow['ports']
                and ping['seconds'] - connected >= 50):
            ack = next(e for e in frames if e.get('frame') == 'PING' and e['ack'] and e['opaque'] == ping['opaque']
                       and e['ports'] == ping['ports'][::-1] and e['seconds'] >= ping['seconds'])
            pairs.append(dict(ping_seconds=ping['seconds'], connection_age_seconds=ping['seconds']-connected, ack_ms=(ack['seconds']-ping['seconds'])*1000,
                              during_downstream_wait=any(s['start_unix'] <= ping['unix_time'] <= s['start_unix']+s['duration_seconds'] for s in stalls)))
    complete = [e for e in events if e['event'] == 'workload_complete']
    if result.returncode == 0:
        assert pairs and all(p['ack_ms'] < 10000 for p in pairs), pairs
        assert any(p['during_downstream_wait'] for p in pairs), ('No PING observed during downstream wait', pairs, stalls)
        calls = [e for e in events if e['event'] == 'rpc_start']
        done = [e for e in events if e['event'] == 'rpc_done']
        assert len(calls) == len(done) == 1 and calls[0]['method'].endswith('/ExecutePlan'), (calls, done)
        assert done[0]['code'] == 'OK' and done[0]['seconds'] - calls[0]['seconds'] >= 70, done
        assert len(complete) == 1
        end = complete[0]
        assert (end['rows'], end['unique_ids'], end['payload_hashes_verified'], end['total']) == (1000000,1000000,1000000,499999500000)
        assert end['elapsed'] >= 75 and end['batches'] >= 16
        assert result_flow['pending_segments'] == result_flow['pending_bytes'] == 0
        return dict(outcome='COMPLETE', result=end, pings=pairs, result_flow=result_flow, capture_drops=capture['drops'])
    # Preserve the exact historical failure oracle; other errors fail S3.
    sys.path.insert(0, str(SAIL/'tests'))
    from stream_contract import RESET_DETAILS
    errors = [e for e in events if e['event'] == 'workload_error']
    assert len(errors) == 1 and RESET_DETAILS in errors[0]['details'] and 70 <= errors[0]['elapsed'] <= 90
    calls = [e for e in events if e['event'] == 'rpc_start']
    done = [e for e in events if e['event'] == 'rpc_done']
    assert len(calls) == len(done) == 1 and calls[0]['method'].endswith('/ExecutePlan'), (calls, done)
    assert (done[0]['code'], done[0]['code_number'], done[0]['details']) == ('INTERNAL', 13, RESET_DETAILS), done
    raise AssertionError(dict(outcome='HISTORICAL_RESET', result=errors[0], pings=pairs))
