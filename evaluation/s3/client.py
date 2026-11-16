"""Typed Spark Connect authentication oracle; tokens only enter through files."""
import json
import os
import sys
import uuid
from pathlib import Path

import grpc
from pyspark.sql.connect.proto import base_pb2
from pyspark.sql.connect.proto import base_pb2_grpc

endpoint, token_file, expected = sys.argv[1:]
token = Path(token_file).read_text().strip() if token_file != '-' else ''
channel = grpc.secure_channel(endpoint, grpc.ssl_channel_credentials(
    root_certificates=Path(os.environ['GRPC_DEFAULT_SSL_ROOTS_FILE_PATH']).read_bytes()))
stub = base_pb2_grpc.SparkConnectServiceStub(channel)
request = base_pb2.ExecutePlanRequest(session_id=str(uuid.uuid4()))
request.user_context.user_id = 'client-controlled-user'
request.plan.root.sql.query = 'SELECT 42 AS answer'
metadata = [('authorization', 'Bearer ' + token)] if token else []
try:
    responses = list(stub.ExecutePlan(request, metadata=metadata, timeout=20))
    assert expected == 'OK', 'Rejected-token operation succeeded'
    assert any(r.HasField('arrow_batch') for r in responses), 'No real result'
    print(json.dumps(dict(code='OK', result_batches=sum(r.HasField('arrow_batch') for r in responses))))
except grpc.RpcError as error:
    assert error.code().name == expected, (error.code().name, expected)
    print(json.dumps(dict(code=error.code().name)))
finally:
    channel.close()
