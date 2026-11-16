"""Descriptor evidence from the exact hash-locked PySpark client, without a server."""
import json
from pyspark.sql.connect.proto import base_pb2, relations_pb2, commands_pb2


def fields(descriptor):
    return {f.name: dict(number=f.number, type=f.message_type.full_name if f.message_type else f.type)
            for f in descriptor.fields}

result = {}
for message in (base_pb2.ExecutePlanRequest, base_pb2.Plan, base_pb2.UserContext,
                relations_pb2.Relation, relations_pb2.Read, relations_pb2.SQL,
                commands_pb2.Command):
    result[message.DESCRIPTOR.full_name] = fields(message.DESCRIPTOR)
# Concrete variants whose visible table information has different completeness.
examples = {}
for label, relation in [('sql', relations_pb2.Relation()), ('named_table', relations_pb2.Relation()),
                        ('path', relations_pb2.Relation())]:
    if label == 'sql': relation.sql.query = 'SELECT * FROM catalog.namespace.table'
    elif label == 'named_table': relation.read.named_table.unparsed_identifier = 'catalog.namespace.table'
    else:
        relation.read.data_source.format = 'parquet'
        relation.read.data_source.paths.append('s3://bucket/prefix')
    examples[label] = str(relation)
print(json.dumps(dict(descriptors=result, examples=examples), indent=2))
