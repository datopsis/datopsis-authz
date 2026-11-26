# Adapted from pinned lakehouse-integration evaluation/authz/exercise.py (Apache-2.0).
"""C1–C8: stable backend acceptance contract, identical on both native CPUs."""

import os
import platform
import time
import traceback

from common import WORK, decode, run, save, wait
from s1_fixture import BACKEND_NETWORK, setup

RESULTS = {}
CASES = tuple(f"C{i}" for i in range(1, 9))


def initialize(arch):
    RESULTS["run"] = {
        "architecture": arch,
        "uname": platform.machine(),
        "url": os.environ["RUN_URL"],
    }
    for case in CASES:
        RESULTS[case] = {"status": "blocked", "reason": "Fixture prerequisites have not completed"}
    save("results.json", RESULTS)


def record(name, fn, required=False):
    start = time.monotonic()
    try:
        result = {"status": "pass", "value": fn()}
    except Exception as exc:
        result = {
            "status": "fail",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "traceback": traceback.format_exc(),
        }
    result["seconds"] = round(time.monotonic() - start, 4)
    RESULTS[name] = result
    save("results.json", RESULTS)
    print(name + ": " + result["status"], flush=True)
    if required:
        assert result["status"] == "pass", result
    return result


def denial(fn):
    from pyiceberg.exceptions import ForbiddenError, NoSuchNamespaceError, NoSuchTableError

    try:
        fn()
    except (ForbiddenError, NoSuchNamespaceError, NoSuchTableError) as exc:
        return {"type": type(exc).__name__, "message": str(exc)}
    raise AssertionError("Denied operation succeeded")


def write_denials(reader):
    import pyarrow as pa

    table = reader.load_table("bakeoff.sample")
    return {
        "create_namespace": denial(lambda: reader.create_namespace("forbidden")),
        "create_table": denial(
            lambda: reader.create_table(
                "bakeoff.no", schema=pa.schema([pa.field("id", pa.int64())])
            )
        ),
        "append": denial(
            lambda: table.append(pa.Table.from_pylist([{"id": 3, "label": "forbidden"}]))
        ),
        "overwrite": denial(
            lambda: table.overwrite(pa.Table.from_pylist([{"id": 3, "label": "forbidden"}]))
        ),
        "delete": denial(lambda: table.delete("id = 1")),
        "commit": denial(
            lambda: table.transaction().set_properties(test="denied").commit_transaction()
        ),
        "drop": denial(lambda: reader.drop_table("bakeoff.sample")),
        "rename": denial(lambda: reader.rename_table("bakeoff.sample", "bakeoff.renamed")),
    }


def evaluate(arch):
    initialize(arch)
    catalog, operator, key = setup(arch, record)
    provider, http = catalog.provider, catalog.http
    human = provider.human()["access_token"]
    provider.human_token = human
    claims = decode(human)[1]
    assert "lake-readers" in claims["groups"]
    admin = catalog.pyiceberg(operator)
    namespace = "namespace:" + admin.load_namespace_properties("bakeoff")["namespace_id"]
    from s1_fixture import grant as backend_grant

    def tuples(user, relation, obj, delete=False):
        return backend_grant(catalog, key, user, relation, obj, delete)

    human_id = "user:oidc~" + claims["sub"]
    reader = None

    def grants():
        nonlocal reader
        tuples(human_id, "select", namespace)
        reader = catalog.pyiceberg(human)
        namespaces = reader.list_namespaces()
        assert namespaces == [("bakeoff",)], namespaces
        grant_url = catalog.base + '/management/v1/permissions/namespace/' + namespace.split(':',1)[1] + '/grants'
        for method in ('GET','POST'):
            response = http.request(method, grant_url, headers={'Authorization':'Bearer '+human},
                **({'json':{'subject':{'kind':'User','id':'oidc~'+claims['sub']},'access':'owner'}} if method == 'POST' else {}))
            assert response.status_code == 403, ('reader_grant_management',method,response.status_code)
        unsupported = http.request('POST',catalog.base+'/management/v1/permissions/unsupported',headers={'Authorization':'Bearer '+operator},json={})
        assert unsupported.status_code == 403, unsupported.status_code
        return {
            "namespaces": namespaces,
            "allowed": catalog.read(reader),
            "other_list": denial(lambda: reader.list_tables("denied")),
            "other_read": denial(lambda: reader.load_table("denied.sample")),
            "writes": write_denials(reader),
        }

    record("C1", grants)

    def inheritance():
        import pyarrow as pa

        later = admin.create_table("bakeoff.later", schema=pa.schema([pa.field("id", pa.int64())]))
        later.append(pa.Table.from_pylist([{"id": 7}]))
        try:
            assert set(reader.list_tables("bakeoff")) == {
                ("bakeoff", "sample"),
                ("bakeoff", "later"),
            }
            assert reader.load_table("bakeoff.later").scan().to_arrow().to_pylist() == [{"id": 7}]
        finally:
            admin.drop_table("bakeoff.later")
        admin.create_namespace("single")
        for name in ("one", "sibling"):
            table = admin.create_table(
                "single." + name, schema=pa.schema([pa.field("id", pa.int64())])
            )
            table.append(pa.Table.from_pylist([{"id": 8}]))
        table_id = str(admin.load_table("single.one").metadata.table_uuid)
        # The same genuine human subject has only a single-table grant in this namespace.
        tuples(human_id, "select", f"lakekeeper_table:{catalog.warehouse_id}/{table_id}")
        assert reader.load_table("single.one").scan().to_arrow().to_pylist() == [{"id": 8}]
        try:
            listed = reader.list_tables("single")
            assert listed == [("single", "one")], listed
        except Exception as exc:
            from pyiceberg.exceptions import ForbiddenError, NoSuchNamespaceError

            assert isinstance(exc, (ForbiddenError, NoSuchNamespaceError)), exc
            listed = type(exc).__name__
        return {
            "namespace_covers_new_table": True,
            "single_table_rows": [{"id": 8}],
            "single_table_list": listed,
            "sibling": denial(lambda: reader.load_table("single.sibling")),
        }

    record("C2", inheritance)

    def groups():
        tuples(human_id, "select", namespace, True)
        try:
            # Direct verified groups replace registered roles and tuple sync.
            negative = denial(lambda: catalog.read(reader))
            tuples("group:lake-readers", "select", namespace)
            allowed = catalog.read(catalog.pyiceberg(human))
            tuples("group:lake-readers", "select", namespace, True)
            denied = denial(lambda: catalog.read(reader))
            from common import save
            save("C3-direct-claims.json", {
                "unmapped_claim_denied": negative,
                "mapped_group_exact_rows": allowed,
                "removed_mapping_old_token_denied": denied,
                "adaptation": "Live authoritative groups with mandatory 250ms cache; JWT groups ignored",
            })
            # Keep the original old-token membership-removal control strict.
            # A stateless claim adapter is expected to FAIL here: the JWT still
            # contains lake-readers. Mapping revocation above is not a substitute.
            tuples("group:lake-readers", "select", namespace)
            user_url = provider.base + '/auth/v1/users/' + claims['sub']
            original_user = http.json('GET', user_url, headers=provider.admin)
            try:
                removed = provider.remove_group(claims['sub'])
                acknowledged = time.monotonic()
                assert "lake-readers" not in (removed.get("groups") or [])
                samples = []
                while time.monotonic() - acknowledged < 30:
                    response = http.request('GET', catalog.base + f'/catalog/v1/{catalog.warehouse_id}/namespaces/bakeoff/tables/sample', headers={'Authorization':'Bearer '+human})
                    samples.append({'seconds_since_ack':time.monotonic()-acknowledged,'status':response.status_code})
                    assert response.status_code in (200,403,404), response.status_code
                    if response.status_code in (403,404): break
                    time.sleep(.025)
                assert samples[-1]['status'] in (403,404), samples
                assert decode(human)[1]['exp'] > time.time(), 'Must deny old unexpired token'
                old_token_denied = denial(lambda: catalog.read(reader))
            finally:
                http.json('PUT', user_url, headers=provider.admin, json=original_user)
                time.sleep(.3)
            return {"old_token_after_IdP_removal": old_token_denied, "samples":samples}
        finally:
            tuples("group:lake-readers", "select", namespace, True)
            tuples(human_id, "select", namespace)

    record("C3", groups)
    def idp_outage():
        # Positive control, then a real IdP outage after cache expiry.
        catalog.read(reader)
        run('docker','stop',provider.container)
        try:
            time.sleep(.3)
            response = http.request('GET', catalog.base + f'/catalog/v1/{catalog.warehouse_id}/namespaces/bakeoff/tables/sample', headers={'Authorization':'Bearer '+human})
            assert response.status_code in (403,500,503), response.status_code
            body = response.json()
            assert body.get('error',{}).get('type'), body
            assert not any(k in body for k in ('metadata','config','storage-credentials'))
        finally:
            run('docker','start',provider.container)
            wait(lambda:http.request('GET',provider.base+'/auth/v1/health').status_code==200,180)
        catalog.read(reader)
        return {'outage_status':response.status_code,'error_type':body['error']['type'],'recovered':True}
    record('idp_outage_fail_closed', idp_outage, required=True)

    def revoke():
        catalog.read(catalog.pyiceberg(human))
        acknowledged = tuples(human_id, "select", namespace, True)
        samples = []
        while time.monotonic() - acknowledged < 30:
            response = http.request(
                "GET",
                catalog.base
                + f"/catalog/v1/{catalog.warehouse_id}/namespaces/bakeoff/tables/sample",
                headers={"Authorization": "Bearer " + human},
            )
            samples.append(
                {
                    "seconds_since_ack": time.monotonic() - acknowledged,
                    "status": response.status_code,
                }
            )
            assert response.status_code in (200, 403, 404), (response.status_code, response.text)
            if response.status_code in (403, 404):
                return {
                    "first_denial_seconds": samples[-1]["seconds_since_ack"],
                    "samples": samples,
                    "scope": "Delete acknowledgment to first fresh REST denial; issued storage credentials excluded",
                }
            time.sleep(0.1)
        raise AssertionError({"revocation_not_seen_within_seconds": 30, "samples": samples})

    record("C4", revoke)
    tuples("user:oidc~lakekeeper", "select", namespace)

    def machines():
        from engine_clients import sail, trino

        def pyiceberg():
            client = catalog.pyiceberg()
            return {
                "allowed": catalog.read(client),
                "other_read": denial(lambda: client.load_table("denied.sample")),
                "writes": write_denials(client),
            }

        outcomes = {
            "pyiceberg": record("C5.pyiceberg", pyiceberg),
            "trino": record("C5.trino", lambda: trino(catalog)),
            "sail": record("C5.sail", lambda: sail(catalog)),
        }
        assert all(r["status"] == "pass" for r in outcomes.values()), outcomes
        return outcomes

    record("C5", machines)

    def credentials():
        token = provider.token()
        base = catalog.base + f"/catalog/v1/{catalog.warehouse_id}/namespaces/"
        auth = {
            "Authorization": "Bearer " + token,
            "X-Iceberg-Access-Delegation": "vended-credentials",
        }
        denied = http.request("GET", base + "denied/tables/sample", headers=auth)
        assert denied.status_code in (403, 404), {"denied_http_status": denied.status_code}
        assert not any(
            k in denied.text
            for k in ("s3.access-key-id", "s3.secret-access-key", "s3.session-token")
        ), "Denied response contains S3 credential fields"
        allowed = http.json("GET", base + "bakeoff/tables/sample", headers=auth)
        config = allowed.get("config", {})
        credential_blocks = allowed.get("storage-credentials", [])
        for block in credential_blocks:
            assert not any(
                k in block.get("config", {})
                for k in ("s3.access-key-id", "s3.secret-access-key", "s3.session-token")
            ), sorted(block.get("config", {}))
        # Phase C retains sts-enabled=false. Record exactly the config names, never key material.
        assert not any(
            k in config for k in ("s3.access-key-id", "s3.secret-access-key", "s3.session-token")
        ), list(config)
        return {
            "denied_status": denied.status_code,
            "denied_credentials": False,
            "read_only_config_keys": sorted(config),
            "storage_credential_config_keys": [
                sorted(block.get("config", {})) for block in credential_blocks
            ],
            "sts_enabled": False,
            "scope": "Read grant, no STS keys with this profile; source scopes documented separately",
        }

    record("C6", credentials)
    from security import evaluate as security

    from s1_fixture import restore, snapshot
    state_before_outage = snapshot(catalog, key)
    record("C7", lambda: security(catalog, operator, human, namespace, tuples))
    # Preserve each destructive test's failure while giving C8 its own valid
    # starting fixture. Restoration happens between cases, never during checks.
    record("fixture_reset_before_C8", lambda: restore(catalog, key, state_before_outage), required=True)

    def operations():
        # Retain the complete graph and decisions across a process restart.
        catalog.read(catalog.pyiceberg())
        from s1_fixture import snapshot
        before = snapshot(catalog, key)
        run("docker", "restart", "cedar")
        wait(lambda: snapshot(catalog, key) is not None)
        after = snapshot(catalog, key)
        assert before == after, "Cedar restart lost relationship/grant state"
        catalog.read(catalog.pyiceberg())
        denial(lambda: catalog.pyiceberg().load_table("denied.sample"))
        for _ in range(2):
            from s1_fixture import migrate
            migrate(catalog)
        assert snapshot(catalog, key) == before
        catalog.read(catalog.pyiceberg())
        denial(lambda: catalog.pyiceberg().load_table("denied.sample"))
        return {"grants_preserved": True, "migration_repetitions": 2}

    record("C8", operations)
    record("fixture_reset_after_C8", lambda: restore(catalog, key, state_before_outage), required=True)
    record("unchanged_rows", lambda: catalog.read(admin), required=True)
    assert all(RESULTS[case]["status"] == "pass" for case in CASES), (
        "Incomplete acceptance; see results.json"
    )
