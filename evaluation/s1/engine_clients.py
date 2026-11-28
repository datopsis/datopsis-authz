"""Reuse engine assertions; normalize only the generated Trino fixture config."""

from pathlib import Path
from unittest.mock import patch

import engines
from common import ROOT, WORK, run, secret, write

sail = engines.sail


def trino(catalog):
    original_copy = engines.shutil.copytree
    original_container = engines.container
    directory = WORK / "trino-authz"

    def copy_profile(source, destination, *args, **kwargs):
        result = original_copy(source, destination, *args, **kwargs)
        if Path(source) == ROOT / "integration/trino":
            destination = Path(destination)
            path = destination / "node.properties"
            lines = path.read_text().splitlines()
            # The pinned helper appends the key that Phase A already supplied.
            definitions = [
                line for line in lines if line.startswith("node.internal-address=")
            ]
            assert definitions == ["node.internal-address=trino"], definitions
            path.write_text(
                "\n".join(
                    line
                    for line in lines
                    if not line.startswith("node.internal-address=")
                )
                + "\n"
            )
            path = destination / "catalog/iceberg.properties"
            config = path.read_text()
            old = "iceberg.rest-catalog.uri=https://catalog:8181/catalog"
            assert config.count(old) == 1
            path.write_text(
                config.replace(
                    old, "iceberg.rest-catalog.uri=" + catalog.base + "/catalog"
                )
            )
            # Keep the pinned image's strict PKCS12 profile; its shared source
            # profile points at /run/tls, which this evaluation never mounts.
            password = secret()
            run(
                "keytool",
                "-importcert",
                "-noprompt",
                "-alias",
                "s1-ca",
                "-file",
                catalog.provider.ca,
                "-keystore",
                destination / "spike-trust.p12",
                "-storetype",
                "PKCS12",
                "-storepass",
                password,
            )
            write(destination / "spike-trust-password", password)
            write(destination / "spike-ca.pem", catalog.provider.ca.read_text())
            write(
                destination / "truststore.properties",
                "path=/etc/trino/spike-trust.p12\ntype=PKCS12\npassword-file=/etc/trino/spike-trust-password\n",
            )
        return result

    def start_container(name, *args, **kwargs):
        if name == "trino":
            config_path = directory / "config.properties"
            config = run("sudo", "cat", config_path)
            old = "internal-communication.https.truststore.path=/ca/ca.pem"
            assert config.count(old) == 1
            run(
                "sudo",
                "tee",
                config_path,
                input=config.replace(
                    old,
                    "internal-communication.https.truststore.path=/etc/trino/spike-ca.pem",
                )
                + "\n",
            )
            protected = [
                config_path,
                directory / "truststore.properties",
                directory / "spike-trust.p12",
                directory / "spike-trust-password",
                directory / "spike-ca.pem",
            ]
            run("sudo", "chown", "10001:0", *protected)
            run("sudo", "chmod", "0400", *protected)
        return original_container(name, *args, **kwargs)

    with (
        patch.object(engines.shutil, "copytree", copy_profile),
        patch.object(engines, "container", start_container),
    ):
        return engines.trino(catalog)
