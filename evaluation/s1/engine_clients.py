"""Reuse engine assertions; normalize only the generated Trino fixture config."""
from pathlib import Path
from unittest.mock import patch

import engines
from common import ROOT

sail = engines.sail


def trino(catalog):
    original_copy = engines.shutil.copytree

    def copy_profile(source, destination, *args, **kwargs):
        result = original_copy(source, destination, *args, **kwargs)
        if Path(source) == ROOT / 'integration/trino':
            path = Path(destination) / 'node.properties'
            lines = path.read_text().splitlines()
            # Phase A's source profile already sets this. The pinned evaluation
            # helper appends it again. Keep its final generated value identical
            # while ensuring exactly one definition, as Trino's launcher requires.
            definitions = [line for line in lines if line.startswith('node.internal-address=')]
            assert definitions == ['node.internal-address=trino'], definitions
            path.write_text('\n'.join(line for line in lines if not line.startswith('node.internal-address=')) + '\n')
        return result

    with patch.object(engines.shutil, 'copytree', copy_profile):
        return engines.trino(catalog)
