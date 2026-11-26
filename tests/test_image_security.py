"""Security boundaries in embedded-inventory parsing, without builds or scans."""
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
import zlib

spec = importlib.util.spec_from_file_location('shipped', 'scripts/shipped-rustsec.py')
shipped = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shipped)


def elf(metadata, section=b'.dep-v0'):
    blob = zlib.compress(json.dumps(metadata).encode())
    names = b'\0.shstrtab\0'+section+b'\0'
    header = bytearray(64)
    header[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', header, 40, 64)
    struct.pack_into('<HHH', header, 58, 64, 3, 1)
    strings_at = 64+3*64
    sections = bytes(64)
    sections += struct.pack('<IIQQQQIIQQ', 1,3,0,0,strings_at,len(names),0,0,1,0)
    sections += struct.pack('<IIQQQQIIQQ', 11,1,0,0,strings_at+len(names),len(blob),0,0,1,0)
    return bytes(header)+sections+names+blob


class EmbeddedInventory(unittest.TestCase):
    def parse(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'binary'
            path.write_bytes(data)
            return shipped.inventory(path)

    def valid(self):
        return {'format':2,'packages':[
            {'name':'application','version':'0.0.1','root':True,'source':'local'},
            {'name':'runtime','version':'1.0.0','source':'crates.io'},
            {'name':'macro','version':'1.0.0','source':'crates.io','kind':'build'}]}

    def test_embedded_runtime_and_build_identities_are_preserved(self):
        expected = self.valid()
        self.assertEqual(self.parse(elf(expected)), expected)

    def test_absent_or_invalid_auditable_data_never_qualifies(self):
        for data in [b'not elf', elf(self.valid(), b'.other'), elf({'format':2,'packages':[]})]:
            with self.assertRaises((ValueError,KeyError,struct.error)):
                self.parse(data)

    def test_missing_proc_macro_classification_or_binary_root_blocks(self):
        for change in [dict(format=1),dict(packages=[{'name':'crate','version':'1'}])]:
            with self.assertRaises(ValueError):
                self.parse(elf({**self.valid(),**change}))

    def test_unknown_kind_blocks_instead_of_becoming_build_only(self):
        info = self.valid()
        info['packages'][1]['kind']='unknown'
        with self.assertRaises(ValueError):
            self.parse(elf(info))
