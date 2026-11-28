"""Data-driven fixability policy across every advisory type and runtime scope."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path('scripts').resolve()))
from rustsec_policy import classify, markdown, parse_runtime_tree


def finding(patched, kind=None, name='library'):
    return {'package':{'name':name,'version':'1.0.0'},
            'advisory':{'id':'RUSTSEC-2099-0001','informational':kind},
            'versions':{'patched':patched,'unaffected':[]}}


def report(row):
    return {'settings':{'ignore':[],'severity':None,'target_arch':[],'target_os':[],
                        'informational_warnings':['unmaintained','unsound','notice']},
            'vulnerabilities':{'list':[row] if row['advisory']['informational'] is None else []},
            'warnings':{row['advisory']['informational']:[row]} if row['advisory']['informational'] else {}}


class FixabilityPolicy(unittest.TestCase):
    runtime = {('library','1.0.0')}

    def test_multiple_cargo_trees_allow_separators_and_repeated_dependencies(self):
        tree = 'first v1.0.0 (/source/first)\nlibrary v1.0.0 (*)\n\nsecond v2.0.0\nlibrary v1.0.0\n'
        self.assertEqual(parse_runtime_tree(tree), {('first','1.0.0'),('second','2.0.0'),('library','1.0.0')})

    def test_empty_or_malformed_cargo_tree_fails_closed(self):
        for tree in ['', '\n  \n', 'invalid', 'crate version', 'crate v']:
            with self.subTest(tree=tree), self.assertRaises(ValueError):
                parse_runtime_tree(tree)

    def test_any_shipped_advisory_with_a_patch_blocks(self):
        for kind in [None,'unsound','unmaintained','notice']:
            with self.subTest(kind=kind):
                r=classify(report(finding(['>=1.0.1'],kind)),self.runtime)
                self.assertEqual(len(r['blocking']),1)
                self.assertEqual(r['report_only_no_patch'],[])

    def test_no_patch_is_reported_for_every_advisory_type(self):
        for kind in [None,'unsound','unmaintained','notice']:
            with self.subTest(kind=kind):
                r=classify(report(finding([],kind)),self.runtime)
                self.assertEqual(r['blocking'],[])
                self.assertEqual(len(r['report_only_no_patch']),1)
                self.assertIn('RUSTSEC-2099-0001',markdown('test',r))

    def test_build_only_or_unselected_is_report_only_even_when_fixable(self):
        r=classify(report(finding(['>=1.0.1'],'unsound')),set())
        self.assertEqual(r['blocking'],[])
        self.assertEqual(len(r['report_only_build_or_unselected']),1)

    def test_missing_or_malformed_patch_data_fails_closed(self):
        for patched in [None,'>=1.0.1',[None],['']]:
            with self.assertRaises(ValueError):
                classify(report(finding(patched)),self.runtime)
        row=finding([]);del row['versions']['patched']
        with self.assertRaises(KeyError):classify(report(row),self.runtime)

    def test_classification_does_not_mutate_or_duplicate_raw_evidence(self):
        raw=report(finding([],'unmaintained'));before=copy.deepcopy(raw)
        self.assertEqual(classify(raw,self.runtime),classify(raw,self.runtime))
        self.assertEqual(raw,before)

    def test_filters_and_ignore_lists_fail_instead_of_hiding_advisories(self):
        for field,value in [('ignore',['RUSTSEC-2099-0001']),('severity','high'),
                            ('target_arch',['x86_64']),('target_os',['linux']),
                            ('informational_warnings',['unmaintained'])]:
            raw=report(finding([]));raw['settings'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):
                classify(raw,self.runtime)
