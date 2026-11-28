"""Tracking notifications must never become per-ID exemptions or repeated noise."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path('scripts').resolve()))
spec=importlib.util.spec_from_file_location('tracking','scripts/rustsec-tracking.py')
tracking=importlib.util.module_from_spec(spec);spec.loader.exec_module(tracking)


def row(patched=None, guidance=''):
    return {'crate':'library','version':'1.0.0','advisory':'RUSTSEC-2099-0001',
            'type':'unmaintained','patched':patched or [],'replacement_guidance':guidance,
            'scopes':['authz/amd64','authz/arm64']}


class FakeIssues:
    def __init__(self):
        self.issue=None;self.created=0;self.edited=0;self.comments=[]

    def __call__(self,*args,payload=None):
        if '--paginate' in args:
            return [[copy.deepcopy(self.issue)] if self.issue else []]
        method=args[args.index('--method')+1]
        if args[-1].endswith('/comments'):
            self.comments.append(payload['body']);return {}
        if method=='POST':
            self.created+=1
            self.issue={'number':42,'html_url':'https://github.com/example/project/issues/42',
                        'state':'open','body':payload['body']}
            return copy.deepcopy(self.issue)
        self.edited+=1;self.issue.update(payload);return copy.deepcopy(self.issue)


class Tracking(unittest.TestCase):
    def publish(self, api, value, previous_no_patch=True, provenance='run one'):
        key=tracking.key(value)
        return tracking.publish('example/project',{key:value} if previous_no_patch else {},
                                {key:value},provenance,api=api)

    def test_one_issue_and_no_comment_for_unchanged_set_or_new_run(self):
        api=FakeIssues();self.publish(api,row())
        url,changed=self.publish(api,row(),provenance='new head / newer database / another run')
        self.assertFalse(changed);self.assertEqual(api.created,1)
        self.assertEqual(api.edited,0);self.assertEqual(api.comments,[])
        self.assertEqual(len(tracking.decode(api.issue['body'])),1)

    def test_patch_appearing_is_flagged_once_without_creating_another_issue(self):
        api=FakeIssues();self.publish(api,row())
        self.publish(api,row(['>=1.0.1']),previous_no_patch=False)
        self.assertEqual(api.created,1);self.assertEqual(len(api.comments),1)
        self.assertIn('FIX AVAILABLE',api.comments[0])
        self.publish(api,row(['>=1.0.1']),previous_no_patch=False)
        self.assertEqual(len(api.comments),1)

    def test_replacement_guidance_change_is_flagged_once(self):
        api=FakeIssues();self.publish(api,row())
        self.publish(api,row(guidance='Recommended alternative: maintained-library.'))
        self.assertIn('Replacement guidance',api.comments[0]);self.assertEqual(len(api.comments),1)
        self.publish(api,row(guidance='Recommended alternative: maintained-library.'))
        self.assertEqual(len(api.comments),1)

    def test_build_only_or_unselected_advisory_cannot_enter_the_issue(self):
        records=tracking.tracking_records([],{}, {})
        self.assertEqual(records,[])

    def test_resolution_updates_same_issue_and_does_not_repeat(self):
        api=FakeIssues();self.publish(api,row())
        tracking.publish('example/project',{}, {},'new run',api=api)
        self.assertEqual(api.created,1);self.assertIn('Resolved',api.comments[0])
        tracking.publish('example/project',{}, {},'later run',api=api)
        self.assertEqual(len(api.comments),1)

    def test_corrupt_state_cannot_silently_reset_tracking_or_create_duplicate(self):
        api=FakeIssues();self.publish(api,row());api.issue['body']=tracking.MARKER
        with self.assertRaises(ValueError):self.publish(api,row())
        self.assertEqual(api.created,1);self.assertEqual(api.comments,[])

    def test_partial_native_evidence_is_never_a_clean_or_empty_tracking_set(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):tracking.snapshots(Path(directory))

    def test_retry_after_uncertain_comment_delivery_cannot_duplicate_it(self):
        api=FakeIssues();self.publish(api,row())
        def uncertain(*args,**kwargs):
            result=api(*args,**kwargs)
            if args[-1].endswith('/comments'):
                raise RuntimeError('comment accepted but response lost')
            return result
        value=row(['>=1.0.1']);identity=tracking.key(value)
        with self.assertRaises(RuntimeError):
            tracking.publish('example/project',{}, {identity:value},'new run',api=uncertain)
        self.publish(api,value,previous_no_patch=False)
        self.assertEqual(len(api.comments),1)
