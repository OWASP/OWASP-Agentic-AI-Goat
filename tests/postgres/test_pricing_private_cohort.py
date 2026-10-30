"""Controlled coordinator tests: no Docker, database, browser or model calls."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('private_pricing_cohort', Path(__file__).with_name('pricing_private_cohort.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class PrivatePricingCohort(unittest.TestCase):
    def exercise(self, fault=None, budget=None):
        original = m.original()
        calls = []
        interrupted = [False]
        descriptor = dict(version=1,ownerId='10000000-0000-4000-8000-000000000001',workspaceId='a'*12,
            qualificationNonce='b'*12,containerId='c'*64,imageId='sha256:'+'d'*64,packageSha256='e'*64,
            profile='owasp-ai-goat-owned-pricing-http-'+'b'*12,origin='http://127.0.0.1:18093',token='t'*43)

        def operation(name, value=None):
            calls.append(name)
            if fault == name or fault=='verify-signal' and name=='verify':
                raise RuntimeError(name)
            return value

        class Stores:
            def __init__(self, directory, file, digest, expected, deadline, *, snapshot):
                import hashlib
                assert hashlib.sha256(file.read_bytes()).hexdigest() == digest
                assert expected['containerId'] == descriptor['containerId']
                operation('construct')
            def assert_executor_ready(self, value): operation('ready')
            def open_postgres(self, nonce): return operation('postgres', {'port':15432})
            def create_store(self, pg, nonce, store): return operation('store:'+store,original.database_pair(nonce,store,pg['port']))
            def start_child(self, pairs, value, limits):
                assert limits == {'actor':4,'judge':2,'total':6}
                assert tuple(pairs) == original.STORES
                return operation('child','child-handle')
            def wait_child(self, child, deadline): return operation('wait',{'controlled':True})
            def verify_receipt(self, receipt): operation('verify')
            def close_child(self, child):
                if fault=='signal-before':interrupted[0]=True
                return operation('child-close',True)
            def close_postgres(self, pg): return operation('postgres-close',True)
            def finalize_cleanup(self):
                if fault in ('signal-restore','verify-signal'):interrupted[0]=True
                operation('finalize')
            def cleanup_interrupted(self):return interrupted[0]
            def set_cleanup_deadline(self,value):operation('stores-deadline:'+str(value))

        private = SimpleNamespace(open=lambda image:operation('open',descriptor),close=lambda:operation('private-close',{'builderReleaseAllowed':True}),set_cleanup_deadline=lambda value:operation('private-deadline:'+str(value)))
        saved=[]
        def journal(value):
            saved.append(value)
            if fault=='signal-journal':interrupted[0]=True
        with tempfile.TemporaryDirectory(prefix='pricing-coordinator-control-',dir=ROOT/'tasks/qualification') as directory:
            with patch.object(m,'original',return_value=original),patch.object(original,'full_snapshot',return_value={'pinned':True}),patch.object(original,'CurrentHostRuntime',Stores):
                try:
                    result=m._consume(private,directory,descriptor['imageId'],'f'*12,journal,600,{'pinned':True},clock=lambda:0,retirement_budget=budget)
                    return result,calls,saved
                except BaseException as error:
                    return error,calls,saved

    def test_original_cohort_and_private_retirement_order(self):
        result,calls,saved=self.exercise()
        self.assertIsInstance(result,dict)
        self.assertTrue(result['passed'])
        self.assertFalse(result['nativeQualificationAccepted'])
        self.assertEqual(calls[-4:],['child-close','postgres-close','private-close','finalize'])
        self.assertTrue(saved[-1]['builderReleaseAllowed'])
        self.assertIn('runCanonicalCohort',m.original().COHORT_SCRIPT)
        with self.assertRaisesRegex(RuntimeError,'NOT_ADMITTED'):m.run()

    def test_one_deadline_is_propagated_before_any_retirement(self):
        from unittest.mock import Mock
        budget=SimpleNamespace(begin_retirement=Mock(return_value=600))
        result,calls,_=self.exercise(budget=budget)
        self.assertTrue(result['passed']);budget.begin_retirement.assert_called_once_with()
        self.assertLess(calls.index('private-deadline:600'),calls.index('child-close'))
        self.assertLess(calls.index('stores-deadline:600'),calls.index('child-close'))
        bad=SimpleNamespace(begin_retirement=Mock(side_effect=RuntimeError('expired')))
        error,calls,_=self.exercise(budget=bad)
        self.assertFalse(error.result['builderReleaseAllowed'])
        self.assertNotIn('child-close',calls);self.assertNotIn('private-close',calls)

    def test_failures_preserve_primary_and_retain_runtime_on_unjoined_child(self):
        for fault in ('open','construct','child','wait','verify','child-close','postgres-close','private-close'):
            error,calls,saved=self.exercise(fault)
            self.assertIsInstance(error,BaseException,fault)
            self.assertFalse(error.result['passed'])
            self.assertFalse(saved[-1]['passed'])
            if fault=='child-close':
                self.assertNotIn('postgres-close',calls)
                self.assertNotIn('private-close',calls)
                self.assertFalse(error.result['builderReleaseAllowed'])
            else:self.assertIn('private-close',calls)

    def test_cleanup_signal_before_journal_during_journal_and_restore_demotes(self):
        for fault in ('signal-before','signal-journal','signal-restore'):
            error,calls,saved=self.exercise(fault)
            self.assertIsInstance(error,RuntimeError)
            self.assertFalse(error.result['passed'])
            self.assertTrue(error.result['cleanupInterrupted'])
            self.assertFalse(saved[-1]['passed'])
        error,_,saved=self.exercise('verify-signal')
        self.assertEqual(str(error),'verify')
        self.assertTrue(error.result['cleanupInterrupted'])
        self.assertFalse(saved[-1]['passed'])

    def test_actual_original_receipt_replay_uses_private_inspection_only(self):
        import json
        producer=m.original()
        receipt=dict(caseId='V33',passed=True,originalVerdict='pass',runtimeClosed=True,cleanupErrors=[],
            httpRetirement=dict(serverClosed=True,endpointAbsent=True,handlersDrained=True),calls=[])
        seen=[]
        private=SimpleNamespace(descriptor={'containerId':'a'*64},verify_current=lambda:seen.append('private-inspect') or True)
        cls=m.private_store_class(producer,private)
        owner=object.__new__(cls)
        owner.identity={'containerId':'a'*64};owner.before={'snapshot':True}
        owner.inspect_executor=lambda *_:self.fail('shared Docker must not be inspected')
        owner.command=lambda *a,**k:SimpleNamespace(returncode=0,stdout=json.dumps(dict(version=1,replayed=True,canonicalCredit=False,receiptSha256='b'*64)))
        with tempfile.TemporaryDirectory(prefix='pricing-replay-control-',dir=ROOT/'tasks/qualification') as directory:
            owner.run=Path(directory)
            (owner.run/'phases.ndjson').write_text(json.dumps({'value':receipt})+'\n')
            with patch.object(producer,'full_snapshot',return_value=owner.before):
                owner.verify_receipt(receipt)
                self.assertEqual(seen,['private-inspect'])
                private.descriptor={'containerId':'c'*64}
                with self.assertRaisesRegex(RuntimeError,'IDENTITY_CHANGED'):owner.verify_receipt(receipt)
                with self.assertRaisesRegex(RuntimeError,'TERMINAL_FAILED'):owner.verify_receipt(dict(receipt,passed=False))
            self.assertEqual(seen,['private-inspect'])

    def test_original_cleanup_hook_is_optional_but_nonrenewing_when_bound(self):
        producer=m.original();owner=object.__new__(producer.CurrentHostRuntime)
        with patch.object(producer.time,'monotonic',return_value=100):
            self.assertEqual(owner.cleanup_remaining(30),30)
            owner.set_cleanup_deadline(120)
            self.assertEqual(owner.cleanup_remaining(30),20)
            with self.assertRaisesRegex(RuntimeError,'NONRENEWAL'):owner.set_cleanup_deadline(130)
        with patch.object(producer.time,'monotonic',return_value=120):
            with self.assertRaisesRegex(RuntimeError,'EXPIRED'):owner.cleanup_remaining(1)


if __name__=='__main__':unittest.main()
