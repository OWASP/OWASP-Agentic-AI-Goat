#!/usr/bin/env python3
"""Offline launcher contracts: no Docker, PostgreSQL, Ollama or Node calls."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).with_name('run-legacy-sensitive-loop-actual8b-isolated.py')
spec = importlib.util.spec_from_file_location('sensitive_launcher', PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
D = hashlib.sha256(b'fixture').hexdigest()
CHECKS = {
    'protected_file': ('exactToolSequence','protectedBoundary','fixtureContentBound'),
    'observed_template_two_hop': ('exactToolSequence','observedTemplateBound','commandSimulated','simulationDisclosureMarker'),
    'sibling_isolation': ('exactToolSequence','accessDenied','outsideRootDenial','siblingMarkerAbsent'),
}

def call(phase='actor'):
    return dict(phase=phase, requestSha256=D, requestBytes=12, outputSha256=D,
                outputBytes=10, configuredContextTokens=32768 if phase=='judge' else None, completed=True)

def report():
    rows=[]
    for name, actions in [('protected_file',['read_teaching_file']),('observed_template_two_hop',['read_teaching_file','render_ssi_template']),('sibling_isolation',['read_teaching_file'])]:
        trajectory=[dict(ordinal=i+1,action=action,decisionDigest=D,hopDigest=D,
                    previousHopDigest=D if i else None,observationSha256=D,receiptCompleted=True)
                    for i,action in enumerate(actions)]
        rows.append(dict(name=name,passed=True,failedPositive=False,toolCalls=len(actions),receiptCount=len(actions),
                         trajectory=trajectory,scenarioChecks=dict.fromkeys(CHECKS[name],True),verdict='fail' if name=='sibling_isolation' else 'pass',
                         completed=name!='sibling_isolation',durable=False,failureStage=None,failureCode=None,receiptReadFailed=False,calls=[call() for _ in range(len(actions)+2)]+[call('judge')]))
    return dict(version=1,cohort=m.COHORT,model=m.MODEL,digest=m.MODEL_DIGEST,qualification='qualified',
                modelVerifiedBefore=True,modelVerifiedAfter=True,cases=rows,
                cancellation=dict(passed=True,actorCalls=1,judgeCalls=0,calls=[call()]),failures=[])

class Contract(unittest.TestCase):
    def check(self,value,qualified=True):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'qualification.json'
            path.write_text(json.dumps(value));path.chmod(0o600)
            return m.validate_qualification(path,require_qualified=qualified)

    def test_valid_exact_effects_and_unspecified_actor_context(self):
        self.assertEqual(self.check(report())['qualification'],'qualified')

    def test_honest_failed_positive_retained(self):
        value=report(); row=value['cases'][0]
        row.update(passed=False,failedPositive=True,verdict='fail',completed=False,failureStage='judge_validation',failureCode='ERR_ASSERTION')
        value.update(qualification='incomplete',failures=['protected_file'])
        self.check(value,False)
        with self.assertRaises(RuntimeError): self.check(value)

    def test_failed_effect_counts_retained_without_completed_trajectory(self):
        value=report();value.update(qualification='incomplete',failures=['protected_file'])
        value['cases'][0].update(passed=False,failedPositive=True,verdict='unavailable',completed=False,
            failureStage='actor',failureCode='23514',scenarioChecks=dict.fromkeys(CHECKS['protected_file']),trajectory=[],toolCalls=1,receiptCount=1)
        self.check(value,False)
        value['cases'][0].update(receiptReadFailed=True,toolCalls=None,receiptCount=None)
        self.check(value,False)

    def test_reject_unbounded_or_inconsistent_failure_diagnostics(self):
        value=report();value.update(qualification='incomplete',failures=['protected_file'])
        value['cases'][0].update(passed=False,failedPositive=True,verdict='unavailable',completed=False,
            failureStage='actor',failureCode='23514',scenarioChecks=dict.fromkeys(CHECKS['protected_file']))
        for update in ({'failureStage':'private prompt'}, {'failureCode':'raw error'},
                       {'failureCode':None}, {'receiptReadFailed':True}, {'toolCalls':None},
                       {'toolCalls':-1}, {'receiptCount':7}, {'receiptCount':2}):
            with self.subTest(update=update):
                changed=copy.deepcopy(value);changed['cases'][0].update(update)
                with self.assertRaises(RuntimeError):self.check(changed,False)
        for update in ({'failureStage':'actor'}, {'failureCode':'23514'}, {'receiptReadFailed':True}):
            changed=report();changed['cases'][0].update(update)
            with self.assertRaises(RuntimeError):self.check(changed,False)

    def test_scenario_failure_diagnostics_are_retained(self):
        value=report();value.update(qualification='incomplete',failures=['observed_template_two_hop'])
        row=value['cases'][1]
        row.update(passed=False,failedPositive=True,verdict='unavailable',completed=False,
            failureStage='scenario_validation',failureCode='ERR_ASSERTION')
        row['scenarioChecks']['simulationDisclosureMarker']=False
        self.check(value,False)

    def test_reject_missing_extra_nonboolean_and_inconsistent_scenario_checks(self):
        mutators=[lambda c:c.pop('protectedBoundary'), lambda c:c.update(extra=True),
                  lambda c:c.update(protectedBoundary='raw output'), lambda c:c.update(protectedBoundary=1),
                  lambda c:c.update(protectedBoundary=False), lambda c:c.update(protectedBoundary=None)]
        for mutate in mutators:
            changed=report();mutate(changed['cases'][0]['scenarioChecks'])
            with self.assertRaises(RuntimeError):self.check(changed,False)
        changed=report();changed.update(qualification='incomplete',failures=['protected_file'])
        changed['cases'][0].update(passed=False,failedPositive=True,failureStage='actor',failureCode='UNCLASSIFIED')
        with self.assertRaises(RuntimeError):self.check(changed,False)
        changed['cases'][0].update(failureStage='scenario_validation',scenarioChecks=dict.fromkeys(CHECKS['protected_file']))
        with self.assertRaises(RuntimeError):self.check(changed,False)

    def test_infrastructure_failure_before_model_retained(self):
        value=report();value.update(qualification='incomplete',modelVerifiedBefore=False,cases=[],
            cancellation=dict(passed=False,actorCalls=0,judgeCalls=0,calls=[]),failures=['qualification_infrastructure'])
        self.check(value,False)

    def test_reject_inconsistent_flags_and_evidence(self):
        mutators=[lambda r:r['cases'][0].update(verdict='fail'),
                  lambda r:r['cases'][0].update(durable=True),
                  lambda r:r['cases'][0].update(failedPositive=True),
                  lambda r:r['cases'][0].update(receiptCount=0),
                  lambda r:r['cases'][1]['trajectory'][1].update(previousHopDigest=None),
                  lambda r:r['cases'][1]['trajectory'][1].update(action='read_teaching_file'),
                  lambda r:r['cases'][0]['calls'][-1].update(completed=False),
                  lambda r:r['cancellation'].update(judgeCalls=1),
                  lambda r:r.update(modelVerifiedAfter=False),
                  lambda r:r['cases'][0]['calls'].append(call()),
                  lambda r:r['cases'][0]['calls'].pop(0),
                  lambda r:r['cases'][0].update(prompt='private')]
        for mutate in mutators:
            with self.subTest(mutate=mutate):
                value=report();mutate(value)
                with self.assertRaises(RuntimeError):self.check(value,False)

    def test_cleanup_refuses_unowned_container(self):
        result=type('Result',(),dict(returncode=0,stdout=json.dumps([dict(Id='a'*64,Name='/wrong',Config=dict(Labels={}))]),stderr=''))()
        with patch.object(m,'run',return_value=result) as run:
            with self.assertRaisesRegex(RuntimeError,'unowned'):
                m.remove_owned_container(['docker'],'owned',None,{'owner':'root'})
            self.assertEqual(run.call_count,1)

    def test_container_absence_requires_exact_target(self):
        result=type('Result',(),dict(returncode=1,stdout='',stderr='daemon unavailable'))()
        with patch.object(m,'run',return_value=result):
            with self.assertRaises(RuntimeError):m.docker_object_absent(['docker'],'owned')
        self.assertTrue(m.docker_missing_exact_target('Error: No such object: owned','owned'))
        self.assertFalse(m.docker_missing_exact_target('No such object: sibling','owned'))

    def test_child_journal_precedes_getpgid_failure_and_preserves_bootstrap(self):
        state={'processes':{}}; persisted=[]
        child=type('Child',(),dict(pid=123))()
        def fail(pid):
            self.assertEqual(persisted[-1]['bootstrap']['expectedPgid'],123)
            raise ProcessLookupError()
        with self.assertRaises(ProcessLookupError):
            m.register_owned_process(child,state,lambda:persisted.append(copy.deepcopy(state['processes'])),getpgid=fail,name='bootstrap')
        self.assertEqual(state['processes']['bootstrap']['pid'],123)

    def test_grant_consumed_once_and_terminal_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'grant.json';expected={'grantId':'fixture','ownerHandle':None}
            m.save_json(path,dict(expected,status='granted'))
            m.consume_one_use_grant(path,expected,Path(directory))
            with self.assertRaises(RuntimeError):m.consume_one_use_grant(path,expected,Path(directory))
            grant=json.loads(path.read_text());grant['ownerHandle']=42;m.save_json(path,grant)
            m.record_terminal_grant(path,'fixture',42,dict(runStatus='terminal_fail_cleaned',completedAt='fixture',evidence=directory,cleanupErrors=[],suite={}),True)
            self.assertEqual(json.loads(path.read_text())['runStatus'],'terminal_fail')

    def test_failed_cohort_retains_hashed_readonly_evidence(self):
        value=report();value.update(qualification='incomplete',failures=['protected_file'])
        value['cases'][0].update(passed=False,failedPositive=True,verdict='fail',completed=False,failureStage='judge_validation',failureCode='ERR_ASSERTION')
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'qualification.json';path.write_text(json.dumps(value));path.chmod(0o600)
            log=Path(directory)/'native.tap';log.write_text('not ok 1 - incomplete\n');log.chmod(0o600)
            log_digest=m.retain_artifact(log)
            m.validate_qualification(path,require_qualified=False)
            evidence_digest=m.retain_artifact(path)
            self.assertEqual(log_digest,m.sha256(log));self.assertEqual(evidence_digest,m.sha256(path))
            self.assertEqual(path.stat().st_mode & 0o777,0o400)
            self.assertEqual(log.stat().st_mode & 0o777,0o400)
        source=PATH.read_text()
        self.assertLess(source.index("state['suite']['logSha256'] = retain_artifact(log_path)"),source.index('if exit_code or not group_absent:'))
        self.assertLess(source.index('qualification_sha = retain_artifact(qualification_path)'),source.index('if exit_code or not group_absent:'))

    def test_source_no_migration_credentials_in_model_environment(self):
        source=PATH.read_text()
        env=source.split('        child_env = {',1)[1].split('        bootstrap_env =',1)[0]
        self.assertNotIn('MIGRATION_URL',env)
        self.assertIn('PG_LEGACY_SENSITIVE_LOOP_RUNTIME_URL',env)
        self.assertIn("name='bootstrap'",source)
        self.assertIn("state['postflightModelInventory'] = query_model_tags()",source)
        self.assertIn("signal.signal(signum, signal.SIG_IGN)",source)
        self.assertIn("if node_sha != NODE_SHA256",source)

if __name__=='__main__':unittest.main()
