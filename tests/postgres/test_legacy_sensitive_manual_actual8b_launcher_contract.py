#!/usr/bin/env python3
"""Offline launcher contracts: no Docker, PostgreSQL or Ollama calls; Node evaluates the pure JS contract."""
import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import shutil
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).with_name('run-legacy-sensitive-manual-actual8b-isolated.py')
spec = importlib.util.spec_from_file_location('sensitive_launcher', PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
D = hashlib.sha256(b'fixture').hexdigest()
def call():
    return dict(phase='judge',requestSha256=D,requestBytes=12,outputSha256=D,outputBytes=10,configuredContextTokens=32768,completed=True)

def report():
    return dict(version=1,cohort=m.COHORT,model=m.MODEL,digest=m.MODEL_DIGEST,qualification='qualified',
        modelVerifiedBefore=True,modelVerifiedAfter=True,casesPreservedSibling=True,
        cases=[dict(name=name,objectiveId=objective,operation=operation,passed=True,failedPositive=False,
                    toolCalls=1,receiptCount=1,receiptCompleted=True,observationSha256=D,
                    scenarioChecks=dict(independentEffects=True,canonicalFacts=True),failureStage=None,failureCode=None,
                    receiptReadFailed=False,verdict='pass' if positive else 'fail',completed=positive,durable=False,calls=[call()])
               for name,(objective,operation,positive) in m.MANUAL_CASES.items()],
        cancellation=dict(passed=True,actorCalls=0,judgeCalls=0,calls=[]),failures=[])

class Contract(unittest.TestCase):
    def check(self,value,qualified=True):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'qualification.json';path.write_text(json.dumps(value));path.chmod(0o600)
            return m.validate_qualification(path,require_qualified=qualified)

    def test_complete_manual_report(self):
        self.assertEqual(self.check(report())['qualification'],'qualified')
        self.assertEqual(len(report()['cases']),11)

    def test_fail_closed_mutations(self):
        mutations=[lambda r:r['cases'].pop(),lambda r:r['cases'].append(r['cases'][0]),
            lambda r:r['cases'][0]['calls'][0].update(phase='actor'),
            lambda r:r['cases'][0]['calls'][0].update(configuredContextTokens=8192),
            lambda r:r['cases'][0]['calls'][0].update(requestBytes=0),
            lambda r:r['cases'][0]['calls'][0].update(outputBytes=0),
            lambda r:r['cases'][0]['calls'][0].update(completed=False),
            lambda r:r['cases'][0].update(calls=[]),lambda r:r['cases'][0].update(receiptCompleted=False),
            lambda r:r['cases'][0].update(receiptCount=0),lambda r:r['cases'][0].update(observationSha256=None),
            lambda r:r['cases'][0].update(durable=True),lambda r:r['cases'][0].update(prompt='private'),
            lambda r:r['cases'][3].update(verdict='pass'),lambda r:r.update(casesPreservedSibling=False),
            lambda r:r.update(modelVerifiedAfter=False),lambda r:r['cancellation'].update(actorCalls=1),
            lambda r:r['cancellation'].update(judgeCalls=1,calls=[call()]),
            lambda r:r['cases'][0]['scenarioChecks'].update(independentEffects=False)]
        for mutate in mutations:
            value=report();mutate(value)
            with self.assertRaises(RuntimeError):self.check(value)

    def test_failed_prejudge_receipts_are_retained_without_model(self):
        for stage in ('admission','tool','receipt_validation','scenario_validation'):
            value=report();row=value['cases'][0]
            value.update(qualification='incomplete',failures=[row['name']])
            row.update(passed=False,failedPositive=True,failureStage=stage,failureCode='ERR_ASSERTION',calls=[])
            if stage!='scenario_validation':row['scenarioChecks']=dict(independentEffects=None,canonicalFacts=None)
            self.check(value,False)
            row['calls']=[call()]
            with self.assertRaises(RuntimeError):self.check(value,False)
            row.update(calls=[],receiptReadFailed=True,toolCalls=None,receiptCount=None)
            self.check(value,False)

    def test_infrastructure_report_nullable_digest(self):
        value=report();value.update(qualification='incomplete',modelVerifiedBefore=False,modelVerifiedAfter=False,
            casesPreservedSibling=False,cases=[],failures=['qualification_infrastructure','model_provenance'],
            cancellation=dict(passed=False,actorCalls=0,judgeCalls=0,calls=[]))
        self.check(value,False)
        with self.assertRaises(RuntimeError):self.check(value)
        row=report()['cases'][0];row.update(passed=False,failedPositive=True,toolCalls=0,receiptCount=0,
            receiptCompleted=False,observationSha256=None,scenarioChecks=dict(independentEffects=None,canonicalFacts=None),
            failureStage='tool',failureCode='UNCLASSIFIED',calls=[])
        value['cases']=[row];value['failures'].append(row['name']);self.check(value,False)

    def test_manual_manifest_source_and_identity(self):
        source=PATH.read_text()
        self.assertEqual(m.SCOPE,'legacy_sensitive_manual_actual8b')
        self.assertEqual(m.COHORT,'legacy-sensitive-manual-actual8b-v1')
        self.assertEqual(m.TEST_PATH,'tests/postgres/legacySensitiveManualActual8b.integration.test.js')
        self.assertIn('tests/fixtures/legacySensitiveManualOwnedCases.js',source)
        self.assertIn('tests/fixtures/legacySensitiveManualReportContract.js',source)
        self.assertNotIn('legacySensitiveAgentProduction.js',source)
        self.assertNotIn('decisionObserveGraph.js',source)
        self.assertIn("'name': 'legacySensitiveManualActual8b'",source)

    def test_python_js_report_contract_parity(self):
        values=[report()]
        for field in ('requestBytes','outputBytes'):
            for invalid in (True,-1,9007199254740992,'1',None,1.5):
                value=report();value['cases'][0]['calls'][0][field]=invalid;values.append(value)
        for field in ('requestSha256','outputSha256'):
            for invalid in ('short',None,12):
                value=report();value['cases'][0]['calls'][0][field]=invalid;values.append(value)
        for field in ('request','response','extra'):
            value=report();value['cases'][0][field]='private';values.append(value)
        value=report();value.update(qualification='incomplete',casesPreservedSibling=False,failures=['sibling_case_isolation']);values.append(value)
        expected=[]
        for value in values:
            try:self.check(value,False);expected.append(True)
            except RuntimeError:expected.append(False)
        script="const {validateLegacySensitiveManualReport:v}=require('./tests/fixtures/legacySensitiveManualReportContract');let s='';process.stdin.on('data',c=>s+=c);process.stdin.on('end',()=>process.stdout.write(JSON.stringify(JSON.parse(s).map(r=>{try{v(r,{requireQualified:false});return true}catch{return false}}))));"
        node=shutil.which('node');self.assertIsNotNone(node)
        result=subprocess.run([node,'-e',script],input=json.dumps(values),text=True,capture_output=True,
                              cwd=PATH.parent.parent.parent,timeout=10,env={})
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout),expected)

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

    def test_source_no_migration_credentials_in_model_environment(self):
        source=PATH.read_text()
        env=source.split('        child_env = {',1)[1].split('        bootstrap_env =',1)[0]
        self.assertNotIn('MIGRATION_URL',env)
        self.assertIn('PG_LEGACY_SENSITIVE_MANUAL_RUNTIME_URL',env)
        self.assertIn("name='bootstrap'",source)
        self.assertIn("state['postflightModelInventory'] = query_model_tags()",source)
        self.assertIn("signal.signal(signum, signal.SIG_IGN)",source)
        self.assertIn("if node_sha != NODE_SHA256",source)

if __name__=='__main__':unittest.main()
