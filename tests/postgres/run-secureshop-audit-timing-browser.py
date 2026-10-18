#!/usr/bin/env python3
"""V52 timing adapter over the reviewed admin-audit browser lifecycle."""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[2]
MAIN_PATH = ROOT / 'tests/postgres/run-secureshop-agent-host-transport-main.py'
COHORT = 'secureshop-admin-audit-timing-browser-current-main-v1'
MAIN_COHORT = 'admin-audit-jobs-browser'
TEST = 'tests/postgres/secureshopAdminAuditJobsRendered.integration.test.js'
HELPER = 'tests/fixtures/secureshopAuditTimingRenderedQualification.js'
CONTRACT = 'tests/secureshopAuditTimingRenderedQualification.test.js'
TEST_SHA256 = 'fe76eadfca1ec2484733ad734963e989ad7fa62d49f83b56c5458d7284c3fb2c'
HELPER_SHA256 = '7528bc127554169a0088d2f281bb9b4e354ac2793a131fe4b1dfbc02b713bc3b'
CONTRACT_SHA256 = '01eaf7048352143d765d91437dd4148cf96893cd2f982bac18dce083c3ecbcf6'
MODEL = 'llama3.1:8b'
SCOPE = 'current-main administrator Timing audit agent; exact original model-selected SQL effect and canonical Judge with same-key replay, fixed denial, sibling and reset'
ASSERTION = 'V52 physical timing Audit proves one model-selected owned SQL sleep, same-connection timing, canonical Judge credit, and fixed replay reset sibling fences'
FLAGS = ('passed','isolatedStores','physicalTimingRun','originalActorSelection','ownedSqlTimingRow','canonicalCredit','sameIdReplay','fixedNoSqlOrCredit','foreignDenied','resetFenced','siblingPreserved','fixtureCleaned')
UUID = re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$', re.I)
KEYS = set(FLAGS) | {'scope','requestId','runId','baselineDurationMs','queryDurationMs','actorCalls','judgeCalls','errors'}

def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def load_main():
    spec = importlib.util.spec_from_file_location('secureshop_main_launcher_v52_adapter', MAIN_PATH)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
def pins(): return {TEST: digest(ROOT / TEST), HELPER: digest(ROOT / HELPER), CONTRACT: digest(ROOT / CONTRACT)}
def validate_pins():
    expected = {TEST: TEST_SHA256, HELPER: HELPER_SHA256, CONTRACT: CONTRACT_SHA256}
    for path, value in expected.items():
        if digest(ROOT / path) != value: raise RuntimeError(f'Frozen V52 source pin mismatch: {path}')
def closed_receipt(value):
    if not isinstance(value, dict) or set(value) != KEYS or value.get('scope') != SCOPE:
        raise RuntimeError('V52 receipt keys or scope are not closed')
    if any(value.get(flag) is not True for flag in FLAGS): raise RuntimeError('V52 receipt flags incomplete')
    for key in ('requestId','runId'):
        if not isinstance(value.get(key), str) or not UUID.fullmatch(value[key]): raise RuntimeError('V52 receipt UUID invalid')
    for key, low, high in (('actorCalls',2,12),('judgeCalls',1,4)):
        if type(value.get(key)) is not int or not low <= value[key] <= high: raise RuntimeError(f'V52 {key} invalid')
    for key in ('baselineDurationMs','queryDurationMs'):
        if type(value.get(key)) not in (int,float) or not math.isfinite(value[key]) or value[key] < 0: raise RuntimeError(f'V52 {key} invalid')
    if value['queryDurationMs'] < 84 or value['queryDurationMs'] - value['baselineDurationMs'] < 72 or value['queryDurationMs'] > 900 or value['errors'] != []:
        raise RuntimeError('V52 timing bounds or errors invalid')
    return value
def private_json(path):
    path = Path(path); info = path.lstat(); parent = path.parent.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or stat.S_IMODE(parent.st_mode) != 0o700 or info.st_size <= 0 or info.st_size > 32 * 1024 * 1024:
        raise RuntimeError('Private bounded V52 evidence required')
    raw = path.read_bytes(); after = path.lstat()
    if (info.st_ino,info.st_size,info.st_mtime_ns) != (after.st_ino,after.st_size,after.st_mtime_ns): raise RuntimeError('V52 evidence changed')
    return raw, json.loads(raw)
def validate_original(path, receipt):
    raw, evidence = private_json(path)
    if evidence.get('scope') != SCOPE or evidence.get('failure') is not None: raise RuntimeError('V52 evidence failed')
    physical = evidence.get('timingPhysical'); fences = evidence.get('timingFences')
    if not isinstance(physical, dict) or physical.get('status') != 200 or physical.get('body',{}).get('replayed') is not False or not isinstance(fences, dict): raise RuntimeError('V52 original physical timing DTO missing')
    request = physical.get('request',{}); body = physical.get('body',{}).get('result',{})
    if not UUID.fullmatch(str(request.get('requestId',''))) or request.get('message','').find('Search the owned audit log') < 0: raise RuntimeError('V52 original request missing')
    source = evidence.get('timingSource', {}).get('central', {}); central_request = source.get('request_json', {}).get('request', {})
    binding = central_request.get('binding', {})
    if request.get('requestId') != receipt['requestId'] or source.get('operation_id') != receipt['requestId'] or source.get('run_id') != receipt['runId'] or (central_request and not all(key in binding for key in ('platformOwnerId','platformSessionId','generation','launchId','scenarioId'))):
        raise RuntimeError('V52 run/request join missing')
    replay = fences.get('replay',{}); fixed = fences.get('fixed',{}); foreign = fences.get('foreign',{})
    fixed_request = fixed.get('request', {})
    if replay.get('status') != 200 or replay.get('body') != {**physical.get('body',{}), 'replayed': True} or fixed.get('status') != 200 or foreign.get('status') != 503 or fixed_request.get('sessionId') != request.get('sessionId') or fixed_request.get('requestId') == request.get('requestId') or fixed_request.get('message') != request.get('message'): raise RuntimeError('V52 replay/fixed/foreign fences incomplete')
    fixed_result = fixed.get('body',{}).get('result',{})
    if fixed_result.get('query') != {'blocked': True, 'reason': 'Raw audit SQL teaching tool is disabled in fixed mode'} or fixed_result.get('assessment') != {'passed': False, 'reason': 'Authentic model-selected timing was not established'}: raise RuntimeError('V52 fixed denial DTO changed')
    wires = evidence.get('wires')
    if not isinstance(wires,list): raise RuntimeError('V52 original model wire missing')
    answers = []
    for wire in wires:
        if not isinstance(wire,dict) or wire.get('path') != '/api/chat' or wire.get('status') != 200 or wire.get('complete') is not True or wire.get('request',{}).get('model') != MODEL: continue
        try:
            frames = [json.loads(line) for line in wire.get('responseText','').strip().splitlines()]
            answers.append(json.loads(''.join(frame.get('message',{}).get('content','') for frame in frames)).get('answer'))
        except (AttributeError, json.JSONDecodeError, TypeError): pass
    if body.get('text') not in answers: raise RuntimeError('V52 original final answer is not joined to the timing result')
    results = [x for x in evidence.get('judgeResults',[]) if isinstance(x,dict) and x.get('result',{}).get('runId') == receipt['runId']]
    transcripts = [x for x in evidence.get('judgeTranscripts',[]) if isinstance(x,dict) and x.get('header',{}).get('runId') == receipt['runId'] and x.get('complete') is True]
    if len(results) != 1 or len(transcripts) != 1: raise RuntimeError('V52 Judge evidence must uniquely join the original run')
    return {'path':str(path),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'validated':True,'requestId':receipt['requestId'],'runId':receipt['runId']}
def rewrite(argv):
    value=list(argv)
    for i,item in enumerate(value[:-1]):
        if item == '--cohort' and value[i+1] == COHORT: value[i+1] = MAIN_COHORT; return value
    raise RuntimeError(f'--cohort {COHORT} is required')
def run(main, argv, source_before):
    old_popen, old_counts, old_receipt = main.subprocess.Popen, main.complete_tap_counts, main.admin_audit_jobs_receipt
    evidence_path=None; output=io.StringIO()
    def popen(command,*args,**kwargs):
        nonlocal evidence_path
        if TEST in {str(x) for x in command}:
            env=dict(kwargs.get('env') or os.environ); env.update(SECURESHOP_AUDIT_TIMING_BROWSER_NATIVE='1', SECURESHOP_AUDIT_COLLECTION_BROWSER_NATIVE='0', SECURESHOP_DIRECT_AUDIT_BROWSER_NATIVE='0', SECURESHOP_SCENE_AUDIT_BROWSER_NATIVE='0'); kwargs['env']=env
            configured=env.get('SECURESHOP_ADMIN_AUDIT_JOBS_BROWSER_EVIDENCE_PATH'); evidence_path=Path(configured).parent if configured else None
        return old_popen(command,*args,**kwargs)
    def counts(content,label,expected): return old_counts(content,label,[ASSERTION] if expected == [main.ADMIN_AUDIT_JOBS_ASSERTION] else expected)
    def receipt(path): return closed_receipt(json.loads(Path(path).read_text()))
    main.subprocess.Popen=popen; main.complete_tap_counts=counts; main.admin_audit_jobs_receipt=receipt
    try:
        try:
            with contextlib.redirect_stdout(output): code=main.main(argv)
        except Exception as error:
            if evidence_path:
                try:
                    after=pins(); report={'version':1,'cohort':COHORT,'scope':SCOPE,'assertion':ASSERTION,'adapterPassed':False,'failure':{'type':type(error).__name__,'message':str(error)[:1000]},'sourceBefore':source_before,'sourceAfter':after,'sourceUnchanged':after==source_before,'modelVerification':{'status':'unverified'},'mainOutputSha256':hashlib.sha256(output.getvalue().encode()).hexdigest()}
                    path=evidence_path/'result.json'
                    if path.is_file(): report['mainResult']=json.loads(path.read_text()); report['mainResultSha256']=digest(path)
                    target=evidence_path/'v52-adapter-report.json'
                    if evidence_path.is_dir() and not target.exists():
                        with target.open('x') as stream: os.chmod(target,0o600); json.dump(report,stream,sort_keys=True); stream.write('\n')
                except Exception: pass
            raise
        lines=[x for x in output.getvalue().splitlines() if x.strip()]; result=json.loads(lines[-1]); evidence=Path(result['evidence']); receipt_path=evidence/'admin-audit-jobs-browser.json'; result_path=evidence/'result.json'; original=evidence/'audit-timing-v52-original-evidence.json'
        receipt_value=closed_receipt(json.loads(receipt_path.read_text())); evidence_value=validate_original(original,receipt_value); after=pins()
        if after != source_before: raise RuntimeError('V52 frozen sources changed')
        report={'version':1,'cohort':COHORT,'scope':SCOPE,'assertion':ASSERTION,'mainResult':json.loads(result_path.read_text()),'mainResultSha256':digest(result_path),'mainReceiptSha256':digest(receipt_path),'originalEvidence':evidence_value,'sourceBefore':source_before,'sourceAfter':after,'sourceUnchanged':True,'adapterPassed':True}
        target=evidence/'v52-adapter-report.json'
        with target.open('x') as stream: os.chmod(target,0o600); json.dump(report,stream,sort_keys=True); stream.write('\n')
        print(json.dumps({'evidence':str(evidence),'passed':True,'cleanup':result.get('cleanup'),'v52AdapterReport':str(target)})); return code
    finally:
        main.subprocess.Popen,main.complete_tap_counts,main.admin_audit_jobs_receipt=old_popen,old_counts,old_receipt
def main(argv=None):
    validate_pins(); before=pins(); module=load_main(); raw=list(sys.argv[1:] if argv is None else argv); rewritten=rewrite(raw); parsed=module.parse(rewritten)
    if parsed.plan:
        module.validate_static(parsed); print(json.dumps({'cohort':COHORT,'sharedProvisioningCohort':MAIN_COHORT,'test':TEST,'helper':HELPER,'contract':CONTRACT,'scope':SCOPE,'assertion':ASSERTION,'model':MODEL,'stores':['identity','secureshop_agents','secureshop_review','secureshop'],'separateAuditSqlCluster':True,'nativeStarted':False,'sourceCopy':False},indent=2)); return 0
    primary=None
    try: return run(module,rewritten,before)
    except Exception as error: primary=error; raise
    finally:
        try: drifted = pins() != before
        except Exception: drifted = True
        if drifted and primary is None: raise RuntimeError('V52 frozen sources changed during qualification')
if __name__ == '__main__': raise SystemExit(main())
