# Explicit v5 fresh prospective diagnostic; original v3/v4 remain unchanged.
"""Explicit main-only diagnostic supervisor. Plan never launches or allocates."""
import argparse, hashlib, importlib.util, json, os, shutil, signal, subprocess, sys, tempfile, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
HELPER=ROOT/'tests/postgres/sql_nosql_process_ownership.py'
ENTRY='tests/fixtures/ragWholeEvidenceDefenseMainV5.js'
INPUT='tests/release-inputs/rag-whole-evidence-v5-prospective12-inputs-v1.json'
INPUT_SHA='a64f47280cfa2d081ddec41d16f0a6e5fd96b8d9204d75bb29b9042a4268b83a'

def profile(a):
    if getattr(a,'profile','')=='dpi-side-compact-conjunction6-8b':
        cfg=profile(argparse.Namespace(profile='dpi-side-selected-semantic6'))
        return {**cfg,'calls':12,'seconds':2280,'childProfile':'semantic-side-compact-conjunction-v24-8b',
            'required':cfg['required']|{'server/agent-runtime/dpiSideCompactConjunctionCandidate.js','server/agent-runtime/dpiSideConjunctionCandidate.js','server/agent-runtime/dpiSideSourceLinkCandidate.js','server/agent-runtime/dpiSelectedCompactContextCandidate.js','server/agent-runtime/dpiSelectedContextCandidate.js','server/agent-runtime/dpiSelectedResponseConsistencyPolicy.js','server/agent-runtime/referenceComparisonVerifier.js'}}
    if getattr(a,'profile','')=='dpi-source-response-assessment-v2-12-8b':
        cfg=profile(argparse.Namespace(profile='dpi-source-response-assessment12-8b'))
        return {**cfg,'childProfile':'semantic-source-response-assessment-v2-8b',
            'required':cfg['required']|{'server/agent-runtime/dpiSourceResponseAssessmentV2Candidate.js'}}
    if getattr(a,'profile','')=='dpi-source-response-assessment12-8b':
        cfg=profile(argparse.Namespace(profile='dpi-simple-assessment12-8b'))
        return {**cfg,'childProfile':'semantic-source-response-assessment-v1-8b','calls':24,'seconds':3720,
            'expectations':'tests/release-inputs/dpi-source-response-twelve-expectations-v1.json',
            'expectationsSha':'43fea3f82cf253ae3f81758db1f7cf01c3058a4fabec0d27ee5fc99f24fe71d9',
            'required':cfg['required']|{'server/agent-runtime/dpiSourceResponseAssessmentCandidate.js'}}
    if getattr(a,'profile','')=='dpi-simple-assessment12-8b':
        cfg=profile(argparse.Namespace(profile='dpi-selected-response-regression8-8b'))
        return {**cfg,'childProfile':'semantic-simple-assessment-v1-8b','calls':12,'seconds':2280,
            'input':'tests/release-inputs/dpi-simple-assessment-twelve-input-v1.json',
            'sha':'cb71b9a8afe1bb7e32ca44293c419a8bd1b66478ebe8c8bd99fe24095626bb2e',
            'expectations':'tests/release-inputs/dpi-simple-assessment-twelve-expectations-v1.json',
            'expectationsSha':'afe8e3b3b6e381051691c5a6883fc99f3cc0e4ced586df695db13e43337e90a0',
            'required':cfg['required']|{'server/agent-runtime/dpiSimpleAssessmentCandidate.js'}}
    if getattr(a,'profile','')=='dpi-selected-response-regression8-8b':
        cfg=profile(argparse.Namespace(profile='dpi-selected-response-consistency4-8b'))
        return {**cfg,'childProfile':'semantic-selected-response-regression-v14-8b','calls':8,'seconds':1560,
            'input':'tests/release-inputs/dpi-selected-response-regression-eight-input-v1.json',
            'sha':'cac21182b44423a7a1aba9e8df6ac629838d6d6bf0cd9ef157ef90cb811e8df3',
            'expectations':'tests/release-inputs/dpi-selected-response-regression-eight-expectations-v1.json',
            'expectationsSha':'1fea2273c1c1144f38256a837586a38fc4e81f1108d82978b5610a36ddc0777c'}
    if getattr(a,'profile','')=='dpi-selected-response-consistency4-8b':
        cfg=profile(argparse.Namespace(profile='dpi-selected-objective-technique4-8b'))
        return {**cfg,'childProfile':'semantic-selected-response-consistency-v14-8b','required':cfg['required']|{'server/agent-runtime/dpiSelectedResponseConsistencyCandidate.js'}}
    if getattr(a,'profile','')=='dpi-selected-objective-technique4-8b':
        cfg=profile(argparse.Namespace(profile='dpi-selected-role-technique4'))
        return {**cfg,'childProfile':'semantic-selected-objective-technique-v13-8b','required':cfg['required']|{'server/agent-runtime/dpiSelectedObjectiveTechniqueCandidate.js'}}
    if getattr(a,'profile','')=='dpi-selected-role-technique4':
        cfg=profile(argparse.Namespace(profile='dpi-selected-source-technique4'))
        return {**cfg,'childProfile':'semantic-selected-role-technique-v12','required':cfg['required']|{'server/agent-runtime/dpiSelectedRoleTechniqueCandidate.js'}}
    if getattr(a,'profile','')=='dpi-selected-source-technique4':
        cfg=profile(argparse.Namespace(profile='dpi-semantic-server-ids-side'))
        return {**cfg,'calls':4,'seconds':840,'childProfile':'semantic-selected-source-technique-v11',
            'input':'tests/release-inputs/dpi-selected-source-technique-four-input-v1.json',
            'sha':'d1527d4cc6d6727852147538f471351e4783e723e10046c51ae27cf33dd2ae81',
            'expectations':'tests/release-inputs/dpi-selected-source-technique-four-expectations-v1.json',
            'expectationsSha':'950177e11aff3cd5e29adc24b1e9cb0c570f07356f6022b3160648e5b936de59',
            'required':cfg['required']|{'server/agent-runtime/dpiSelectedSourceTechniqueCandidate.js','server/agent-runtime/dpiSelectedCompactContextCandidate.js','server/agent-runtime/dpiSelectedContextCandidate.js'}}
    if getattr(a,'profile','')=='dpi-techniques-selected-semantic6':
        cfg=profile(argparse.Namespace(profile='dpi-semantic-server-ids-side'))
        return {**cfg,'calls':6,'seconds':1140,'childProfile':'semantic-techniques-selected-v6'}
    if getattr(a,'profile','')=='dpi-techniques-selected-semantic6-remaining2':
        cfg=profile(argparse.Namespace(profile='dpi-techniques-selected-semantic6'))
        return {**cfg,'calls':2,'seconds':480,'childProfile':'semantic-techniques-selected-v6-remaining2'}
    if getattr(a,'profile','')=='dpi-side-conjunction-remaining1':
        cfg=profile(argparse.Namespace(profile='dpi-side-source-link-semantic6'))
        return {**cfg,'calls':1,'seconds':600,'childProfile':'semantic-side-conjunction-v8-remaining1','required':cfg['required']|{'server/agent-runtime/dpiSideConjunctionCandidate.js'}}
    if getattr(a,'profile','')=='dpi-side-source-link-semantic6':
        cfg=profile(argparse.Namespace(profile='dpi-side-selected-semantic6'))
        return {**cfg,'childProfile':'semantic-side-source-link-v7','required':cfg['required']|{'server/agent-runtime/dpiSideSourceLinkCandidate.js'}}
    if getattr(a,'profile','')=='dpi-side-selected-semantic6':
        cfg=profile(argparse.Namespace(profile='dpi-semantic-server-ids-side'))
        return {**cfg,'calls':6,'seconds':1140,'childProfile':'semantic-selected-v6','input':'tests/release-inputs/dpi-side-selected-semantic6-input-v1.json','sha':'8c63d672f3f7f17ea20a9120288bf8291f55bf95217a955042fcae82f26317ae','expectations':'tests/release-inputs/dpi-side-selected-semantic6-expectations-v1.json','expectationsSha':'90254ee77765c9cfa0969ef0743cb3da41b4f386a3ab1f6780847778b6a95ba7'}
    if getattr(a,'profile','')=='dpi-semantic-whole-intent':
        cfg=profile(argparse.Namespace(profile='dpi-semantic-server-ids-side'))
        return {**cfg,'calls':16,'seconds':1860,'childProfile':'semantic-whole-intent-v1','input':'tests/release-inputs/dpi-whole-task-intent-qualification8-inputs-v1.json','sha':'d9dddf09ed7fc58c39a11aa953f518cc3b85f3ab1022d094d83d5a7f14d5853c','required':cfg['required']|{'server/agent-runtime/dpiWholeTaskIntentCandidate.js'}}
    if getattr(a,'profile','')=='dpi-semantic-source-first-side':
        cfg=profile(argparse.Namespace(profile='dpi-semantic-server-ids-side'))
        return {**cfg,'calls':8,'seconds':1080,'childProfile':'semantic-source-first-side-v1','required':cfg['required']|{'server/agent-runtime/dpiSourceFirstServerIdsCandidate.js'}}
    if getattr(a,'profile','rag-v5') in ('dpi-semantic-server-ids','dpi-semantic-server-ids-smoke','dpi-semantic-server-ids-side'):
        cfg=profile(argparse.Namespace(profile='dpi-semantic-schema-visible'))
        smoke=getattr(a,'profile','')=='dpi-semantic-server-ids-smoke'
        if getattr(a,'profile','')=='dpi-semantic-server-ids-side':return {**cfg,'calls':4,'seconds':600,'childProfile':'semantic-server-ids-side-v1','required':cfg['required']|{'server/agent-runtime/dpiDirectWitnessCandidate.js','server/agent-runtime/dpiDirectWitnessServerIdsCandidate.js','server/agent-runtime/dpiServerEvidenceCatalog.js','server/agent-runtime/dpiTechniqueWitness.js'}}
        return {**cfg,'calls':10 if smoke else 28,'seconds':1140 if smoke else 3120,'childProfile':'semantic-server-ids-smoke-v1' if smoke else 'semantic-server-ids-v1','required':cfg['required']|{'server/agent-runtime/dpiDirectWitnessCandidate.js','server/agent-runtime/dpiDirectWitnessServerIdsCandidate.js','server/agent-runtime/dpiServerEvidenceCatalog.js','server/agent-runtime/dpiTechniqueWitness.js'}}
    if getattr(a,'profile','rag-v5')=='dpi-semantic-direct-witness':
        cfg=profile(argparse.Namespace(profile='dpi-semantic-schema-visible'))
        return {**cfg,'childProfile':'semantic-direct-witness-v1','required':cfg['required']|{'server/agent-runtime/dpiDirectWitnessCandidate.js'}}
    if getattr(a,'profile','rag-v5')=='dpi-semantic-schema-visible':
        cfg=profile(argparse.Namespace(profile='dpi-semantic-compact'))
        return {**cfg,'input':'tests/release-inputs/dpi-schema-visible-prospective20-inputs-v1.json','sha':'0045f70f8b9b2a3ea45b9bfef310f4eabd142c6b5dfb4b626d2d2de907af6631','childProfile':'semantic-schema-visible-v1'}
    if getattr(a,'profile','rag-v5')=='dpi-semantic-compact':
        return {'entry':'tests/fixtures/dpiSpanCalibrationMain.js','input':'tests/release-inputs/dpi-semantic-prospective-supplied20-inputs-v1.json','sha':'ed88a5688b7ea001505c5b797a545429d79f8d1d40ea6f1e24e66a95bab518ec','prefix':'DPI_SPAN','folder':'dpi-span-calibration','seconds':6120,'calls':56,'childProfile':'semantic-compact-v1','required':{'tests/fixtures/dpiSpanCalibration.js','server/agent-runtime/dpiTaskContributionSpanCandidate.js','server/agent-runtime/dpiTaskContributionComparison.js','server/agent-runtime/dpiSemanticCompactCandidate.js','server/agent-runtime/dpiSemanticDecisionCandidate.js','server/agent-runtime/dpiPolicyContract.js','tests/fixtures/ragWholeEvidenceActualTransport.js'}}
    if getattr(a,'profile','rag-v5')=='dpi-span':
        return {'entry':'tests/fixtures/dpiSpanCalibrationMain.js','input':'tests/release-inputs/neutral-task-technique-calibration-inputs-v2.json','sha':'d54c97ec7940df24ac949d96155a93994c2e0a2b8d24d30b3c3c9b81a99c2c62','prefix':'DPI_SPAN','folder':'dpi-span-calibration','seconds':7380,'calls':96,'required':{'tests/fixtures/dpiSpanCalibration.js','server/agent-runtime/dpiTaskContributionSpanCandidate.js','server/agent-runtime/dpiTaskContributionComparison.js','tests/fixtures/ragWholeEvidenceActualTransport.js'}}
    if getattr(a,'profile','rag-v5')!='rag-v5':raise ValueError('Unknown profile')
    return {'entry':ENTRY,'input':INPUT,'sha':INPUT_SHA,'prefix':'RAG_WHOLE_EVIDENCE_V5','folder':'rag-whole-evidence-v5','seconds':780,'calls':12,'required':{'tests/fixtures/ragWholeEvidenceDefenseDiagnosticV5.js','server/agent-runtime/ragWholeEvidenceDefenseContractV5.js','server/agent-runtime/ragWholeEvidenceDefenseContractV4.js','tests/fixtures/ragWholeEvidenceActualTransport.js','server/agent-runtime/ragWholeEvidenceDefenseContract.js'}}

def digest(p):
    value=hashlib.sha256()
    with open(p,'rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):value.update(block)
    return value.hexdigest()
def exact(p):
    p=Path(p)
    if not p.is_absolute() or p.resolve()!=p:raise ValueError('Canonical path required')
    return p

def validate_regression_admission(m,cfg):
    child=cfg.get('childProfile')
    if child=='semantic-side-compact-conjunction-v24-8b':
        pins={row['path']:row['sha256'] for row in m['files']}
        candidate='server/agent-runtime/dpiSideCompactConjunctionCandidate.js';base='server/agent-runtime/dpiSideConjunctionCandidate.js'
        if candidate not in pins or base not in pins:raise ValueError('Side compact-conjunction candidate missing')
        expected={'version':'dpi-side-compact-conjunction-v24-calibration-v1','inputSha256':cfg['sha'],'sourceProtocol':'dpi-side-selected-semantic6-v1','protocol':'dpi-side-compact-conjunction-v9','candidatePath':candidate,'candidateSha256':pins[candidate],'baseProtocol':'dpi-side-conjunction-v8','baseCandidatePath':base,'baseCandidateSha256':pins[base],'contextTokens':20480,'providerTimeoutMs':180000,'transportTimeoutMs':180000,'reusedCorpus':True,'changedProtocol':True,'labelsExternal':True,'actorProof':False,'creditProof':False}
        actual=m.get('sideCompactAdmission')
        if actual!=expected or 'regressionAdmission' in m or 'sourceTechniqueAdmission' in m:raise ValueError('Side compact-conjunction admission mismatch')
        return
    if child in ('semantic-selected-source-technique-v11','semantic-selected-role-technique-v12','semantic-selected-objective-technique-v13-8b','semantic-selected-response-consistency-v14-8b','semantic-selected-response-regression-v14-8b','semantic-simple-assessment-v1-8b','semantic-source-response-assessment-v1-8b','semantic-source-response-assessment-v2-8b'):
        pins={row['path']:row['sha256'] for row in m['files']}
        candidate='server/agent-runtime/dpiSourceResponseAssessmentV2Candidate.js' if child=='semantic-source-response-assessment-v2-8b' else 'server/agent-runtime/dpiSourceResponseAssessmentCandidate.js' if child=='semantic-source-response-assessment-v1-8b' else 'server/agent-runtime/dpiSimpleAssessmentCandidate.js' if child=='semantic-simple-assessment-v1-8b' else 'server/agent-runtime/dpiSelectedResponseConsistencyCandidate.js' if child in ('semantic-selected-response-consistency-v14-8b','semantic-selected-response-regression-v14-8b') else 'server/agent-runtime/dpiSelectedObjectiveTechniqueCandidate.js' if child=='semantic-selected-objective-technique-v13-8b' else 'server/agent-runtime/dpiSelectedRoleTechniqueCandidate.js' if child=='semantic-selected-role-technique-v12' else 'server/agent-runtime/dpiSelectedSourceTechniqueCandidate.js'
        if candidate not in pins:raise ValueError('Source-technique candidate missing')
        expected={'version':'dpi-selected-source-technique-calibration-v1','inputSha256':cfg['sha'],'protocol':'dpi-source-response-assessment-v2' if child=='semantic-source-response-assessment-v2-8b' else 'dpi-source-response-assessment-v1' if child=='semantic-source-response-assessment-v1-8b' else 'dpi-simple-assessment-v1' if child=='semantic-simple-assessment-v1-8b' else 'dpi-selected-response-consistency-v14' if child in ('semantic-selected-response-consistency-v14-8b','semantic-selected-response-regression-v14-8b') else 'dpi-selected-objective-technique-v13' if child=='semantic-selected-objective-technique-v13-8b' else 'dpi-selected-role-technique-v12' if child=='semantic-selected-role-technique-v12' else 'dpi-selected-source-technique-v11','candidatePath':candidate,'candidateSha256':pins[candidate],'contextTokens':20480,'providerTimeoutMs':180000,'transportTimeoutMs':180000,'sourceOnly':True,'labelsExternal':True}
        actual=m.get('sourceTechniqueAdmission')
        if actual!=expected or type(actual.get('sourceOnly')) is not bool or type(actual.get('labelsExternal')) is not bool or 'regressionAdmission' in m:raise ValueError('Source-technique admission mismatch')
        return
    if child not in ('semantic-direct-witness-v1','semantic-server-ids-v1','semantic-server-ids-smoke-v1','semantic-server-ids-side-v1','semantic-techniques-selected-v6','semantic-source-first-side-v1','semantic-whole-intent-v1','semantic-side-source-link-v7','semantic-side-conjunction-v8-remaining1','semantic-techniques-selected-v6-remaining2'):return
    pins={row['path']:row['sha256'] for row in m['files']}
    if child=='semantic-techniques-selected-v6-remaining2':
        candidate='server/agent-runtime/dpiDirectWitnessServerIdsCandidate.js'
        if candidate not in pins:raise ValueError('Selected recovery candidate missing')
        expected={'version':'dpi-techniques-selected-semantic6-recovery-v1','inputSha256':cfg['sha'],'sourceProtocol':'dpi-semantic-compact-candidate-v2-schema-visible','protocol':'dpi-direct-witness-server-ids-v6','candidatePath':candidate,'candidateSha256':pins[candidate],'selectedCaseIds':['DPG006','DPG007'],'reusedEvidence':True,'heldOut':False,'recovery':True,'subset':True}
    elif child=='semantic-side-conjunction-v8-remaining1':
        candidate='server/agent-runtime/dpiSideConjunctionCandidate.js';base='server/agent-runtime/dpiSideSourceLinkCandidate.js';replay={'path':'tests/release-inputs/dpi-side-conjunction-v8-retained-replay-v1.json','sha256':'b9f3341769276f0b3e104dc2c6449cc6f238ca31d6b5371c0e84b2288a9229e0'}
        if candidate not in pins or base not in pins or replay['path'] in pins or digest(ROOT/replay['path'])!=replay['sha256']:raise ValueError('Conjunction recovery authority mismatch')
        expected={'version':'dpi-side-conjunction-recovery-v1','inputSha256':cfg['sha'],'sourceProtocol':'dpi-side-selected-semantic6-v1','protocol':'dpi-side-conjunction-v8','candidatePath':candidate,'candidateSha256':pins[candidate],'baseProtocol':'dpi-side-source-link-v7','baseCandidatePath':base,'baseCandidateSha256':pins[base],'retainedReplay':replay,'selectedCaseId':'ambiguous-aws-link','reusedEvidence':True,'heldOut':False,'recovery':True,'subset':True}
    else:
        candidate='server/agent-runtime/dpiSideSourceLinkCandidate.js' if child=='semantic-side-source-link-v7' else 'server/agent-runtime/dpiWholeTaskIntentCandidate.js' if child=='semantic-whole-intent-v1' else 'server/agent-runtime/dpiSourceFirstServerIdsCandidate.js' if child=='semantic-source-first-side-v1' else 'server/agent-runtime/dpiDirectWitnessCandidate.js' if child=='semantic-direct-witness-v1' else 'server/agent-runtime/dpiDirectWitnessServerIdsCandidate.js'
        if candidate not in pins:raise ValueError('Direct candidate missing')
        expected={'version':'dpi-side-source-link-regression-v1' if child=='semantic-side-source-link-v7' else 'dpi-direct-witness-regression-v1' if child=='semantic-direct-witness-v1' else 'dpi-server-ids-regression-v1','inputSha256':cfg['sha'],'sourceProtocol':'dpi-side-selected-semantic6-v1' if child=='semantic-side-source-link-v7' else 'dpi-whole-task-intent-qualification8-v1' if child=='semantic-whole-intent-v1' else 'dpi-semantic-compact-candidate-v2-schema-visible','protocol':'dpi-side-source-link-v7' if child=='semantic-side-source-link-v7' else 'dpi-whole-task-intent-server-ids-v5' if child=='semantic-whole-intent-v1' else 'dpi-direct-witness-candidate-v1' if child=='semantic-direct-witness-v1' else 'dpi-source-first-server-ids-v1' if child=='semantic-source-first-side-v1' else 'dpi-direct-witness-server-ids-v6','candidatePath':candidate,'candidateSha256':pins[candidate],'reusedEvidence':True,'heldOut':False}
    actual=m.get('regressionAdmission')
    if actual!=expected or type(actual.get('reusedEvidence')) is not bool or type(actual.get('heldOut')) is not bool:raise ValueError('Direct regression authority mismatch')

STRONG_JUDGE={'model':'llama3.3:70b','digest':'a6eb4748fd2990ad2952b2335a95a7f952d1a06119a0aa6a2df6cd052a93a3fa'}
def judge_selection(a,manifest):
    model=getattr(a,'judge_model',None);digest_value=getattr(a,'judge_model_digest',None)
    if getattr(a,'profile',None) in ('dpi-selected-objective-technique4-8b','dpi-selected-response-consistency4-8b','dpi-selected-response-regression8-8b','dpi-simple-assessment12-8b','dpi-source-response-assessment12-8b','dpi-source-response-assessment-v2-12-8b','dpi-side-compact-conjunction6-8b'):
        expected={'model':'llama3.1:8b','digest':'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'}
        if model is not None or digest_value is not None or 'judgeIdentity' in manifest or manifest.get('defaultJudgeIdentity')!=expected:raise ValueError('Pinned default 8B identity required')
        return None
    if model is None and digest_value is None:
        if getattr(a,'profile',None) in ('dpi-selected-source-technique4','dpi-selected-role-technique4'):raise ValueError('Explicit source-technique Judge identity required')
        if 'judgeIdentity' in manifest:raise ValueError('Explicit Judge identity arguments required')
        return None
    if getattr(a,'profile',None) not in ('dpi-semantic-direct-witness','dpi-semantic-server-ids','dpi-semantic-server-ids-smoke','dpi-semantic-server-ids-side','dpi-techniques-selected-semantic6','dpi-semantic-source-first-side','dpi-semantic-whole-intent','dpi-side-selected-semantic6','dpi-side-source-link-semantic6','dpi-side-conjunction-remaining1','dpi-techniques-selected-semantic6-remaining2','dpi-selected-source-technique4','dpi-selected-role-technique4') or {'model':model,'digest':digest_value}!=STRONG_JUDGE or manifest.get('judgeIdentity')!=STRONG_JUDGE:raise ValueError('Judge identity scope or digest mismatch')
    return dict(STRONG_JUDGE)

def admit(a):
    for p,h in [(exact(a.manifest),a.manifest_sha256),(exact(a.node),a.node_sha256),(Path(sys.executable).resolve(),a.python_sha256),(Path(__file__).resolve(),a.supervisor_sha256),(HELPER,a.helper_sha256)]:
        if digest(p)!=h:raise ValueError('Pin mismatch')
    m=json.loads(Path(a.manifest).read_text())
    if m['version']!=1 or m['root']!=str(ROOT) or m['node']!={'path':a.node,'sha256':a.node_sha256}:raise ValueError('Manifest identity mismatch')
    seen=set()
    for row in m['files']:
        p=row['path']
        if Path(p).is_absolute() or '..' in Path(p).parts or p in seen:raise ValueError('Invalid manifest path')
        seen.add(p)
        if digest(exact(ROOT/p))!=row['sha256']:raise ValueError('Manifest source mismatch')
    cfg=profile(a)
    judge_selection(a,m)
    validate_regression_admission(m,cfg)
    if cfg.get('childProfile') and m.get('profile')!=cfg['childProfile']:raise ValueError('Manifest profile mismatch')
    if not ({cfg['entry'],cfg['input']}|cfg['required']).issubset(seen):raise ValueError('Required diagnostic closure missing')
    if digest(ROOT/cfg['input'])!=cfg['sha']:raise ValueError('Frozen input changed')
    if cfg.get('expectations'):
        if m.get('expectations')!={'path':cfg['expectations'],'sha256':cfg['expectationsSha']} or cfg['expectations'] in seen:raise ValueError('Expectation authority mismatch')
        if digest(ROOT/cfg['expectations'])!=cfg['expectationsSha']:raise ValueError('Frozen expectations changed')
    return m

def publish(p,value):
    tmp=p.with_suffix('.tmp')
    with open(tmp,'x',opener=lambda name,flags:os.open(name,flags,0o600)) as f:
        json.dump(value,f);f.flush();os.fsync(f.fileno())
    os.replace(tmp,p)
    fd=os.open(p.parent,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)

def members(pgid,sid):
    r=subprocess.run(['/bin/ps','-axo','pid=,pgid=,uid='],env={'PATH':'/usr/bin:/bin','LANG':'C'},capture_output=True,text=True,check=True,timeout=2)
    found=[]
    for line in r.stdout.splitlines():
        pid,group,uid=map(int,line.split())
        if group!=pgid:continue
        try:
            if uid!=os.getuid() or os.getsid(pid)!=sid:raise RuntimeError('Unknown group identity')
        except ProcessLookupError:continue
        found.append(pid)
    return found

def stop_group(child,pgid,sid):
    until=time.monotonic()+25
    if members(pgid,sid):os.killpg(pgid,signal.SIGTERM)
    grace=min(until,time.monotonic()+8)
    while members(pgid,sid) and time.monotonic()<grace:child.poll();time.sleep(.05)
    if members(pgid,sid):os.killpg(pgid,signal.SIGKILL)
    child.wait(timeout=max(.1,min(8,until-time.monotonic())))
    while members(pgid,sid) and time.monotonic()<until:time.sleep(.05)
    if members(pgid,sid):raise RuntimeError('Owned group remains')

def release_child(child,state,record):
    state['nativePid']=child.pid;state['nativeStarted']=True;record()
    child.stdin.write(b'1');child.stdin.flush();child.stdin.close()

def main(argv):
    p=argparse.ArgumentParser(allow_abbrev=False)
    for key in ['manifest','manifest-sha256','node','node-sha256','python-sha256','supervisor-sha256','helper-sha256']:p.add_argument('--'+key,required=True)
    p.add_argument('--judge-model');p.add_argument('--judge-model-digest')
    p.add_argument('--plan',action='store_true')
    p.add_argument('--profile',choices=['rag-v5','dpi-span','dpi-semantic-compact','dpi-semantic-schema-visible','dpi-semantic-direct-witness','dpi-semantic-server-ids','dpi-semantic-server-ids-smoke','dpi-semantic-server-ids-side','dpi-techniques-selected-semantic6','dpi-semantic-source-first-side','dpi-semantic-whole-intent','dpi-side-selected-semantic6','dpi-side-source-link-semantic6','dpi-side-conjunction-remaining1','dpi-side-compact-conjunction6-8b','dpi-techniques-selected-semantic6-remaining2','dpi-selected-source-technique4','dpi-selected-role-technique4','dpi-selected-objective-technique4-8b','dpi-selected-response-consistency4-8b','dpi-selected-response-regression8-8b','dpi-simple-assessment12-8b','dpi-source-response-assessment12-8b','dpi-source-response-assessment-v2-12-8b'],default='rag-v5')
    flags=[s.split('=')[0] for s in argv if s.startswith('--')]
    if len(flags)!=len(set(flags)):raise ValueError('Duplicate flag')
    a=p.parse_args(argv);admitted=admit(a);cfg=profile(a);judge=judge_selection(a,admitted or {})
    if a.plan:print(json.dumps({'allocation':False,'childSeconds':cfg['seconds'],'cleanupSeconds':30,'stores':0,'maximumInference':cfg['calls'],'maximumMetadata':1,**({'judgeIdentity':judge} if judge else {})}));return 0
    spec=importlib.util.spec_from_file_location('rag_owned_processes',HELPER);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    if Path(module.__file__).resolve()!=HELPER:raise RuntimeError('Helper origin')
    if shutil.disk_usage(ROOT).free < 2*1024**3+512*1024**2+16*1024**2:raise RuntimeError('Artifact space plus reserve required')
    parent=ROOT/'backups/private-recovery'/cfg['folder'];parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    s=parent.lstat()
    if parent.resolve()!=parent or s.st_uid!=os.getuid() or s.st_mode&0o777!=0o700:raise RuntimeError('Private evidence parent required')
    evidence=Path(tempfile.mkdtemp(prefix='run-',dir=parent));os.chmod(evidence,0o700)
    for name in ['home','tmp','results']:(evidence/name).mkdir(mode=0o700)
    state={'parentPid':os.getpid(),'status':'preparing','manifestSha256':a.manifest_sha256,'evidenceRoot':str(evidence),'children':[],'cleanupVerified':False,'failure':None}
    record=lambda:publish(evidence/'ownership.json',state)
    owned=module.OwnedProcesses(stop_group,lambda row:(state['children'].append(row),record()));owned.install()
    previous=signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError('Phase deadline')))
    code=1
    try:
        clean={'PATH':str(Path(a.node).parent)+':/usr/bin:/bin','HOME':str(evidence/'home'),'TMPDIR':str(evidence/'tmp'),'LANG':'C',cfg['prefix']+'_RELEASE_REQUIRED':'1',cfg['prefix']+'_DIAGNOSTIC':'1',cfg['prefix']+'_MANIFEST':a.manifest,cfg['prefix']+'_MANIFEST_SHA256':a.manifest_sha256,cfg['prefix']+'_OUTPUT_ROOT':str(evidence/'results')}
        if judge:clean.update(DPI_SPAN_JUDGE_MODEL=judge['model'],DPI_SPAN_JUDGE_MODEL_DIGEST=judge['digest'])
        if cfg.get('childProfile'):clean[cfg['prefix']+'_PROFILE']=cfg['childProfile']
        record();print(json.dumps({'evidenceRoot':str(evidence)}),flush=True);signal.setitimer(signal.ITIMER_REAL,cfg['seconds'])
        with open(evidence/'child.log','xb',opener=lambda name,flags:os.open(name,flags,0o600)) as log:
            child=owned.launch([a.node,str(ROOT/cfg['entry'])],name='rag-whole-evidence',cwd=ROOT,env=clean,stdout=log,stderr=subprocess.STDOUT,start_new_session=True,stdin=subprocess.PIPE)
            release_child(child,state,record)
            deadline=time.monotonic()+cfg['seconds']
            while child.poll() is None:
                if time.monotonic()>=deadline:raise TimeoutError('Child deadline')
                if log.tell()>16*1024*1024:raise RuntimeError('Log cap')
                time.sleep(.1)
            code=child.returncode
        state['childExitCode']=code;state['status']='child-exited'
    except BaseException as error:state['failure']=type(error).__name__;code=1
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);owned.mask_cleanup_signals();signal.setitimer(signal.ITIMER_REAL,30)
        try:owned.cleanup();state['cleanupVerified']=True
        except BaseException as error:state['cleanupFailure']=type(error).__name__;code=1
        finally:signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous);owned.restore()
        if (evidence/'child.log').exists() and (evidence/'child.log').stat().st_size>16*1024*1024:state['failure']='LogCap';code=1
        try:
            admit(a);state['sourceUnchanged']=True
        except BaseException as error:state['sourceUnchanged']=False;state['integrityFailure']=type(error).__name__;code=1
        state['status']='terminal' if code==0 and state['cleanupVerified'] else 'failed';record()
    return code
if __name__=='__main__':
    try:sys.exit(main(sys.argv[1:]))
    except Exception as error:print(json.dumps({'status':'admission-failed','error':type(error).__name__}));sys.exit(1)
