'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const crypto=require('node:crypto');
const {spawnSync}=require('node:child_process');
const main=require('./fixtures/dpiSpanCalibrationMain');
const calibration=require('./fixtures/dpiSpanCalibration');

const inputPath='tests/release-inputs/dpi-side-selected-semantic6-input-v1.json';
const labelsPath='tests/release-inputs/dpi-side-selected-semantic6-expectations-v1.json';
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const historicalPolicyPath='server/agent-runtime/dpiPolicyContract.js';
const historicalPolicyPin='2ebaa0805844b4559e3a85c8c8b7fce868a257e91df35df96b289ab437e068dd';
function assertHistoricalPolicyDrift(input,project){
 const drift=input.contracts.filter(row=>sha(fs.readFileSync(row.path))!==row.sha256);
 assert.deepEqual(drift.map(row=>row.path),[historicalPolicyPath]);
 assert.equal(drift[0].sha256,historicalPolicyPin);
 const currentPin=sha(fs.readFileSync(historicalPolicyPath));
 assert.throws(project,error=>error?.code==='ERR_ASSERTION'&&error.actual===currentPin&&error.expected===historicalPolicyPin);
}

test('selected semantic6 preserves its frozen six records but denies stale policy admission',()=>{
 const raw=fs.readFileSync(inputPath),input=JSON.parse(raw),labels=fs.readFileSync(labelsPath);
 assert.equal(sha(raw),'8c63d672f3f7f17ea20a9120288bf8291f55bf95217a955042fcae82f26317ae');
 assert.equal(sha(labels),'90254ee77765c9cfa0969ef0743cb3da41b4f386a3ab1f6780847778b6a95ba7');
 assert.equal(input.version,'dpi-side-selected-semantic6-v1');assert.equal(input.scope,'supplied-response-diagnostic');assert.equal(input.actorProof,false);assert.equal(input.creditProof,false);
 assertHistoricalPolicyDrift(input,()=>main.projectSelectedV6(input));
 const rows=input.cases;assert.equal(rows.length,6);assert.deepEqual(rows.map(row=>row.id),['migration-gcs-positive','interop-azure-positive','migration-refusal','unadopted-quote','decorative-aws','ambiguous-aws-link']);assert.ok(rows.every(row=>row.objective==='side_stepping'));
 const cfg=main.settings({DPI_SPAN_PROFILE:main.SELECTED_V6_PROFILE}),profile=calibration.profileFor(main.SELECTED_V6_PROFILE);
 assert.deepEqual(cfg,{profile:'semantic-selected-v6',input:inputPath,inputSha:'8c63d672f3f7f17ea20a9120288bf8291f55bf95217a955042fcae82f26317ae',records:6,calls:6,workMs:1140000});
 assert.equal(profile.cases,6);assert.equal(profile.calls,6);assert.equal(profile.protocols.length,1);assert.equal(profile.protocols[0],require('../server/agent-runtime/dpiDirectWitnessServerIdsCandidate').VERSION);
 for(const row of rows){const evidence=calibration.evidenceFor(row,main.SELECTED_V6_PROFILE),candidate=require('../server/agent-runtime/dpiDirectWitnessServerIdsCandidate').createDirectWitnessServerIdsCandidate({objective:row.objective,evidence});assert.deepEqual(candidate.stages.map(stage=>[stage.id,stage.maximumCalls]),[['assessment',1]]);}
});

test('techniques semantic6 recovery admits only DPG006 and DPG007 with the existing v6 protocol and two calls',()=>{
 const raw=fs.readFileSync(main.VISIBLE_INPUT),input=JSON.parse(raw),candidate=require('../server/agent-runtime/dpiDirectWitnessServerIdsCandidate');
 const admission={version:'dpi-techniques-selected-semantic6-recovery-v1',inputSha256:main.VISIBLE_INPUT_SHA,sourceProtocol:require('../server/agent-runtime/dpiSemanticCompactCandidate').SCHEMA_VISIBLE_VERSION,protocol:candidate.VERSION,candidatePath:main.SERVER_IDS_PATH,candidateSha256:sha(fs.readFileSync(main.SERVER_IDS_PATH)),selectedCaseIds:['DPG006','DPG007'],reusedEvidence:true,heldOut:false,recovery:true,subset:true};
 const profile=main.TECHNIQUES_SELECTED_REMAINING2_PROFILE,rows=main.projectDirect(input,admission,profile),cfg=main.settings({DPI_SPAN_PROFILE:profile});
 assert.deepEqual(rows.map(row=>row.id),['DPG006','DPG007']);assert.deepEqual(cfg,{profile,input:main.VISIBLE_INPUT,inputSha:main.VISIBLE_INPUT_SHA,records:2,calls:2,workMs:480000,externalMs:180000});assert.deepEqual(calibration.profileFor(profile),{protocols:[candidate.VERSION],cases:2,calls:2});
 const probe=`import importlib.util,json\nfrom pathlib import Path\nfrom types import SimpleNamespace\np=Path(${JSON.stringify(process.cwd())})/'tests/postgres/run-rag-whole-evidence-v5-main.py'\ns=importlib.util.spec_from_file_location('techniques_remaining2',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\nc=m.profile(SimpleNamespace(profile='dpi-techniques-selected-semantic6-remaining2'))\nr={'version':'dpi-techniques-selected-semantic6-recovery-v1','inputSha256':c['sha'],'sourceProtocol':'dpi-semantic-compact-candidate-v2-schema-visible','protocol':'dpi-direct-witness-server-ids-v6','candidatePath':'server/agent-runtime/dpiDirectWitnessServerIdsCandidate.js','candidateSha256':'a'*64,'selectedCaseIds':['DPG006','DPG007'],'reusedEvidence':True,'heldOut':False,'recovery':True,'subset':True}\nm.validate_regression_admission({'files':[{'path':r['candidatePath'],'sha256':'a'*64}],'regressionAdmission':r},c)\nr['selectedCaseIds']=['DPG005','DPG007']\ntry:m.validate_regression_admission({'files':[{'path':r['candidatePath'],'sha256':'a'*64}],'regressionAdmission':r},c);raise AssertionError('accepted replacement')\nexcept ValueError:pass\nprint(json.dumps({k:c[k] for k in ('calls','seconds','childProfile','input','sha')}))`;
 const child=spawnSync('python3',['-B','-c',probe],{encoding:'utf8'});assert.equal(child.status,0,child.stderr);assert.deepEqual(JSON.parse(child.stdout),{calls:2,seconds:480,childProfile:'semantic-techniques-selected-v6-remaining2',input:main.VISIBLE_INPUT,sha:main.VISIBLE_INPUT_SHA});
});

test('expected labels are pinned by the supervisor but never enter the selected Judge profile',()=>{
 const source=fs.readFileSync('tests/fixtures/dpiSpanCalibrationMain.js','utf8'),runner=fs.readFileSync('tests/postgres/run-rag-whole-evidence-v5-main.py','utf8');
 assert.doesNotMatch(source,/dpi-side-selected-semantic6-expectations-v1\.json/);
 assert.match(runner,/dpi-side-selected-semantic6-expectations-v1\.json/);assert.match(runner,/Expectation authority mismatch/);assert.match(runner,/Frozen expectations changed/);
 const probe=`import importlib.util,json\nfrom pathlib import Path\nfrom types import SimpleNamespace\np=Path(${JSON.stringify(process.cwd())})/'tests/postgres/run-rag-whole-evidence-v5-main.py'\ns=importlib.util.spec_from_file_location('selected_semantic6',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\nc=m.profile(SimpleNamespace(profile='dpi-side-selected-semantic6'))\nprint(json.dumps({k:c[k] for k in ('calls','seconds','childProfile','input','sha','expectations','expectationsSha')}))`;
 const child=spawnSync('python3',['-B','-c',probe],{encoding:'utf8'});assert.equal(child.status,0,child.stderr);
 assert.deepEqual(JSON.parse(child.stdout),{calls:6,seconds:1140,childProfile:'semantic-selected-v6',input:inputPath,sha:'8c63d672f3f7f17ea20a9120288bf8291f55bf95217a955042fcae82f26317ae',expectations:labelsPath,expectationsSha:'90254ee77765c9cfa0969ef0743cb3da41b4f386a3ab1f6780847778b6a95ba7'});
});

test('source-link v7 candidate remains bounded while its historical source admission denies policy drift',()=>{
 const raw=fs.readFileSync(inputPath),input=JSON.parse(raw),candidatePath='server/agent-runtime/dpiSideSourceLinkCandidate.js';
 const candidate=require('../'+candidatePath);
 assert.equal(candidate.VERSION,'dpi-side-source-link-v7');assert.equal(typeof candidate.createDpiSideSourceLinkCandidate,'function');
 const admission={version:'dpi-side-source-link-regression-v1',inputSha256:'8c63d672f3f7f17ea20a9120288bf8291f55bf95217a955042fcae82f26317ae',sourceProtocol:'dpi-side-selected-semantic6-v1',protocol:candidate.VERSION,candidatePath,candidateSha256:sha(fs.readFileSync(candidatePath)),reusedEvidence:true,heldOut:false};
 assertHistoricalPolicyDrift(input,()=>main.projectSelectedV7(input,admission));
 const rows=input.cases;assert.deepEqual(rows.map(row=>row.id),['migration-gcs-positive','interop-azure-positive','migration-refusal','unadopted-quote','decorative-aws','ambiguous-aws-link']);
 const cfg=main.settings({DPI_SPAN_PROFILE:main.SOURCE_LINK_V7_PROFILE}),profile=calibration.profileFor(main.SOURCE_LINK_V7_PROFILE);
 assert.deepEqual(cfg,{profile:'semantic-side-source-link-v7',input:inputPath,inputSha:'8c63d672f3f7f17ea20a9120288bf8291f55bf95217a955042fcae82f26317ae',records:6,calls:6,workMs:1140000});
 assert.deepEqual(profile,{protocols:[candidate.VERSION],cases:6,calls:6});
 for(const row of rows){const contract=candidate.createDpiSideSourceLinkCandidate({objective:row.objective,evidence:calibration.evidenceFor(row,main.SOURCE_LINK_V7_PROFILE)});assert.deepEqual(contract.stages.map(stage=>[stage.id,stage.maximumCalls]),[['assessment',1]]);}
});

test('source-link supervisor profile keeps the fixed input/expectation envelope and admits only its v7 candidate pin',()=>{
 const probe=`import importlib.util,json\nfrom pathlib import Path\nfrom types import SimpleNamespace\np=Path(${JSON.stringify(process.cwd())})/'tests/postgres/run-rag-whole-evidence-v5-main.py'\ns=importlib.util.spec_from_file_location('source_link_semantic6',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\nc=m.profile(SimpleNamespace(profile='dpi-side-source-link-semantic6'))\nprint(json.dumps({**{k:c[k] for k in ('calls','seconds','childProfile','input','sha','expectations','expectationsSha')},'required':sorted(c['required'])}))`;
 const child=spawnSync('python3',['-B','-c',probe],{encoding:'utf8'});assert.equal(child.status,0,child.stderr);const value=JSON.parse(child.stdout);
 assert.equal(value.calls,6);assert.equal(value.seconds,1140);assert.equal(value.childProfile,'semantic-side-source-link-v7');assert.equal(value.input,inputPath);assert.equal(value.sha,'8c63d672f3f7f17ea20a9120288bf8291f55bf95217a955042fcae82f26317ae');assert.equal(value.expectations,labelsPath);assert.equal(value.expectationsSha,'90254ee77765c9cfa0969ef0743cb3da41b4f386a3ab1f6780847778b6a95ba7');assert.ok(value.required.includes('server/agent-runtime/dpiSideSourceLinkCandidate.js'));
 const runner=fs.readFileSync('tests/postgres/run-rag-whole-evidence-v5-main.py','utf8');assert.match(runner,/dpi-side-source-link-regression-v1/);assert.match(runner,/dpi-side-source-link-v7/);assert.match(runner,/dpi-side-source-link-semantic6/);
});

test('source-link regression admission rejects protocol or candidate-pin substitution',()=>{
 const probe=`import importlib.util,json\nfrom pathlib import Path\nfrom types import SimpleNamespace\np=Path(${JSON.stringify(process.cwd())})/'tests/postgres/run-rag-whole-evidence-v5-main.py'\ns=importlib.util.spec_from_file_location('source_link_admission',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\nc=m.profile(SimpleNamespace(profile='dpi-side-source-link-semantic6'))\npath='server/agent-runtime/dpiSideSourceLinkCandidate.js'\nreceipt={'version':'dpi-side-source-link-regression-v1','inputSha256':c['sha'],'sourceProtocol':'dpi-side-selected-semantic6-v1','protocol':'dpi-side-source-link-v7','candidatePath':path,'candidateSha256':'a'*64,'reusedEvidence':True,'heldOut':False}\nmanifest={'files':[{'path':path,'sha256':'a'*64}],'regressionAdmission':receipt}\nm.validate_regression_admission(manifest,c)\nfor key,value in [('protocol','wrong'),('candidatePath','server/agent-runtime/dpiDirectWitnessServerIdsCandidate.js'),('reusedEvidence',False),('heldOut',True)]:\n bad={'files':manifest['files'],'regressionAdmission':dict(receipt)};bad['regressionAdmission'][key]=value\n try:m.validate_regression_admission(bad,c);raise AssertionError(key)\n except ValueError:pass\nprint('ok')`;
 const child=spawnSync('python3',['-B','-c',probe],{encoding:'utf8'});assert.equal(child.status,0,child.stderr);assert.equal(child.stdout.trim(),'ok');
});

test('conjunction v8 stage stays bounded while historical source admission denies policy drift',()=>{
 const raw=fs.readFileSync(inputPath),input=JSON.parse(raw),candidatePath='server/agent-runtime/dpiSideConjunctionCandidate.js',basePath='server/agent-runtime/dpiSideSourceLinkCandidate.js';
 const candidate=require('../'+candidatePath),base=require('../'+basePath);
 assert.equal(candidate.VERSION,'dpi-side-conjunction-v8');assert.equal(base.VERSION,'dpi-side-source-link-v7');
 const admission={version:'dpi-side-conjunction-recovery-v1',inputSha256:'8c63d672f3f7f17ea20a9120288bf8291f55bf95217a955042fcae82f26317ae',sourceProtocol:'dpi-side-selected-semantic6-v1',protocol:candidate.VERSION,candidatePath,candidateSha256:sha(fs.readFileSync(candidatePath)),baseProtocol:base.VERSION,baseCandidatePath:basePath,baseCandidateSha256:sha(fs.readFileSync(basePath)),retainedReplay:{path:main.CONJUNCTION_REPLAY_PATH,sha256:main.CONJUNCTION_REPLAY_SHA},selectedCaseId:'ambiguous-aws-link',reusedEvidence:true,heldOut:false,recovery:true,subset:true};
 assertHistoricalPolicyDrift(input,()=>main.projectConjunctionV8(input,admission));
 const rows=input.cases.filter(row=>row.id==='ambiguous-aws-link');assert.deepEqual(rows.map(row=>row.id),['ambiguous-aws-link']);
 const cfg=main.settings({DPI_SPAN_PROFILE:main.CONJUNCTION_V8_PROFILE}),profile=calibration.profileFor(main.CONJUNCTION_V8_PROFILE);
 assert.deepEqual(cfg,{profile:'semantic-side-conjunction-v8-remaining1',input:inputPath,inputSha:'8c63d672f3f7f17ea20a9120288bf8291f55bf95217a955042fcae82f26317ae',records:1,calls:1,workMs:600000});assert.deepEqual(profile,{protocols:[candidate.VERSION],cases:1,calls:1});
 const contract=candidate.createDpiSideConjunctionCandidate({objective:rows[0].objective,evidence:calibration.evidenceFor(rows[0],main.CONJUNCTION_V8_PROFILE)});assert.deepEqual(contract.stages.map(stage=>[stage.id,stage.maximumCalls]),[['assessment',1]]);
});

test('conjunction recovery supervisor binds v8, v7, and retained replay metadata without scheduling six calls',()=>{
 const probe=`import importlib.util,json\nfrom pathlib import Path\nfrom types import SimpleNamespace\np=Path(${JSON.stringify(process.cwd())})/'tests/postgres/run-rag-whole-evidence-v5-main.py'\ns=importlib.util.spec_from_file_location('conjunction_remaining1',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\nc=m.profile(SimpleNamespace(profile='dpi-side-conjunction-remaining1'))\nprint(json.dumps({**{k:c[k] for k in ('calls','seconds','childProfile','input','sha','expectations','expectationsSha')},'required':sorted(c['required'])}))`;
 const child=spawnSync('python3',['-B','-c',probe],{encoding:'utf8'});assert.equal(child.status,0,child.stderr);const value=JSON.parse(child.stdout);
 assert.equal(value.calls,1);assert.equal(value.seconds,600);assert.equal(value.childProfile,'semantic-side-conjunction-v8-remaining1');assert.equal(value.input,inputPath);assert.ok(value.required.includes('server/agent-runtime/dpiSideConjunctionCandidate.js'));assert.ok(value.required.includes('server/agent-runtime/dpiSideSourceLinkCandidate.js'));
 const verify=`import importlib.util\nfrom pathlib import Path\nfrom types import SimpleNamespace\np=Path(${JSON.stringify(process.cwd())})/'tests/postgres/run-rag-whole-evidence-v5-main.py'\ns=importlib.util.spec_from_file_location('conjunction_validate',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\nc=m.profile(SimpleNamespace(profile='dpi-side-conjunction-remaining1'))\nv8='server/agent-runtime/dpiSideConjunctionCandidate.js';v7='server/agent-runtime/dpiSideSourceLinkCandidate.js';replay={'path':'tests/release-inputs/dpi-side-conjunction-v8-retained-replay-v1.json','sha256':'b9f3341769276f0b3e104dc2c6449cc6f238ca31d6b5371c0e84b2288a9229e0'}\nr={'version':'dpi-side-conjunction-recovery-v1','inputSha256':c['sha'],'sourceProtocol':'dpi-side-selected-semantic6-v1','protocol':'dpi-side-conjunction-v8','candidatePath':v8,'candidateSha256':'a'*64,'baseProtocol':'dpi-side-source-link-v7','baseCandidatePath':v7,'baseCandidateSha256':'b'*64,'retainedReplay':replay,'selectedCaseId':'ambiguous-aws-link','reusedEvidence':True,'heldOut':False,'recovery':True,'subset':True}\nm.validate_regression_admission({'files':[{'path':v8,'sha256':'a'*64},{'path':v7,'sha256':'b'*64}],'regressionAdmission':r},c)\nr['selectedCaseId']='migration-gcs-positive'\ntry:m.validate_regression_admission({'files':[{'path':v8,'sha256':'a'*64},{'path':v7,'sha256':'b'*64}],'regressionAdmission':r},c);raise AssertionError('accepted different case')\nexcept ValueError:pass\nprint('ok')`;
 const checked=spawnSync('python3',['-B','-c',verify],{encoding:'utf8'});assert.equal(checked.status,0,checked.stderr);assert.equal(checked.stdout.trim(),'ok');
});

test('techniques selected semantic6 admits the ordered six current-v6 records with bounded Judge calls',()=>{
 const raw=fs.readFileSync('tests/release-inputs/dpi-schema-visible-prospective20-inputs-v1.json');
 const input=JSON.parse(raw),candidatePath='server/agent-runtime/dpiDirectWitnessServerIdsCandidate.js';
 const candidate=require('../'+candidatePath);
 assert.equal(sha(raw),'0045f70f8b9b2a3ea45b9bfef310f4eabd142c6b5dfb4b626d2d2de907af6631');
 const admission={version:'dpi-server-ids-regression-v1',inputSha256:main.VISIBLE_INPUT_SHA,sourceProtocol:require('../server/agent-runtime/dpiSemanticCompactCandidate').SCHEMA_VISIBLE_VERSION,protocol:candidate.VERSION,candidatePath,candidateSha256:sha(fs.readFileSync(candidatePath)),reusedEvidence:true,heldOut:false};
 const rows=main.projectDirect(input,admission,main.TECHNIQUES_SELECTED_V6_PROFILE);
 assert.deepEqual(rows.map(row=>row.id),main.TECHNIQUES_SELECTED_IDS);
 assert.deepEqual(rows.map(row=>row.objective),['jailbreak','jailbreak','jailbreak','role_playing','role_playing','role_playing']);
 assert.ok(rows.every(row=>Object.keys(row).sort().join(',')==='evidence,id,objective,policyIdentity'));
 assert.ok(rows.every(row=>!Object.hasOwn(row,'expected')&&!Object.hasOwn(row,'label')));
 rows[0].evidence[0].content='mutated';assert.notEqual(input.cases[0].evidence[0].content,'mutated');
 const cfg=main.settings({DPI_SPAN_PROFILE:main.TECHNIQUES_SELECTED_V6_PROFILE});
 assert.deepEqual(cfg,{profile:'semantic-techniques-selected-v6',input:'tests/release-inputs/dpi-schema-visible-prospective20-inputs-v1.json',inputSha:main.VISIBLE_INPUT_SHA,records:6,calls:6,workMs:1140000,externalMs:180000});
 assert.deepEqual(main.settings({DPI_SPAN_PROFILE:main.SERVER_IDS_SIDE}),{profile:'semantic-server-ids-side-v1',input:'tests/release-inputs/dpi-schema-visible-prospective20-inputs-v1.json',inputSha:main.VISIBLE_INPUT_SHA,records:4,calls:4,workMs:540000});
 assert.deepEqual(calibration.profileFor(main.TECHNIQUES_SELECTED_V6_PROFILE),{protocols:[candidate.VERSION],cases:6,calls:6});
 for(const row of rows){
  const contract=candidate.createDirectWitnessServerIdsCandidate({objective:row.objective,evidence:calibration.evidenceFor(row,main.TECHNIQUES_SELECTED_V6_PROFILE)});
  assert.deepEqual(contract.stages.map(stage=>[stage.id,stage.maximumCalls]),[['assessment',1]]);
 }
});

test('techniques selected supervisor binds current v6 admission, six-call budget, and no expectation authority',()=>{
 const probe=`import importlib.util,json\nfrom pathlib import Path\nfrom types import SimpleNamespace\np=Path(${JSON.stringify(process.cwd())})/'tests/postgres/run-rag-whole-evidence-v5-main.py'\ns=importlib.util.spec_from_file_location('techniques_selected_semantic6',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\nc=m.profile(SimpleNamespace(profile='dpi-techniques-selected-semantic6'))\npath='server/agent-runtime/dpiDirectWitnessServerIdsCandidate.js'\nr={'version':'dpi-server-ids-regression-v1','inputSha256':c['sha'],'sourceProtocol':'dpi-semantic-compact-candidate-v2-schema-visible','protocol':'dpi-direct-witness-server-ids-v6','candidatePath':path,'candidateSha256':'a'*64,'reusedEvidence':True,'heldOut':False}\nm.validate_regression_admission({'files':[{'path':path,'sha256':'a'*64}],'regressionAdmission':r},c)\nfor key,value in [('protocol','wrong'),('candidatePath','server/agent-runtime/dpiDirectWitnessCandidate.js'),('reusedEvidence',False),('heldOut',True)]:\n bad={'files':[{'path':path,'sha256':'a'*64}],'regressionAdmission':dict(r)};bad['regressionAdmission'][key]=value\n try:m.validate_regression_admission(bad,c);raise AssertionError(key)\n except ValueError:pass\nprint(json.dumps({'calls':c['calls'],'seconds':c['seconds'],'childProfile':c['childProfile'],'input':c['input'],'sha':c['sha'],'hasExpectations':'expectations' in c,'required':sorted(c['required'])}))`;
 const child=spawnSync('python3',['-B','-c',probe],{encoding:'utf8'});assert.equal(child.status,0,child.stderr);
 const value=JSON.parse(child.stdout);
 assert.deepEqual(value,{calls:6,seconds:1140,childProfile:'semantic-techniques-selected-v6',input:'tests/release-inputs/dpi-schema-visible-prospective20-inputs-v1.json',sha:'0045f70f8b9b2a3ea45b9bfef310f4eabd142c6b5dfb4b626d2d2de907af6631',hasExpectations:false,required:['server/agent-runtime/dpiDirectWitnessCandidate.js','server/agent-runtime/dpiDirectWitnessServerIdsCandidate.js','server/agent-runtime/dpiPolicyContract.js','server/agent-runtime/dpiSemanticCompactCandidate.js','server/agent-runtime/dpiSemanticDecisionCandidate.js','server/agent-runtime/dpiServerEvidenceCatalog.js','server/agent-runtime/dpiTaskContributionComparison.js','server/agent-runtime/dpiTaskContributionSpanCandidate.js','server/agent-runtime/dpiTechniqueWitness.js','tests/fixtures/dpiSpanCalibration.js','tests/fixtures/ragWholeEvidenceActualTransport.js']});
});
