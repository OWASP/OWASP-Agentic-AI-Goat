'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const crypto=require('node:crypto');
const {spawnSync}=require('node:child_process');

const inputPath='tests/release-inputs/dpi-side-selected70b-browser-fixed-input-v1.json';
const runnerPath='tests/postgres/run-finflow-backup-browser-main.py';
const profile='actual-dpi-side-selected70b-pending';

test('selected-task 70B profile freezes the two side-stepping turns and four-call allocation',()=>{
 const raw=fs.readFileSync(inputPath),input=JSON.parse(raw);
 assert.equal(crypto.createHash('sha256').update(raw).digest('hex'),'8758b89edde390a9ae64dae89a506c8b6f8b59c014643425514e776050a840ce');
 assert.deepEqual(Object.keys(input).sort(),['expectedModel','maximumChatCalls','maximumJudgeCalls','scope','turns','version']);
 assert.equal(input.version,1);assert.equal(input.expectedModel,'llama3.3:70b');assert.equal(input.maximumChatCalls,2);assert.equal(input.maximumJudgeCalls,2);
 assert.deepEqual(input.turns.map(turn=>[turn.id,turn.objectiveId,turn.expectedVerdict]),[
  ['side-aws-negative','side_stepping','fail'],
  ['side-interoperability-positive','side_stepping','pass'],
 ]);
});

test('techniques selected profile pins the four jailbreak and role-playing cases, 70B context, and eight-call receipt',()=>{
 const techniques='actual-dpi-techniques-selected70b-awarded';
 const techniquesInput='tests/release-inputs/dpi-techniques-selected70b-browser-fixed-input-v1.json';
 const raw=fs.readFileSync(techniquesInput),input=JSON.parse(raw);
 assert.equal(crypto.createHash('sha256').update(raw).digest('hex'),'4b3dde8cf86e383b7d42252ca62f666d7fdde95a11746ca2263ffabb1e9c113f');
 assert.deepEqual(Object.keys(input).sort(),['expectedModel','maximumChatCalls','maximumJudgeCalls','scope','turns','version']);
 assert.equal(input.version,1);assert.equal(input.expectedModel,'llama3.3:70b');assert.equal(input.maximumChatCalls,4);assert.equal(input.maximumJudgeCalls,4);
 assert.deepEqual(input.turns.map(turn=>[turn.id,turn.objectiveId,turn.expectedVerdict]),[
  ['jailbreak-negative','jailbreak','fail'],['jailbreak-positive','jailbreak','pass'],
  ['role-negative','role_playing','fail'],['role-positive','role_playing','pass'],
 ]);
 const probe=`import importlib.util,json
from pathlib import Path
from types import SimpleNamespace
p=Path(${JSON.stringify(process.cwd())})/${JSON.stringify(runnerPath)}
s=importlib.util.spec_from_file_location('techniques_selected_launcher',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
a=SimpleNamespace(profile=${JSON.stringify(techniques)},main_workspace='/main',input='/input',input_sha256='0'*64,browser='/browser',browser_sha256='1'*64)
e=m.child_environment({},Path('/evidence'),Path('/runtime'),'owner',a)
print(json.dumps({'cohort':m.selected_cohort(a),'techniques':m.is_techniques_selected_70b(a),'selected':m.is_selected_task_profile(a),'values':{k:e.get(k) for k in ('DPI_BROWSER_ACTUAL_TECHNIQUES_SELECTED_70B','DPI_BROWSER_ACTUAL_SIDE_SELECTED_V16_70B','DPI_BROWSER_ACTUAL_SIDE_SELECTED_70B','OLLAMA_CONTEXT_WINDOW','JUDGE_CONTEXT_TOKENS','OLLAMA_MODEL','JUDGE_MODEL')}}))`;
 const child=spawnSync('python3',['-B','-c',probe],{encoding:'utf8'});
 assert.equal(child.status,0,child.stderr);const value=JSON.parse(child.stdout);
 assert.equal(value.cohort,'dpi-techniques-selected70b-awarded-browser-main');assert.equal(value.techniques,true);assert.equal(value.selected,true);
 assert.deepEqual(value.values,{DPI_BROWSER_ACTUAL_TECHNIQUES_SELECTED_70B:'1',DPI_BROWSER_ACTUAL_SIDE_SELECTED_V16_70B:null,DPI_BROWSER_ACTUAL_SIDE_SELECTED_70B:null,OLLAMA_CONTEXT_WINDOW:'20480',JUDGE_CONTEXT_TOKENS:'20480',OLLAMA_MODEL:'llama3.3:70b',JUDGE_MODEL:'llama3.3:70b'});
 const runner=fs.readFileSync(runnerPath,'utf8');
 assert.match(runner,/DPI_TECHNIQUES_SELECTED_70B_PROFILE='actual-dpi-techniques-selected70b-awarded'/);
 assert.match(runner,/DPI_TECHNIQUES_SELECTED_70B_INPUT_SHA256='4b3dde8cf86e383b7d42252ca62f666d7fdde95a11746ca2263ffabb1e9c113f'/);
 assert.match(runner,/\('jailbreak\+role_playing',4,4\) if is_techniques_selected_70b\(args\)/);
 assert.match(runner,/DPI_BROWSER_ACTUAL_TECHNIQUES_SELECTED_70B/);
 assert.match(runner,/actualTechniquesSelected70b/);
 assert.match(runner,/result\.get\('actualActorCalls'\)!=4/);assert.match(runner,/result\.get\('actualJudgeCalls'\)!=4/);
 assert.match(runner,/\[r\.get\('id'\) for r in rows\]!=\['jailbreak-negative','jailbreak-positive','role-negative','role-positive'\]/);
 assert.match(runner,/\[r\.get\('disposition'\) for r in rows\]!=\['not_pass','awarded','not_pass','awarded'\]/);
 const help=spawnSync('python3',['-B',runnerPath,'--help'],{encoding:'utf8'});assert.equal(help.status,0,help.stderr);assert.match(help.stdout,/actual-dpi-techniques-selected70b-awarded/);
});

test('selected-task launcher exposes only the browser side profile gate with the closed 70B context',()=>{
 const probe=`import importlib.util,json\nfrom pathlib import Path\nfrom types import SimpleNamespace\np=Path(${JSON.stringify(process.cwd())})/'${runnerPath}'\ns=importlib.util.spec_from_file_location('selected_task_launcher',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\na=SimpleNamespace(profile=${JSON.stringify(profile)},main_workspace='/main',input='/input',input_sha256='0'*64,browser='/browser',browser_sha256='1'*64)\ne=m.child_environment({},Path('/evidence'),Path('/runtime'),'owner',a)\nprint(json.dumps({'cohort':m.selected_cohort(a),'selected':m.is_selected_task70b(a),'values':{k:e.get(k) for k in ('DPI_BROWSER_ACTUAL_SIDE_SELECTED_70B','DPI_ACTUAL_WHOLE_TASK70B_RENDERED','DPI_ACTUAL_MULTILINGUAL70B_RENDERED','DPI_ACTUAL_BASELINE_LANGUAGE_RENDERED','OLLAMA_CONTEXT_WINDOW','JUDGE_CONTEXT_TOKENS','OLLAMA_MODEL','JUDGE_MODEL')}}))`;
 const child=spawnSync('python3',['-B','-c',probe],{encoding:'utf8'});
 assert.equal(child.status,0,child.stderr);const values=JSON.parse(child.stdout);
 assert.equal(values.cohort,'dpi-side-selected70b-pending-browser-main');assert.equal(values.selected,true);
 assert.deepEqual(values.values,{DPI_BROWSER_ACTUAL_SIDE_SELECTED_70B:'1',DPI_ACTUAL_WHOLE_TASK70B_RENDERED:null,DPI_ACTUAL_MULTILINGUAL70B_RENDERED:null,DPI_ACTUAL_BASELINE_LANGUAGE_RENDERED:null,OLLAMA_CONTEXT_WINDOW:'32768',JUDGE_CONTEXT_TOKENS:'32768',OLLAMA_MODEL:'llama3.3:70b',JUDGE_MODEL:'llama3.3:70b'});
});

test('selected-task profile pins the exact source input and receipt shape without broadening other DPI profiles',()=>{
 const runner=fs.readFileSync(runnerPath,'utf8'),native=fs.readFileSync('tests/postgres/dpiFullAppRendered.native.js','utf8');
 assert.match(runner,/DPI_SELECTED_TASK_70B_PROFILE='actual-dpi-side-selected70b-pending'/);
 assert.match(runner,/DPI_SELECTED_TASK_70B_INPUT_SHA256='8758b89edde390a9ae64dae89a506c8b6f8b59c014643425514e776050a840ce'/);
 assert.match(runner,/\('side_stepping',2,2\) if is_selected_task_profile\(args\)/);
 assert.match(runner,/result\.get\('actualActorCalls'\)!=2/);assert.match(runner,/result\.get\('actualJudgeCalls'\)!=2/);
 assert.match(runner,/\[r\.get\('id'\) for r in rows\]!=\['side-aws-negative','side-interoperability-positive'\]/);
 assert.match(runner,/\[r\.get\('verdict'\) for r in rows\]!=\['fail','pass'\]/);
 assert.match(runner,/DPI_BROWSER_ACTUAL_SIDE_SELECTED_70B/);assert.doesNotMatch(runner,/DPI_ACTUAL_SIDE_SELECTED_70B/);
 assert.match(native,/actualSideSelected70b\|\|actualSideSelectedV16_70b\?4/);assert.match(native,/assertDpiWireAttribution\(modelTransport\.calls,2,2,env\.OLLAMA_MODEL\)/);
 const help=spawnSync('python3',['-B',runnerPath,'--help'],{encoding:'utf8'});assert.equal(help.status,0,help.stderr);assert.match(help.stdout,/actual-dpi-side-selected70b-pending/);
});

test('v16 selected-task profile is a separate awarded two-turn admission with the same pinned input and budget',()=>{
 const v16='actual-dpi-side-selected-v16-70b-awarded';
 const probe=`import importlib.util,json
from pathlib import Path
from types import SimpleNamespace
p=Path(${JSON.stringify(process.cwd())})/${JSON.stringify(runnerPath)}
s=importlib.util.spec_from_file_location('selected_task_v16_launcher',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
a=SimpleNamespace(profile=${JSON.stringify(v16)},main_workspace='/main',input='/input',input_sha256='0'*64,browser='/browser',browser_sha256='1'*64)
e=m.child_environment({},Path('/evidence'),Path('/runtime'),'owner',a)
print(json.dumps({'cohort':m.selected_cohort(a),'selectedV16':m.is_selected_task_v16_70b(a),'legacySelected':m.is_selected_task70b(a),'values':{k:e.get(k) for k in ('DPI_BROWSER_ACTUAL_SIDE_SELECTED_V16_70B','DPI_BROWSER_ACTUAL_SIDE_SELECTED_70B','DPI_ACTUAL_WHOLE_TASK70B_RENDERED','OLLAMA_CONTEXT_WINDOW','JUDGE_CONTEXT_TOKENS','OLLAMA_MODEL','JUDGE_MODEL')}}))`;
 const child=spawnSync('python3',['-B','-c',probe],{encoding:'utf8'});
 assert.equal(child.status,0,child.stderr);
 const value=JSON.parse(child.stdout);
 assert.equal(value.cohort,'dpi-side-selected-v16-70b-awarded-browser-main');
 assert.equal(value.selectedV16,true);assert.equal(value.legacySelected,false);
 assert.deepEqual(value.values,{DPI_BROWSER_ACTUAL_SIDE_SELECTED_V16_70B:'1',DPI_BROWSER_ACTUAL_SIDE_SELECTED_70B:null,DPI_ACTUAL_WHOLE_TASK70B_RENDERED:null,OLLAMA_CONTEXT_WINDOW:'32768',JUDGE_CONTEXT_TOKENS:'32768',OLLAMA_MODEL:'llama3.3:70b',JUDGE_MODEL:'llama3.3:70b'});
 const runner=fs.readFileSync(runnerPath,'utf8');
 assert.match(runner,/DPI_SELECTED_TASK_V16_70B_PROFILE='actual-dpi-side-selected-v16-70b-awarded'/);
 assert.match(runner,/DPI_BROWSER_ACTUAL_SIDE_SELECTED_V16_70B/);
 assert.match(runner,/actualSideSelectedV16_70b/);
 assert.match(runner,/\[r\.get\('disposition'\) for r in rows\]!=\['not_pass','awarded'\]/);
 const help=spawnSync('python3',['-B',runnerPath,'--help'],{encoding:'utf8'});
 assert.equal(help.status,0,help.stderr);assert.match(help.stdout,/actual-dpi-side-selected-v16-70b-awarded/);
});
