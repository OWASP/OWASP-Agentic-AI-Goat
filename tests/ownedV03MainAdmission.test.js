'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const admission=require('./postgres/ownedV03MainAdmission');
const source=fs.readFileSync(require.resolve('./postgres/ownedV03MainAdmission'),'utf8');
function reader({readFailure=false,closeFailure=false,changed=false,nlink=1,size=3,linkChanged=false}={}){
 const stat={isFile:()=>true,nlink,size,dev:1,ino:2,mtimeMs:3,ctimeMs:4};let stats=0,closed=0;
 const fd={stat:async()=>({...stat,ino:++stats>1&&changed?5:2,nlink:stats>1&&linkChanged?3:nlink}),read:async bytes=>{if(readFailure)throw Error('primary-read');Buffer.from('abc').copy(bytes);return {bytesRead:3};},
  close:async()=>{closed++;if(closeFailure)throw Error('close');}};
 const mock={realpath:async x=>x,open:async()=>fd};
 const fragment=source.slice(source.indexOf('async function sourceBytes('),source.indexOf('async function verifySources('));
 const read=new Function('fs','native','fail','path','__dirname',fragment+';return sourceBytes;')(mock,{constants:{}},code=>Object.assign(Error(code),{code}),require('node:path'),require('node:path').join(__dirname,'postgres'));
 return {read,closed:()=>closed};
}
test('source reader uses stable observations and closes descriptor',async()=>{
 const f=reader();assert.equal((await f.read('/synthetic',8)).toString(),'abc');assert.equal(f.closed(),1);
});
test('source change denies admission',async()=>{
 const f=reader({changed:true});await assert.rejects(f.read('/synthetic',8),{code:'V03_MAIN_SOURCE_CHANGED'});assert.equal(f.closed(),1);
});
test('only canonical Node permits two stable links and its bounded executable size',async()=>{
 const node=require('node:path').resolve(__dirname,'../tasks/runtime/node/node_modules/node/bin/node');
 assert.equal((await reader({nlink:2}).read(node,1)).toString(),'abc');
 await assert.rejects(reader({nlink:2}).read('/synthetic',8),{code:'V03_MAIN_SOURCE_FILE'});
 await assert.rejects(reader({nlink:3}).read(node,8),{code:'V03_MAIN_SOURCE_FILE'});
 await assert.rejects(reader({nlink:2,linkChanged:true}).read(node,8),{code:'V03_MAIN_SOURCE_CHANGED'});
 await assert.rejects(reader({size:256*1024**2+1}).read(node,8),{code:'V03_MAIN_SOURCE_FILE'});
});
test('source close failure preserves primary and cleanup debt',async()=>{
 const f=reader({readFailure:true,closeFailure:true});await assert.rejects(f.read('/synthetic',8),e=>e.message==='primary-read'&&e.cleanupDebt===true);
});
test('close failure alone cannot return source bytes',async()=>{
 await assert.rejects(reader({closeFailure:true}).read('/synthetic',8),e=>e.cleanupDebt===true);
});
test('JSON owner cannot create inherited admission file',async()=>{
 await assert.rejects(admission.writeAdmission({},'/synthetic',{}, {}, []),{code:'V03_COMBINED_OWNER_REQUIRED'});
});
function template(){
 const root=require('node:path').resolve(__dirname,'..'),run='a'.repeat(32);
 return {root,run,argv:[root+'/tests/postgres/run-secureshop-agent-host-transport-main.py',
  '--v03-private-run-id',run,'--v03-private-plan-sha256','@V03_PLAN_SHA256@',
  '--v03-private-channel-fd','3','--v03-private-admission-fd','4']};
}
test('MAIN template binds one digest without modifying the pre-hash plan',()=>{
 const {root,run,argv}=template(),before=JSON.stringify(argv),digest='b'.repeat(64);
 const result=admission.bindMainArgvTemplate(root,run,digest,argv);
 assert.equal(JSON.stringify(argv),before);assert.equal(result.mainArgv[4],digest);
 assert.equal(result.expectedMainArgvSha256,require('node:crypto').createHash('sha256').update(JSON.stringify(result.mainArgv)).digest('hex'));
 assert.ok(Object.isFrozen(result.mainArgv));
});
test('MAIN template denies duplicate authority flags and misplaced placeholders',()=>{
 const {root,run,argv}=template();
 for(const bad of [[...argv,'--v03-private-channel-fd','3'],[...argv,'@V03_PLAN_SHA256@'],
   argv.map(value=>value==='@V03_PLAN_SHA256@'?'b'.repeat(64):value),[...argv,'prefix@V03_PLAN_SHA256@']])
  assert.throws(()=>admission.bindMainArgvTemplate(root,run,'b'.repeat(64),bad),{code:'V03_MAIN_TEMPLATE'});
});
test('MAIN template cannot change fixed executable, run binding, or descriptor numbers',()=>{
 const {root,run,argv}=template();
 for(const [index,value]of [[0,'/other/main.py'],[2,'c'.repeat(32)],[6,'5'],[8,'6']]){
  const bad=[...argv];bad[index]=value;
  assert.throws(()=>admission.bindMainArgvTemplate(root,run,'b'.repeat(64),bad),{code:'V03_MAIN_TEMPLATE'});
 }
});
test('MAIN template rejects every argparse equals-form authority override',()=>{
 const {root,run,argv}=template();
 for(const flag of ['--v03-private-run-id','--v03-private-plan-sha256',
   '--v03-private-channel-fd','--v03-private-admission-fd'])
  for(const value of ['5',run,''])
   assert.throws(()=>admission.bindMainArgvTemplate(root,run,'b'.repeat(64),[...argv,flag+'='+value]),
    {code:'V03_MAIN_TEMPLATE'});
 const main=fs.readFileSync(require.resolve('./postgres/run-secureshop-agent-host-transport-main.py'),'utf8');
 assert.match(main,/argparse\.ArgumentParser\(allow_abbrev=False\)/);
});
function fullGrammar(){
 const {root,run}=template(),digest='b'.repeat(64),values={};
 for(const key of admission._internals.MAIN_OPTIONS)values[key]=key.endsWith('-sha256')?digest:root+'/tasks/qualification/'+key;
 Object.assign(values,{'main-workspace':root,node:root+'/tasks/runtime/node/node_modules/node/bin/node',docker:root+'/tasks/runtime/container/bin/docker',
  'docker-host':'unix://'+root+'/.qualification/goat-q/docker.sock','docker-daemon':'test-daemon','current-host-profile':'goat-q','image-id':'sha256:'+digest,'evidence-parent':root+'/tasks/qualification',
  cohort:'merchant-listing-image-optimize-v03-browser','v03-native-proof-kind':'current-host-v1','v03-private-run-id':run,'v03-private-plan-sha256':digest,
  'v03-private-channel-fd':'3','v03-private-admission-fd':'4','ollama-model-sha256':'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e',
  'browser-root':'/Applications/Google Chrome.app',browser:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'});
 const argv=[root+'/tests/postgres/run-secureshop-agent-host-transport-main.py',...Object.entries(values).flatMap(([key,value])=>['--'+key,value])];
 const pins=Object.fromEntries(['node','docker'].map(key=>[values[key].slice(root.length+1),digest]));
 const pg={docker:values.docker,host:values['docker-host'],daemonId:values['docker-daemon'],image:values['image-id']};
 return {root,run,digest,argv,pins,pg};
}
test('full original V03 grammar binds cohort, fixed executables, PG and all fresh proof fields',()=>{
 const f=fullGrammar();assert.equal(admission.validateFullMainArgv(f.root,f.run,f.digest,f.argv,f.pins,f.pg).cohort,'merchant-listing-image-optimize-v03-browser');
});
test('full grammar rejects extras, omissions, equals forms, abbreviations and semantic alternatives',()=>{
 const f=fullGrammar(),check=argv=>admission.validateFullMainArgv(f.root,f.run,f.digest,argv,f.pins,f.pg);
 for(const argv of [[...f.argv,'--plan'],f.argv.slice(0,-2),[...f.argv,'--cohort','transport']])assert.throws(()=>check(argv));
 for(const [flag,value]of [['--cohort','transport'],['--v03-native-proof-kind','historical-v1'],['--v03-private-channel-fd','5'],['--current-host-profile','other'],['--evidence-parent','/tmp/out'],['--evidence-parent',f.root+'/tasks/qualification/nested'],['--browser','/other/chrome'],['--ollama-model-sha256','c'.repeat(64)]]){
  const argv=[...f.argv];argv[argv.indexOf(flag)+1]=value;assert.throws(()=>check(argv));
 }
 for(const flag of ['--cohort=transport','--v03-private-run','--unknown']){const argv=[...f.argv];argv[1]=flag;assert.throws(()=>check(argv));}
 assert.throws(()=>admission.validateFullMainArgv(f.root,f.run,f.digest,f.argv,{},f.pg));
 assert.throws(()=>admission.validateFullMainArgv(f.root,f.run,f.digest,f.argv,f.pins,{...f.pg,daemonId:'other'}));
});

test('mandatory browser barrier omission denies before source reads or native startup',async()=>{
 const root=require('node:path').resolve(__dirname,'..');
 const pins=Object.fromEntries(['tests/postgres/ownedV03PrivateExecutors.js','tests/postgres/v03_private_executors.py',
 'tests/postgres/run-secureshop-agent-host-transport-main.py','tests/postgres/darwin_process_inventory.py',
 'tasks/runtime/node/node_modules/node/bin/node'].map(p=>[p,'a'.repeat(64)]));
 await assert.rejects(admission.verifySources(root,pins),{code:'V03_MAIN_SOURCE_SET'});
 const parent=fs.readFileSync(require.resolve('./postgres/ownedV03ParentEntry'),'utf8');
 assert.ok(parent.indexOf('await require(\'./ownedV03MainAdmission\').verifySources(root,admitted.plan.sourcePins)')<parent.indexOf('const producers='));
});
