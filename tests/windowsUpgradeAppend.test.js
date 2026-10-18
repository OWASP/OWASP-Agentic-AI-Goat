'use strict';
// Controlled consumer tests. Native NTFS/ACL and maintenance-lease
// qualification remain separate from these publication contract checks.
const {test}=require('node:test'),assert=require('node:assert/strict'),{createHash}=require('node:crypto');
const {createEnvironmentAppender}=require('../scripts/application-upgrade');
const {createSetupUpgradeEnvironmentAppender}=require('../scripts/setup-application');
const {prepareAdditiveEnvironmentPublication}=require('../scripts/lib/setup-additive-environment-publication');
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const root='C:\\workspace',directory='C:\\Users\\Synthetic\\private',id=hash(root).slice(0,12),envPath=root+'\\.env',pendingPath=envPath+'.upgrade';
const originalBytes=Buffer.from('PRIVATE_SETTING="preserved"'),encodedAdditions='NEW_DATABASE_URL="postgresql://synthetic.invalid/db"\n';
function fixture(){
 const files=new Map([[envPath,Buffer.from(originalBytes)]]),intents=new Map(),calls=[];let deny=false,replaceBeforePublish=false;
 const native={inspectPrivateDirectory:p=>{assert.equal(p,directory);if(deny)throw Error('SECRET ACL detail');},readPrivateWorkspaceFile:p=>{calls.push(['readWorkspace',p]);if(deny||!files.has(p))throw Error('SECRET read detail');return Buffer.from(files.get(p));},readPrivateFile:p=>{if(deny||!files.has(p))throw Error('SECRET private detail');return Buffer.from(files.get(p));}};
 const receipt=intent=>({state:intent.committed?'committed':'prepared',intentSha256:hash(Buffer.from(intent.binding.intentPath)),size:intent.result.length,identity:{volumeSerial:1,fileId:'0000000000000001'}});
 const publication={preparePrivatePublication:options=>{
  calls.push(['prepare',options]);let intent=intents.get(options.intentPath);
  if(intent){assert.deepEqual(options.originalBytes,intent.original);assert.deepEqual(options.resultBytes,intent.result);}
  else{const current=files.get(options.targetPath);if(options.originalBytes===null?current:!current?.equals(options.originalBytes))throw Error('SECRET unexpected target');intent={binding:options,original:options.originalBytes===null?null:Buffer.from(options.originalBytes),result:Buffer.from(options.resultBytes),committed:false};intents.set(options.intentPath,intent);}
  return receipt(intent);
 },inspectPrivatePublication:binding=>{const intent=intents.get(binding.intentPath);if(!intent)throw Error('missing intent');return receipt(intent);},publishPrivatePublication:binding=>{
  calls.push(['publish',binding]);if(replaceBeforePublish&&binding.targetPath===envPath)files.set(envPath,Buffer.from('operator changed bytes'));const intent=intents.get(binding.intentPath),current=files.get(binding.targetPath);
  if(!intent||(!intent.committed&&(intent.original===null?current:!current?.equals(intent.original)))||(intent.committed&&!current?.equals(intent.result)))throw Error('SECRET changed target');
  files.set(binding.targetPath,Buffer.from(intent.result));intent.committed=true;return receipt(intent);
 }};
 const dependencies={platform:'win32',privateState:native,publication,realpath:p=>p,exists:p=>files.has(p)};
 const append=createEnvironmentAppender({platform:'win32',preparePublication:options=>prepareAdditiveEnvironmentPublication(options,undefined,dependencies)}).appendPrivateEnvironment;
 const caller=createSetupUpgradeEnvironmentAppender({root,directory,id},{filesystemPlatform:'win32',append,privateState:native,fileSystem:{readFile(){throw Error('Raw read forbidden');}}});
 return{files,intents,calls,caller,append,deny(){deny=true;},replaceBeforePublish(){replaceBeforePublish=true;}};
}
const args={purpose:'database-pairs',envPath,pendingPath,originalBytes,encodedAdditions};
test('Windows upgrade caller binds explicit private context and retains original/journal across retry',async()=>{
 const f=fixture();await f.caller.append(args);const result=Buffer.concat([originalBytes,Buffer.from('\n'+encodedAdditions)]);assert.deepEqual(f.files.get(envPath),result);
 const journal=[...f.files.keys()].find(p=>p.startsWith(directory+'\\additive-environment-'));assert(journal);const doc=JSON.parse(f.files.get(journal));assert.equal(doc.root,root);assert.equal(doc.directory,directory);assert.equal(doc.id,id);assert.equal(doc.original,originalBytes.toString('base64'));
 const retained=f.files.get(journal),count=f.intents.size;await f.caller.append(args);assert.equal(f.intents.size,count);assert.deepEqual(f.files.get(journal),retained);assert.deepEqual(f.files.get(envPath),result);
});
test('Windows setup uses native workspace reread and distinct IDs for its two append purposes',async()=>{
 const f=fixture();await f.caller.append(args);const current=await f.caller.readOriginalBytes(envPath);assert.deepEqual(current,f.files.get(envPath));
 await f.caller.append({...args,purpose:'password-reset-key',originalBytes:current,encodedAdditions:'SS_PASSWORD_RESET_KEY_PATH="C:\\Synthetic\\key.json"\n'});
 const docs=[...f.files].filter(([p])=>p.endsWith('.json')).map(([,bytes])=>JSON.parse(bytes));assert.equal(docs.length,2);assert.notEqual(docs[0].operationId,docs[1].operationId);assert.equal(docs[1].original,current.toString('base64'));assert(f.calls.some(([op,p])=>op==='readWorkspace'&&p===envPath));
});
test('Windows changed original or additions selects a different binding and cannot overwrite unexpected bytes',async()=>{
 for(const change of [{originalBytes:Buffer.from('different original')},{encodedAdditions:'OTHER="changed"\n'}]){
  const f=fixture();await f.caller.append(args);const before=Buffer.from(f.files.get(envPath)),retained=f.intents.size;
  await assert.rejects(f.caller.append({...args,...change}),{code:'UPGRADE_PRIVATE_STATE_INVALID'});assert.deepEqual(f.files.get(envPath),before);assert.equal(f.intents.size,retained);
 }
});
test('Windows caller rejects missing/mismatched explicit context and legacy path before publication',async()=>{
 const f=fixture();for(const options of [{},{publicationContext:{root,directory,id,operationId:'11111111-1111-4111-a111-111111111111'},envPath:'C:\\other\\.env'},{publicationContext:{root,directory,id,operationId:'11111111-1111-4111-a111-111111111111'},pendingPath:envPath+'.other'}]){
  await assert.rejects(f.append({...args,...options}),{code:'UPGRADE_PRIVATE_STATE_INVALID'});
 }assert.equal(f.intents.size,0);assert.deepEqual(f.files.get(envPath),originalBytes);
});
test('Windows unexpected bytes after preparation retain private journals and refuse publication',async()=>{
 const f=fixture();f.replaceBeforePublish();await assert.rejects(f.caller.append(args),{code:'UPGRADE_PRIVATE_STATE_INVALID'});
 assert.equal(f.files.get(envPath).toString(),'operator changed bytes');assert.equal(f.intents.size,2);
 const doc=JSON.parse([...f.files].find(([p])=>p.endsWith('.json'))[1]);assert.equal(doc.original,originalBytes.toString('base64'));
});
test('Windows private read/publication denials are scrubbed without replacement',async()=>{
 const f=fixture();f.deny();await assert.rejects(f.caller.readOriginalBytes(envPath),e=>e.code==='UPGRADE_PRIVATE_STATE_INVALID'&&!String(e.stack).includes('SECRET'));
 await assert.rejects(f.caller.append(args),e=>e.code==='UPGRADE_PRIVATE_STATE_INVALID'&&!String(e.stack).includes('SECRET'));assert.equal(f.intents.size,0);assert.deepEqual(f.files.get(envPath),originalBytes);
});
test('POSIX setup caller retains original append arguments and ordinary reread',async()=>{
 const calls=[],bytes=Buffer.from('posix original');const caller=createSetupUpgradeEnvironmentAppender({root:'/workspace',directory:'/private',id:'synthetic'},{filesystemPlatform:'darwin',append:options=>calls.push(options),fileSystem:{readFile:p=>{assert.equal(p,'/workspace/.env');return bytes;}},privateState:new Proxy({},{get(){throw Error('Native Windows forbidden');}})});
 await caller.append({...args,envPath:'/workspace/.env',pendingPath:'/workspace/.env.upgrade'});assert.deepEqual(calls,[{envPath:'/workspace/.env',pendingPath:'/workspace/.env.upgrade',originalBytes,encodedAdditions}]);assert.equal(await caller.readOriginalBytes('/workspace/.env'),bytes);
});
