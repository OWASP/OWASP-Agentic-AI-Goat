'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {createUpgradeStateInspector}=require('../scripts/application-upgrade');
const envPath='C:\\Workspaces\\app\\.env',manifestPath='C:\\Users\\Synthetic\\private\\provisioning.json';
const plan=[{schema:'identity',runtimeVariable:'IDENTITY_DATABASE_URL',migrationVariable:'IDENTITY_MIGRATION_DATABASE_URL'}];
const configuration={IDENTITY_DATABASE_URL:'postgresql://synthetic-runtime.invalid/db',IDENTITY_MIGRATION_DATABASE_URL:'postgresql://synthetic-migration.invalid/db'};
function fixture(){
 const calls=[],files=new Map([[envPath,Buffer.from(Object.entries(configuration).map(([key,value])=>key+'='+value).join('\n')+'\nPRIVATE_SETTING=preserved\n')],[manifestPath,Buffer.from(JSON.stringify({version:1,status:'complete',plan,configuration}))]]);
 const denied=new Set();let pending=false,statFailure=false;
 const read=(operation,file)=>{calls.push([operation,file]);if(denied.has(file))throw Object.assign(Error('SECRET detail'),{code:'ENOENT',stdout:'SECRET',stderr:'SECRET'});return files.get(file);};
 const privateState={readPrivateWorkspaceFile:file=>read('workspace',file),readPrivateFile:file=>read('private',file),createPrivateFile(){throw Error('Mutation forbidden');}};
 const fileSystem={async lstat(file){assert.equal(file,envPath+'.upgrade');if(statFailure)throw Object.assign(Error('SECRET directory failure'),{code:'EACCES'});if(pending)return{};throw Object.assign(Error('Absent'),{code:'ENOENT'});}};
 return{files,calls,denied,inspect:createUpgradeStateInspector({platform:'win32',privateState,fileSystem}).inspectUpgradeState,pending(){pending=true;},denyStat(){statFailure=true;}};
}
const options={envPath,manifestPath,currentPlan:plan};
// Controlled adapters demonstrate operation selection and fail-closed policy;
// they are not evidence of native NTFS/ACL qualification.
test('Windows upgrade reads workspace env and private manifest through their distinct native authorities',async()=>{
 const f=fixture(),before=Buffer.from(f.files.get(envPath));const state=await f.inspect(options);
 assert.deepEqual(f.calls,[['workspace',envPath],['private',manifestPath]]);
 assert.deepEqual(state.envBytes,before);assert.equal(state.parsed.PRIVATE_SETTING,'preserved');assert.deepEqual(state.manifest.configuration,configuration);assert.equal(state.pendingPath,envPath+'.upgrade');assert.deepEqual(f.files.get(envPath),before);
});
test('Windows denied reads are scrubbed invalid-state errors and cannot become missing-file repair',async()=>{
 for(const file of [envPath,manifestPath]){
  const f=fixture();f.denied.add(file);await assert.rejects(f.inspect(options),error=>error.code==='UPGRADE_PRIVATE_STATE_INVALID'&&error.message==='UPGRADE_PRIVATE_STATE_INVALID'&&!error.cause&&!JSON.stringify(error).includes('SECRET'));
  assert.equal(f.files.size,2);assert.equal(f.calls.filter(([operation])=>operation==='workspace').length,1);
 }
});
test('Windows interrupted publication or inaccessible staging stops before native content read',async()=>{
 for(const [configure,code]of [['pending','UPGRADE_ENV_RECOVERY_REQUIRED'],['denyStat','UPGRADE_PRIVATE_STATE_INVALID']]){
  const f=fixture();f[configure]();await assert.rejects(f.inspect(options),{code});assert.deepEqual(f.calls,[]);
 }
});
test('Windows native read still rejects malformed or oversized buffers and invalid manifests',async()=>{
 for(const bytes of [Buffer.from('invalid'),Buffer.from(JSON.stringify({version:2,status:'complete',plan,configuration})),Buffer.from(JSON.stringify({version:1,status:'pending',plan,configuration})),Buffer.from(JSON.stringify({version:1,status:'complete',plan:[null],configuration})),Buffer.alloc(1024*1024+1),undefined]){
  const f=fixture();f.files.set(manifestPath,bytes);await assert.rejects(f.inspect(options),{code:'UPGRADE_PRIVATE_STATE_INVALID'});
 }
});
test('Windows upgrade retains duplicate variable, pair and manifest consistency admission',async()=>{
 for(const [source,code]of [[f=>f.files.get(envPath).toString()+`IDENTITY_DATABASE_URL=${configuration.IDENTITY_DATABASE_URL}\n`,'UPGRADE_ENV_CONFLICT'],[()=>`IDENTITY_DATABASE_URL=${configuration.IDENTITY_DATABASE_URL}\n`,'UPGRADE_ENV_MANIFEST_MISMATCH'],[()=>`IDENTITY_DATABASE_URL=postgresql://other.invalid/db\nIDENTITY_MIGRATION_DATABASE_URL=${configuration.IDENTITY_MIGRATION_DATABASE_URL}\n`,'UPGRADE_ENV_MANIFEST_MISMATCH']]){
  const f=fixture();f.files.set(envPath,Buffer.from(source(f)));await assert.rejects(f.inspect(options),{code});
 }
});
