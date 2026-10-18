'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),{createHash}=require('node:crypto');
const plan=require('../db/postgres/provision-application').provisioningPlan();
const source=require.resolve('../scripts/lib/application-maintenance-plan-configuration');
function harness(){
 const root='C:\\workspace',homeDirectory='C:\\Users\\learner',id=createHash('sha256').update(root).digest('hex').slice(0,12),directory=path.win32.join(homeDirectory,'.dvaia',id),calls=[],files=new Map(),denied=new Set(),metadata=new Map();
 const text=plan.flatMap(r=>[r.runtimeVariable,r.migrationVariable]).map(k=>`${k}=postgresql://role:private@localhost/database`).join('\n');
 files.set(path.win32.join(directory,'provisioning.json'),Buffer.from('{}'));
 files.set(path.win32.join(root,'.env'),Buffer.from(text));
 files.set(path.win32.join(directory,'local-postgres.json'),Buffer.from(JSON.stringify({version:1,id,name:`dvaia-postgres-${id}`,port:15432,password:'a'.repeat(64)})));
 const error=code=>Object.assign(Error('private secret diagnostic'),{code});
 const read=(operation,file)=>{calls.push([operation,file]);if(denied.has(file)||!files.has(file))throw error('WINDOWS_PRIVATE_STATE_DENIED');return files.get(file);};
 const native={inspectPrivateDirectory(file){calls.push(['inspect',file]);if(denied.has(file))throw error('WINDOWS_PRIVATE_STATE_DENIED');assert.equal(file,directory);return{path:file,size:null,identity:{volumeSerial:1,fileId:'0000000000000001'}};},readPrivateFile:file=>read('private',file),readPrivateWorkspaceFile:file=>read('workspace',file)};
 const fakeFs=new Proxy({realpathSync:value=>value,lstatSync(file){calls.push(['existence',file]);if(metadata.has(file))throw error(metadata.get(file));if(!files.has(file))throw error('ENOENT');return {}; }},{get(target,key){if(key in target)return target[key];return()=>{throw Error('Raw filesystem operation forbidden: '+String(key));};}});
 const module={exports:{}};const mocks={'node:fs':fakeFs,'node:path':path.win32,'node:os':{homedir:()=>homeDirectory},'./windows-private-state':native,'../../db/postgres/provision-application':{provisioningPlan:()=>plan},'dotenv':require('dotenv'),'./setup-local-postgres-state':require('../scripts/lib/setup-local-postgres-state')};
 vm.runInNewContext(fs.readFileSync(source,'utf8'),{require:name=>mocks[name]||require(name),module,exports:module.exports,process:{platform:'win32'},__dirname:path.win32.join(root,'scripts','lib'),Buffer,Set,Object,JSON},{filename:source});
 return{load:module.exports.loadMaintenancePlanConfiguration,root,homeDirectory,directory,files,denied,metadata,calls,text,options:{root,homeDirectory}};
}
const failure={code:'MAINTENANCE_PLAN_CONFIGURATION_UNAVAILABLE'};
test('Windows maintenance uses workspace leaf admission only for .env and strict private journal reads',()=>{
 const h=harness(),r=h.load(h.options);assert(Object.isFrozen(r));assert(Object.isFrozen(r.environment));assert.equal(Object.keys(r.environment).length,33);assert.match(r.environment.PG_ADMIN_DATABASE_URL,/@127.0.0.1:15432\/postgres$/);
 assert.deepEqual(h.calls.filter(c=>c[0]==='workspace'),[['workspace',path.win32.join(h.root,'.env')]]);
 assert.deepEqual(h.calls.filter(c=>c[0]==='private').map(c=>path.win32.basename(c[1])),['provisioning.json','local-postgres.json','ctf-delivery.json']);
 assert.equal(h.calls[0][0],'inspect');
});
test('Windows optional journal absence requires fresh exact ENOENT; explicit admin is still required',()=>{
 const h=harness();h.files.delete(path.win32.join(h.directory,'local-postgres.json'));
 assert.throws(()=>h.load(h.options),failure);const r=h.load({...h.options,adminUrl:'postgresql://operator:private@localhost/postgres'});assert.equal(r.deliveryManifestPath,undefined);
 assert(h.calls.some(c=>c[0]==='existence'&&c[1].endsWith('local-postgres.json')));
});
test('Windows present native denial or inaccessible optional metadata is never absence or raw-read fallback',()=>{
 for(const kind of ['present','inaccessible'])for(const name of ['local-postgres.json','ctf-delivery.json']){
  const h=harness(),file=path.win32.join(h.directory,name);h.files.set(file,Buffer.from('{}'));h.denied.add(file);if(kind==='inaccessible')h.metadata.set(file,'EACCES');
  assert.throws(()=>h.load({...h.options,adminUrl:'postgresql://operator:private@localhost/postgres'}),e=>e.code===failure.code&&!e.message.includes('secret'));
 }
});
test('Windows native directory/env/required manifest denial fails closed without POSIX uid/mode reads',()=>{
 for(const name of ['directory','env','manifest']){const h=harness(),file=name==='directory'?h.directory:name==='env'?path.win32.join(h.root,'.env'):path.win32.join(h.directory,'provisioning.json');h.denied.add(file);assert.throws(()=>h.load(h.options),failure);}
});
test('Windows duplicate/missing pairs and malformed local journal preserve existing validation and redaction',()=>{
 for(const kind of ['duplicate','missing','local','manifest','oversize']){
  const h=harness();if(kind==='local')h.files.set(path.win32.join(h.directory,'local-postgres.json'),Buffer.from('{}'));
  else if(kind==='manifest')h.files.set(path.win32.join(h.directory,'provisioning.json'),Buffer.from('secret'));
  else h.files.set(path.win32.join(h.root,'.env'),Buffer.from(kind==='duplicate'?h.text+'\nIDENTITY_DATABASE_URL: secret':kind==='oversize'?'x'.repeat(1048577):'IDENTITY_DATABASE_URL=secret'));
  assert.throws(()=>h.load({...h.options,adminUrl:'postgresql://operator:private@localhost/postgres'}),e=>e.code===failure.code&&!e.message.includes('secret'));
 }
});
test('Windows delivery config requires paired environment variable and strict private manifest',()=>{
 for(const kind of ['complete','env-only','manifest-only']){
  const h=harness();if(kind!=='manifest-only')h.files.set(path.win32.join(h.root,'.env'),Buffer.from(h.text+'\nCTF_DELIVERY_DATABASE_URL=postgresql://delivery:private@localhost/ctf'));
  if(kind!=='env-only')h.files.set(path.win32.join(h.directory,'ctf-delivery.json'),Buffer.from('{}'));
  if(kind==='complete')assert.equal(h.load(h.options).deliveryManifestPath,path.win32.join(h.directory,'ctf-delivery.json'));else assert.throws(()=>h.load(h.options),failure);
 }
});
