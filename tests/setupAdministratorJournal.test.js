'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),vm=require('node:vm');
const file=path.resolve(__dirname,'../scripts/lib/setup-administrator-journal.js'),{ensureAdministratorJournal:ensure}=require(file);
function fixture(t){const directory=fs.mkdtempSync(path.join(os.tmpdir(),'setup-admin-journal-'));fs.chmodSync(directory,0o700);t.after(()=>fs.rmSync(directory,{recursive:true,force:true}));return{directory,file:path.join(directory,'administrator.json')};}
function variant(overrides){const module={exports:{}};vm.runInNewContext(fs.readFileSync(file,'utf8'),{module,process,Buffer,require:n=>n==='node:fs'?{...fs,...overrides}:require(n.startsWith('.')?path.resolve(path.dirname(file),n):n)});return module.exports.ensureAdministratorJournal;}
test('fresh training credential persists exactly and existing custom valid bytes are never rotated',t=>{const f=fixture(t),first=ensure(f),bytes=fs.readFileSync(f.file);assert.deepEqual(first,{username:'admin',email:'admin@owasp-ai-goat.local',password:'admin123'});assert.equal(fs.statSync(f.file).mode&0o777,0o600);assert.deepEqual(ensure(f),first);assert(fs.readFileSync(f.file).equals(bytes));const custom={username:'Abhinav',email:'admin@owasp-ai-goat.local',password:'owned synthetic administrator'};const encoded=JSON.stringify(custom,null,4)+'\n';fs.writeFileSync(f.file,encoded);assert.deepEqual(ensure(f),custom);assert.equal(fs.readFileSync(f.file,'utf8'),encoded);});
test('short credential exception admits only the exact approved training journal',t=>{const f=fixture(t);for(const changed of [{username:'instructor'},{email:'other@example.invalid'},{password:'other123'}]){const bytes=JSON.stringify({username:'admin',email:'admin@owasp-ai-goat.local',password:'admin123',...changed});fs.writeFileSync(f.file,bytes,{mode:0o600});assert.throws(()=>ensure(f),{code:'SETUP_ADMINISTRATOR_JOURNAL_INVALID'});assert.equal(fs.readFileSync(f.file,'utf8'),bytes);}});
test('file fsync failure prevents bootstrap callback and retry reuses retained credential',t=>{const f=fixture(t);let bootstrap=0;const broken=variant({fsyncSync:()=>{throw Error('controlled fsync failure');}});assert.throws(()=>{const credentials=broken(f);bootstrap++;return credentials;},{code:'SETUP_ADMINISTRATOR_JOURNAL_INVALID'});assert.equal(bootstrap,0);const bytes=fs.readFileSync(f.file),expected=JSON.parse(bytes);assert.deepEqual(ensure(f),expected);assert(fs.readFileSync(f.file).equals(bytes));});
test('directory fsync failure on existing journal prevents return without rotating bytes',t=>{const f=fixture(t);ensure(f);const bytes=fs.readFileSync(f.file),order=[];const broken=variant({fsyncSync:fd=>{const dir=fs.fstatSync(fd).isDirectory();order.push(dir?'directory':'file');if(dir)throw Error('directory flush failed');fs.fsyncSync(fd);}});assert.throws(()=>broken(f),{code:'SETUP_ADMINISTRATOR_JOURNAL_INVALID'});assert.deepEqual(order,['file','directory']);assert(fs.readFileSync(f.file).equals(bytes));});
test('malformed, mode, symlink, hardlink and owner conflicts refuse without replacement',t=>{const f=fixture(t);fs.writeFileSync(f.file,'partial',{mode:0o600});assert.throws(()=>ensure(f),{code:'SETUP_ADMINISTRATOR_JOURNAL_INVALID'});assert.equal(fs.readFileSync(f.file,'utf8'),'partial');fs.unlinkSync(f.file);ensure(f);const bytes=fs.readFileSync(f.file);fs.chmodSync(f.file,0o644);assert.throws(()=>ensure(f));fs.chmodSync(f.file,0o600);fs.renameSync(f.file,f.file+'.retained');fs.symlinkSync(f.file+'.retained',f.file);assert.throws(()=>ensure(f));fs.unlinkSync(f.file);fs.linkSync(f.file+'.retained',f.file);assert.throws(()=>ensure(f));fs.unlinkSync(f.file);fs.renameSync(f.file+'.retained',f.file);const wrong=variant({fstatSync:fd=>{const s=fs.fstatSync(fd);return Object.assign(Object.create(s),{uid:s.uid+1});}});assert.throws(()=>wrong(f));assert(fs.readFileSync(f.file).equals(bytes));});
test('only fresh integration opts into the training profile after durable journal admission and initializer',()=>{const s=fs.readFileSync(path.resolve(__dirname,'../scripts/setup-application.js'),'utf8'),fresh=s.indexOf("if (request.kind !== 'fresh')"),admit=s.indexOf('ensureAdministratorJournal({ directory })'),init=s.indexOf('await initializeApplication({ maintenanceScope })',admit),bootstrap=s.indexOf('bootstrapAdmin({ pool, ...administrator, initialTrainingProfile: true })',init);assert(fresh>0&&fresh<admit&&admit<init&&init<bootstrap);assert.equal((s.match(/bootstrapAdmin\(/g)||[]).length,1);assert(s.includes("await fs.writeFile(filename, content, { flag: 'wx', mode: 0o600 })"));const b=fs.readFileSync(path.resolve(__dirname,'../db/postgres/bootstrap-admin.js'),'utf8');assert(b.includes('BOOTSTRAP_ADMIN_CREDENTIAL_MISMATCH'));});

function windowsFixture(initial){
 const directory='C:\\Users\\Learner\\.owasp-ai-goat\\owned',file=directory+'\\administrator.json',calls=[];
 let bytes=initial,unsafe=false;
 const privateState={
  inspectPrivateDirectory(p){assert.equal(p,directory);calls.push('inspect');},
  createPrivateFile(p,value){assert.equal(p,file);calls.push('create');if(bytes!==undefined)throw Error('CREATE_NEW conflict');bytes=Buffer.from(value);},
  readPrivateFile(p){assert.equal(p,file);calls.push('read');if(unsafe||bytes===undefined)throw Error('native read denied');return Buffer.from(bytes);},
 };
 return {calls,options:{directory,platform:'win32',privateState,exists:p=>{assert.equal(p,file);calls.push('exists');return bytes!==undefined;}},get bytes(){return bytes;},set bytes(value){bytes=value;},set unsafe(value){unsafe=value;}};
}
const training={username:'admin',email:'admin@owasp-ai-goat.local',password:'admin123'};

test('controlled Windows missing journal uses create-new, safe reread and exact training defaults',()=>{
 const f=windowsFixture(),value=ensure(f.options);
 assert.deepEqual(value,training);assert.equal(Object.isFrozen(value),true);
 assert.equal(f.bytes.toString(),JSON.stringify(training,null,2)+'\n');
 assert.deepEqual(f.calls,['inspect','exists','create','read','inspect']);
 const bytes=Buffer.from(f.bytes);assert.deepEqual(ensure(f.options),training);assert(f.bytes.equals(bytes));
 assert.equal(f.calls.filter(v=>v==='create').length,1);
});
test('controlled Windows preserves valid old custom journal bytes without any reset',()=>{
 const custom={username:'instructor',email:'owner@example.invalid',password:'older valid synthetic credential'},bytes=Buffer.from(JSON.stringify(custom,null,4)+'\n'),f=windowsFixture(bytes);
 assert.deepEqual(ensure(f.options),custom);assert(f.bytes.equals(bytes));
 assert.deepEqual(f.calls,['inspect','exists','read','inspect']);
});
test('controlled Windows unsafe existing reads never fall back to creation',()=>{
 const bytes=Buffer.from(JSON.stringify(training)),f=windowsFixture(bytes);f.unsafe=true;
 assert.throws(()=>ensure(f.options),{code:'SETUP_ADMINISTRATOR_JOURNAL_INVALID'});
 assert.deepEqual(f.calls,['inspect','exists','read']);assert(f.bytes.equals(bytes));
});
test('controlled Windows malformed and credential conflicts preserve bytes and refuse return',()=>{
 for(const bytes of [Buffer.from('partial'),Buffer.alloc(4097,32),
  ...[{username:'instructor'},{email:'other@example.invalid'},{password:'other123'},{unexpected:true}].map(change=>Buffer.from(JSON.stringify({...training,...change})))]){
  const f=windowsFixture(bytes);assert.throws(()=>ensure(f.options),{code:'SETUP_ADMINISTRATOR_JOURNAL_INVALID'});
  assert(f.bytes.equals(bytes));assert.equal(f.calls.includes('create'),false);
 }
});
test('controlled Windows advisory absence race cannot replace an existing journal',()=>{
 const bytes=Buffer.from(JSON.stringify({username:'instructor',email:'owner@example.invalid',password:'race retained credential'})),f=windowsFixture(bytes);
 f.options.exists=()=>false;
 assert.throws(()=>ensure(f.options),{code:'SETUP_ADMINISTRATOR_JOURNAL_INVALID'});
 assert(f.bytes.equals(bytes));assert.deepEqual(f.calls,['inspect','create']);
});
test('controlled Windows native create, reread and parent inspection failures prevent credential return',()=>{
 for(const stage of ['first-parent','create','read','last-parent']){
  const f=windowsFixture();let inspections=0;
  for(const method of ['inspectPrivateDirectory','createPrivateFile','readPrivateFile']){
   const original=f.options.privateState[method];f.options.privateState[method]=(...args)=>{
    if(method==='inspectPrivateDirectory')inspections++;
    if((stage==='first-parent'&&inspections===1&&method==='inspectPrivateDirectory')||(stage==='last-parent'&&inspections===2&&method==='inspectPrivateDirectory')||(stage==='create'&&method==='createPrivateFile')||(stage==='read'&&method==='readPrivateFile'))throw Error('private native request bytes');
    return original(...args);
   };
  }
  let bootstrap=0;assert.throws(()=>{ensure(f.options);bootstrap++;},error=>{assert.equal(error.code,'SETUP_ADMINISTRATOR_JOURNAL_INVALID');assert.doesNotMatch(error.message,/private native request/);assert.equal(error.cause,undefined);return true;});assert.equal(bootstrap,0);
  if(stage==='read'||stage==='last-parent'){const bytes=Buffer.from(f.bytes);const restored=windowsFixture(bytes);assert.deepEqual(ensure(restored.options),training);assert(restored.bytes.equals(bytes));assert.equal(restored.calls.includes('create'),false);}
 }
});
test('controlled Windows invalid parent namespace is denied before helper execution',()=>{
 for(const directory of ['\\\\host\\share\\private','C:\\Private\\..\\owned','C:\\Private\\NUL','C:\\Private\\owned:stream','C:\\']){
  const f=windowsFixture();assert.throws(()=>ensure({...f.options,directory}),{code:'SETUP_ADMINISTRATOR_JOURNAL_INVALID'});assert.deepEqual(f.calls,[]);
 }
});

test('pure retained-byte administrator parser admits only canonical training exception without filesystem work',()=>{
 const {validateAdministratorJournal}=require('../scripts/lib/setup-administrator-journal'),approved={username:'admin',email:'admin@owasp-ai-goat.local',password:'admin123'},bytes=Buffer.from(JSON.stringify(approved));
 const result=validateAdministratorJournal(bytes);assert.deepEqual(result,approved);assert(Object.isFrozen(result));assert.equal(bytes.toString(),JSON.stringify(approved));
 for(const patch of [{username:'instructor'},{email:'other@example.test'},{password:'other123'},{extra:true}])assert.throws(()=>validateAdministratorJournal(Buffer.from(JSON.stringify({...approved,...patch}))),{code:'SETUP_ADMINISTRATOR_JOURNAL_INVALID'});
});
