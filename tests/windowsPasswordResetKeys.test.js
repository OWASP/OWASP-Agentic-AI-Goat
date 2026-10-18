'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {createWindowsPrivateState}=require('../scripts/lib/windows-private-state');
const {createPasswordResetKeyLoader}=require('../server/services/secureshopPasswordResetKeys');
const {createPasswordResetKeySetup}=require('../scripts/lib/setup-password-reset-key');
const directory='C:\\Users\\Synthetic\\private',filePath=directory+'\\secureshop-reset-key.json';
const valid=()=>Buffer.from(JSON.stringify({version:1,activeKeyId:'active',keys:{active:Buffer.alloc(32,7).toString('base64url')}}));
// These bounded fake helper responses exercise caller dispatch and failure
// policy; only Windows qualification proves native ACL/handle behavior.
function fixture(){
 const calls=[],files=new Map();let denyDirectory=false,denyRead=false,failCreate=false,removeOnReadDeny=false;
 const privateState=createWindowsPrivateState({platform:'win32',systemRoot:'C:\\Windows',execute(executable,args,options){
  const request=JSON.parse(options.input);calls.push(request.operation);
  assert.equal(executable,'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
  const directoryOperation=request.operation==='inspectPrivateDirectory';
  if(request.operation==='readPrivateFile'&&denyRead&&removeOnReadDeny)files.delete(request.path);
  if(directoryOperation&&denyDirectory||request.operation==='readPrivateFile'&&(denyRead||!files.has(request.path)))throw Error('private helper diagnostics must not escape');
  if(request.operation==='createPrivateFile'){
   if(files.has(request.path))throw Error('Existing file');
   if(failCreate){files.set(request.path,Buffer.from('partial'));throw Error('Partial creation');}
   files.set(request.path,Buffer.from(request.bytesBase64,'base64'));
  }
  const bytes=files.get(request.path);
  return JSON.stringify({version:1,ok:true,operation:request.operation,path:request.path,size:directoryOperation?null:bytes.length,
   identity:{volumeSerial:1,fileId:'0000000000000001'},...(request.operation==='readPrivateFile'?{bytesBase64:bytes.toString('base64')}:{})});
 }});
 const fileSystem={lstatSync(file){if(files.has(file))return{};throw Object.assign(Error('Missing'),{code:'ENOENT'});}};
 return{files,calls,loader:createPasswordResetKeyLoader({platform:'win32',privateState}),setup:createPasswordResetKeySetup({platform:'win32',privateState,fileSystem}),denyParent(){denyDirectory=true;},denyFile(remove=false){denyRead=true;removeOnReadDeny=remove;},partialCreate(){failCreate=true;}};
}
test('Windows native private read retains strict key decoding without POSIX uid admission',()=>{
 const f=fixture();f.files.set(filePath,valid());const result=f.loader.loadPasswordResetKeys({filePath});
 assert.equal(result.activeKeyId,'active');assert.deepEqual(result.keys.get('active'),Buffer.alloc(32,7));
 assert.deepEqual(f.calls,['inspectPrivateDirectory','readPrivateFile']);
});
test('Windows explicit setup creates only absent keys through exclusive private native creation',()=>{
 const f=fixture();assert.deepEqual(f.setup.ensurePasswordResetKey({directory}),{filePath,created:true});
 const bytes=Buffer.from(f.files.get(filePath));assert.equal(f.loader.loadPasswordResetKeys({filePath}).keys.size,1);
 assert.deepEqual(f.setup.ensurePasswordResetKey({directory}),{filePath,created:false});assert.deepEqual(f.files.get(filePath),bytes);
 assert.equal(f.calls.filter(operation=>operation==='createPrivateFile').length,1);
});
test('Windows denied ACLs and malformed or oversized keys cannot trigger rotation',()=>{
 for(const kind of ['parent','file','malformed','size','material','unknown','active']){
  const f=fixture();let bytes=valid();
  if(kind==='malformed')bytes=Buffer.from('not JSON');
  if(kind==='size')bytes=Buffer.alloc(4097,32);
  if(kind==='material')bytes=Buffer.from(JSON.stringify({version:1,activeKeyId:'active',keys:{active:'bad'}}));
  if(kind==='unknown')bytes=Buffer.from(JSON.stringify({...JSON.parse(valid()),unknown:true}));
  if(kind==='active')bytes=Buffer.from(JSON.stringify({...JSON.parse(valid()),activeKeyId:'absent'}));
  f.files.set(filePath,bytes);if(kind==='parent')f.denyParent();if(kind==='file')f.denyFile();
  assert.throws(()=>f.setup.ensurePasswordResetKey({directory}),{code:'PASSWORD_RESET_KEY_UNAVAILABLE'});
  assert.deepEqual(f.files.get(filePath),bytes);assert.equal(f.calls.includes('createPrivateFile'),false);
 }
});
test('Windows native creation failure retains a partial key and later setup never replaces it',()=>{
 const f=fixture();f.partialCreate();assert.throws(()=>f.setup.ensurePasswordResetKey({directory}),{code:'WINDOWS_PRIVATE_STATE_DENIED'});
 assert.equal(f.files.get(filePath).toString(),'partial');
 assert.throws(()=>f.setup.ensurePasswordResetKey({directory}),{code:'PASSWORD_RESET_KEY_UNAVAILABLE'});
 assert.equal(f.calls.filter(operation=>operation==='createPrivateFile').length,1);
});
test('Windows runtime never creates a missing key and all helper diagnostics are sanitized',()=>{
 const f=fixture();assert.throws(()=>f.loader.loadPasswordResetKeys({filePath}),error=>error.code==='PASSWORD_RESET_KEY_UNAVAILABLE'&&!error.cause&&error.message==='Private password reset key unavailable');
 assert.equal(f.files.size,0);assert.equal(f.calls.includes('createPrivateFile'),false);
});

test('Windows a denied named key disappearing during read never triggers replacement creation',()=>{
 const f=fixture();f.files.set(filePath,valid());f.denyFile(true);
 assert.throws(()=>f.setup.ensurePasswordResetKey({directory}),{code:'PASSWORD_RESET_KEY_UNAVAILABLE'});
 assert.equal(f.files.has(filePath),false);assert.equal(f.calls.includes('createPrivateFile'),false);
});
