'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {admitParentBrowser}=require('./fixtures/secureshopEnabledSystemRebuildBrowser');
test('System browser admission binds parent receipt and rejects unbound or altered capabilities',()=>{
 const outer=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'system-browser-admission-'))),root=path.join(outer,'runtime');fs.mkdirSync(root,{mode:0o700});
 const profile=path.join(root,'system-rebuild-browser');fs.mkdirSync(profile,{mode:0o700});const executable=path.join(outer,'synthetic-browser');fs.writeFileSync(executable,'controlled executable bytes');const file=path.join(outer,'browser.json'),hash=b=>crypto.createHash('sha256').update(b).digest('hex');
 const value={version:1,sourceRoot:fs.realpathSync(path.resolve(__dirname,'..')),runtimeRoot:root,endpoint:'ws://127.0.0.1:32123/devtools/browser/01234567-89ab-cdef-0123-456789abcdef',executable,executableSha256:hash(fs.readFileSync(executable)),profile,processIdentity:{pid:12345,pgid:12344,uid:process.getuid(),start:'controlled identity; no real process'}};
 const write=v=>{const bytes=JSON.stringify(v);fs.writeFileSync(file,bytes,{mode:0o600});return {SS_SYSTEM_BROWSER_ADMISSION:file,SS_SYSTEM_BROWSER_ADMISSION_SHA256:hash(bytes)};};
 try{
  assert.deepEqual(admitParentBrowser(root,write(value)),value);
  assert.throws(()=>admitParentBrowser(root,{SS_SYSTEM_BROWSER_ENDPOINT:value.endpoint}));
  const env=write(value);fs.appendFileSync(file,' ');assert.throws(()=>admitParentBrowser(root,env));
  for(const patch of [{endpoint:value.endpoint.replace('127.0.0.1','example.invalid')},{runtimeRoot:outer},{profile:outer},{executableSha256:'0'.repeat(64)},{processIdentity:{...value.processIdentity,uid:process.getuid()+1}},{processIdentity:{...value.processIdentity,start:''}}])assert.throws(()=>admitParentBrowser(root,write({...value,...patch})));
  const privateEnv=write(value);fs.chmodSync(file,0o644);assert.throws(()=>admitParentBrowser(root,privateEnv));
 }finally{fs.rmSync(outer,{recursive:true,force:true});}
});
