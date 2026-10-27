'use strict';
// Proposed fixture-only adapter to the existing Darwin birth journal protocol.
const assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto');
async function acknowledge({root,evidencePath,profile,browser,env=process.env}){
 const run=path.dirname(evidencePath),temporary=path.join(run,'runtime/tmp');
 assert.equal(path.dirname(run),path.join(root,'tasks/qualification'));assert.match(path.basename(run),/^run-[A-Za-z0-9_-]+$/);
 assert.equal(env.TMPDIR,temporary);assert.equal(env.MAC_CHROMIUM_TMPDIR,temporary);
 assert.equal(path.dirname(profile),temporary);assert.match(path.basename(profile),/^(dvaia-role-admin-(policy|audit)|dvaia-q64-admin-acl)-[A-Za-z0-9_-]+$/);
 const record=path.join(run,'rolechoices-browser-birth.json'),ack=path.join(run,'rolechoices-browser-ack.json');
 assert.equal(env.SECURESHOP_ROLECHOICES_BROWSER_RECORD_PATH,record);assert.equal(env.SECURESHOP_ROLECHOICES_BROWSER_ACK_PATH,ack);
 const child=browser.process();assert(Number.isSafeInteger(child?.pid)&&child.pid>1);
 const value=require('./secureshopDarwinBrowserBirth').captureBrowserRecord({root,kind:'rolechoices_browser',pid:child.pid,
  executablePath:env.PUPPETEER_EXECUTABLE_PATH,executableSha256:env.SECURESHOP_ROLECHOICES_BROWSER_SHA256,env});
 const bytes=Buffer.from(JSON.stringify(value)+'\n');assert(bytes.length<=4096);
 const fd=await fs.open(record,'wx',0o600);try{await fd.writeFile(bytes);await fd.sync();}finally{await fd.close();}
 const until=Date.now()+20000;
 while(Date.now()<until){
  try{const h=await fs.open(ack,require('node:fs').constants.O_RDONLY|require('node:fs').constants.O_NOFOLLOW|require('node:fs').constants.O_NONBLOCK);
   let raw;try{const s=await h.stat();assert(s.isFile()&&s.uid===process.getuid()&&s.nlink===1&&(s.mode&511)===384&&s.size>0&&s.size<=4096);raw=Buffer.alloc(s.size+1);const r=await h.read(raw,0,raw.length,0);assert.equal(r.bytesRead,s.size);const after=await h.stat(),named=await fs.lstat(ack);for(const k of ['dev','ino','size','mtimeMs','ctimeMs']){assert.equal(after[k],s[k]);assert.equal(named[k],s[k]);}assert(named.isFile());raw=raw.subarray(0,r.bytesRead);}finally{await h.close();}
   const accepted=JSON.parse(raw);assert.equal(accepted.schemaVersion,1);assert.equal(accepted.recordSha256,crypto.createHash('sha256').update(bytes).digest('hex'));
   assert.equal(accepted.browserPid,child.pid);assert.equal(accepted.parentPid,process.ppid);assert.equal(accepted.profile,profile);return;
  }catch(error){if(error.code!=='ENOENT')throw error;}
  await new Promise(resolve=>setTimeout(resolve,25));
 }
 throw Error('RoleChoices live browser acknowledgement unavailable');
}
module.exports={acknowledge};
