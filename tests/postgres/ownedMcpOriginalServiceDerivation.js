'use strict';
// Constructs only a source-pinned service-specific module in memory. No native
// execution, producer capability minting, shared source edits or live admission.
const fs=require('node:fs/promises'),native=require('node:fs'),path=require('node:path');
const crypto=require('node:crypto'),Module=require('node:module');
const lease=require('./ownedMcpOriginalServiceLease');
const SOURCE_SHA='ab71e0fb17929f9323e1ff92f452b96b1b813641e4f70c1f3c6a555873a37c22';
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const fail=code=>Object.assign(new Error(code),{code});
const quote=x=>"'"+x.replace(/'/g,"'\\''")+"'";
function leaseCommand(op,profile='original-service'){
 lease.specification(profile);
 if(!['create','holder-claim','holder-read','active',...Object.keys(lease.PHASES).flatMap(p=>['claim-'+p,'check-'+p])].includes(op))
  throw fail('ORIGINAL_SERVICE_LEASE_OPERATION');
 return '/usr/bin/python3 -I -S -B -c '+quote(lease.guestSource(profile))+' "$root" "$nonce" '+op;
}
function replaceOnce(source,from,to){
 if(source.split(from).length!==2)throw fail('ORIGINAL_SERVICE_DERIVATION_ANCHOR');
 return source.replace(from,to);
}
function deriveSource(source,profile='original-service'){
 lease.specification(profile);
 if(sha(source)!==SOURCE_SHA||lease.TOTAL_MS!==7400000)throw fail('ORIGINAL_SERVICE_DERIVATION_SOURCE');
 const expression=x=>'${'+JSON.stringify(x)+'}';
 const prepare="prepare:guard+`\nmkdir -m 700 \"$root\"\nprintf '%s' \"$nonce\" > \"$root/owner\"";
 let result=replaceOnce(source,prepare,prepare+'\n'+expression(leaseCommand('create',profile)));
 result=replaceOnce(result,'setsid /usr/bin/unshare --net -- /usr/bin/sleep 900',
  expression('holder_seconds=$('+leaseCommand('holder-claim',profile)+')\n')+'setsid /usr/bin/unshare --net -- /usr/bin/sleep "$holder_seconds"');
 result=replaceOnce(result,'"$(printf \'/usr/bin/sleep\\\\n900\')"',
  expression('"$(printf \'%s\\n%s\' /usr/bin/sleep "$('+leaseCommand('holder-read',profile)+')")"'));
 result=replaceOnce(result,"current['argv']==['/usr/bin/sleep','900']",
  "current['argv']==['/usr/bin/sleep',read(ROOT+'/original-service-holder.seconds')]");
 return result;
}
async function loadOriginalServiceBounded(profile='original-service'){
 const selected=lease.specification(profile);
 const filename=path.join(__dirname,'ownedMcpBoundedBuild.js');
 if(await fs.realpath(filename)!==filename)throw fail('ORIGINAL_SERVICE_DERIVATION_PATH');
 const fd=await fs.open(filename,native.constants.O_RDONLY|native.constants.O_NOFOLLOW);let source;
 try{
  const before=await fd.stat();if(!before.isFile()||before.nlink!==1||before.size>1024**2)throw fail('ORIGINAL_SERVICE_DERIVATION_FILE');
  source=await fd.readFile('utf8');const after=await fd.stat();
  if(before.size!==after.size||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs)throw fail('ORIGINAL_SERVICE_DERIVATION_CHANGED');
 }finally{await fd.close();}
 const text=deriveSource(source,profile),derived=new Module(filename,module);
 derived.filename=filename;derived.paths=Module._nodeModulePaths(__dirname);derived._compile(text,filename);
 return Object.freeze({bounded:derived.exports,sourceSha256:SOURCE_SHA,derivedSha256:sha(text),
  leaseTarget:selected.target,totalMs:selected.totalMs,executionApproved:false});
}
module.exports={loadOriginalServiceBounded,SOURCE_SHA,leaseCommand,_internals:{deriveSource,replaceOnce}};
