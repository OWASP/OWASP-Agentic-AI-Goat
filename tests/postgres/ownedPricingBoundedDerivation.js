'use strict';
// In-memory, exact-source derivation for Pricing only. The shared file and its
// V23/System factories are never edited. Import does not launch a process.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),Module=require('node:module');
const lease=require('./ownedPricingRuntimeLease');
const SOURCE_SHA='ab71e0fb17929f9323e1ff92f452b96b1b813641e4f70c1f3c6a555873a37c22';
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const fail=code=>Object.assign(new Error(code),{code});
const quote=x=>"'"+x.replace(/'/g,"'\\''")+"'";
const LEASE_PY=String.raw`import os,sys,stat,json,time,re
root,run,op=sys.argv[1:]
def need(v):
 if not v:raise RuntimeError('PRICING_LEASE_UNPROVEN')
need(re.fullmatch('[a-f0-9]{32}',run) and root=='/var/tmp/dvaia-v23-build-'+run and os.path.realpath(root)==root)
s=os.lstat(root);need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700)
def read(name):
 fd=os.open(root+'/'+name,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and 0<s.st_size<=4096)
  b=os.read(fd,4097);need(len(b)==s.st_size);return b.decode('ascii')
 finally:os.close(fd)
need(read('owner')==run)
def save(name,value):
 fd=os.open(root+'/'+name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  b=value.encode('ascii')
  while b:
   n=os.write(fd,b);need(n>0);b=b[n:]
  os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
total=2616000;target='original-v33-pricing-total-lease-v1'
if op=='create':
 start=time.monotonic_ns()//1000000
 save('pricing-lease.json',json.dumps(dict(version=1,target=target,runId=run,clock='linux-monotonic-ms',startedAtMs=start,expiresAtMs=start+total),sort_keys=True,separators=(',',':')))
else:
 r=json.loads(read('pricing-lease.json'))
 need(type(r) is dict and set(r)=={'version','target','runId','clock','startedAtMs','expiresAtMs'})
 need(type(r['version']) is int and r['version']==1 and r['target']==target and r['runId']==run and r['clock']=='linux-monotonic-ms')
 need(type(r['startedAtMs']) is int and r['startedAtMs']>=0 and type(r['expiresAtMs']) is int and r['expiresAtMs']==r['startedAtMs']+total)
 now=time.monotonic_ns()//1000000;need(now>=r['startedAtMs'])
 if op=='claim':
  remaining=r['expiresAtMs']-now;need(1000<remaining<=total)
  seconds=format((remaining-1)/1000,'.3f');save('pricing-holder.seconds',seconds);print(seconds,end='')
 elif op=='read':
  seconds=read('pricing-holder.seconds');need(re.fullmatch('[1-9][0-9]*\.[0-9]{3}',seconds) and 0<float(seconds)<=total/1000);print(seconds,end='')
 elif op=='active':
  need(now<r['expiresAtMs']);print(r['expiresAtMs'],end='')
 else:need(False)
`;
function once(source,old,replacement){if(source.split(old).length!==2)throw fail('PRICING_DERIVATION_ANCHOR');return source.replace(old,replacement);}
function leaseProgram(profile='v33'){
 const p=lease.profile(profile);
 return profile==='v33'?LEASE_PY:once(LEASE_PY,"total=2616000;target='original-v33-pricing-total-lease-v1'",`total=${p.totalMs};target='${p.target}'`);
}
function deriveSource(source,profile='v33'){
 if(sha(source)!==SOURCE_SHA||lease.TOTAL_MS!==2616000||lease.TARGET!=='original-v33-pricing-total-lease-v1')throw fail('PRICING_DERIVATION_SOURCE');
 const cmd=op=>'/usr/bin/python3 -I -S -B -c '+quote(leaseProgram(profile))+' "$root" "$nonce" '+op;
 const expression=x=>'${'+JSON.stringify(x)+'}';
 const start="prepare:guard+`\nmkdir -m 700 \"$root\"\nprintf '%s' \"$nonce\" > \"$root/owner\"";
 let result=once(source,start,start+'\n'+expression(cmd('create')));
 result=once(result,'setsid /usr/bin/unshare --net -- /usr/bin/sleep 900',expression('holder_seconds=$('+cmd('claim')+')\n')+'setsid /usr/bin/unshare --net -- /usr/bin/sleep "$holder_seconds"');
 result=once(result,'"$(printf \'/usr/bin/sleep\\\\n900\')"',expression('"$(printf \'%s\\n%s\' /usr/bin/sleep "$('+cmd('read')+')")"'));
 result=once(result,"current['argv']==['/usr/bin/sleep','900']","current['argv']==['/usr/bin/sleep',read(ROOT+'/pricing-holder.seconds')]");
 // This compiled module exposes only Pricing. The shared default and V23
 // factory bytes stay untouched; relay source SHA is verified upstream.
 result=once(result,'  // Loading the frozen definition supplies DNS_CODE for exact descendant checks;',
  "  if (metadataOnly) for (const mode of ['connector','adapter']) children[mode]=require('./ownedPricingEgressPolicy')._internals.deriveChild(children[mode]);\n  // Loading the frozen definition supplies DNS_CODE for exact descendant checks;");
 return result;
}
function loadPricingBounded(profile='v33'){
 const selected=lease.profile(profile);
 const name=path.join(__dirname,'ownedMcpBoundedBuild.js');if(fs.realpathSync(name)!==name)throw fail('PRICING_DERIVATION_PATH');
 const fd=fs.openSync(name,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);let source;
 try{const a=fs.fstatSync(fd);if(!a.isFile()||a.nlink!==1||a.size>1024**2)throw fail('PRICING_DERIVATION_FILE');
  source=fs.readFileSync(fd,'utf8');const z=fs.fstatSync(fd);if(['dev','ino','size','mtimeMs','ctimeMs'].some(k=>a[k]!==z[k]))throw fail('PRICING_DERIVATION_CHANGED');
 }finally{fs.closeSync(fd);}
 const text=deriveSource(source,profile),m=new Module(name,module);m.filename=name;m.paths=Module._nodeModulePaths(__dirname);m._compile(text,name);
 // Expose only the Pricing factory: callers cannot use derived V23/System paths.
 return Object.freeze({sourceSha256:SOURCE_SHA,derivedSha256:sha(text),totalMs:selected.totalMs,
  pricingMetadataQualificationPlan:m.exports._internals.pricingMetadataQualificationPlan});
}
module.exports={loadPricingBounded,SOURCE_SHA,_internals:{deriveSource,once,LEASE_PY,leaseProgram}};
