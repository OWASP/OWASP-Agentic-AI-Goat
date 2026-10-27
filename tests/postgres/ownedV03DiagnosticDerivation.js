'use strict';
// Fixed V03-only derivation of the reviewed private builder. No source copies,
// caller recipe/command replacement, execution, or capability construction.
const crypto=require('node:crypto');
const SOURCE_SHA='ab71e0fb17929f9323e1ff92f452b96b1b813641e4f70c1f3c6a555873a37c22';
const fail=code=>Object.assign(new Error(code),{code});
const quote=value=>"'"+value.replace(/'/g,"'\\''")+"'";
const LEASE_PY=String.raw`import os,sys,stat,json,time,re,select,hashlib
ROOT,RUN,OP=sys.argv[1:]
def require(value):
 if not value:raise RuntimeError('V03_DIAGNOSTIC_LEASE_UNPROVEN')
require(re.fullmatch('[a-f0-9]{32}',RUN) and ROOT=='/var/tmp/dvaia-v23-build-'+RUN and os.path.realpath(ROOT)==ROOT)
info=os.lstat(ROOT);require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o700)
def read(name):
 fd=os.open(ROOT+'/'+name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);require(stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=4096)
  raw=os.read(fd,4097);after=os.fstat(fd)
  require(len(raw)==before.st_size and all(getattr(before,key)==getattr(after,key) for key in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')))
  return raw.decode('ascii')
 finally:os.close(fd)
def save(name,value):
 fd=os.open(ROOT+'/'+name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  raw=value.encode('ascii')
  while raw:
   count=os.write(fd,raw);require(count>0);raw=raw[count:]
  os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
TARGET='original-v03-combined-preparation-lease-v1'
TOTAL=11096000
with open('/proc/sys/kernel/random/boot_id','r',encoding='ascii') as stream:BOOT=stream.read(38).strip()
require(re.fullmatch('[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}',BOOT))
if OP=='create':
 # The owning driver maps one absolute parent endpoint using its authenticated
 # clock sample. Arbitrary host preparation/transit cannot renew this endpoint.
 ready,_,_=select.select([0],[],[],5);require(bool(ready))
 raw=os.read(0,4097);require(len(raw)<=4096);request=json.loads(raw)
 require(type(request) is dict and set(request)=={'version','runId','parentRunId','combinedPlanSha256','guestBootId','expiresAtMs'})
 require(type(request['version']) is int and request['version']==1 and request['runId']==RUN
         and type(request['parentRunId']) is str and re.fullmatch('[a-f0-9]{32}',request['parentRunId'])
         and hashlib.sha256((request['parentRunId']+':v03-diagnostic').encode('ascii')).hexdigest()[:32]==RUN
         and type(request['combinedPlanSha256']) is str and re.fullmatch('[a-f0-9]{64}',request['combinedPlanSha256'])
         and request['guestBootId']==BOOT and type(request['expiresAtMs']) is int)
 start=time.monotonic_ns()//1000000
 require(start+1000<request['expiresAtMs']<=start+TOTAL)
 row=dict(version=1,target=TARGET,runId=RUN,clock='linux-monotonic-ms',startedAtMs=start,
          expiresAtMs=request['expiresAtMs'],guestBootId=BOOT,combinedPlanSha256=request['combinedPlanSha256'],parentRunId=request['parentRunId'])
 save('v03-combined-lease.json',json.dumps(row,sort_keys=True,separators=(',',':')))
else:
 row=json.loads(read('v03-combined-lease.json'))
 require(type(row) is dict and set(row)=={'version','target','runId','parentRunId','clock','startedAtMs','expiresAtMs','combinedPlanSha256','guestBootId'})
 require(type(row['version']) is int and row['version']==1 and row['target']==TARGET and row['runId']==RUN and row['clock']=='linux-monotonic-ms'
         and type(row['parentRunId']) is str and re.fullmatch('[a-f0-9]{32}',row['parentRunId'])
         and hashlib.sha256((row['parentRunId']+':v03-diagnostic').encode('ascii')).hexdigest()[:32]==RUN
         and type(row['combinedPlanSha256']) is str and re.fullmatch('[a-f0-9]{64}',row['combinedPlanSha256']) and row['guestBootId']==BOOT)
 require(type(row['startedAtMs']) is int and type(row['expiresAtMs']) is int and 0<=row['startedAtMs']<row['expiresAtMs']<=row['startedAtMs']+TOTAL)
 now=time.monotonic_ns()//1000000;require(now>=row['startedAtMs'])
 if OP=='claim':
  left=row['expiresAtMs']-now;require(1000<left<=TOTAL)
  value=format((left-1)/1000,'.3f');save('v03-holder.seconds',value);print(value,end='')
 elif OP=='read':
  value=read('v03-holder.seconds');require(re.fullmatch(r'[1-9][0-9]*\.[0-9]{3}',value) and 0<float(value)<=TOTAL/1000);print(value,end='')
 elif OP=='active':require(now<row['expiresAtMs']);print(row['expiresAtMs'],end='')
 else:require(False)
`;
function replaceOnce(source,before,after){
 if(source.split(before).length!==2)throw fail('DIAGNOSTIC_LEASE_ANCHOR');
 return source.replace(before,after);
}
if(LEASE_PY.split(':v03-diagnostic').length!==3)throw fail('V03_LEASE_DOMAIN_ANCHOR');
const LISTINGS_LEASE_PY=LEASE_PY.replaceAll(':v03-diagnostic',':v03-listings');
function deriveFixed(source,leaseSource){
 if(crypto.createHash('sha256').update(source).digest('hex')!==SOURCE_SHA)throw fail('DIAGNOSTIC_LEASE_SOURCE');
 const command=op=>'/usr/bin/python3 -I -S -B -c '+quote(leaseSource)+' "$root" "$nonce" '+op;
 const expression=value=>'${'+JSON.stringify(value)+'}';
 const prepare="prepare:guard+`\nmkdir -m 700 \"$root\"\nprintf '%s' \"$nonce\" > \"$root/owner\"";
 let result=replaceOnce(source,prepare,prepare+'\n'+expression(command('create')));
 result=replaceOnce(result,'setsid /usr/bin/unshare --net -- /usr/bin/sleep 900',
  expression('holder_seconds=$('+command('claim')+')\n')+'setsid /usr/bin/unshare --net -- /usr/bin/sleep "$holder_seconds"');
 result=replaceOnce(result,'"$(printf \'/usr/bin/sleep\\\\n900\')"',
  expression('"$(printf \'%s\\n%s\' /usr/bin/sleep "$('+command('read')+')")"'));
 return replaceOnce(result,"current['argv']==['/usr/bin/sleep','900']",
  "current['argv']==['/usr/bin/sleep',read(ROOT+'/v03-holder.seconds')]");
}
function deriveSource(source){return deriveFixed(source,LEASE_PY);}
function deriveListingsSource(source){return deriveFixed(source,LISTINGS_LEASE_PY);}
module.exports={SOURCE_SHA,deriveSource,deriveListingsSource,LEASE_PY,LISTINGS_LEASE_PY};
