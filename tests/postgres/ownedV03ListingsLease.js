'use strict';
// Fixed guest phase windows supplied only by the owning driver's authenticated
// clock mapping. Import/plan generation does not mint a host producer capability.
const PHASES=Object.freeze({build:1800000,settlement:680000,startup:60000,
 cohort:1210000,retirement:1080000,cleanup:2520000});
const GUEST_SOURCE=String.raw`import os,sys,stat,json,time,re,select,hashlib
ROOT,RUN,OP,PHASE=sys.argv[1:]
LIMITS={'build':1800000,'settlement':680000,'startup':60000,'cohort':1210000,'retirement':1080000,'cleanup':2520000}
def need(value):
 if not value:raise RuntimeError('V03_LISTINGS_PHASE_UNPROVEN')
def unique(pairs):
 out={}
 for key,value in pairs:need(key not in out);out[key]=value
 return out
def decode(raw):return json.loads(raw,object_pairs_hook=unique)
need(OP in ('claim','check') and PHASE in LIMITS and re.fullmatch('[a-f0-9]{32}',RUN))
need(ROOT=='/var/tmp/dvaia-v23-build-'+RUN and os.path.realpath(ROOT)==ROOT)
info=os.lstat(ROOT);need(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o700)
def read(name):
 fd=os.open(ROOT+'/'+name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=4096)
  raw=os.read(fd,4097);after=os.fstat(fd)
  need(len(raw)==before.st_size and all(getattr(before,k)==getattr(after,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')))
  return raw.decode('ascii')
 finally:os.close(fd)
def save(name,row):
 raw=json.dumps(row,sort_keys=True,separators=(',',':')).encode('ascii')
 fd=os.open(ROOT+'/'+name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  while raw:
   count=os.write(fd,raw);need(count>0);raw=raw[count:]
  os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
need(read('owner')==RUN)
parent=decode(read('v03-combined-lease.json'))
need(type(parent) is dict and set(parent)=={'version','target','parentRunId','runId','clock','startedAtMs','expiresAtMs','combinedPlanSha256','guestBootId'})
need(type(parent['version']) is int and parent['version']==1 and parent['target']=='original-v03-combined-preparation-lease-v1' and parent['runId']==RUN and parent['clock']=='linux-monotonic-ms')
need(type(parent['parentRunId']) is str and re.fullmatch('[a-f0-9]{32}',parent['parentRunId']) and hashlib.sha256((parent['parentRunId']+':v03-listings').encode()).hexdigest()[:32]==RUN)
need(type(parent['combinedPlanSha256']) is str and re.fullmatch('[a-f0-9]{64}',parent['combinedPlanSha256']))
with open('/proc/sys/kernel/random/boot_id','r',encoding='ascii') as stream:boot=stream.read(38).strip()
need(re.fullmatch('[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}',boot) and parent['guestBootId']==boot)
need(type(parent['startedAtMs']) is int and type(parent['expiresAtMs']) is int and 0<=parent['startedAtMs']<parent['expiresAtMs']<=parent['startedAtMs']+11096000)
now=time.monotonic_ns()//1000000
need(parent['startedAtMs']<=now<parent['expiresAtMs'])
keys=list(LIMITS);index=keys.index(PHASE)
def checked(row,phase,active=True):
 need(type(row) is dict and set(row)=={'parentRunId','runId','combinedPlanSha256','guestBootId','phase','startedAtMs','deadlineMs'})
 need(row['parentRunId']==parent['parentRunId'] and row['runId']==RUN and row['combinedPlanSha256']==parent['combinedPlanSha256'] and row['guestBootId']==boot and row['phase']==('cohortClaim' if phase=='cohort' else phase))
 # The first mapped build window begins before guest lease creation. Its
 # fixed deadline remains capped by the parent; creation is not a new epoch.
 need(type(row['startedAtMs']) is int and type(row['deadlineMs']) is int and 0<=row['startedAtMs']<=now and row['startedAtMs']<row['deadlineMs']<=parent['expiresAtMs'])
 if active:need(now<row['deadlineMs'])
 span=row['deadlineMs']-row['startedAtMs'];need(0<span<=LIMITS[phase])
 if phase=='cohort':
  need(span==1210000)
  if OP=='claim' and active:need(now-row['startedAtMs']<10000 and row['deadlineMs']-now>=1200000)
 return row
for later in keys[index+1:]:
 try:read('v03-listings-phase-'+later+'.json')
 except FileNotFoundError:continue
 need(False)
name='v03-listings-phase-'+PHASE+'.json'
if OP=='claim':
 if index and PHASE not in ('retirement','cleanup'):
  checked(decode(read('v03-listings-phase-'+keys[index-1]+'.json')),keys[index-1],False)
 ready,_,_=select.select([0],[],[],5);need(bool(ready));raw=os.read(0,4097);need(len(raw)<=4096)
 row=checked(decode(raw),PHASE);save(name,row)
else:row=checked(decode(read(name)),PHASE)
print(json.dumps(row,sort_keys=True,separators=(',',':')))
`;
function command(op,phase){
 if(!['claim','check'].includes(op)||!Object.hasOwn(PHASES,phase))throw Error('V03_LISTINGS_PHASE_ARGUMENT');
 const quoted="'"+GUEST_SOURCE.replace(/'/g,"'\\''")+"'";
 return '/usr/bin/python3 -I -S -B -c '+quoted+' "$root" "$nonce" '+op+' '+phase;
}
function boundedPhase(script,phase){
 if(typeof script!=='string'||!Object.hasOwn(PHASES,phase)&&phase!=='artifact-retirement')throw Error('V03_LISTINGS_PHASE_ARGUMENT');
 const quote=value=>"'"+value.replace(/'/g,"'\\''")+"'";
 const header='set -eu\numask 077\nroot=$1\nnonce=$2\n';
 const read=phase==='artifact-retirement'?command('check','settlement')+' 2>/dev/null || '+command('check','cleanup'):command('check',phase);
 const quietRead=phase==='artifact-retirement'?'('+read+')':read;
 const remaining="import json,sys,time,math; r=json.load(sys.stdin); n=r['deadlineMs']/1000-time.monotonic(); assert math.isfinite(n) and n>0; print(format(n,'.9f'),end='')";
 // Both checks use the same exclusive guest record. The timer cannot mint or
 // renew a phase and the original script retains all resource identity guards.
 return header+'remaining=$( ('+read+') | /usr/bin/python3 -I -S -B -c '+quote(remaining)+')\n'+
  '/usr/bin/timeout --signal=TERM --kill-after=10 "$remaining" /bin/sh -c '+
  quote(header+quietRead+' >/dev/null\n'+script)+' owned-v03-listings "$root" "$nonce" "${3:-}"\n';
}
module.exports={PHASES,GUEST_SOURCE,command,boundedPhase};
