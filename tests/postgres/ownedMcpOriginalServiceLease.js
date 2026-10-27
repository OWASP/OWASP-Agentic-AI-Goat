'use strict';
// Closed prospective original-service lease. These records are timing evidence,
// never a capability, successful phase proof, or resource-absence evidence.
const TARGET='original-v23-service-total-lease-v1';
const PHASES=Object.freeze({build:1800000,settlement:680000,startup:120000,
  cohort:1200000,retirement:1080000,cleanup:2520000});
const TOTAL_MS=Object.values(PHASES).reduce((a,b)=>a+b,0);
const fail=code=>Object.assign(new Error(code),{code});
const V39_PHASES=Object.freeze({...PHASES,build:960000,cohort:480000});
const LISTINGS_PHASES=Object.freeze({...PHASES,startup:60000,cohort:540000});
function specification(profile='original-service'){
 if(!['original-service','v39-atomic-pair','q05-registered-pair','listings-manager-browser'].includes(profile))throw fail('ORIGINAL_LEASE_PROFILE');
 if(profile==='listings-manager-browser')return Object.freeze({profile,target:'original-listings-manager-total-lease-v1',
  phases:LISTINGS_PHASES,totalMs:Object.values(LISTINGS_PHASES).reduce((a,b)=>a+b,0),workMs:null});
 return profile==='original-service'?Object.freeze({profile,target:TARGET,phases:PHASES,totalMs:TOTAL_MS,workMs:null}):
  Object.freeze({profile,target:profile==='v39-atomic-pair'?'v39-atomic-pair-total-lease-v1':'q05-registered-pair-total-lease-v1',phases:V39_PHASES,
   totalMs:960000+PHASES.retirement+PHASES.cleanup,workMs:960000});
}
function windowFor(startedAtMs,now,phase,profile='original-service'){
 const selected=specification(profile),phases=selected.phases,total=selected.totalMs;
  if(!Number.isSafeInteger(startedAtMs)||startedAtMs<0
    ||!Number.isSafeInteger(now)||now<startedAtMs
    ||startedAtMs>Number.MAX_SAFE_INTEGER-total
    ||!Object.hasOwn(phases,phase))throw fail('ORIGINAL_LEASE_INPUT');
  const keys=Object.keys(phases),reserve=keys.slice(keys.indexOf(phase)+1).reduce((n,k)=>n+phases[k],0);
  const expiresAtMs=startedAtMs+total;
  const latest=selected.workMs&&!['retirement','cleanup'].includes(phase)?startedAtMs+selected.workMs:expiresAtMs-reserve;
  const deadlineMs=Math.min(now+phases[phase],latest);
  if(deadlineMs<=now||(!selected.workMs&&phase==='cohort'&&deadlineMs-now!==phases.cohort))
    throw fail('ORIGINAL_LEASE_RESERVE');
  return Object.freeze({phase,startedAtMs:now,deadlineMs,leaseExpiresAtMs:expiresAtMs,
    executionApproved:false,resourceAbsenceProven:false});
}
// Fixed guest source; paths, clock, target and phase limits are not caller input.
function guestSource(profile='original-service'){
const selected=specification(profile),pair=selected.workMs!==null;
return String.raw`import os,sys,stat,json,time,re
ROOT,RUN,OP=sys.argv[1:]
TARGET='${selected.target}'
TOTAL=${selected.totalMs}
PHASES={${Object.entries(selected.phases).map(([k,v])=>"'"+k+"':"+v).join(',')}}
def require(v):
 if not v:raise RuntimeError('ORIGINAL_SERVICE_LEASE_UNPROVEN')
require(re.fullmatch('[a-f0-9]{32}',RUN) and ROOT=='/var/tmp/dvaia-v23-build-'+RUN and os.path.realpath(ROOT)==ROOT)
s=os.lstat(ROOT);require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700)
def read(name):
 fd=os.open(ROOT+'/'+name,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=4096)
  b=os.read(fd,4097);require(len(b)==s.st_size);return b.decode('ascii')
 finally:os.close(fd)
def save(name,value):
 fd=os.open(ROOT+'/'+name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  b=value.encode('ascii')
  while b:
   n=os.write(fd,b);require(n>0);b=b[n:]
  os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'))
require(read('owner')==RUN)
now=time.monotonic_ns()//1000000
if OP=='create':
 require(now>=0)
 save('original-service-lease.json',encoded(dict(version=1,target=TARGET,runId=RUN,clock='linux-monotonic-ms',startedAtMs=now,expiresAtMs=now+TOTAL)))
else:
 row=json.loads(read('original-service-lease.json'))
 require(type(row) is dict and set(row)=={'version','target','runId','clock','startedAtMs','expiresAtMs'})
 require(type(row['version']) is int and row['version']==1 and row['target']==TARGET and row['runId']==RUN and row['clock']=='linux-monotonic-ms')
 require(type(row['startedAtMs']) is int and row['startedAtMs']>=0 and type(row['expiresAtMs']) is int and row['expiresAtMs']==row['startedAtMs']+TOTAL and now>=row['startedAtMs'])
 if OP=='holder-claim':
  left=row['expiresAtMs']-now;require(1000<left<=TOTAL)
  value=format((left-1)/1000,'.3f');save('original-service-holder.seconds',value);print(value,end='')
 elif OP=='holder-read':
  value=read('original-service-holder.seconds');require(re.fullmatch('[1-9][0-9]*\.[0-9]{3}',value) and 0<float(value)<=TOTAL/1000)
  print(value,end='') # Identity-only read is allowed after expiry for cleanup.
 elif OP=='active':
  require(now<row['expiresAtMs']);print(row['expiresAtMs'],end='')
 else:
  match=re.fullmatch('(claim|check)-(build|settlement|startup|cohort|retirement|cleanup)',OP);require(match)
  action,phase=match.groups();keys=list(PHASES);index=keys.index(phase)
  reserve=sum(PHASES[k] for k in keys[index+1:]);latest=row['expiresAtMs']-reserve${pair?"\n  if phase not in ('retirement','cleanup'):latest=row['startedAtMs']+960000":''}
  name='original-service-phase-'+phase+'.json'
  for later in keys[index+1:]:
   try:read('original-service-phase-'+later+'.json')
   except FileNotFoundError:continue
   require(False) # Later phases revoke both new claims and prior dispatch checks.
  if action=='claim':
   # Cleanup may be claimed after any failed phase. Other transitions require
   # their previous timing record, not an invented successful phase receipt.
   if index and phase!='cleanup':
    previous=json.loads(read('original-service-phase-'+keys[index-1]+'.json'))
    prior=keys[index-1];priorLatest=row['expiresAtMs']-sum(PHASES[k] for k in keys[index:])${pair?"\n    if prior not in ('retirement','cleanup'):priorLatest=row['startedAtMs']+960000":''}
    require(type(previous) is dict and set(previous)=={'version','target','runId','phase','startedAtMs','deadlineMs'})
    require(type(previous['version']) is int and previous['version']==1 and previous['target']==TARGET and previous['runId']==RUN and previous['phase']==prior)
    require(type(previous['startedAtMs']) is int and row['startedAtMs']<=previous['startedAtMs']<=now and type(previous['deadlineMs']) is int)
    require(previous['deadlineMs']==min(previous['startedAtMs']+PHASES[prior],priorLatest) and previous['deadlineMs']>previous['startedAtMs'])
   end=min(now+PHASES[phase],latest);require(end>now)
   ${pair?"# V39 cohort is capped by the original once-only parent work deadline.":"if phase=='cohort':require(end-now==PHASES[phase])"}
   result=dict(version=1,target=TARGET,runId=RUN,phase=phase,startedAtMs=now,deadlineMs=end)
   save(name,encoded(result))
  else:result=json.loads(read(name))
  require(type(result) is dict and set(result)=={'version','target','runId','phase','startedAtMs','deadlineMs'})
  require(type(result['version']) is int and result['version']==1 and result['target']==TARGET and result['runId']==RUN and result['phase']==phase)
  require(type(result['startedAtMs']) is int and row['startedAtMs']<=result['startedAtMs']<=now and type(result['deadlineMs']) is int)
  require(result['deadlineMs']==min(result['startedAtMs']+PHASES[phase],latest) and now<result['deadlineMs'])
  ${pair?"# No new cohort window after the parent work deadline.":"if phase=='cohort':require(result['deadlineMs']-result['startedAtMs']==PHASES[phase])"}
  print(encoded(result),end='')
`;
}
const GUEST=guestSource();
module.exports={TARGET,PHASES,TOTAL_MS,windowFor,GUEST,specification,guestSource};
