#!/usr/bin/env python3
"""Resume the exact held service after the applied-prefix preservation audit."""
import argparse, fcntl, hashlib, json, os, pathlib, signal, subprocess, tempfile, time, urllib.parse
from datetime import datetime, timezone

ROOT=pathlib.Path(__file__).resolve().parents[2]; OWNER='/root/workshop_authenticity'
PRIOR=pathlib.Path('/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/owasp-ai-goat-secureshop-owned-prefix-live-60fsfayr')
EXPECTED_PRIVATE='f424c99efdcc3985588c841070dbeb6a2ca0c76d1776776a7fd9a3cddcadff2e'
parser=argparse.ArgumentParser();parser.add_argument('--grant-file',required=True);parser.add_argument('--grant-id',required=True)
parser.add_argument('--watcher-pid',type=int,required=True);parser.add_argument('--backend-pid',type=int,required=True);args=parser.parse_args()
if (args.watcher_pid,args.backend_pid)!=(60889,93105):raise RuntimeError('exact held process pair is required')
base={k:os.environ[k] for k in ('PATH','HOME','TMPDIR') if k in os.environ};os.umask(0o077)
evidence=pathlib.Path(tempfile.mkdtemp(prefix='owasp-ai-goat-secureshop-prefix-resume-'));ownership=evidence/'ownership.json'
state={'owner':OWNER,'grantId':args.grant_id,'launcherPid':os.getpid(),'ownerHandle':None,'evidence':str(evidence),'runStatus':'preparing','watcherPid':args.watcher_pid,'backendPid':args.backend_pid}
def write():ownership.write_text(json.dumps(state,indent=2)+'\n');os.chmod(ownership,0o600)
def ps(pid,field):return subprocess.run(['ps','-p',str(pid),'-o',field+'='],env=base,capture_output=True,text=True,check=True).stdout.strip()
def process_state(pid):
 r=subprocess.run(['ps','-p',str(pid),'-o','stat='],env=base,capture_output=True,text=True)
 return r.stdout.strip() if r.returncode==0 else None
def config():
 code="require('dotenv').config({quiet:true});process.stdout.write(JSON.stringify({i:process.env.IDENTITY_MIGRATION_DATABASE_URL,a:process.env.SECURESHOP_AGENTS_MIGRATION_DATABASE_URL}))"
 return json.loads(subprocess.run(['node','-e',code],cwd=ROOT,env=base,capture_output=True,text=True,check=True).stdout)
def pg_env(url):
 p=urllib.parse.urlparse(url);e=dict(base,PGHOST=p.hostname,PGPORT=str(p.port or 5432),PGDATABASE=urllib.parse.unquote(p.path[1:]),PGUSER=urllib.parse.unquote(p.username or ''))
 if p.password is not None:e['PGPASSWORD']=urllib.parse.unquote(p.password)
 return e
def query(url,sql):return subprocess.run(['psql','-X','-v','ON_ERROR_STOP=1','-At','-c',sql],env=pg_env(url),capture_output=True,check=True).stdout
def row_state(url,store,prior):
 changed=[]
 for key,value in prior.items():
  if key.startswith('@') or key=='dvaia_migrations.ledger' or key=='secureshop_agents.mcp_tool_cache':continue
  schema,table=key.split('.',1);projection="to_jsonb(t) - 'conversation_purpose'" if key=='secureshop_agents.agent_sessions' else 'to_jsonb(t)'
  relation=f'"{schema}"."{table}"';rows=query(url,f'COPY (SELECT ({projection})::text FROM {relation} t ORDER BY ({projection})::text) TO STDOUT')
  current={'rows':int(query(url,f'SELECT count(*) FROM {relation}')),'sha256':hashlib.sha256(rows).hexdigest()}
  if current!=value:changed.append(key)
 return changed
def cache_from_dump(dump):
 with tempfile.TemporaryDirectory(prefix='owasp-ai-goat-cache-diff-') as directory:
  target=pathlib.Path(directory)/'data.sql';subprocess.run(['pg_restore','--data-only','--table=mcp_tool_cache','--file',str(target),str(dump)],env=base,check=True)
  lines=target.read_text().splitlines();start=next(i for i,line in enumerate(lines) if line.startswith('COPY secureshop_agents.mcp_tool_cache '));head=lines[start]
  columns=head[head.index('(')+1:head.index(')')].split(', ');rows=[]
  for line in lines[start+1:]:
   if line=='\\.':break
   rows.append(dict(zip(columns,line.split('\t'))))
  return rows
def cache_current(url):
 columns=['id','server_name','tool_name','description','input_schema_json','cached_at'];text=query(url,'COPY (SELECT '+','.join(columns)+' FROM secureshop_agents.mcp_tool_cache ORDER BY server_name,tool_name) TO STDOUT')
 return [dict(zip(columns,line.split('\t'))) for line in text.decode().splitlines() if line]
def cache_compare(prior,current):
 key=lambda row:(row['server_name'],row['tool_name']);a={key(row):row for row in prior};b={key(row):row for row in current};changed=set()
 for identity,row in a.items():
  other=b.get(identity)
  if other is None:changed.add('@missing');continue
  changed.update(column for column in row if row[column]!=other[column])
 for identity in b:
  if identity not in a:changed.add('@new')
 return {'priorRows':len(a),'currentRows':len(b),'keySetsEqual':set(a)==set(b),'changedColumns':sorted(changed)}
def audit():
 private=ROOT/'.env'
 if private.is_symlink() or hashlib.sha256(private.read_bytes()).hexdigest()!=EXPECTED_PRIVATE:raise RuntimeError('private configuration differs from held audit')
 manifest=json.loads((PRIOR/'backup-manifest.json').read_text());urls=config()
 identity_changes=row_state(urls['i'],'identity',manifest['stores']['identity']);agent_changes=row_state(urls['a'],'secureshop_agents',manifest['stores']['secureshop_agents'])
 cache=cache_compare(cache_from_dump(PRIOR/'secureshop_agents.dump'),cache_current(urls['a']))
 if identity_changes or agent_changes or cache!={'priorRows':60,'currentRows':60,'keySetsEqual':True,'changedColumns':['cached_at','id']}:
  raise RuntimeError('retained/current row preservation boundary differs')
 heads={'identity':json.loads(query(urls['i'],"SELECT json_agg(x ORDER BY name)::text FROM (SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name DESC LIMIT 3)x").decode()),'agents':json.loads(query(urls['a'],"SELECT json_agg(x ORDER BY name)::text FROM (SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name DESC LIMIT 3)x").decode())}
 expected={'identity':[{'name':'0051_secureshop_mcp_trust.sql','checksum':'8644c25726fdbe6b417aa9700fb8e7a54ec1062b1d8f69dcd5f90cabe6ecf508'},{'name':'0052_secureshop_controlled_ssrf.sql','checksum':'85cbb7d4b4d6835c720e13f81092a47f414c74cc1503f82eee48544e7a3fa07e'},{'name':'0053_codebot_request_journal.sql','checksum':'25958c7c062ea915134000eef60202fc6ec7cb187e8f93064e900c0074cfa712'}],'agents':[{'name':'0011_secureshop_mcp_trust.sql','checksum':'06cc0794509b2744e1fc2f0d4dcdc3f10e303e61acb54b44ec90ab1e479179d0'},{'name':'0012_secureshop_controlled_ssrf.sql','checksum':'a6c1f07d4207b5cf1413d553ef3de6068ca2c8c29eab87672e803fbf12caafc9'},{'name':'0013_secureshop_conversation_purpose.sql','checksum':'4446bed59d6734d19066f5ef8486e3c254dbb90681c2a155edecf57949682b9d'}]}
 if heads!=expected:raise RuntimeError('applied migration heads differ')
 return {'allOtherRowsEqual':True,'cache':cache,'privateConfigSha256':EXPECTED_PRIVATE,'heads':heads}
def identities():
 if 'nodemon' not in ps(args.watcher_pid,'command') or not ps(args.backend_pid,'command').endswith('node server/index.js') or int(ps(args.backend_pid,'ppid'))!=args.watcher_pid:return False
 return process_state(args.watcher_pid).startswith('T') and process_state(args.backend_pid).startswith('T')
write();summary=audit()
if not identities():raise RuntimeError('exact held process identities changed')
grant_path=pathlib.Path(args.grant_file).resolve()
with grant_path.open('r+') as f:
 fcntl.flock(f.fileno(),fcntl.LOCK_EX);g=json.load(f)
 if g.get('grantId')!=args.grant_id or g.get('status')!='granted' or g.get('owner')!=OWNER or g.get('allowedLaunches')!=1:raise RuntimeError('exact resume grant unavailable')
 g.update(status='consumed',consumerPid=os.getpid(),launcherPid=os.getpid(),ownerHandle=None,evidence=str(evidence),consumedAt=datetime.now(timezone.utc).isoformat());f.seek(0);json.dump(g,f,indent=2);f.write('\n');f.truncate();f.flush();os.fsync(f.fileno())
for _ in range(300):
 g=json.load(open(grant_path));handle=g.get('ownerHandle')
 if g.get('consumerPid')==os.getpid() and isinstance(handle,int) and handle>0:state['ownerHandle']=handle;write();break
 time.sleep(.1)
else:raise RuntimeError('actual owner handle was not registered')
resumed=False
try:
 os.kill(args.backend_pid,signal.SIGCONT);os.kill(args.watcher_pid,signal.SIGCONT);resumed=True
 for _ in range(60):
  probe=subprocess.run(['node','-e',"fetch('http://127.0.0.1:8081/api/monitoring/health').then(r=>process.exit(r.status===200?0:1)).catch(()=>process.exit(1))"],cwd=ROOT,env=base)
  if probe.returncode==0:break
  time.sleep(.5)
 else:raise RuntimeError('resumed backend did not become healthy')
 after=audit()
 if after!=summary:raise RuntimeError('rows or private configuration changed while resuming held service')
 state.update(runStatus='passed',audit=summary,health200=True);write()
except BaseException:
 if resumed:
  for pid in (args.watcher_pid,args.backend_pid):
   try:os.kill(pid,signal.SIGSTOP)
   except ProcessLookupError:pass
 state['runStatus']='failed';write();raise
finally:
 with grant_path.open('r+') as f:
  fcntl.flock(f.fileno(),fcntl.LOCK_EX);g=json.load(f);g.update(runStatus=state['runStatus'],terminalAt=datetime.now(timezone.utc).isoformat(),evidence=str(evidence));f.seek(0);json.dump(g,f,indent=2);f.write('\n');f.truncate();f.flush();os.fsync(f.fileno())
print(evidence)
