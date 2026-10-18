"""Closed current auth/CTF SQL profile; importing this module starts no resources."""
import argparse,hashlib,json,os,re,shutil,subprocess,time,uuid
from pathlib import Path
from full_backend_auth_contract import validate_package,inventory,prepare_evidence_root
from mail_disclosure_cleanup_budget import CleanupBudget
from sql_nosql_process_ownership import OwnedProcesses
from owned_diagnostic_process_cleanup import stop_directive_child
from mcp_connected_baseline_contract import validate_docker_cli
NODE_SHA='56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
IMAGE='sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
MIGRATION='e0ceab31af4c5bb1aa9d31f56743cd70875b23669bf29ec277937f5d9d94c235'
LIMIT=64*1024*1024
SUITES=(('auth','tests/postgres/authHttp.integration.test.js',300),('ctf','tests/postgres/ctfCanonicalAdminPolicy.integration.test.js',180))
def modes(root):return {str(p.relative_to(root)):p.lstat().st_mode for p in root.rglob("*")}
def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def arguments(argv):
 flags=[value.split("=",1)[0] for value in argv if value.startswith("--")]
 if len(flags)!=len(set(flags)):raise ValueError("Duplicate option")
 p=argparse.ArgumentParser()
 p.add_argument('--cohort',choices=['platform-auth-ctf0123'],required=True)
 for key in ['manifest','manifest-sha256','node-binary','node-sha256','docker-binary','docker-sha256','docker-host','daemon-id','postgres-image','evidence-root']:p.add_argument('--'+key,required=True)
 return p.parse_args(argv)
def plan(nonce):
 if not re.fullmatch('[a-f0-9]{12}',nonce):raise ValueError('Invalid nonce')
 return {'auth':'dvaia_test_auth_http_'+nonce,'fresh':'dvaia_test_ctf_adminpolicy_fresh_'+nonce,'populated':'dvaia_test_ctf_adminpolicy_populated_'+nonce}
def environment(home,port,databases,suite):
 env={'PATH':'/usr/bin:/bin','HOME':str(home),'TMPDIR':str(home),'PG_TEST_DISPOSABLE':'yes','DVAIA_AUTH_CTF_PROFILE':'1','DVAIA_AUTH_CTF_PORT':str(port),'PGCONNECT_TIMEOUT':'5','PGOPTIONS':'-c statement_timeout=15000 -c idle_in_transaction_session_timeout=30000'}
 pairs=[('PG_HTTP_TEST',databases['auth'])] if suite=='auth' else [('PG_CTF_CANONICAL_ADMIN_FRESH',databases['fresh']),('PG_CTF_CANONICAL_ADMIN_POPULATED',databases['populated'])]
 for prefix,db in pairs:
  for role in ['MIGRATION','RUNTIME']:env[prefix+'_'+role+'_URL']=f'postgresql://dvaia_identity_{role.lower()}@127.0.0.1:{port}/{db}'
 if suite=='ctf':env['CTF_CANONICAL_ADMIN_ISOLATED']='1'
 return env
def validate(args,source):
 if any(key.endswith("DATABASE_URL") or key.startswith("PG_HTTP_TEST_") or key.startswith("PG_CTF_CANONICAL_ADMIN_") for key in os.environ):raise RuntimeError("Inherited database configuration refused")
 node=Path(args.node_binary)
 if not node.is_absolute() or node.is_symlink() or node.resolve()!=node or args.node_sha256!=NODE_SHA or digest(node)!=NODE_SHA:raise RuntimeError('Canonical current Node required')
 validate_docker_cli(args.docker_binary,args.docker_sha256)
 if not args.docker_host.startswith('unix:///') or not args.daemon_id or args.postgres_image!=IMAGE:raise RuntimeError('Owned Docker pins required')
 validate_package(source,Path(args.manifest),args.manifest_sha256,node,NODE_SHA)
 if digest(source/'db/postgres/identity-migrations/0123_ctf_canonical_admin_policy.sql')!=MIGRATION:raise RuntimeError('0123 pin mismatch')
 if shutil.disk_usage(source).free<2*1024**3+512*1024**2+LIMIT:raise RuntimeError('Two GiB reserve plus runtime/log space required')
 return node

def check_log_budget(root):
 if sum(p.stat().st_size for p in root.glob('*.tap'))>LIMIT:raise RuntimeError('Log limit')
def verify_exited_suite(child,root,log):
 # Recheck the aggregate even when the child exited before the polling loop.
 check_log_budget(root)
 text=log.read_text()
 if child.returncode!=0 or not all(re.search(pattern,text) for pattern in [r'(?m)^# pass 1\s*$',r'(?m)^# fail 0\s*$',r'(?m)^# skipped 0\s*$']):raise RuntimeError('Suite TAP incomplete')

def cleanup_resources(owned,remove,inspect,budget):
 result={}
 for key,fn in [('processes',owned.cleanup),('container',remove),('absence',lambda:inspect() is None)]:
  try:
   if key=='container' and result.get('processes') is not True:raise RuntimeError('Physical child absence unproved; retain cluster')
   value=budget.run(fn);result[key]=value is not False
  except BaseException as error:result[key]=False;result[key+'Error']=type(error).__name__
 return result

def main(argv):
 args=arguments(argv);source=Path(__file__).resolve().parents[2];work=CleanupBudget(600)
 node=work.run(lambda:validate(args,source));before=work.run(lambda:inventory(source));before_modes=work.run(lambda:modes(source))
 root=prepare_evidence_root(args.evidence_root,[source.parent]);home=root/'home';home.mkdir(mode=0o700)
 nonce=uuid.uuid4().hex[:12];databases=plan(nonce);name='dvaia-auth-ctf-'+nonce;label=uuid.uuid4().hex
 docker=[args.docker_binary,'--host',args.docker_host];env={'PATH':'/usr/bin:/bin','HOME':str(home),'TMPDIR':str(home)}
 state={'scope':'platform-auth-ctf0123','status':'preparing','container':name,'owner':label,'suites':{},'cleanup':{},'children':[]};container=None;budget=work
 def save():
  path=root/'result.json';path.write_text(json.dumps(state,indent=2)+'\n');os.chmod(path,0o600)
 def command(argv,**kw):return subprocess.run(argv,env=env,timeout=min(kw.pop('timeout',15),budget.remaining()),check=True,**kw)
 def inspect():
  p=subprocess.run(docker+['container','inspect',name],env=env,capture_output=True,text=True,timeout=min(10,budget.remaining()))
  if p.returncode==1 and p.stderr.strip() in [f'Error: No such container: {name}',f'Error response from daemon: No such container: {name}',f'Error: No such object: {name}']:return None
  if p.returncode:raise RuntimeError('Container inspection unavailable')
  row=json.loads(p.stdout)[0]
  if row['Config']['Labels'].get('dvaia.test.owner')!=label or (container and row['Id']!=container):raise RuntimeError('Container identity mismatch')
  return row
 def members(child):
  found=[]
  for line in command(['ps','-axo','pid=,pgid=,uid='],capture_output=True,text=True).stdout.splitlines():
   pid,pgid,uid=map(int,line.split())
   if pgid==child.pid:
    if uid!=os.getuid() or os.getsid(pid)!=child.pid:raise RuntimeError('Unproven child group')
    found.append(pid)
  return found
 def stop(child,*_):return stop_directive_child(child,lambda _:members(child),budget)
 def remove_owned():
  row=inspect()
  if row:command(docker+['rm','-f',row['Id']],stdout=subprocess.DEVNULL)
 owned=OwnedProcesses(stop,lambda row:state['children'].append(row));owned.install();save()
 try:
  def execute():
   nonlocal container
   if command(docker+['info','--format','{{.ID}}'],capture_output=True,text=True).stdout.strip()!=args.daemon_id:raise RuntimeError('Daemon mismatch')
   if command(docker+['image','inspect','postgres:18','--format','{{.Id}}'],capture_output=True,text=True).stdout.strip()!=IMAGE:raise RuntimeError('Image mismatch')
   if inspect() is not None:raise RuntimeError('Container exists')
   command(docker+['run','-d','--pull','never','--name',name,'--label','dvaia.test.owner='+label,'--memory','1g','--cpus','2','--pids-limit','128','--tmpfs','/var/lib/postgresql:rw,size=1073741824','-e','POSTGRES_HOST_AUTH_METHOD=trust','-p','127.0.0.1::5432',IMAGE,'-c','max_connections=100'],capture_output=True)
   row=inspect();container=row['Id'];state['containerId']=container;save()
   binding=row['NetworkSettings']['Ports']['5432/tcp'];assert len(binding)==1 and binding[0]['HostIp']=='127.0.0.1';port=int(binding[0]['HostPort'])
   ready=time.monotonic()+30
   while True:
    r=subprocess.run(docker+['exec',container,'pg_isready','-h','127.0.0.1','-U','postgres'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=min(2,budget.remaining()))
    if r.returncode==0:break
    if time.monotonic()>ready:raise TimeoutError('PostgreSQL readiness')
    time.sleep(.1)
   def sql(text):command(docker+['exec',container,'psql','-U','postgres','-v','ON_ERROR_STOP=1','-c',text],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   sql('CREATE ROLE dvaia_identity_migration LOGIN; CREATE ROLE dvaia_identity_runtime LOGIN;')
   for db in databases.values():
    sql('CREATE DATABASE '+db+' OWNER dvaia_identity_migration;')
    sql('REVOKE ALL ON DATABASE '+db+' FROM PUBLIC; GRANT CONNECT ON DATABASE '+db+' TO dvaia_identity_migration,dvaia_identity_runtime;')
   for suite,file,seconds in SUITES:
    log=root/(suite+'.tap');deadline=min(time.monotonic()+seconds,work.deadline)
    with log.open('xb') as output:
     child=owned.launch([str(node),'--test',str(source/file)],name=suite,cwd=source,env=environment(home,port,databases,suite),stdout=output,stderr=output,start_new_session=True)
     while child.poll() is None:
      check_log_budget(root)
      if time.monotonic()>=deadline:raise TimeoutError('Suite deadline')
      time.sleep(.05)
     owned.finish(child)
    verify_exited_suite(child,root,log)
    state['suites'][suite]={'passed':True,'logSha256':digest(log)};save()
   state['status']='passed'
  work.run(execute)
 except BaseException as error:state['status']='failed';state['failure']=type(error).__name__
 finally:
  owned.mask_cleanup_signals();budget=CleanupBudget(120)
  state['cleanup']=cleanup_resources(owned,remove_owned,inspect,budget)
  owned.restore();budget=CleanupBudget(120)
  try:state['integrity']=budget.run(lambda:inventory(source)==before and modes(source)==before_modes)
  except BaseException as error:state['integrity']=False;state['integrityError']=type(error).__name__
  if not state.get('integrity') or any(state['cleanup'].get(k) is not True for k in ['processes','container','absence']):state['status']='failed'
  save()
 return 0 if state['status']=='passed' else 1
