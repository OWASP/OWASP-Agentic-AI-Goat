#!/usr/bin/env python3
"""Root-only launcher for the FinFlow actual8B qualification cohort.
Consumes one registered slot, verifies the immutable staged closure, provisions
owned loopback-only PostgreSQL 18 databases, runs the gated test, and cleans up.
"""
import argparse, hashlib, json, os, re, secrets, signal, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path
SCOPE='finflow_recon_actual8b'; STAGE='actual8b-v3'; IMAGE='postgres:18'; SOCKET='unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock'
FIXTURES={
 'server/sensitive_files/traversal-fixtures/config/llm_config.yml':'e2cb44baf52a6124d812723bf775cd2d6a7fbe100e71cb2053669ce57d345eab',
 'server/sensitive_files/traversal-fixtures/config/secrets.env':'58dc81956934ce9fae23e65af3674f27dc6d46f07326a54404c4a874e27d027a',
 'server/sensitive_files/traversal-fixtures/etc/passwd':'5265ffbe93eac180b81969b9de24ac2638ca2f98b3c8f6f06d6f0025f3bec1f2',
}
def sha(p):
 h=hashlib.sha256();
 with open(p,'rb') as f:
  for b in iter(lambda:f.read(1<<20),b''): h.update(b)
 return h.hexdigest()
def save(p,v):
 p=Path(p); p.parent.mkdir(parents=True,exist_ok=True); q=Path(str(p)+f'.{os.getpid()}.pending'); q.write_text(json.dumps(v,indent=2,sort_keys=True)+'\n'); os.chmod(q,0o600); os.replace(q,p)
def run(c,**kw): return subprocess.run(c,check=False,text=True,**kw)
def verify_fixtures(root,files):
 fixture=root/'source/server/sensitive_files/traversal-fixtures'
 if fixture.is_symlink() or not fixture.is_dir() or Path(os.path.realpath(fixture))!=fixture: raise RuntimeError('canonical controlled fixture root required')
 expected_files={Path(k).relative_to('server/sensitive_files/traversal-fixtures').as_posix() for k in FIXTURES}
 expected_dirs={'config','etc'}; actual_files=set(); actual_dirs=set()
 for p in fixture.rglob('*'):
  rel=p.relative_to(fixture).as_posix()
  if p.is_symlink(): raise RuntimeError(f'controlled fixture symlink forbidden {rel}')
  if p.is_dir(): actual_dirs.add(rel)
  elif p.is_file(): actual_files.add(rel)
  else: raise RuntimeError(f'controlled fixture type invalid {rel}')
 if actual_files!=expected_files or actual_dirs!=expected_dirs: raise RuntimeError('controlled fixture inventory mismatch')
 for rel,digest in FIXTURES.items():
  p=root/'source'/rel
  if files.get(f'source/{rel}')!=digest or sha(p)!=digest: raise RuntimeError(f'controlled fixture mismatch {rel}')
def ensure_private_root(p):
 p=Path(p); p.mkdir(parents=True,exist_ok=True,mode=0o700); os.chmod(p,0o700); st=p.lstat()
 if p.is_symlink() or not p.is_dir() or Path(os.path.realpath(p))!=p.resolve() or st.st_uid!=os.getuid() or st.st_mode&0o077: raise RuntimeError(f'private writable root required {p}')
def main():
 ap=argparse.ArgumentParser()
 for n in ('grant-file','grant-id','owner','owner-handle-file','docker-host','container-nonce','canonical-workspace','package-root','manifest','managed-node','postgres-image-id','scope'): ap.add_argument('--'+n,required=True)
 a=ap.parse_args(); root=Path(a.package_root).resolve(); manifest=Path(a.manifest).resolve(); grant=Path(a.grant_file).resolve(); handle=Path(a.owner_handle_file).resolve(); node=Path(a.managed_node).resolve()
 if a.owner!='/root' or a.scope!=SCOPE or a.docker_host!=SOCKET or not re.fullmatch('[0-9a-f]{12}',a.container_nonce): raise RuntimeError('launch binding invalid')
 if root.is_symlink() or not root.is_dir() or manifest.is_symlink() or not manifest.is_file(): raise RuntimeError('immutable package required')
 m=json.loads(manifest.read_text()); files=m.get('files',{})
 for rel,d in files.items():
  p=root/rel
  if p.is_symlink() or not p.is_file() or sha(p)!=d: raise RuntimeError(f'source mismatch {rel}')
 verify_fixtures(root,files)
 ms=sha(manifest); deps=m.get('dependencyFiles',{}); dependency_links=m.get('dependencySymlinks',{})
 for rel,d in deps.items():
  p=root/'source'/rel
  if p.is_symlink() or not p.is_file() or sha(p)!=d: raise RuntimeError(f'dependency mismatch {rel}')
 dependency_root=root/'source'/'node_modules'
 if dependency_root.is_symlink() or not dependency_root.is_dir(): raise RuntimeError('private dependency root required')
 for rel,target in dependency_links.items():
  p=root/'source'/rel
  if not p.is_symlink() or os.readlink(p)!=target or not p.resolve().is_relative_to(dependency_root.resolve()): raise RuntimeError(f'dependency symlink mismatch {rel}')
 dependency_snapshot=json.dumps({'files':deps,'symlinks':dependency_links},sort_keys=True,separators=(',',':')).encode()
 if hashlib.sha256(dependency_snapshot).hexdigest()!=m.get('dependencySnapshotSha256'): raise RuntimeError('dependency snapshot mismatch')
 if not node.is_file() or node.is_symlink() or run([str(node),'--version'],capture_output=True).stdout.strip()!='v26.8.2': raise RuntimeError('managed Node mismatch')
 preflight=run([str(node),'--test','source/tests/finflowGraphEventContract.test.js','source/tests/postgres/finflowActual8bSourceClosure.test.js','source/tests/postgres/finflowReconActual8b.integration.test.js'],cwd=root,env={k:os.environ[k] for k in ('PATH','HOME','TMPDIR') if k in os.environ},capture_output=True,timeout=60)
 if preflight.returncode: raise RuntimeError('source startup preflight failed: '+preflight.stdout[-500:])
 ns=sha(node); image=['docker','--host',a.docker_host]; got=run(image+['image','inspect','--format','{{.Id}}',IMAGE],capture_output=True)
 if got.returncode or got.stdout.strip()!=a.postgres_image_id: raise RuntimeError('image identity mismatch')
 if not handle.is_file() or handle.is_symlink() or handle.stat().st_mode&0o77: raise RuntimeError('private handle required')
 hv=handle.read_text().strip();
 if not hv.isdecimal() or int(hv)<=0: raise RuntimeError('opaque handle invalid')
 expected={'grantId':a.grant_id,'owner':'/root','allowedLaunches':1,'dockerHost':a.docker_host,'containerNonce':a.container_nonce,'canonicalWorkspaceRoot':str(Path(a.canonical_workspace).resolve()),'candidateSourceRoot':str(root/'source'),'candidateManifestSha256':ms,'sourceHashes':files,'dependencySnapshotSha256':m.get('dependencySnapshotSha256'),'managedNodePath':str(node),'managedNodeSha256':ns,'postgresImageRef':IMAGE,'postgresImageId':a.postgres_image_id,'stage':STAGE,'scope':a.scope,'expectedOwnerHandle':int(hv),'ownerHandlePath':str(handle),'ownerHandleFileSha256':sha(handle),'expectedLauncherPid':os.getpid()}
 g=json.loads(grant.read_text())
 if g.get('status')!='granted' or any(g.get(k)!=v for k,v in expected.items()): raise RuntimeError('exact grant binding mismatch')
 lock=Path(str(grant)+'.consume-lock')
 try: lock.mkdir(mode=0o700)
 except FileExistsError: raise RuntimeError('grant already consumed')
 try:
  g=json.loads(grant.read_text())
  if g.get('status')!='granted' or any(g.get(k)!=v for k,v in expected.items()): raise RuntimeError('grant changed')
  g.update(status='consumed',consumerPid=os.getpid(),launcherPid=os.getpid()); save(grant,g)
 finally: lock.rmdir()
 print('WAITING_OWNER_HANDLE',flush=True); deadline=time.monotonic()+60
 while time.monotonic()<deadline:
  v=json.loads(grant.read_text()).get('ownerHandle')
  if v is not None:
   if v!=int(hv): raise RuntimeError('registered handle mismatch')
   break
  time.sleep(.1)
 else: raise RuntimeError('owner handle registration timeout')
 evidence=Path.home()/'.owasp-ai-goat/native-verification'/f'{SCOPE}-{a.container_nonce}'; evidence.mkdir(parents=True,exist_ok=False); os.chmod(evidence,0o700)
 log=evidence/'native.log'; own=evidence/'ownership.json'; cid=None; child=None; name=f'owasp-ai-goat-finflow-actual8b-{a.container_nonce}'; state={'version':1,'owner':'/root','grantId':a.grant_id,'ownerHandle':int(hv),'launcherPid':os.getpid(),'candidateSourceRoot':str(root/'source'),'candidateManifestSha256':ms,'sourceHashes':files,'dependencySnapshotSha256':m.get('dependencySnapshotSha256'),'managedNodePath':str(node),'managedNodeSha256':ns,'postgresImageRef':IMAGE,'postgresImageId':a.postgres_image_id,'stage':STAGE,'scope':a.scope,'evidence':str(evidence),'runStatus':'owner_registered'}; save(own,state)
 def reap():
  nonlocal child
  if child and child.poll() is None:
   os.killpg(os.getpgid(child.pid),signal.SIGTERM)
   try: child.wait(10)
   except subprocess.TimeoutExpired: os.killpg(os.getpgid(child.pid),signal.SIGKILL); child.wait(10)
 def cleanup():
  reap()
  if cid:
   x=run(image+['inspect',cid],capture_output=True)
   if x.returncode==0:
    info=json.loads(x.stdout)[0]; labels=info.get('Config',{}).get('Labels',{}) or {}
    if info.get('Name')!='/'+name or labels.get('owasp-ai-goat.owner')!='/root' or labels.get('owasp-ai-goat.grant')!=a.grant_id or labels.get('owasp-ai-goat.nonce')!=a.container_nonce: raise RuntimeError('unowned cleanup refused')
    run(image+['rm','--force',cid],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  return run(image+['inspect',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0
 try:
  x=run(image+['run','--detach','--pull','never','--name',name,'--label','owasp-ai-goat.owner=/root','--label',f'owasp-ai-goat.grant={a.grant_id}','--label',f'owasp-ai-goat.nonce={a.container_nonce}','--label',f'owasp-ai-goat.stage={STAGE}','--tmpfs','/var/lib/postgresql:rw,size=268435456','-e','POSTGRES_USER=owasp_ai_goat_bootstrap','-e','POSTGRES_HOST_AUTH_METHOD=trust','-p','127.0.0.1::5432',IMAGE,'-c','shared_buffers=16MB','-c','max_connections=64'],capture_output=True,timeout=60)
  if x.returncode: raise RuntimeError(x.stderr.strip())
  cid=x.stdout.strip(); state.update(containerId=cid,runStatus='container_started'); save(own,state)
  for _ in range(90):
   if run(image+['exec',cid,'pg_isready','-U','owasp_ai_goat_bootstrap'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0: break
   time.sleep(.5)
  else: raise RuntimeError('postgres readiness timeout')
  port=run(image+['port',cid,'5432/tcp'],capture_output=True).stdout.strip();
  if not re.fullmatch(r'127\.0\.0\.1:\d+',port): raise RuntimeError('loopback port required')
  p=port.rsplit(':',1)[1]
  def psql(sql,db='postgres'):
   y=run(image+['exec',cid,'psql','-U','owasp_ai_goat_bootstrap','-d',db,'-v','ON_ERROR_STOP=1','-c',sql],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=45)
   if y.returncode: raise RuntimeError('psql failed: '+y.stderr.strip())
  for role in ('dvaia_identity_migration','dvaia_identity_runtime','dvaia_finflow_migration','dvaia_finflow_runtime'): psql(f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS')
  for db,owner,runtime in (('owasp_ai_goat_test_finflow_recon_identity','dvaia_identity_migration','dvaia_identity_runtime'),('owasp_ai_goat_test_finflow_recon_store','dvaia_finflow_migration','dvaia_finflow_runtime')):
   psql(f'CREATE DATABASE {db} OWNER {owner}')
   psql(f'REVOKE CONNECT ON DATABASE {db} FROM PUBLIC; GRANT CONNECT ON DATABASE {db} TO {owner},{runtime}')
  app_data=evidence/'app-data'; backup_root=app_data/'finflow-backups'
  for private_root in (app_data,app_data/'logs',app_data/'finflow-traversal-targets'): ensure_private_root(private_root)
  if os.path.lexists(backup_root): raise RuntimeError('application-owned backup leaf must be absent')
  env={k:os.environ[k] for k in ('PATH','HOME','TMPDIR') if k in os.environ}; env.update(PG_TEST_DISPOSABLE='yes',FINFLOW_RECON_ACTUAL8B_ISOLATED='1',FINFLOW_RECON_ACTUAL8B_STAGE=STAGE,OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=str(root),PLATFORM_DATABASE_ENGINE='postgres',WORKSHOP_DATABASE_ENGINE='postgres',SENSITIVE_INFO_AGGREGATE_RESET_ENABLED='true',AI_PROVIDER='ollama',OLLAMA_BASE_URL='http://127.0.0.1:11434',OLLAMA_MODEL='llama3.1:8b',JUDGE_PROVIDER='ollama',JUDGE_MODEL='llama3.1:8b',JWT_SECRET=secrets.token_urlsafe(32),OWASP_AI_GOAT_APP_DATA_ROOT=str(app_data),LOGS_DIR=str(app_data/'logs'),FINFLOW_TRAVERSAL_TARGET_ROOT=str(app_data/'finflow-traversal-targets'),FINFLOW_BACKUP_ROOT=str(backup_root),IDENTITY_DATABASE_URL=f'postgresql://dvaia_identity_runtime@127.0.0.1:{p}/owasp_ai_goat_test_finflow_recon_identity',IDENTITY_MIGRATION_DATABASE_URL=f'postgresql://dvaia_identity_migration@127.0.0.1:{p}/owasp_ai_goat_test_finflow_recon_identity',FINFLOW_WORKSHOP_DATABASE_URL=f'postgresql://dvaia_finflow_runtime@127.0.0.1:{p}/owasp_ai_goat_test_finflow_recon_store',FINFLOW_WORKSHOP_MIGRATION_DATABASE_URL=f'postgresql://dvaia_finflow_migration@127.0.0.1:{p}/owasp_ai_goat_test_finflow_recon_store',FINFLOW_RECON_ACTUAL8B_EVIDENCE_PATH=str(evidence/'actor-evidence.json'),NODE_ENV='test')
  with open(log,'w') as out:
   os.chmod(log,0o600); child=subprocess.Popen([str(node),'--test','--test-concurrency=1','source/tests/postgres/finflowReconActual8b.integration.test.js'],cwd=root,env=env,stdout=out,stderr=subprocess.STDOUT,start_new_session=True); state.update(childPid=child.pid,runStatus='test_running'); save(own,state); code=child.wait(timeout=1800); child=None
  if code!=0: raise RuntimeError(f'cohort exited {code}')
  state.update(runStatus='test_passed',logSha256=sha(log))
 except Exception as e: state.update(runStatus='test_failed',failure=str(e)[:500],logSha256=sha(log) if log.exists() else None); raise
 finally:
  clean=cleanup(); state.update(cleanup={'childReaped':child is None or child.poll() is not None,'containerAbsent':clean,'clean':clean},completedAt=datetime.now(timezone.utc).isoformat(),runStatus='terminal_pass_cleaned' if state.get('runStatus')=='test_passed' and clean else 'terminal_fail_cleaned' if clean else 'terminal_fail_cleanup_uncertain'); save(own,state)
 if state['runStatus']!='terminal_pass_cleaned': raise RuntimeError('qualification incomplete')
 print(json.dumps({'status':state['runStatus'],'evidence':str(evidence),'logSha256':state.get('logSha256')},sort_keys=True))
if __name__=='__main__':
 try: main()
 except Exception as e: print('launcher failure:',e,file=sys.stderr); sys.exit(1)
