#!/usr/bin/env python3
"""Owned PostgreSQL18 candidate-only HTTP receipt qualification, no installed URLs."""
import subprocess,pathlib,uuid,time,os,json,hashlib
root=pathlib.Path(__file__).resolve().parents[2]
D=['/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker','--host','unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock']
nonce=uuid.uuid4().hex[:12];name='dvaia-audit-search-'+nonce;database='dvaia_test_audit_search_'+nonce
node=pathlib.Path.home()/'.dvaia/runtimes/node-v26.9.0-darwin-arm64/bin/node'
result={'name':name,'candidateOnly':True,'actualModel':False,'actualNetworkEffects':False}
files=['tests/postgres/secureshopAuditSearchIsolation.design.test.js']
result['sourceHashes']={f:hashlib.sha256((root/f).read_bytes()).hexdigest() for f in files}
def run(args,**kwargs):return subprocess.run(args,check=True,text=True,capture_output=True,timeout=120,**kwargs)
try:
 assert not run(D+['ps','-aq','--filter','name=^/'+name+'$']).stdout.strip()
 run(D+['run','-d','--pull','never','--name',name,'--label','dvaia.owner='+nonce,'--tmpfs','/var/lib/postgresql:rw,size=536870912','-e','POSTGRES_USER=http_test_admin','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432','postgres:18','-c','shared_buffers=16MB','-c','max_connections=24','-c','max_wal_size=16MB','-c','min_wal_size=4MB'])
 result['postgresImage']=run(D+['inspect','--format','{{.Image}}',name]).stdout.strip()
 for _ in range(80):
  probe=subprocess.run(D+['exec',name,'pg_isready','-h','127.0.0.1','-U','http_test_admin'],capture_output=True,timeout=5)
  if probe.returncode==0:break
  time.sleep(.25)
 else:raise RuntimeError('owned PostgreSQL not ready')
 run(D+['exec','-i',name,'psql','-h','127.0.0.1','-U','http_test_admin','-d','postgres','-v','ON_ERROR_STOP=1'],input='CREATE ROLE search_learner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT; CREATE ROLE search_sibling LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT; CREATE DATABASE '+database+';')
 run(D+['exec','-i',name,'psql','-h','127.0.0.1','-U','http_test_admin','-d',database,'-v','ON_ERROR_STOP=1'],input="CREATE SCHEMA owned_a; CREATE SCHEMA owned_b; REVOKE CREATE ON SCHEMA public FROM PUBLIC; CREATE TABLE owned_a.audit_events(id bigint,actor text,action text,target text,params_json jsonb,ts timestamptz); INSERT INTO owned_a.audit_events VALUES(1,'ordinary','read','first','{}',now()),(2,'other','read','second','{}',now()); CREATE TABLE owned_a.teaching_secrets(id bigint,secret text); INSERT INTO owned_a.teaching_secrets VALUES(7,'OWNED_SYNTHETIC_CANARY_A'); CREATE TABLE owned_b.teaching_secrets(id bigint,secret text); INSERT INTO owned_b.teaching_secrets VALUES(8,'SIBLING_SYNTHETIC_CANARY_B'); GRANT USAGE ON SCHEMA owned_a TO search_learner; GRANT SELECT ON ALL TABLES IN SCHEMA owned_a TO search_learner; GRANT USAGE ON SCHEMA owned_b TO search_sibling; GRANT SELECT ON ALL TABLES IN SCHEMA owned_b TO search_sibling;")
 port=run(D+['port',name,'5432/tcp']).stdout.strip().rsplit(':',1)[1]
 env={k:os.environ[k] for k in ['HOME','PATH','TMPDIR'] if k in os.environ};env.update(PG_AUDIT_SEARCH_DESIGN='yes',PG_AUDIT_SEARCH_URL=f'postgresql://search_learner@127.0.0.1:{port}/{database}')
 test=subprocess.run([str(node),'--test','tests/postgres/secureshopAuditSearchIsolation.design.test.js'],cwd=root,env=env,text=True,capture_output=True,timeout=120)
 result.update(exitCode=test.returncode,stdout=test.stdout,stderr=test.stderr)
finally:
 subprocess.run(D+['rm','-f',name],capture_output=True,timeout=15)
 result['containerAbsent']=not run(D+['ps','-aq','--filter','name=^/'+name+'$']).stdout.strip()
 result['sourceUnchanged']=all(hashlib.sha256((root/f).read_bytes()).hexdigest()==value for f,value in result['sourceHashes'].items())
 (root/'tasks/secureshop-audit-search-isolation-design-2026-09-19.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({key:value for key,value in result.items() if key not in ['stdout','stderr','sourceHashes']}))
 if result.get('exitCode')!=0:print(result.get('stdout',''),result.get('stderr',''));raise SystemExit(1)
