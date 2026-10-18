#!/usr/bin/env python3
"""Owned PostgreSQL18 candidate-only HTTP receipt qualification, no installed URLs."""
import subprocess,pathlib,uuid,time,os,json,hashlib
root=pathlib.Path(__file__).resolve().parents[2]
D=['/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker','--host','unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock']
nonce=uuid.uuid4().hex[:12];name='dvaia-http-receipt-'+nonce;database='dvaia_test_http_'+nonce
node=pathlib.Path.home()/'.dvaia/runtimes/node-v26.9.0-darwin-arm64/bin/node'
result={'name':name,'candidateOnly':False,'actualModel':False,'actualNetworkEffects':False}
files=['docs/modernization/drafts/mcp-http/0083_mcp_http_operations.candidate.sql','server/database/postgres/mcpHttpReceiptRepository.js','server/services/mcp/ownedHttpReceipt.js','tests/postgres/mcpHttpLifecycle.integration.test.js','tests/fixtures/mcpOwnedHttpReceipt.js']
files += ['server/services/mcp/ownedHttpClient.js','server/services/mcp/ownedHttpToolAdapter.js','sidecars/sandbox-runner/owned-http/canonical.js','server/services/mcp/sandboxShell.js']
files += [str(p.relative_to(root)) for p in sorted((root/'db/postgres/identity-migrations').glob('*.sql'))]
files += ['scripts/install/mcp-owned-http-setup.js','scripts/setup-application.js','db/postgres/workshop-migrations/mcp/0005_mcp_http_child_leases.sql','server/services/mcp/ownedQualification.js','server/services/mcp/ownedHttpCapability.js','scripts/install/mcp-owned-http-activate.js','server/services/mcp/ownedResourceComposition.js','server/services/mcp/ownedResourceApplication.js','server/services/mcp/ownedHttpCompositeTargets.js','server/database/postgres/mcpResourceRepository.js','server/database/postgres/mcpHttpLeaseRepository.js','docs/modernization/drafts/mcp-http/0005_mcp_http_child_leases.candidate.sql']
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
 run(D+['exec','-i',name,'psql','-h','127.0.0.1','-U','http_test_admin','-d','postgres','-v','ON_ERROR_STOP=1'],input='CREATE ROLE dvaia_identity_runtime LOGIN; CREATE ROLE dvaia_identity_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION; CREATE DATABASE '+database+' OWNER dvaia_identity_migration; CREATE ROLE dvaia_mcp_runtime LOGIN; CREATE ROLE dvaia_mcp_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION; CREATE DATABASE '+database+'_mcp OWNER dvaia_mcp_migration;')
 port=run(D+['port',name,'5432/tcp']).stdout.strip().rsplit(':',1)[1]
 env={k:os.environ[k] for k in ['HOME','PATH','TMPDIR'] if k in os.environ};env.update({k:os.environ[k] for k in ['MCP_HTTP_TEST_BASE_URL','MCP_HTTP_TEST_TOKEN'] if k in os.environ});env.update(PG_TEST_DISPOSABLE='yes',PG_HTTP_RUNTIME_URL=f'postgresql://dvaia_identity_runtime@127.0.0.1:{port}/{database}',PG_HTTP_MIGRATION_URL=f'postgresql://dvaia_identity_migration@127.0.0.1:{port}/{database}')
 env.update(PG_MCP_RUNTIME_URL=f'postgresql://dvaia_mcp_runtime@127.0.0.1:{port}/{database}_mcp',PG_MCP_MIGRATION_URL=f'postgresql://dvaia_mcp_migration@127.0.0.1:{port}/{database}_mcp',MCP_CLI_TEST_URL=os.environ['MCP_CLI_TEST_URL'],MCP_CLI_TEST_TOKEN=os.environ['MCP_CLI_TEST_TOKEN'])
 test=subprocess.run([str(node),'--test','tests/postgres/mcpHttpLifecycle.integration.test.js'],cwd=root,env=env,text=True,capture_output=True,timeout=120)
 result['actualNetworkEffects']='REAL_CLI_HTTP_APPLICATION_RESET_DELETION_DISABLED_DEBT_SIBLING_VERIFIED' in test.stdout
 result.update(exitCode=test.returncode,stdout=test.stdout,stderr=test.stderr,actualNetworkEffects='REAL_CLI_HTTP_APPLICATION_RESET_DELETION_DISABLED_DEBT_SIBLING_VERIFIED' in test.stdout)
finally:
 subprocess.run(D+['rm','-f',name],capture_output=True,timeout=15)
 result['containerAbsent']=not run(D+['ps','-aq','--filter','name=^/'+name+'$']).stdout.strip()
 result['sourceUnchanged']=all(hashlib.sha256((root/f).read_bytes()).hexdigest()==value for f,value in result['sourceHashes'].items())
 (root/'tasks/mcp-http-lifecycle-db-2026-09-19.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({key:value for key,value in result.items() if key not in ['stdout','stderr','sourceHashes']}))
 if result.get('exitCode')!=0:print(result.get('stdout',''),result.get('stderr',''));raise SystemExit(1)
