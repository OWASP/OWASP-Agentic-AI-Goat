#!/usr/bin/env python3
"""Owned model-free protected-operation uncertainty and journal qualification."""
import pathlib,tempfile,subprocess,uuid,time,json,os,hashlib
root=pathlib.Path(__file__).resolve().parents[2];work=pathlib.Path(tempfile.mkdtemp(prefix='dvaia-protected-lostack-native-'));source=work/'source';source.mkdir();node=str(pathlib.Path.home()/'.dvaia/runtimes/node-v26.9.0-darwin-arm64/bin/node');name='dvaia-protected-'+uuid.uuid4().hex[:12];D=['/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker','--host','unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'];out={'workspace':str(work),'container':name,'actualModel':False}
def run(a,**kw):return subprocess.run(a,check=True,text=True,capture_output=True,**kw)
try:
 code="const fs=require('fs'),path=require('path'),{createCopyFilter}=require('./scripts/lib/isolated-source-copy');for(const name of ['server','db','tests','sidecars','scripts'])fs.cpSync(name,path.join(process.argv[1],name),{recursive:true,filter:createCopyFilter(process.cwd())});for(const name of ['package.json','package-lock.json'])fs.copyFileSync(name,path.join(process.argv[1],name));fs.symlinkSync(path.join(process.cwd(),'node_modules'),path.join(process.argv[1],'node_modules'));"
 run([node,'-e',code,str(source)],cwd=root)
 run(D+['run','-d','--pull','never','--name',name,'--label','dvaia.owner='+name,'--tmpfs','/var/lib/postgresql:rw,size=536870912','-e','POSTGRES_USER=owned_admin','-e','POSTGRES_HOST_AUTH_METHOD=trust','-p','127.0.0.1::5432','postgres:18'])
 for _ in range(80):
  if subprocess.run(D+['exec',name,'pg_isready','-h','127.0.0.1','-U','owned_admin'],capture_output=True).returncode==0:break
  time.sleep(.25)
 run(D+['exec','-i',name,'psql','-h','127.0.0.1','-U','owned_admin','-v','ON_ERROR_STOP=1','-d','postgres'],input='CREATE ROLE dvaia_identity_migration LOGIN;CREATE ROLE dvaia_identity_runtime LOGIN;CREATE DATABASE dvaia_test_lostack OWNER dvaia_identity_migration;')
 port=run(D+['port',name,'5432/tcp']).stdout.strip().rsplit(':',1)[1]
 env={k:os.environ[k] for k in ['HOME','PATH','TMPDIR'] if k in os.environ};env.update(PG_TEST_DISPOSABLE='yes',NODE_ENV='test',WORKSHOP_DATABASE_ENGINE='postgres',PLATFORM_DATABASE_ENGINE='postgres',PG_GRAPH_TEST_RUNTIME_URL=f'postgresql://dvaia_identity_runtime@127.0.0.1:{port}/dvaia_test_lostack',PG_GRAPH_TEST_MIGRATION_URL=f'postgresql://dvaia_identity_migration@127.0.0.1:{port}/dvaia_test_lostack')
 files=['tests/postgres/mcpProtectedLostAck.integration.test.js','tests/helpers/mcpProtectedTargetFixture.js','sidecars/sandbox-runner/mcpTargets.js','sidecars/sandbox-runner/protected-operations/operationStore.js','sidecars/sandbox-runner/ownedTargetApi.js','sidecars/sandbox-runner/Dockerfile','server/services/mcp/sandboxShell.js','server/services/mcp/ownedTargetClient.js','server/services/mcp/sdk/vulnerableMcpServer.js','server/services/mcp/protocolContext.js','server/agent-runtime/postgresRunLedger.js','sidecars/sandbox-runner/mcpProtectedState.js'];out['hashes']={f:hashlib.sha256((source/f).read_bytes()).hexdigest() for f in files}
 r=subprocess.run([node,'--test','tests/postgres/mcpProtectedLostAck.integration.test.js'],cwd=source,env=env,capture_output=True,text=True,timeout=120);(work/'result.log').write_text(r.stdout+r.stderr);out['exitCode']=r.returncode;print(r.stdout[-3000:]+r.stderr[-1000:]);out['sourceUnchanged']=all(hashlib.sha256((root/f).read_bytes()).hexdigest()==h for f,h in out['hashes'].items())
finally:
 inspect=subprocess.run(D+['inspect','--format','{{index .Config.Labels "dvaia.owner"}}',name],capture_output=True,text=True)
 if inspect.returncode==0 and inspect.stdout.strip()==name:run(D+['rm','-f',name])
 out['containerAbsent']=not run(D+['ps','-aq','--filter','name=^/'+name+'$']).stdout.strip();(root/'tasks/mcp-protected-journal-connected-native-2026-09-19.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out))
