import os,pathlib,tempfile,subprocess,secrets,json,time,hashlib,signal,shutil,sys
repo=pathlib.Path('/Users/averma5/Documents/github/Damn-Vulnerable-AI-Application')
root=pathlib.Path(tempfile.mkdtemp(prefix='dvaia-ipi-document-rendered-'));os.chmod(root,0o700);workspace=root/'source'
node='/Users/averma5/.dvaia/runtimes/node-v26.9.0-darwin-arm64/bin/node'
docker=['/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker','--host','unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock']
image='sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
env={'PATH':str(pathlib.Path(node).parent)+':/usr/bin:/bin','HOME':os.environ['HOME'],'TMPDIR':str(root)}
nonce=secrets.token_hex(6);name='dvaia-workshop-rag-'+nonce;cid=None;child=None;result=1;cleaned=False
actual='--actual' in sys.argv
restore='--restore' in sys.argv
sha=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def receipt(name,value):
 p=root/name;p.write_text(json.dumps(value,indent=2)+'\n');os.chmod(p,0o600)
def run(args):return subprocess.run(args,check=True,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=120).stdout.strip()
def absent(pid,group=False):
 try:(os.killpg if group else os.kill)(pid,0);return False
 except ProcessLookupError:return True
try:
 subprocess.run([node,'-e',"require('./scripts/lib/isolated-source-copy').copyIsolatedSource(process.argv[1],process.argv[2])",str(repo),str(workspace)],cwd=repo,env=env,check=True,timeout=120)
 (workspace/'node_modules').symlink_to(repo/'node_modules',target_is_directory=True)
 (workspace/'client/node_modules').symlink_to(repo/'client/node_modules',target_is_directory=True)
 files=['client/src/components/workshop/WorkshopExperience.js','client/src/pages/challenges/IndirectPromptInjectionChallenge.js','client/src/components/workshop/useWorkshopResetController.js','client/src/context/AuthContext.js','server/routes/ragInjection.js','server/services/workshopRagReadiness.js','server/services/workshopRagComposition.js','server/services/csrfDurableRagResources.js','server/services/workshopRagStore.js','server/services/ragVectorStore.js','server/services/embeddingRuntimeFingerprint.js','server/services/secureshopProductEmbedder.js','server/database/postgres/workshopRagRepository.js','server/database/postgres/workshopRagRevisionRepository.js','docs/modernization/drafts/workshop-rag/0082_workshop_rag_sources.candidate.sql','tests/postgres/ipiDocumentRendered.integration.test.js','tests/fixtures/workshopRagStoreRestore.cjs','package.json','package-lock.json']
 receipt('source-hashes.json',{f:sha(workspace/f) for f in files})
 receipt('migration-hashes.json',{p.name:sha(p) for p in sorted((workspace/'db/postgres/identity-migrations').glob('*.sql'))})
 if actual:
  cache=pathlib.Path('/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/dvaia-embedding-430-255u6f1z/cache')
  if not cache.is_dir():raise RuntimeError('Reviewed public model cache unavailable')
  shutil.copytree(cache,workspace/'model-cache')
  env.update(XENOVA_CACHE=str(workspace/'model-cache'),HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1',WORKSHOP_RAG_ACTUAL_EMBEDDING='1')
 receipt('container-intent.json',{'name':name,'image':image,'ownerLabel':nonce})
 cid=run(docker+['run','--detach','--pull','never','--name',name,'--label','dvaia.test.owner='+nonce,'-e','POSTGRES_HOST_AUTH_METHOD=trust','-p','127.0.0.1::5432',image])
 receipt('container-created.json',{'name':name,'id':cid})
 for attempt in range(60):
  try:run(docker+['exec',cid,'pg_isready','-h','127.0.0.1','-U','postgres']);break
  except subprocess.CalledProcessError:time.sleep(.25)
 else:raise RuntimeError('Owned database unavailable')
 port=run(docker+['port',cid,'5432/tcp']).split(':')[-1]
 base=docker+['exec',cid,'psql','-h','127.0.0.1','-U','postgres','-v','ON_ERROR_STOP=1','-c']
 run(base+['CREATE ROLE dvaia_identity_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE dvaia_identity_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;'])
 db='dvaia_test_workshop_rag_'+nonce;run(base+[f'CREATE DATABASE {db} OWNER dvaia_identity_migration'])
 if restore:env['WORKSHOP_RAG_CHILD_RESTORE']='1'
 env.update(PG_TEST_DISPOSABLE='yes',WORKSHOP_RAG_ROUTES_NATIVE='1',DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace),WORKSHOP_RAG_EVIDENCE_PATH=str(root/'service-evidence.json'))
 for role in ['migration','runtime']:env['WORKSHOP_RAG_'+role.upper()+'_URL']=f'postgresql://dvaia_identity_{role}@127.0.0.1:{port}/{db}'
 with open(root/'tests.log','w') as output:
  child=subprocess.Popen([node,'--test','tests/postgres/ipiDocumentRendered.integration.test.js'],cwd=workspace,env=env,stdout=output,stderr=output,start_new_session=True)
  receipt('child-intent.json',{'pid':child.pid,'pgid':child.pid});result=child.wait(timeout=240)
finally:
 if child and child.poll() is None:
  os.killpg(child.pid,signal.SIGTERM)
  try:child.wait(timeout=5)
  except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=5)
 if cid:
  owned=json.loads(run(docker+['inspect',cid]))[0]
  if owned['Config']['Labels'].get('dvaia.test.owner')!=nonce:raise RuntimeError('Ownership changed')
  run(docker+['rm','--force','--volumes',cid]);cleaned=not run(docker+['ps','--all','--quiet','--filter','id='+cid])
 evidence={'directory':str(root),'exitCode':result,'actualEmbedding':actual,'containerId':cid,'containerRemoved':cleaned,'pidAbsent':child is None or absent(child.pid),'pgidAbsent':child is None or absent(child.pid,True)}
 receipt('result.json',evidence);(repo/'tasks/ipi-document-rendered-2026-09-19.json').write_text(json.dumps(evidence,indent=2)+'\n');print(json.dumps(evidence))
sys.exit(result)
