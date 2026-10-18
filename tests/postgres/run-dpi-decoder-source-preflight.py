#!/usr/bin/env python3
"""Source-only owned decoder controls; never provisions databases or invokes real models."""
import hashlib,json,os,pathlib,subprocess,tempfile
source=pathlib.Path(__file__).resolve().parents[2]
node=pathlib.Path('/Users/averma5/.dvaia/runtimes/node-v26.10.0-darwin-arm64/bin/node')
digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert digest(node)=='56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
root=pathlib.Path(tempfile.mkdtemp(prefix='dvaia-dpi-decoder-source-'));os.chmod(root,0o700)
tests=['dpiObfuscationGraph','dpiAnswerComparison','dpiStructuredJudge','dpiScopedAlignment','objectiveJudge','objectiveJudgmentRepositoryMetadata','secureshopMailReplyComparison','secureshopMailGroundedComparison']
subprocess.run([str(node),'-e',"const fs=require('node:fs'),path=require('node:path'),{createCopyFilter}=require('./scripts/lib/isolated-source-copy');for(const name of ['server','shared','db/postgres','tests/fixtures'])if(fs.existsSync(path.join(process.argv[1],name)))fs.cpSync(path.join(process.argv[1],name),path.join(process.argv[2],name),{recursive:true,filter:createCopyFilter(process.argv[1])});",str(source),str(root)],cwd=source,check=True,timeout=30)
for name in [*[f'tests/{x}.test.js' for x in tests],'tests/postgres/run-dpi-decoder-source-preflight.py','package.json','package-lock.json']:
 dest=root/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes((source/name).read_bytes())
(root/'node_modules').symlink_to(source/'node_modules',target_is_directory=True)
state={'status':'preparing','noModel':True,'noDatabase':True,'noBrowser':True,'launcherPid':os.getpid(),'nodeSha256':digest(node),'sourceSha256':{str(p.relative_to(root)):digest(p) for p in root.rglob('*') if p.is_file()}}
(root/'ownership.json').write_text(json.dumps(state,indent=2)+'\n')
with (root/'tests.log').open('w') as log:
 result=subprocess.run([str(node),'--test',*[f'tests/{x}.test.js' for x in tests]],cwd=root,env={'PATH':str(node.parent)+':/usr/bin:/bin','AI_PROVIDER':'mock'},stdout=log,stderr=log,timeout=60)
assert all(digest(root/n)==h for n,h in state['sourceSha256'].items())
state.update(status='prepared' if result.returncode==0 else 'failed',logSha256=digest(root/'tests.log'),allFrozenHashesVerified=True)
(root/'ownership.json').write_text(json.dumps(state,indent=2)+'\n');print(json.dumps({'root':str(root),'status':state['status'],'sourceFiles':len(state['sourceSha256'])}))
raise SystemExit(result.returncode)
