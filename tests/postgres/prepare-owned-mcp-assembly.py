#!/usr/bin/env python3
"""Freeze reviewed MCP assembly source and dependency bytes; never launch resources."""
import argparse,json,os,shutil,subprocess,tempfile
from pathlib import Path
from owned_mcp_assembly_freeze import inventory,dependencies,digest,verify,sha
SOURCE=Path(__file__).resolve().parents[2]
NODE=Path('/Users/averma5/.owasp-ai-goat/runtimes/node-v26.10.0-darwin-arm64/bin/node')
NODE_SHA='56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--startup-only',action='store_true');parser.add_argument('--invocation-journal',action='store_true');parser.add_argument('--invocation-compile-only',action='store_true');parser.add_argument('--invocation-kernel-only',action='store_true');args=parser.parse_args()
 if sum([args.startup_only,args.invocation_journal,args.invocation_compile_only,args.invocation_kernel_only])>1:raise RuntimeError('Closed diagnostic modes are exclusive')
 if sha(NODE)!=NODE_SHA:raise RuntimeError('Node pin mismatch')
 root=Path(tempfile.mkdtemp(prefix='owasp-ai-goat-mcp-assembly-preflight-'));root.chmod(0o700);destination=root/'source';destination.mkdir(mode=0o700)
 source=inventory(SOURCE);deps=dependencies(SOURCE);source_sha,dependency_sha=digest(source),digest(deps)
 for name,row in source.items():
  original=SOURCE/name;target=destination/name;target.parent.mkdir(parents=True,exist_ok=True)
  if row['kind']=='symlink':
   if not original.resolve().is_relative_to(SOURCE):raise RuntimeError('Source symlink escapes workspace')
   target.symlink_to(row['target'])
  else:shutil.copy2(original,target)
 (destination/'node_modules').symlink_to(SOURCE/'node_modules',target_is_directory=True)
 verify(SOURCE,source_sha,dependency_sha);snapshot=verify(destination,source_sha,dependency_sha)
 controls=[('node',[str(NODE),'--test','tests/secureshopOwnedMcpAssemblyContracts.test.js',*(['tests/secureshopOwnedMcpInvocationJournal.test.js','tests/secureshopOwnedMcpInvocationLifecycle.test.js','tests/secureshopOwnedMcpInvocationRecovery.test.js','tests/secureshopOwnedMcpInvocationManager.test.js'] if args.invocation_journal else [])]),('python',['python3','-B','tests/postgres/test_owned_mcp_assembly_launcher.py'])]
 if args.invocation_compile_only or args.invocation_kernel_only:controls=[('node',[str(NODE),'--test','tests/secureshopOwnedMcpInvocationOsSource.test.js','tests/secureshopOwnedMcpInvocationManager.test.js','tests/secureshopOwnedMcpInvocationRecovery.test.js']),('python',['python3','-B','tests/postgres/test_owned_mcp_invocation_os_launcher.py'])]
 if args.invocation_kernel_only:controls.append(('python-shared',['python3','-B','tests/postgres/test_owned_mcp_assembly_launcher.py']))
 for label,argv in controls:
  result=subprocess.run(argv,cwd=destination,capture_output=True,text=True,timeout=30,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'});(root/(label+'-controls.log')).write_text(result.stdout+result.stderr)
  if result.returncode:raise RuntimeError(label+' controls failed')
 verify(destination,source_sha,dependency_sha)
 for name,row in source.items():
  if row['kind']=='file':(destination/name).chmod(0o400)
 # Root directory remains writable so execution-copy symlink creation cannot
 # mutate the frozen tree. File hashes are the authority; no shared deps edited.
 report={'status':'prepared-no-resources','source':str(destination),'snapshot':snapshot,'sourceManifest':source,'dependencyManifestSha256':dependency_sha,'nodeSha256':NODE_SHA,'bounds':{'parentSeconds':900,'buildSeconds':300,'childSeconds':480,'postgresMiB':1024,'executorMiB':512,'modelCalls':0,'browserCalls':0},'launchArgv':['python3','-B',str(destination/'tests/postgres/run-owned-mcp-assembly-isolated.py'),'--docker-host','unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock','--source-sha256',source_sha,'--dependency-sha256',dependency_sha,'--run'],'artifacts':{name:sha(root/name) for name in [label+'-controls.log' for label,argv in controls]},'resourceLaunch':False}
 if args.startup_only:
  report['bounds']={'parentSeconds':420,'buildSeconds':300,'startupSeconds':30,'childSeconds':0,'postgresMiB':0,'executorMiB':512,'modelCalls':0,'browserCalls':0}
  report['launchArgv'].append('--startup-only');report['scope']='startup-only diagnostic; no native assembly qualification'
 if args.invocation_journal:
  report['launchArgv'].append('--invocation-journal');report['scope']='Invocation journal SQL with controlled manager; five owned databases, canonical agents role pair shared by fresh and upgrade stores; no remote invocation qualification'
 if args.invocation_compile_only:
  report['bounds']={'parentSeconds':600,'buildSeconds':300,'childSeconds':0,'postgresMiB':0,'modelCalls':0,'browserCalls':0}
  report['launchArgv'][2]=str(destination/'tests/postgres/run-owned-mcp-invocation-os-isolated.py');report['launchArgv'].append('--compile-only');report['scope']='Invocation Linux compilation and image asset checks only; no kernel, database, model, browser, network or container launch'
 if args.invocation_kernel_only:
  report['bounds']={'parentSeconds':600,'workSeconds':510,'buildSeconds':300,'childSeconds':180,'cleanupSeconds':75,'postgresMiB':0,'executorMiB':512,'cpus':1,'pids':128,'modelCalls':0,'browserCalls':0}
  report['launchArgv'][2]=str(destination/'tests/postgres/run-owned-mcp-invocation-os-isolated.py');report['launchArgv'].append('--kernel-only');report['scope']='Owned invocation kernel qualification only; isolated image/private volume/internal network/tunnel; no database/model/browser or installed serving claim'
 (root/'preflight.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'root':str(root),'preflightSha256':sha(root/'preflight.json'),**snapshot}))
if __name__=='__main__':main()
