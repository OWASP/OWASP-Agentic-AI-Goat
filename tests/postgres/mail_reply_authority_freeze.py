"""Reply-authority-only immutable admission; importing performs no resource work."""
import argparse,json,subprocess
from pathlib import Path
from owned_mcp_assembly_freeze import NODE,record,dependencies,digest,sha
DOCKER_SHA='95fab203ab36bd2b4f3cd8a1d0dc6d084252f2ec224dc76bfbaebe1540cdd15e'
DAEMON_ID='2c9da9a7-1f8c-490b-af98-87bbf6bf83db'
NODE_SHA='56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
CURRICULUM='server/config/secureshopCurriculum.js'
NEEDLE="function isQualifiedObjective(objectiveId) { return QUALIFIED_OBJECTIVE_SET.has(objectiveId); }"
REPLACEMENT="function isQualifiedObjective(objectiveId) { return objectiveId === 'ss_mail_reply_redirect' || QUALIFIED_OBJECTIVE_SET.has(objectiveId); }"
SCRIPT=r'''const fs=require('node:fs'),path=require('node:path');const [source,dest]=process.argv.slice(1),base=require(path.join(source,'scripts/lib/isolated-source-copy')).createCopyFilter(source),omit=new Set(['server/platform_secrets.json','server/config/secrets.env']);const filter=p=>base(p)&&!fs.lstatSync(p).isSymbolicLink()&&!p.split(path.sep).includes('__pycache__')&&!p.endsWith('.pyc')&&!omit.has(path.relative(source,p).split(path.sep).join('/'));if(dest){fs.cpSync(source,dest,{recursive:true,filter});}else{const names=[];function walk(p){for(const e of fs.readdirSync(p,{withFileTypes:true})){const f=path.join(p,e.name);if(e.isSymbolicLink()||!filter(f))continue;if(e.isDirectory())walk(f);else names.push(path.relative(source,f).split(path.sep).join('/'));}}walk(source);console.log(JSON.stringify(names.sort()));}'''
def inventory(root):
 root=Path(root).resolve()
 names=json.loads(subprocess.run([str(NODE),'-e',SCRIPT,str(root)],capture_output=True,text=True,check=True,timeout=60).stdout)
 return {name:record(root/name) for name in names}
def copy(source,dest):
 subprocess.run([str(NODE),'-e',SCRIPT,str(source),str(dest)],check=True,timeout=120)
def verify(root,source_digest,dependency_digest):
 rows=inventory(root);deps=dependencies(root)
 if digest(rows)!=source_digest:raise RuntimeError('Reviewed reply source byte inventory mismatch')
 if digest(deps)!=dependency_digest:raise RuntimeError('Reviewed reply dependency byte inventory mismatch')
 return rows

def stage_expected(rows,source):
 import hashlib
 data=(Path(source)/CURRICULUM).read_bytes();text=data.decode('utf-8')
 if text.count(NEEDLE)!=1:raise RuntimeError('Exact reply candidate staging source mismatch')
 staged=text.replace(NEEDLE,REPLACEMENT).encode('utf-8')
 expected=dict(rows);expected[CURRICULUM]={'kind':'file','bytes':len(staged),'sha256':hashlib.sha256(staged).hexdigest()}
 return expected,staged

def check_pins(node,docker,daemon_id):
 if sha(node)!=NODE_SHA or sha(docker)!=DOCKER_SHA or daemon_id!=DAEMON_ID:raise RuntimeError('Reviewed reply runtime/Docker/daemon identity mismatch')

def main():
 p=argparse.ArgumentParser();p.add_argument('source');p.add_argument('output');a=p.parse_args()
 source=Path(a.source);rows=inventory(source);deps=dependencies(source)
 Path(a.output).write_text(json.dumps({'source':rows,'dependencies':deps,'sourceDigest':digest(rows),'dependencyDigest':digest(deps)},sort_keys=True))
if __name__=='__main__':main()
