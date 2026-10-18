'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path'),{spawnSync}=require('node:child_process');
const root=path.resolve(__dirname,'..');
test('controlled SSRF launcher copies and verifies every reviewed non-helper input without Docker',()=>{
  const source=String.raw`
import ast,os,shutil,sys
from pathlib import Path
root=Path(sys.argv[1]);sys.path.insert(0,str(root/'tests/postgres'))
from secureshop_ssrf_source_copy import copy_ssrf_source
from native_source_provenance import verify_source_copy
tree=ast.parse((root/'tests/postgres/run-secureshop-ssrf-isolated.py').read_text());tracked=None
for node in ast.walk(tree):
 if isinstance(node,ast.Assign) and any(isinstance(item,ast.Name) and item.id=='tracked' for item in node.targets):
  tracked=ast.literal_eval(node.value);break
assert tracked and len(tracked)==len(set(tracked))
copied=Path('/virtual/dvaia-ssrf-source-copy/source');virtual={};links={}
real_read=Path.read_bytes;real_file=Path.is_file;real_mkdir=Path.mkdir;real_link=Path.symlink_to
def is_virtual(p): return p==copied or copied in p.parents
def read(p): return real_read(virtual[str(p)]) if is_virtual(p) else real_read(p)
def file(p): return str(p) in virtual if is_virtual(p) else real_file(p)
def mkdir(p,*a,**kw):
 if not is_virtual(p): return real_mkdir(p,*a,**kw)
def link(p,target,**kw):
 assert is_virtual(p);links[str(p)]=str(target)
def copy2(src,dst,*a,**kw):
 src=Path(src);dst=Path(dst);assert is_virtual(dst);virtual[str(dst)]=src
def copytree(src,dst,ignore):
 src=Path(src);dst=Path(dst)
 names=os.listdir(src);denied=set(ignore(str(src),names))
 for name in names:
  if name in denied: continue
  item=src/name
  assert not item.is_symlink(),str(item)
  if item.is_dir(): copytree(item,dst/name,ignore)
  else: copy2(item,dst/name)
Path.read_bytes=read;Path.is_file=file;Path.mkdir=mkdir;Path.symlink_to=link
shutil.copytree=copytree;shutil.copy2=copy2
def ignore(_directory,names):
 denied={'.git','node_modules','build','logs','uploads','sensitive_files','workshop_data','vector-indexes','coverage','.cache','__pycache__'}
 return [name for name in names if name in denied or name.startswith('.env') or any(name.endswith(suffix) for suffix in ['.db','.db-wal','.db-shm','.db-journal','.sqlite','.sqlite3','.log'])]
copy_ssrf_source(root,copied,ignore)
copy_tracked=[name for name in tracked if name!='scripts/register-native-owner-handle.py']
expected={name:__import__('hashlib').sha256((root/name).read_bytes()).hexdigest() for name in copy_tracked}
assert verify_source_copy(root,copied,copy_tracked,granted=expected)==expected
assert str(copied/'server/config/secrets.env') not in virtual
assert str(copied/'server/platform_secrets.json') not in virtual
assert not any(Path(name).name.startswith('.env') for name in virtual)
assert not any(Path(name).suffix == '.db' for name in virtual)
assert not copied.exists()
print(len(copy_tracked))
`;
  const result=spawnSync('python3',['-c',source,root],{encoding:'utf8',timeout:15000,env:{...process.env,PYTHONDONTWRITEBYTECODE:'1'}});
  assert.equal(result.status,0,result.stderr);assert.match(result.stdout,/^\d+\n$/);
});

test('controlled SSRF PostgreSQL contract uses the isolated policy tool without importing the commerce summarizer',()=>{
  const contract=require('node:fs').readFileSync(path.join(root,'tests/postgres/secureshopSsrf.integration.test.js'),'utf8');
  const launcher=require('node:fs').readFileSync(path.join(root,'tests/postgres/run-secureshop-ssrf-isolated.py'),'utf8');
  assert.doesNotMatch(contract,/^const \{createServer:createSummarizerServer\}=require/m);
  assert.doesNotMatch(contract,/agent-host\/agents\/summarizer\/server/);
  assert.match(contract,/async function protocol\(t\)[\s\S]*require\('\.\.\/\.\.\/agent-host\/shared\/graphServer'\)/);
  assert.match(contract,/async function protocol\(t\)[\s\S]*require\('\.\.\/\.\.\/agent-host\/agents\/summarizer\/tools\/explain_return_policy'\)/);
  assert.doesNotMatch(contract,/closeSecureShopPools/);
  assert.match(launcher,/\('commerce','dvaia_secureshop_migration','dvaia_secureshop_runtime'\)/);
  assert.match(launcher,/SECURESHOP_DATABASE_URL=urls\['commerce'\]\['runtime'\]/);
  assert.match(launcher,/SECURESHOP_MIGRATION_DATABASE_URL=urls\['commerce'\]\['migration'\]/);
});
