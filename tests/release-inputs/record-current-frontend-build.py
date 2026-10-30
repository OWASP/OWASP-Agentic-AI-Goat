#!/usr/bin/env python3
"""Main application and six-renderer build receipt. Import inert; --execute is root's launch gate."""
import argparse,hashlib,importlib.util,json,os,signal,stat,subprocess,sys,tempfile,time
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2]
AREA=Path(__file__).resolve().parent
REPO_NODE=ROOT/'tasks/runtime/node/node_modules/node/bin/node'
REVIEWED_NPM=Path('/opt/homebrew/lib/node_modules/npm/bin/npm-cli.js')
REVIEWED_NPM_ALIAS=Path('/opt/homebrew/bin/npm')
def digest(p):
 with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def fingerprint(v):return hashlib.sha256(encoded(v)).hexdigest()
def inventory(root,exclude=()):
 root=Path(root);result={}
 if root.is_symlink() or root.resolve()!=root:raise ValueError('Noncanonical inventory root')
 for directory,dirs,files in os.walk(root,followlinks=False):
  if Path(directory)==root:dirs[:]=[n for n in dirs if n not in exclude];files=[n for n in files if n not in exclude]
  for name in sorted(dirs+files):
   p=Path(directory)/name;st=p.lstat();rel=p.relative_to(root).as_posix()
   if p.is_symlink():
    if not p.resolve().is_relative_to(root):raise ValueError('Link outside inventoried root')
    result[rel]={'link':os.readlink(p)}
   elif p.is_dir():result[rel]={'mode':st.st_mode&0o777,'directory':True}
   elif p.is_file():
    sha=digest(p);after=p.lstat()
    if (st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):raise ValueError('File changed during inventory')
    result[rel]={'mode':st.st_mode&0o777,'sha256':sha}
   else:raise ValueError('Unsupported file type')
 return result
def inputs(root):
 env={}
 for base in [root,root/'client']:
  for p in sorted(base.glob('.env*')):
   if p.is_symlink() or not p.is_file():raise ValueError('Invalid environment file')
   env[str(p.relative_to(root))]=digest(p)
 return {'clientSourceInventory':inventory(root/'client/src'),'clientPublicInventory':inventory(root/'client/public'),
 'clientDependencyInventory':inventory(root/'client/node_modules'),'rootDependencyInventory':inventory(root/'node_modules'),
 'clientInputs':inventory(root/'client',('node_modules','build','.git')),'rootBuildScripts':inventory(root/'scripts'),
 'rootPackagePins':{n:digest(root/n) for n in ['package.json','package-lock.json','.npmrc'] if (root/n).exists()},'environmentPins':env,
 'recorderPins':{n:digest(root/n) for n in ['tests/release-inputs/record-current-frontend-build.py','tests/postgres/sql_nosql_process_ownership.py','tests/postgres/darwin_process_inventory.py']}}
def private_inputs(root):
 # Explicit build closure: never enumerate or read installation environment files.
 names=['package.json','package-lock.json','client/package.json','client/package-lock.json',
        'client/index.html','client/secureshop-frame.html','client/vite.config.mjs',
        'client/vite.review-renderer.config.mjs','client/vite.product-description-renderer.config.mjs',
        'client/vite.mail-renderer.config.mjs','client/vite.ticket-renderer.config.mjs','client/vite.search-echo-renderer.config.mjs','client/vite.policy-output-renderer.config.mjs','client/vite.opaque-frame-cors.mjs']
 return {'clientSourceInventory':inventory(root/'client/src'),'clientPublicInventory':inventory(root/'client/public'),
 'clientDependencyInventory':inventory(root/'client/node_modules'),'rootDependencyInventory':inventory(root/'node_modules'),
 'configPins':{n:digest(root/n) for n in names},
 'recorderPins':{n:digest(root/n) for n in ['tests/release-inputs/record-current-frontend-build.py','tests/postgres/sql_nosql_process_ownership.py','tests/postgres/darwin_process_inventory.py']}}
def private_env(root,private,node):
 env=clean_env(root,private,node);output=private/'output/application'
 env.update(BUILD_PATH=str(output),OWASP_AI_GOAT_VITE_ENV_DIR=str(private/'env'),TMP=str(private/'tmp'),TEMP=str(private/'tmp'),XDG_CACHE_HOME=str(private/'cache'))
 for key,name in [('REVIEW','review'),('PRODUCT_DESCRIPTION','product-description'),('MAIL','mail'),('TICKET','ticket'),('SEARCH_ECHO','search-echo'),('POLICY_OUTPUT','policy-output')]:env['SECURESHOP_'+key+'_RENDERER_OUT_DIR']=str(output/('secureshop-'+name+'-renderer'))
 return env
def validate_renderers(root,build):
 specs=[('review','SecureShop.ReviewCard','ReviewCard.jsx',None,'renderer.cjs'),
        ('product-description','SecureShop.Product.Description','ProductDescription.jsx',None,'renderer.cjs'),
        ('mail','SecureShop.MailMessageBody','MailMessageBody.jsx','mailMessageClientRenderer.jsx','renderer.js'),
        ('ticket','SecureShop.AdminTicketBody','AdminTicketBody.jsx','ticketDetailClientRenderer.jsx','renderer.js'),
        ('search-echo','SecureShop.SearchEcho','AgentLane/SearchEcho.jsx','searchEchoClientRenderer.jsx','renderer.js'),
        ('policy-output','SecureShop.PolicyFinalResponse','AgentLane/Turn.jsx','policyOutputClientRenderer.jsx','renderer.js')]
 for name,component,source,entry,artifact_name in specs:
  directory=build/('secureshop-'+name+'-renderer')
  if directory.resolve()!=directory or (directory/'manifest.json').is_symlink():raise RuntimeError('Noncanonical renderer output')
  manifest=json.loads((directory/'manifest.json').read_text())
  keys=['version','component','source','sourceSha256','artifact','artifactSha256']+(['entry','entrySha256'] if entry else [])
  prefix='client/src/pages/secureshop/components/'
  expected_entry=('client/src/pages/secureshop/' if name in ('search-echo','policy-output') else prefix)+entry if entry else None
  if set(manifest)!=set(keys) or manifest['version']!=1 or manifest['component']!=component or manifest['source']!=prefix+source or manifest['artifact']!=artifact_name or entry and manifest['entry']!=expected_entry:raise RuntimeError('Renderer manifest mismatch')
  for key in ['source']+(['entry'] if entry else []):
   rel=Path(manifest[key]);target=root/rel
   if rel.is_absolute() or '..' in rel.parts or target.resolve()!=target or not target.is_relative_to(root/'client/src') or digest(target)!=manifest[key+'Sha256']:raise RuntimeError('Renderer source mismatch')
  artifact=Path(manifest['artifact'])
  if (directory/artifact).resolve()!=directory/artifact:raise RuntimeError('Noncanonical renderer artifact')
  if artifact.name!=str(artifact) or digest(directory/artifact)!=manifest['artifactSha256']:raise RuntimeError('Renderer artifact mismatch')
def private_command(node):
 return [str(node),'--input-type=module','-e',"import {build} from 'vite'; import path from 'node:path'; for (const name of ['vite.config.mjs','vite.review-renderer.config.mjs','vite.product-description-renderer.config.mjs','vite.mail-renderer.config.mjs','vite.ticket-renderer.config.mjs','vite.search-echo-renderer.config.mjs','vite.policy-output-renderer.config.mjs']) { await build({root:process.cwd(),configFile:path.resolve(name),configLoader:'native',envDir:process.env.OWASP_AI_GOAT_VITE_ENV_DIR,cacheDir:path.join(process.env.TMPDIR,'vite-cache')}); }"]
def clean_env(root,private,node,*,repository_only=False):
 search_path=str(node.parent)+(':/opt/homebrew/bin' if repository_only else '')+':/usr/bin:/bin:/usr/sbin:/sbin'
 env={'PATH':search_path,'TMPDIR':str(private/'tmp'),
 'CI':'true','NODE_ENV':'production','BUILD_PATH':str(root/'client/build'),'npm_config_cache':str(private/'npm-cache'),
 'npm_config_update_notifier':'false','npm_config_audit':'false','npm_config_fund':'false','npm_config_offline':'true'}
 if repository_only:
  env.update(TMP=str(private/'tmp'),TEMP=str(private/'tmp'),XDG_CACHE_HOME=str(private/'cache'),
   XDG_CONFIG_HOME=str(private/'config'),npm_config_userconfig=str(private/'npmrc'))
 else:env['HOME']=str(private/'home')
 return env
def save(p,value):
 with Path(p).open('xb') as f:os.fchmod(f.fileno(),0o600);f.write(encoded(value)+b'\n');f.flush();os.fsync(f.fileno())
 fd=os.open(Path(p).parent,os.O_RDONLY)
 try:os.fsync(fd)
 finally:os.close(fd)
def process_inventory():
 helper=ROOT/'tests/postgres/darwin_process_inventory.py'
 spec=importlib.util.spec_from_file_location('frontend_build_process_inventory',helper)
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 return module
def capture_birth(pid):
 if sys.platform!='darwin':raise RuntimeError('Build launch birth witness requires Darwin')
 row=process_inventory().LibProc().identity(pid)
 if row is None or row.pid!=pid or row.pgid!=pid or row.uid!=os.getuid() or os.getsid(pid)!=pid:
  raise RuntimeError('Build launch birth witness unavailable')
 return (row.start_sec,row.start_usec)
def native_members(pgid,births,witness):
 module=process_inventory();api=module.LibProc()
 found=module.owned_group_members(pgid,api=api,births=births)
 if found:
  row=api.identity(pgid)
  if row is None or row.pid!=pgid or row.pgid!=pgid or row.uid!=os.getuid() or os.getsid(pgid)!=pgid or (row.start_sec,row.start_usec)!=witness:
   raise RuntimeError('Original build group birth is unavailable or changed')
 return found
def members(pgid,births=None,witness=None):
 if sys.platform=='darwin':return native_members(pgid,births,witness)
 out=subprocess.run(['/bin/ps','-axo','pid=,pgid=,uid='],capture_output=True,text=True,check=True,timeout=3).stdout;found=[]
 for line in out.splitlines():
  pid,group,uid=map(int,line.split())
  if group!=pgid:continue
  try:
   if uid!=os.getuid() or os.getsid(pid)!=pgid:raise RuntimeError('Unknown process membership')
  except ProcessLookupError:continue
  found.append(pid)
 return found
def stop(child,pgid,sid,witness):
 if pgid!=sid or pgid!=child.pid:raise RuntimeError('Process identity mismatch')
 if not isinstance(witness,tuple) or len(witness)!=2 or any(type(value)!=int or value<0 for value in witness):raise RuntimeError('Build launch birth witness is missing')
 births={}
 for sig,seconds in [(signal.SIGTERM,5),(signal.SIGKILL,5)]:
  if members(pgid,births,witness):
   try:os.killpg(pgid,sig)
   except ProcessLookupError:pass
  end=time.monotonic()+seconds
  while time.monotonic()<end:
   child.poll()
   if not members(pgid,births,witness):break
   time.sleep(.05)
 child.wait(timeout=3)
 if members(pgid,births,witness):raise RuntimeError('Owned build processes remain')
def runtime_path(path,sha256,label,*,executable=False):
 path=Path(path)
 if not path.is_absolute() or path.is_symlink() or path.resolve()!=path or not path.is_file() or not stat.S_ISREG(path.stat().st_mode):raise RuntimeError(f'{label} path is not canonical')
 if executable and not os.access(path,os.X_OK):raise RuntimeError(f'{label} is not executable')
 if len(sha256)!=64 or any(ch not in '0123456789abcdef' for ch in sha256) or digest(path)!=sha256:raise RuntimeError(f'{label} runtime pin mismatch')
 return path
def validate_nested_npm_alias(npm,alias=REVIEWED_NPM_ALIAS):
 alias=Path(alias)
 if not alias.is_symlink() or alias.resolve()!=Path(npm) or not os.access(alias,os.X_OK):
  raise RuntimeError('Repository-only nested npm alias does not resolve to pinned CLI')
 return alias
def repository_evidence_parent():
 parent=ROOT/'tasks/qualification'
 if parent.is_symlink() or parent.resolve()!=parent or not parent.is_dir() or parent.stat().st_uid!=os.getuid() or parent.stat().st_mode&0o077:raise RuntimeError('Repository evidence parent is not private')
 return parent
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--execute',action='store_true');parser.add_argument('--private-external-output',action='store_true');parser.add_argument('--repository-only',action='store_true');parser.add_argument('--node',required=True);parser.add_argument('--node-sha256',required=True);parser.add_argument('--npm-cli',required=True);parser.add_argument('--npm-sha256',required=True);args=parser.parse_args()
 # The paired flags mean private output inside this checkout's owned evidence parent.
 node=runtime_path(args.node,args.node_sha256,'Node',executable=True)
 npm=runtime_path(args.npm_cli,args.npm_sha256,'npm CLI')
 if args.repository_only:
  if node!=REPO_NODE or npm!=REVIEWED_NPM:raise RuntimeError('Repository-only runtime path mismatch')
  validate_nested_npm_alias(npm, REVIEWED_NPM_ALIAS)
 command=private_command(node) if args.private_external_output else [str(node),str(npm),'--prefix','client','run','build']
 if not args.execute:print(json.dumps({'execute':False,'command':command}));return
 os.umask(0o077)
 evidence_parent=repository_evidence_parent() if args.repository_only else None if args.private_external_output else AREA
 out=Path(tempfile.mkdtemp(prefix='frontend-build-',dir=evidence_parent)).resolve();os.chmod(out,0o700)
 for name in ['home','tmp','npm-cache','env','cache','config']:(out/name).mkdir(mode=0o700)
 (out/'npmrc').touch(mode=0o600,exist_ok=False)
 build=out/'output/application' if args.private_external_output else ROOT/'client/build'
 capture=private_inputs if args.private_external_output else inputs
 environment=private_env(ROOT,out,node) if args.private_external_output else clean_env(ROOT,out,node,repository_only=args.repository_only)
 cwd=ROOT/'client' if args.private_external_output else ROOT
 if build.is_symlink() or build.resolve()!=build:raise RuntimeError('Unsafe build output')
 before=capture(ROOT);save(out/'inputs-before.json',before)
 helper=ROOT/'tests/postgres/sql_nosql_process_ownership.py'
 spec=importlib.util.spec_from_file_location('build_owned',helper);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
 children=[];birth_witnesses={}
 def record_child(row):
  if row['status']=='registered':
   try:
    birth_witnesses[row['pid']]=capture_birth(row['pid'])
   except BaseException:
    row={**row,'birthWitness':'unavailable'}
    children.append(row);save(out/('process-%03d.json'%len(children)),row)
    raise
   row={**row,'birthSec':birth_witnesses[row['pid']][0],'birthUsec':birth_witnesses[row['pid']][1]}
  children.append(row);save(out/('process-%03d.json'%len(children)),row)
 save(out/'intent.json',{'command':command,'cwd':str(cwd),'nodeSha256':args.node_sha256,'npmSha256':args.npm_sha256,'inputSha256':fingerprint(before),'output':str(build),'environmentKeys':sorted(environment)})
 owned=mod.OwnedProcesses(lambda child,pgid,sid:stop(child,pgid,sid,birth_witnesses.get(child.pid)),record_child);owned.install();code=None;error=None;cleanup=None
 started=time.time();log=out/'build.log'
 try:
  with log.open('xb') as stream:
   child=owned.launch(command,name='frontend-build',cwd=cwd,env=environment,stdout=stream,stderr=subprocess.STDOUT,start_new_session=True)
   until=time.monotonic()+600
   while child.poll() is None:
    if time.monotonic()>until or log.stat().st_size>32*1024*1024:raise TimeoutError('Build work/log limit')
    time.sleep(.2)
   code=child.returncode;stream.flush();os.fsync(stream.fileno())
 except BaseException as e:error=type(e).__name__
 finally:
  owned.mask_cleanup_signals()
  try:owned.cleanup()
  except BaseException as e:cleanup=type(e).__name__
  owned.restore()
 after=None;output={};postError=None
 try:
  after=capture(ROOT);output=inventory(build)
  if args.private_external_output:
   if list((out/'env').iterdir()):raise RuntimeError('Private build environment changed')
   validate_renderers(ROOT,build)
 except BaseException as e:postError=type(e).__name__
 save(out/'inputs-after.json',after);save(out/'output.json',output)
 receipt={'version':'current-frontend-build-v1','inputMode':'private-repository-v1' if args.private_external_output and args.repository_only else 'private-external-v1' if args.private_external_output else 'legacy','repositoryOnly':args.repository_only,'outputRoot':str(build),'workspace':str(ROOT),'command':command,'exitCode':code,'error':error,'cleanupError':cleanup,'children':children,
 'startedAt':started,'finishedAt':time.time(),'runtimePins':{'node':{'path':str(node),'sha256':digest(node)},'npm':{'path':str(npm),'sha256':digest(npm)}},
 'postError':postError,'logSha256':digest(log),'beforeAfterInputsEqual':before==after,'buildInputInventorySha256':fingerprint(before),'clientBuildInventorySha256':fingerprint(output),
 'clientBuildConfigPins':{n:digest(ROOT/n) for n in ['client/package.json','client/package-lock.json','client/vite.config.mjs','client/index.html']},
 'artifacts':{p.name:digest(p) for p in [out/'inputs-before.json',out/'inputs-after.json',out/'output.json']},
 'qualified':code==0 and error is None and cleanup is None and postError is None and before==after and digest(node)==args.node_sha256 and digest(npm)==args.npm_sha256 and log.stat().st_size<=32*1024*1024 and bool(output)}
 for key in ['clientSourceInventory','clientPublicInventory','clientDependencyInventory','rootDependencyInventory']:receipt[key+'Sha256']=fingerprint(before[key])
 save(out/'report.json',receipt);print(json.dumps({'report':str(out/'report.json'),'sha256':digest(out/'report.json'),'qualified':receipt['qualified']}))
 if not receipt['qualified']:raise SystemExit(1)
if __name__=='__main__':main()
