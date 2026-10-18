#!/usr/bin/env python3
"""Qualify canonical Listings workflows in owned PostgreSQL/executor resources."""
import argparse, hashlib, http.client, json, os, signal, subprocess, tempfile, time, uuid, sys
sys.dont_write_bytecode=True
os.environ['PYTHONDONTWRITEBYTECODE']='1'
from datetime import datetime, timezone
from pathlib import Path
from sensitive_info_recovery_safety import SignalGate
from owned_dependency_overlay import install_owned_metadata, prepare_owned_runtime_directories, vite_config_arguments

EXPECTED_DOCKER='unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
NODE=Path('/Users/averma5/.dvaia/runtimes/node-v26.9.0-darwin-arm64/bin/node')
DOCKER=Path('/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker')
IMAGE='sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
SOURCE=Path(__file__).resolve().parents[2]
parser=argparse.ArgumentParser();parser.add_argument('--docker-host',required=True);parser.add_argument('--actual8b',action='store_true');parser.add_argument('--saved-evidence',action='store_true');parser.add_argument('--production-assembly',action='store_true');parser.add_argument('--actual-grading',action='store_true');parser.add_argument('--actual-grading-browser',action='store_true');parser.add_argument('--dependency-root');parser.add_argument('--node-binary');parser.add_argument('--node-sha256');parser.add_argument('--node-version');parser.add_argument('--catalog-candidate',action='store_true');parser.add_argument('--rendered-catalog',action='store_true');parser.add_argument('--full-app',action='store_true');parser.add_argument('--full-app-retry',action='store_true');parser.add_argument('--dependency-hashes');parser.add_argument('--dpi-rendered',action='store_true');parser.add_argument('--dpi-containment-rendered',action='store_true');parser.add_argument('--dpi-containment-visual',action='store_true');parser.add_argument('--inventory-rendered',action='store_true');parser.add_argument('--inventory-catalog',action='store_true');parser.add_argument('--inventory-grading',action='store_true');parser.add_argument('--mail-header-rendered',action='store_true');parser.add_argument('--mail-header-catalog',action='store_true');parser.add_argument('--mail-header-readiness',action='store_true');parser.add_argument('--mail-reply-rendered',action='store_true');parser.add_argument('--mail-reply-seed-only',action='store_true');parser.add_argument('--mail-reply-dependency-byte-sha256');parser.add_argument('--coupon-rendered',action='store_true');parser.add_argument('--coupon-dependency-byte-sha256');parser.add_argument('--csrf-indirect-dependency-byte-sha256');parser.add_argument('--csrf-full-app',choices=['actual-g2','actual-get-chain','actual-post-chain','actual-indirect-chain','controlled-diagnostic','catalog']);parser.add_argument('--mail-disclosure-rendered',choices=['vuln','fixed']);parser.add_argument('--mail-disclosure-dependency-byte-sha256');parser.add_argument('--mail-disclosure-initialize-only',action='store_true');parser.add_argument('--mail-disclosure-catalog',action='store_true');args=parser.parse_args()
from csrf_indirect_selector import validate as validate_indirect, verify_cache, verify_dependencies as verify_indirect_dependencies
try:validate_indirect(args)
except (ValueError,TypeError) as error:raise SystemExit(str(error))
if args.csrf_full_app=='actual-indirect-chain':verify_cache(SOURCE)
from mail_disclosure_rendered_selector import validate as validate_disclosure, CATALOG_FILES
try:validate_disclosure(args)
except (ValueError,TypeError) as error:raise SystemExit(str(error))
if args.mail_disclosure_catalog:
 for name in CATALOG_FILES:
  if not (SOURCE/name).is_file() or (SOURCE/name).is_symlink():raise SystemExit('Reviewed disclosure catalog fixture closure required')
if args.mail_disclosure_rendered:
 import coupon_dependency_integrity as coupon_integrity
 args.full_app=True
if args.dpi_containment_visual:
 if args.dpi_containment_rendered or args.dpi_rendered:raise SystemExit('DPI visual selector is exclusive with other DPI selectors')
 args.dpi_containment_rendered=True
if args.dpi_containment_rendered:
 if args.dpi_rendered:raise SystemExit('DPI containment selector is exclusive with baseline selector')
 args.dpi_rendered=True
if args.mail_reply_seed_only:
 if args.production_assembly:raise SystemExit('Seed-only cannot use production assembly')
 if args.mail_reply_rendered:raise SystemExit('Seed-only and rendered reply modes are exclusive')
 args.mail_reply_rendered=True # Reuse exact reviewed source/dependency pin gates, not rendered execution.
if args.mail_reply_rendered:
 import re,coupon_dependency_integrity as coupon_integrity
 if not re.fullmatch('[a-f0-9]{64}',args.mail_reply_dependency_byte_sha256 or ''):raise SystemExit('Reply requires reviewed full dependency byte digest')
 if any([args.actual8b,args.actual_grading,args.actual_grading_browser,args.full_app_retry,args.catalog_candidate,args.rendered_catalog,args.saved_evidence,args.dpi_rendered,args.inventory_rendered,args.inventory_catalog,args.inventory_grading,args.mail_header_rendered,args.mail_header_catalog,args.mail_header_readiness,args.csrf_full_app,args.coupon_rendered]):raise SystemExit('Reply rendered cohort must be exclusive')
 if not args.node_binary:raise SystemExit('Reply rendered requires explicit verified Node')
 args.full_app=True
if args.coupon_rendered:
 import re,coupon_dependency_integrity as coupon_integrity
 if not re.fullmatch('[a-f0-9]{64}',args.coupon_dependency_byte_sha256 or ''):raise SystemExit('Coupon requires reviewed full dependency byte digest')
 if any([args.actual8b,args.actual_grading,args.actual_grading_browser,args.full_app_retry,args.catalog_candidate,args.rendered_catalog,args.saved_evidence,args.dpi_rendered,args.inventory_rendered,args.inventory_catalog,args.inventory_grading,args.mail_header_rendered,args.mail_header_catalog,args.mail_header_readiness,args.csrf_full_app]):raise SystemExit('Coupon rendered cohort must be exclusive')
 if not args.node_binary:raise SystemExit('Coupon rendered requires explicit verified Node')
 args.full_app=True
if args.mail_header_catalog or args.mail_header_readiness:
 if args.mail_header_rendered or (args.mail_header_catalog and args.mail_header_readiness):raise SystemExit('Choose one mail header rendered cohort')
 args.mail_header_rendered=True
if args.mail_header_rendered:
 if any([args.actual8b,args.actual_grading,args.actual_grading_browser,args.full_app_retry,args.catalog_candidate,args.rendered_catalog,args.saved_evidence,args.dpi_rendered,args.inventory_rendered,args.inventory_catalog,args.inventory_grading,args.csrf_full_app]):raise SystemExit('Mail header rendered cohort must be exclusive')
 args.full_app=True
if args.csrf_full_app:
 if any([args.actual8b,args.actual_grading,args.actual_grading_browser,args.full_app_retry,args.catalog_candidate,args.rendered_catalog,args.production_assembly,args.saved_evidence,args.dpi_rendered,args.inventory_rendered,args.inventory_catalog,args.inventory_grading]):raise SystemExit('CSRF full-index cohort must be exclusive')
 if not args.node_binary:raise SystemExit('CSRF full-index requires explicit verified Node')
 args.full_app=True
if args.inventory_catalog or args.inventory_grading:
 if args.inventory_rendered or (args.inventory_catalog and args.inventory_grading):raise SystemExit('Choose one inventory browser cohort')
 args.inventory_rendered=True
if args.inventory_rendered:
 if any([args.actual8b,args.actual_grading,args.actual_grading_browser,args.full_app_retry,args.catalog_candidate,args.rendered_catalog,args.saved_evidence,args.dpi_rendered]):raise SystemExit('Inventory rendered mode cannot enable actual model or grading branches')
 args.full_app=True
if args.dpi_rendered:
 if any([args.actual8b,args.actual_grading,args.actual_grading_browser,args.full_app_retry,args.catalog_candidate,args.rendered_catalog,args.production_assembly,args.saved_evidence]):raise SystemExit('DPI rendered mode cannot enable model or Listings effect branches')
 args.full_app=True
if args.full_app_retry:args.full_app=True;args.catalog_candidate=True
if args.node_binary:
 if not args.node_sha256 or not args.node_version:raise SystemExit('explicit Node override requires SHA256 and version')
 NODE=Path(args.node_binary).resolve(strict=True)
 if hashlib.sha256(NODE.read_bytes()).hexdigest()!=args.node_sha256:raise SystemExit('Node override digest mismatch')
DEPENDENCIES=Path(args.dependency_root).resolve(strict=True) if args.dependency_root else SOURCE
indirect_dependency_admission=verify_indirect_dependencies(args,SOURCE)
if args.mail_disclosure_rendered and DEPENDENCIES==SOURCE.resolve():raise SystemExit('Disclosure requires a separately owned dependency donor')
if args.full_app:
 if not args.dependency_hashes:raise SystemExit('full application requires explicit dependency hashes')
 args.production_assembly=not (args.dpi_rendered or args.csrf_full_app)
if args.dpi_rendered and not args.dependency_root:raise SystemExit('DPI rendered mode requires its reviewed dependency root')
if args.rendered_catalog:args.catalog_candidate=True;args.production_assembly=True
if args.actual_grading_browser:args.actual_grading=True
if args.actual_grading:args.production_assembly=True
mode='mail-disclosure-catalog' if args.mail_disclosure_catalog else ('mail-disclosure-'+args.mail_disclosure_rendered) if args.mail_disclosure_rendered else 'mail-reply-rendered' if args.mail_reply_rendered else ('csrf-'+args.csrf_full_app) if args.csrf_full_app else 'dpi-rendered' if args.dpi_rendered else 'listings-integrated'
test_file='tests/postgres/secureshopMailReplySeed.native.js' if args.mail_reply_seed_only else 'tests/postgres/csrfFullIndex.native.js' if args.csrf_full_app else 'tests/postgres/dpiFullAppRendered.native.js' if args.dpi_rendered else 'tests/postgres/secureshopListingsFullApp.native.js' if args.full_app else 'tests/postgres/secureshopListingsIntegrated.native.js'
if args.docker_host!=EXPECTED_DOCKER:raise SystemExit('reviewed isolated Docker host required')
if args.mail_disclosure_rendered:
 browser=Path.home()/'.cache/puppeteer/chrome-headless-shell/mac_arm-152.0.7977.75/chrome-headless-shell-mac-arm64/chrome-headless-shell'
 if not browser.is_file() or browser.is_symlink() or not os.access(browser,os.X_OK) or hashlib.sha256(browser.read_bytes()).hexdigest()!='51083e7cf58ba060a0160b8f447ea04c0e9bada00c30a047259bcfe1217b82c3':raise SystemExit('Disclosure browser pin mismatch before resources')
root=Path(tempfile.mkdtemp(prefix='dvaia-listings-integrated-')).resolve();os.chmod(root,0o700);workspace=root/'source'
container='dvaia-listings-integrated-'+uuid.uuid4().hex[:12];owner=uuid.uuid4().hex
docker=[str(DOCKER),'--host',args.docker_host]
env={'PATH':str(NODE.parent)+':/usr/bin:/bin','HOME':os.environ['HOME'],'TMPDIR':str(root)}
state={'container':container,'owner':owner,'image':IMAGE,'evidence':str(root),'launcherPid':os.getpid(),
 'nodeVersion':None,'containerCreationAttempted':False,'child':None,'runStatus':'preparing','cleanup':None,
 'mode':mode,'createdAt':datetime.now(timezone.utc).isoformat()}
if args.csrf_full_app:state['bounds']={'parentSeconds':600 if args.csrf_full_app=='controlled-diagnostic' else 1920 if args.csrf_full_app in ('actual-get-chain','actual-post-chain','actual-indirect-chain') else 1440,'childSeconds':360 if args.csrf_full_app=='controlled-diagnostic' else 1560 if args.csrf_full_app in ('actual-get-chain','actual-post-chain','actual-indirect-chain') else 960,'buildSeconds':0 if args.csrf_full_app=='controlled-diagnostic' else 180,'maxModelHttp':18 if args.csrf_full_app in ('actual-get-chain','actual-post-chain','actual-indirect-chain') else 8 if args.csrf_full_app=='actual-g2' else 0,'perModelHttpSeconds':60,'stores':16,'postgresMiB':1024}
if args.mail_disclosure_initialize_only:env['MAIL_DISCLOSURE_INITIALIZE_ONLY']='1'
if args.mail_disclosure_rendered:state['bounds']={'parentSeconds':1440,'childSeconds':960,'browserSeconds':180,'buildSeconds':180,'cleanupSeconds':120,'maxModelHttp':4,'stores':16,'postgresMiB':1024}
if args.mail_disclosure_initialize_only:
 state['mode']='mail-disclosure-initializer-diagnostic';state['bounds']={'parentSeconds':600,'childSeconds':330,'browserSeconds':0,'buildSeconds':0,'cleanupSeconds':120,'maxModelHttp':0,'stores':16,'postgresMiB':1024}
if args.mail_reply_rendered:state['bounds']={'parentSeconds':1440,'childSeconds':960,'browserSeconds':600,'buildSeconds':180,'maxModelHttp':12,'perModelHttpSeconds':60,'stores':16,'postgresMiB':1024}
ownership=root/'ownership.json';log_path=root/'tests.log';log_path.touch(mode=0o600)
def persist():ownership.write_text(json.dumps(state,indent=2)+'\n');os.chmod(ownership,0o600)
def run(command,**kwargs):kwargs.setdefault('timeout',120);return subprocess.run(command,check=True,env=kwargs.pop('env',env),**kwargs)
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def exact_absence(name=container):
 query=subprocess.run(docker+['ps','-a','--filter',f'name=^/{name}$','--format','{{.Names}}'],env=env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=30)
 if query.returncode:raise RuntimeError('exact-name container query failed')
 return not query.stdout.strip()
if args.mail_reply_seed_only:state['mode']='mail-reply-seed-only';state['bounds']={'parentSeconds':900,'childSeconds':480,'browserSeconds':0,'buildSeconds':0,'maxModelHttp':0,'stores':16,'postgresMiB':1024}
executor=None;child=None;creation_attempted=False;gate=SignalGate();signal.signal(signal.SIGTERM,gate.handler);signal.signal(signal.SIGINT,gate.handler);signal.signal(signal.SIGALRM,gate.handler);signal.alarm(600 if args.mail_disclosure_initialize_only else 900 if args.mail_reply_seed_only else 600 if args.csrf_full_app=='controlled-diagnostic' else 1920 if args.csrf_full_app in ('actual-get-chain','actual-post-chain','actual-indirect-chain') else 1440 if args.csrf_full_app or args.mail_reply_rendered or args.mail_disclosure_rendered else 900);persist()
def owned_group_members(pgid):
 listing=subprocess.run(['ps','-axo','pid=,pgid=,uid='],env=env,stdout=subprocess.PIPE,text=True,check=True,timeout=5).stdout
 members=[]
 for line in listing.splitlines():
  fields=line.split()
  if len(fields)==3 and int(fields[1])==pgid:
   if int(fields[2])!=os.getuid():raise RuntimeError(f'refusing foreign process in owned group {pgid}')
   members.append(int(fields[0]))
 return members
def stop_child():
 if child is None:return
 pgid=state.get('child',{}).get('pgid')
 if not pgid:return
 if owned_group_members(pgid):os.killpg(pgid,signal.SIGTERM)
 deadline=time.monotonic()+5
 while owned_group_members(pgid) and time.monotonic()<deadline:
  child.poll();time.sleep(.05)
 if owned_group_members(pgid):os.killpg(pgid,signal.SIGKILL)
 try:child.wait(timeout=5)
 except subprocess.TimeoutExpired:pass
 if owned_group_members(pgid):raise RuntimeError('owned Node/browser process group cleanup incomplete')
try:
 version=run([str(NODE),'--version'],stdout=subprocess.PIPE,text=True).stdout.strip()
 if version!=(args.node_version or 'v26.9.0'):raise RuntimeError('reviewed managed Node version required')
 state['nodeVersion']=version;persist()
 if args.coupon_rendered or args.mail_reply_rendered or args.mail_disclosure_rendered:
  if digest(NODE)!=coupon_integrity.NODE_SHA or version!='v26.10.0' or digest(DOCKER)!=coupon_integrity.DOCKER_SHA:raise RuntimeError('Coupon executable pin mismatch')
  state['couponDependencyIntegrity']=coupon_integrity.verify(DEPENDENCIES,json.loads(args.dependency_hashes),(args.mail_disclosure_dependency_byte_sha256 if args.mail_disclosure_rendered else args.mail_reply_dependency_byte_sha256 if args.mail_reply_rendered else args.coupon_dependency_byte_sha256))
 daemon_name=run(docker+['info','--format','{{.Name}}'],stdout=subprocess.PIPE,text=True).stdout.strip()
 if daemon_name!='colima-dvaia-pg-verify':raise RuntimeError('reviewed isolated Docker daemon required')
 if args.coupon_rendered or args.mail_reply_rendered or args.mail_disclosure_rendered:
  daemon_id=run(docker+['info','--format','{{.ID}}'],stdout=subprocess.PIPE,text=True,timeout=10).stdout.strip()
  coupon_integrity.pins(NODE,DOCKER,daemon_id);state['couponDaemonId']=daemon_id
 image_id=run(docker+['image','inspect','--format','{{.Id}}',IMAGE],stdout=subprocess.PIPE,text=True).stdout.strip()
 if image_id!=IMAGE:raise RuntimeError('immutable PostgreSQL image identity mismatch')
 state['dockerDaemon']=daemon_name;state['imageId']=image_id;persist()
 if not exact_absence():raise RuntimeError('owned container name unexpectedly exists')
 run([str(NODE),'-e',"require(process.argv[3]).copyIsolatedSource(process.argv[1],process.argv[2])",str(SOURCE),str(workspace),'./tests/fixtures/csrfSourceCopy' if args.csrf_full_app else './scripts/lib/isolated-source-copy'],cwd=SOURCE)
 if args.dpi_containment_rendered or args.mail_disclosure_rendered or args.csrf_full_app=='actual-indirect-chain':
  state['runtimeWritableDirectories']=prepare_owned_runtime_directories(SOURCE,workspace,root);persist()
 if args.dependency_root:
  import shutil
  report=json.loads((SOURCE/'tasks/dependency-candidate-stage-2026-09-26.json').read_text())
  if args.dpi_rendered:
   from dpi_dependency_authority import validate_dpi_dependency_authority
   authority=json.loads((SOURCE/'tasks/dpi-teaching-rendered-dependency-authority-2026-09-26.json').read_text())
   validate_dpi_dependency_authority(DEPENDENCIES,json.loads(args.dependency_hashes),authority)
  elif not args.mail_disclosure_rendered and args.csrf_full_app!='actual-indirect-chain' and (DEPENDENCIES!=Path(report['directory']).resolve(strict=True) or DEPENDENCIES==SOURCE.resolve()):raise RuntimeError('reviewed candidate dependency root required')
  if not args.dependency_hashes:
   for name,expected in report['baselineHashes'].items():
    if digest(SOURCE/name)!=expected:raise RuntimeError('shared dependency baseline drift: '+name)
  candidate_hashes={}
  for prefix in ['', 'client/']:
   manifest=DEPENDENCIES/(prefix+'package.json');lock=DEPENDENCIES/(prefix+'package-lock.json');installed=DEPENDENCIES/(prefix+'node_modules/.package-lock.json')
   for file in [manifest,lock,installed]:
    if not file.is_file() or not file.resolve().is_relative_to(DEPENDENCIES):raise RuntimeError('candidate dependency file missing or escaped')
    candidate_hashes[str(file.relative_to(DEPENDENCIES))]=digest(file)
   package=json.loads(manifest.read_text());locked=json.loads(lock.read_text())['packages'];module_lock=json.loads(installed.read_text())['packages']
   for field in ['dependencies','devDependencies','optionalDependencies']:
    if package.get(field,{})!=locked[''].get(field,{}):raise RuntimeError('manifest/lock mismatch')
   for location,item in module_lock.items():
    if location not in locked or item.get('version')!=locked[location].get('version'):raise RuntimeError('installed module lock mismatch: '+location)
   for metadata in [manifest,lock]:
    relative=str(metadata.relative_to(DEPENDENCIES))
    install_owned_metadata(metadata,workspace/relative,workspace,candidate_hashes[relative])
  if args.dependency_hashes and candidate_hashes!=json.loads(args.dependency_hashes):raise RuntimeError('explicit dependency hash inventory mismatch')
  state['dependencyCandidate']={'root':str(DEPENDENCIES),'sha256':candidate_hashes,'sharedSourceHashes':{name:digest(SOURCE/name) for name in report['baselineHashes']}}
 if (args.csrf_full_app or args.mail_header_rendered or args.coupon_rendered or args.mail_reply_rendered) and not args.dependency_root:
  names=['package.json','package-lock.json','node_modules/.package-lock.json','client/package.json','client/package-lock.json','client/node_modules/.package-lock.json']
  current={name:digest(DEPENDENCIES/name) for name in names}
  if current!=json.loads(args.dependency_hashes):raise RuntimeError('CSRF exact dependency inventory mismatch')
  state['dependencyCandidate']={'root':str(DEPENDENCIES),'sha256':current}
 (workspace/'node_modules').symlink_to(DEPENDENCIES/'node_modules',target_is_directory=True)
 if args.catalog_candidate:
  before=digest(workspace/'server/config/secureshopCurriculum.js')
  run([str(NODE),'-e',"require('./tests/helpers/secureshopListingsCurriculumCandidate').stage(process.cwd())"],cwd=workspace)
  state['catalogCandidate']={'beforeSha256':before,'afterSha256':digest(workspace/'server/config/secureshopCurriculum.js'),'sharedSourceUnchanged':digest(SOURCE/'server/config/secureshopCurriculum.js')==before}
  env['LISTINGS_CATALOG_CANDIDATE']='1'
  if args.full_app_retry:env['LISTINGS_FULL_APP_RETRY']='1'
 if args.mail_disclosure_rendered:
  env['MAIL_DISCLOSURE_RENDERED']='1';env['MAIL_DISCLOSURE_RENDER_MODE']=args.mail_disclosure_rendered
  if args.mail_disclosure_catalog:env['MAIL_DISCLOSURE_CATALOG_RENDERED']='1'
  state['mailCandidate']={'objective':'ss_mail_cross_persona_read','candidateOnly':True,'staging':'owned fixture before application imports; exact two-file hash manifest'}
 if args.mail_reply_seed_only:env['MAIL_REPLY_SEED_ONLY']='1'
 if args.mail_reply_rendered and not args.mail_reply_seed_only:
  env['MAIL_REPLY_FULL_APP']='1'
  candidate=workspace/'server/config/secureshopCurriculum.js';original=candidate.read_text()
  run([str(NODE),'-e',"const fs=require('fs'),p='./server/config/secureshopCurriculum.js';fs.writeFileSync(p,require('./tests/fixtures/secureshopMailReplyCandidateCatalog').stageMailReplyCandidateCatalog(fs.readFileSync(p,'utf8')));"],cwd=workspace)
  state['mailCandidate']={'objective':'ss_mail_reply_redirect','originalSha256':hashlib.sha256(original.encode()).hexdigest(),'candidateSha256':digest(candidate),'sharedSourceChanged':False}
 if args.mail_header_rendered:
  env['MAIL_HEADER_FULL_APP']='1'
  if args.mail_header_catalog:env['MAIL_HEADER_CATALOG_APP']='1'
  if args.mail_header_readiness:env['MAIL_HEADER_READINESS_APP']='1'
  candidate=workspace/'server/config/secureshopCurriculum.js';original=candidate.read_text()
  run([str(NODE),'-e',"const fs=require('fs'),p='./server/config/secureshopCurriculum.js';fs.writeFileSync(p,require('./tests/fixtures/secureshopMailHeaderCandidateCatalog').stageMailHeaderCandidateCatalog(fs.readFileSync(p,'utf8')));"],cwd=workspace)
  if args.mail_header_readiness:
   run([str(NODE),'-e',"require('./tests/fixtures/secureshopMailReadinessCandidate').stageMailReadinessCandidate(process.cwd())"],cwd=workspace,env={**env,'PG_TEST_DISPOSABLE':'yes'})
  state['mailCandidate']={'objective':'ss_mail_header_construction','originalSha256':hashlib.sha256(original.encode()).hexdigest(),'candidateSha256':digest(candidate),'sharedSourceChanged':False}
 if args.coupon_rendered:
  env['COUPON_FULL_APP']='1';env['DOCKER_HOST']=args.docker_host
  env['PATH']=str(DOCKER.parent)+os.pathsep+env['PATH']
 if args.inventory_rendered:env['INVENTORY_FULL_APP']='1'
 if args.inventory_catalog or args.inventory_grading:
  run([str(NODE),'-e',"const fs=require('fs'),p='./server/config/secureshopCurriculum.js',h=require('./tests/fixtures/secureshopInventoryCandidateCatalog');fs.writeFileSync(p,h.stageInventoryCandidateCatalog(fs.readFileSync(p,'utf8')));h.validateInventoryCandidateCatalog(require(p));"],cwd=workspace)
  if args.inventory_catalog:env['INVENTORY_CATALOG_APP']='1'
  if args.inventory_grading:env['INVENTORY_GRADING_APP']='1'

 if args.full_app:
  # Fail inexpensive fixture/configuration errors before rebuilding the frontend.
  run([str(NODE),'--check',test_file],cwd=workspace)
  run([str(NODE),'-e',"const fs=require('fs'),assert=require('assert/strict');assert.equal(fs.realpathSync(process.cwd()),fs.realpathSync(process.argv[1]));for(const name of ['express','pg','bcryptjs','puppeteer'])require.resolve(name);const m=require('./db/postgres/initialize-application').requiredStoreManifest;assert.equal(m.length,16);assert.equal(new Set(m.flatMap(x=>[x.runtimeVariable,x.migrationVariable])).size,32);if(process.argv[2]!=='dpi')require('./scripts/install/secureshop-owned-listings-qualified-candidate').qualifiedPackage({root:process.cwd(),architecture:'arm64'});const path=require('path');const data=path.join(path.dirname(process.cwd()),'preflight-app-data');require('./scripts/application-data-root').ensureApplicationDataRoot({workspace:process.cwd(),environment:{DVAIA_APP_DATA_ROOT:data}});fs.rmdirSync(data);",str(workspace),'dpi' if args.dpi_rendered or args.csrf_full_app or args.mail_reply_seed_only else 'listings'],cwd=workspace)
 if (args.rendered_catalog or args.full_app) and args.csrf_full_app!='controlled-diagnostic' and not args.mail_reply_seed_only and not args.mail_disclosure_initialize_only:
  (workspace/'client/node_modules').symlink_to(DEPENDENCIES/'client/node_modules',target_is_directory=True)
  with (root/'frontend-build.log').open('w') as build_log:
   run([str(NODE),str(DEPENDENCIES/'client/node_modules/vite/bin/vite.js'),'build',*vite_config_arguments(args.dpi_containment_rendered or args.mail_disclosure_rendered or args.csrf_full_app=='actual-indirect-chain')],cwd=workspace/'client',stdout=build_log,stderr=subprocess.STDOUT,timeout=180)
  if args.full_app and not (args.dpi_rendered or args.csrf_full_app):
   for config in ['vite.review-renderer.config.mjs','vite.product-description-renderer.config.mjs']:
    with (root/(config+'.log')).open('w') as build_log:run([str(NODE),str(DEPENDENCIES/'client/node_modules/vite/bin/vite.js'),'build','--config',config,*vite_config_arguments(args.mail_disclosure_rendered)],cwd=workspace/'client',stdout=build_log,stderr=subprocess.STDOUT,timeout=90)
  elif args.rendered_catalog:env['LISTINGS_RENDERED_CATALOG']='1'
 if args.production_assembly:
  import shutil
  if not args.full_app:shutil.copytree(DEPENDENCIES/'client/build/secureshop-product-description-renderer',workspace/'client/build/secureshop-product-description-renderer')
 canonical_dir=workspace/'canonical-review-through-0021';candidate_dir=workspace/'canonical-review-current'
 prior_dir=workspace/'canonical-review-through-0022'
 import shutil
 for folder in [canonical_dir,candidate_dir,prior_dir]:folder.mkdir()
 for migration in (workspace/'db/postgres/workshop-migrations/secureshop_review').glob('*.sql'):
  ordinal=int(migration.name.split('_',1)[0])
  shutil.copy2(migration,candidate_dir/migration.name)
  if ordinal<=21:shutil.copy2(migration,canonical_dir/migration.name)
  if ordinal<=22:shutil.copy2(migration,prior_dir/migration.name)
 agents_prior=workspace/'canonical-agents-through-0034';agents_prior.mkdir()
 for migration in (workspace/'db/postgres/workshop-migrations/secureshop_agents').glob('*.sql'):
  if int(migration.name.split('_',1)[0])<=34:shutil.copy2(migration,agents_prior/migration.name)
 env['LISTINGS_AGENTS_PRIOR_MIGRATIONS']=str(agents_prior)
 env['OWNED_LISTING_PRIOR_MIGRATIONS']=str(prior_dir)
 env['OWNED_LISTING_CANONICAL_MIGRATIONS']=str(canonical_dir)
 env['OWNED_LISTING_CANDIDATE_MIGRATIONS']=str(candidate_dir)
 inventory=['tests/postgres/csrf_indirect_selector.py','tests/postgres/mail_disclosure_cleanup_budget.py','tests/postgres/mail_disclosure_rendered_selector.py','tests/postgres/coupon_rendered_cleanup.py','tests/postgres/csrf_managed_browser_cleanup.py','tests/postgres/listings_integrated_executor_owner.py','tests/fixtures/secureshopListingsDualListener.native.cjs','tests/fixtures/secureshopListingsIntegratedNative.js','tests/fixtures/secureshopListingsResponseLossProxy.js','tests/postgres/run-listings-integrated-isolated.py','docs/modernization/drafts/secureshop-owned-listings/0024_listing_rewrite_publication.sql','docs/modernization/drafts/secureshop-owned-listings/0023_listing_declined_terminal.sql',test_file,'tests/postgres/run-listings-integrated-isolated.py','tests/postgres/sensitive_info_recovery_safety.py','tests/postgres/dpi_dependency_authority.py','tasks/dpi-teaching-rendered-dependency-authority-2026-09-26.json','docs/modernization/drafts/secureshop-owned-listings/0022_owned_listing_operations.sql','server/services/secureshopListingJournalContract.js','server/services/mcp/protocolContext.js','package-lock.json','package.json','client/package.json','client/package-lock.json','client/vite.config.mjs','client/vite.review-renderer.config.mjs','client/vite.product-description-renderer.config.mjs','client/vite.opaque-frame-cors.mjs']
 if args.coupon_rendered or args.mail_reply_rendered or args.mail_disclosure_rendered:inventory.extend(['tests/postgres/coupon_dependency_integrity.py','tests/postgres/owned_mcp_assembly_freeze.py'])
 for folder in ['sidecars','server/database/postgres','server/services','server/agent-runtime','server/data','db/postgres','scripts/lib','shared','agent-host','server/routes','server/middleware','tests/fixtures','scripts/install','client/src','client/build']:
  inventory.extend(str(item.relative_to(workspace)) for item in sorted((workspace/folder).rglob('*')) if item.is_file())
 if args.csrf_full_app=='actual-indirect-chain':
  state['embeddingAssets']=verify_cache(workspace)
  inventory.extend(state['embeddingAssets'])
 if args.mail_disclosure_catalog:
  for name in CATALOG_FILES:
   if digest(workspace/name)!=digest(SOURCE/name):raise RuntimeError('Copied disclosure catalog fixture mismatch')
  inventory.extend(CATALOG_FILES)
 state['sourceSha256']={name:digest(workspace/name) for name in sorted(set(inventory))};state['candidate0022Sha256']=digest(candidate_dir/'0022_owned_listing_operations.sql');state['preCandidateMigrationCount']=len(list(canonical_dir.glob('*.sql')));state['postCandidateMigrationCount']=len(list(candidate_dir.glob('*.sql')));state['nodeSha256']=digest(NODE);persist()
 run([str(NODE),'--check',test_file],cwd=workspace)
 creation_attempted=True;state['containerCreationAttempted']=True;persist()
 run(docker+['run','--detach','--pull','never','--name',container,'--label','dvaia.test.owner='+owner,
  '--memory','1g','--cpus','2','--pids-limit','128','--tmpfs','/var/lib/postgresql:rw,size='+('1073741824' if args.full_app else '268435456'),'-e','POSTGRES_HOST_AUTH_METHOD=trust',
  '-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432',IMAGE,'-c','shared_buffers=16MB','-c','max_connections='+('100' if args.full_app else '40'),
  '-c','max_wal_size=16MB','-c','min_wal_size=4MB'],stdout=subprocess.DEVNULL)
 details=json.loads(run(docker+['inspect',container],stdout=subprocess.PIPE,text=True).stdout)[0]
 if details.get('Mounts') or details['Config']['Labels'].get('dvaia.test.owner')!=owner:raise RuntimeError('owned PostgreSQL isolation/ownership check failed')
 for _ in range(100):
  ready=subprocess.run(docker+['exec',container,'pg_isready','-h','127.0.0.1','-U','postgres'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2)
  if ready.returncode==0:break
  time.sleep(.25)
 else:raise RuntimeError('owned PostgreSQL unavailable')
 port=int(run(docker+['port',container,'5432/tcp'],stdout=subprocess.PIPE,text=True).stdout.strip().rsplit(':',1)[1])
 server_version=run(docker+['exec',container,'psql','-U','postgres','-d','postgres','-Atc','SHOW server_version'],stdout=subprocess.PIPE,text=True).stdout.strip()
 state['postgresServerVersion']=server_version;state['postgresImageMetadata']=json.loads(run(docker+['image','inspect',IMAGE],stdout=subprocess.PIPE,text=True).stdout)[0].get('Config',{}).get('Labels',{});persist()
 psql=docker+['exec',container,'psql','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1','-c']
 nonce=owner[:12];state['databases']=[]
 stores=json.loads(run([str(NODE),'-e',"console.log(JSON.stringify(require('./db/postgres/initialize-application').requiredStoreManifest))"],cwd=workspace,stdout=subprocess.PIPE,text=True).stdout) if args.full_app else [{'label':label,'schema':schema} for label,schema in [('IDENTITY','identity'),('COMMERCE','secureshop'),('AGENTS','secureshop_agents'),('REVIEW','secureshop_review')]]
 if args.full_app:assert len(stores)==16
 for store in stores:
  schema=store['schema'];migration='dvaia_'+schema+'_migration';runtime='dvaia_'+schema+'_runtime'
  run(psql+[f'CREATE ROLE {migration} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE {runtime} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],stdout=subprocess.DEVNULL)
  database=f'dvaia_test_listings_{nonce}_{schema}'
  run(psql+[f'CREATE DATABASE {database} OWNER {migration}'],stdout=subprocess.DEVNULL)
  run(psql+[f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{runtime}'],stdout=subprocess.DEVNULL)
  state['databases'].append(database)
  migration_variable=store['migrationVariable'] if args.full_app else f"LISTINGS_{store['label']}_MIGRATION_URL"
  runtime_variable=store['runtimeVariable'] if args.full_app else f"LISTINGS_{store['label']}_RUNTIME_URL"
  env[migration_variable]=f'postgresql://{migration}@127.0.0.1:{port}/{database}'
  env[runtime_variable]=f'postgresql://{runtime}@127.0.0.1:{port}/{database}'
 persist()
 if args.csrf_full_app:env['CSRF_FULL_INDEX_MODE']=args.csrf_full_app
 env['LISTINGS_INTEGRATED_NATIVE']='1'
 if args.actual8b:env['LISTINGS_ACTUAL8B']='1'
 if args.saved_evidence:env['LISTINGS_SAVED_EVIDENCE']='1'
 if args.production_assembly:env['LISTINGS_PRODUCTION_ASSEMBLY']='1'
 if args.actual_grading:env['LISTINGS_ACTUAL_GRADING']='1'
 if args.actual_grading_browser:env['LISTINGS_ACTUAL_GRADING_BROWSER']='1'
 env['LISTINGS_EVIDENCE_ROOT']=str(root)
 env['OWNED_LISTING_RESULT']=str(root/'candidate-result.json')
 env.update(NODE_ENV='test',PG_TEST_DISPOSABLE='yes',DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace),
  PLATFORM_DATABASE_ENGINE='postgres',WORKSHOP_DATABASE_ENGINE='postgres',
  AI_PROVIDER='mock',TRANSFORMERS_OFFLINE='1',JWT_SECRET=uuid.uuid4().hex+uuid.uuid4().hex,SESSION_SECRET=uuid.uuid4().hex+uuid.uuid4().hex,
  AWS_EC2_METADATA_DISABLED='true',MCP_WORKSHOP_AUTOSTART='false',MCP_SIDECARS_AUTOSTART='false',SS_ENABLE='false',HF_HUB_OFFLINE='1',
  OLLAMA_BASE_URL='http://127.0.0.1:1',SANDBOX_RUNNER_URL='http://127.0.0.1:1',SSRF_TARGET_URL='http://127.0.0.1:1',
 ROGUE_MCP_URL='http://127.0.0.1:1',MAILPIT_API_URL='http://127.0.0.1:1',MAILPIT_SMTP_HOST='127.0.0.1',MAILPIT_SMTP_PORT='1')
 if args.dpi_containment_rendered:env['DPI_CONTAINMENT_RENDERED']='1'
 if args.dpi_containment_visual:env['DPI_CONTAINMENT_VISUAL']='1'
 from listings_integrated_executor_owner import ExecutorOwner
 if not (args.dpi_rendered or args.csrf_full_app or args.mail_reply_seed_only or args.mail_disclosure_initialize_only):
  executor=ExecutorOwner(workspace,root,docker,owner,env,state,persist)
  env.update(executor.start(shared_manager=args.production_assembly))
 if args.production_assembly and not args.mail_disclosure_initialize_only:
  workspace_id=hashlib.sha256(str(workspace.resolve()).encode()).hexdigest()[:12]
  daemon_id=json.loads(run(docker+['info','--format','{{json .ID}}'],stdout=subprocess.PIPE,text=True).stdout)
  env['LISTINGS_DOCKER_AUTHORITY_SHA']=hashlib.sha256(json.dumps({'version':1,'workspaceId':workspace_id,'host':EXPECTED_DOCKER,'daemonId':daemon_id},separators=(',',':')).encode()).hexdigest()
 with log_path.open('w') as log:
  child=subprocess.Popen([str(NODE),'--test','--test-reporter=tap',test_file],cwd=workspace,env=env,stdout=log,stderr=log,start_new_session=True)
  state['child']={'pid':child.pid,'pgid':os.getpgid(child.pid)};state['runStatus']='test_running';persist()
  try:code=child.wait(timeout=330 if args.mail_disclosure_initialize_only else 480 if args.mail_reply_seed_only else 360 if args.csrf_full_app=='controlled-diagnostic' else 1560 if args.csrf_full_app in ('actual-get-chain','actual-post-chain','actual-indirect-chain') else 960 if args.csrf_full_app or args.mail_reply_rendered or args.mail_disclosure_rendered else 480)
  except subprocess.TimeoutExpired:stop_child();raise RuntimeError('Owned MCP registry candidate qualification timed out')
 if code:raise RuntimeError(f'Owned MCP registry candidate qualification failed ({code}); inspect retained tests.log')
 state['runStatus']='passed';state['logSha256']=digest(log_path);state['runtimeResultSha256']=digest(root/'candidate-result.json');persist()
except BaseException as error:
 if creation_attempted:
  try:
   diagnostic=subprocess.run(docker+['logs','--tail','120',container],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=20)
   (root/'container.log').write_text(diagnostic.stdout);os.chmod(root/'container.log',0o600)
  except Exception as diagnostic_error:state['containerDiagnosticError']=type(diagnostic_error).__name__
 state.update({'runStatus':'failed','errorType':type(error).__name__,'resultSha256':digest(log_path)});persist();raise
finally:
 signal.alarm(0);gate.protect_cleanup();errors=[];remove_code=None;absent=None
 bounded_cleanup=args.mail_disclosure_rendered or args.csrf_full_app=='actual-indirect-chain'
 if bounded_cleanup:
  from mail_disclosure_cleanup_budget import CleanupBudget
  cleanup_budget=CleanupBudget(120)
 def cleanup_step(work):return cleanup_budget.run(work) if bounded_cleanup else work()
 try:cleanup_step(stop_child)
 except Exception as error:errors.append('child:'+type(error).__name__)
 if args.coupon_rendered:
  try:
   from coupon_rendered_cleanup import cleanup as cleanup_coupon
   cleanup_coupon(workspace,root,docker,run,state,persist)
  except Exception as error:errors.append('coupon:'+type(error).__name__)
 if args.csrf_full_app:
  try:
   from csrf_managed_browser_cleanup import cleanup as cleanup_csrf_browser
   state['managedBrowserCleanup']=cleanup_step(lambda:cleanup_csrf_browser(root))
  except Exception as error:errors.append('managedBrowser:'+type(error).__name__)
 if executor:
  try:cleanup_step(executor.close)
  except Exception as error:errors.append('executor:'+type(error).__name__)
 if creation_attempted:
  try:
   if not cleanup_step(exact_absence):
    info=json.loads(cleanup_step(lambda:run(docker+['inspect',container],stdout=subprocess.PIPE,text=True)).stdout)[0]
    if info['Config']['Labels'].get('dvaia.test.owner')!=owner:raise RuntimeError('refusing foreign container cleanup')
    remove_code=cleanup_step(lambda:subprocess.run(docker+['rm','-f','-v',container],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)).returncode
   else:remove_code=0
  except Exception as error:errors.append('remove:'+type(error).__name__)
 try:absent=cleanup_step(exact_absence)
 except Exception as error:errors.append('absence:'+type(error).__name__)
 try:pgid_absent=not state.get('child') or not cleanup_step(lambda:owned_group_members(state['child']['pgid']))
 except Exception as error:errors.append('pgid:'+type(error).__name__);pgid_absent=False
 state['cleanup']={'removeExitCode':remove_code,'containerAbsent':absent,'nodeBrowserPgidAbsent':pgid_absent,
 'errors':errors,'completedAt':datetime.now(timezone.utc).isoformat()}
 if args.csrf_full_app=='actual-indirect-chain':
  try:state['indirectFinalDependencyIntegrity']=cleanup_step(lambda:verify_indirect_dependencies(args,SOURCE))
  except Exception as error:errors.append('indirectIntegrity:'+type(error).__name__)
 if args.coupon_rendered or args.mail_reply_rendered or args.mail_disclosure_rendered:
  try:
   cleanup_step(lambda:coupon_integrity.verify(DEPENDENCIES,json.loads(args.dependency_hashes),(args.mail_disclosure_dependency_byte_sha256 if args.mail_disclosure_rendered else args.mail_reply_dependency_byte_sha256 if args.mail_reply_rendered else args.coupon_dependency_byte_sha256)));state['couponFinalDependencyIntegrity']=True
  except Exception as error:errors.append('couponIntegrity:'+type(error).__name__);state['couponFinalDependencyIntegrity']=False
 if state['runStatus']=='passed' and (errors or absent is not True or pgid_absent is not True or (creation_attempted and remove_code!=0)):state['runStatus']='failed';state['errorType']='CleanupFailed'
 persist()
 if bounded_cleanup:signal.alarm(0)
print(json.dumps({'evidence':str(root),'status':state['runStatus'],'cleanup':state['cleanup']}),flush=True)
if state['runStatus']!='passed':raise SystemExit(1)
