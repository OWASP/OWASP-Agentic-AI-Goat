import os
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from full_backend_auth_contract import REQUIRED, EMBEDDING_ASSETS, QUALIFIED_ADDITIONAL_MIGRATIONS, REVIEWED_MIGRATIONS, STORES, validate_manifest, inventory, validate_fullboot_layout, validate_mcp_indirect_configuration, MCP_MODEL_DIGEST

class Contract(unittest.TestCase):
 def test_student_deletion_literal_lazy_and_transitive_closure_is_required(self):
  from full_backend_auth_contract import (STUDENT_DELETION_SOURCE_ROOTS,
   student_deletion_source_closure,validate_student_deletion_source_closure)
  source=Path(__file__).resolve().parents[2]
  node=source/'tasks/runtime/node/node_modules/node/bin/node'
  closure=student_deletion_source_closure(source,node)
  self.assertTrue(STUDENT_DELETION_SOURCE_ROOTS <= closure)
  for required in ['server/services/studentDeletionRunDrain.js',
                   'server/database/postgres/agentRunReadRepository.js',
                   'server/services/legacyChallengeOwnerCleanup.js',
                   'server/database/postgres/legacyChallengeDb.js',
                   'server/services/legacyUploadLifecycle.js']:
   self.assertIn(required,closure)
  manifest={'files':dict.fromkeys(closure,'a'*64)}
  self.assertEqual(validate_student_deletion_source_closure(source,manifest,node),closure)
  for missing in ['server/services/studentDeletionRunDrain.js','server/services/legacyChallengeOwnerCleanup.js']:
   partial={'files':{key:value for key,value in manifest['files'].items() if key!=missing}}
   with self.assertRaises(RuntimeError):validate_student_deletion_source_closure(source,partial,node)
 def test_student_deletion_ast_ignores_comments_strings_templates_but_keeps_executable_loads(self):
  source=Path(__file__).resolve().parents[2]
  node=source/'tasks/runtime/node/node_modules/node/bin/node'
  script=r"""
const assert=require('node:assert/strict');
const fs=require('node:fs');
const parser=require('./client/node_modules/@babel/parser');
const {references}=require('./tests/fixtures/studentDeletionSourceClosure');
const fake="// require('./comment')\n/* load('./block') */\n"+
  "const doc=\"require('./string')\"; const template=`require('./template')`; "+
  "const pattern=/require/; require /* split */ ( './live' );";
assert.deepEqual(references('server/services/studentDeletionAdapters.js',fake,parser),['./live']);
assert.deepEqual(references('server/services/studentDeletionAdapters.js',
  "load /*split*/ ('./adapter'); require('./runtime')",parser).sort(),
  ['./adapter','./runtime']);
assert.throws(()=>references('server/services/studentDeletionAdapters.js',
  'load(variable)',parser),/dynamic source edge/);
assert.throws(()=>references('other.js','require(variable)',parser),/dynamic source edge/);
assert.throws(()=>references('other.mjs','import(variable)',parser),/dynamic source edge/);
assert.deepEqual(references('other.mjs',"import('./child.mjs'); export * from './sibling.mjs'",parser).sort(),
  ['./child.mjs','./sibling.mjs']);
assert.deepEqual(references('other.js',"require(flag?'./yes':'./no')",parser).sort(),
  ['./no','./yes']);
assert.throws(()=>references('other.js','import(computed)',parser),/dynamic source edge/);
assert.throws(()=>references('other.js','require(`./${computed}`)',parser),/dynamic source edge/);
assert.throws(()=>references('db/postgres/initialize-application.js',
  'const repositories=Object.freeze([]); require(`../../server/database/postgres/${moduleName}`)',parser),
  /dynamic source edge unresolved/);
const initializer=fs.readFileSync('db/postgres/initialize-application.js','utf8');
assert.throws(()=>references('db/postgres/initialize-application.js',initializer+
  '\nfunction decoy(moduleName){return require(`../../server/database/postgres/${moduleName}`)}',parser),
  /dynamic source edge unresolved|Reviewed dynamic-source exception changed/);
assert.throws(()=>references('db/postgres/initialize-application.js',initializer.replace(
  'await require(`../../server/database/postgres/${moduleName}`)[method]();',
  'const moduleName=externalName; await require(`../../server/database/postgres/${moduleName}`)[method]();'),parser),
  /dynamic source edge unresolved|Reviewed dynamic-source exception changed/);
assert.throws(()=>references('db/postgres/initialize-application.js',initializer.replace(
  'for (const [schema, , moduleName, method] of repositories)',
  'const repositories=externalRows; for (const [schema, , moduleName, method] of repositories)'),parser),
  /dynamic source edge unresolved|Reviewed dynamic-source exception changed/);
const startup=fs.readFileSync('scripts/start-application.js','utf8');
assert.throws(()=>references('scripts/start-application.js',startup+
  '\nfunction decoy(kind){return require(`./install/mcp-owned-${kind}`)}',parser),
  /Reviewed dynamic-source exception changed/);
assert.throws(()=>references('scripts/start-application.js',startup.replace(
  'start: options => require(`./install/mcp-owned-${kind}`).startExisting(options)',
  'start: options => {kind=options.kind;return require(`./install/mcp-owned-${kind}`).startExisting(options)}'),parser),
  /Reviewed dynamic-source exception changed/);
for(const file of ['db/postgres/initialize-application.js','scripts/start-application.js',
  'agent-host/shared/vectorStore.js','scripts/setup-application.js']) {
  const original=fs.readFileSync(file,'utf8');
  assert.throws(()=>references(file,original+'\n// changed reviewed bytes',parser),
    /Reviewed dynamic-source exception changed/);
}
assert.deepEqual(references('other.js',"load(variable)",parser),[]);
"""
  result=subprocess.run([str(node),'-e',script],cwd=source,capture_output=True,text=True,
                        timeout=10,env={'PATH':str(node.parent),'NODE_OPTIONS':'--no-addons'})
  self.assertEqual(result.returncode,0,result.stderr[:2000])
 def test_student_deletion_ast_traverses_literal_dynamic_mjs_and_rejects_dynamic_require(self):
  source=Path(__file__).resolve().parents[2]
  node=source/'tasks/runtime/node/node_modules/node/bin/node'
  temporary_parent=source/'tasks/tmp'
  with tempfile.TemporaryDirectory(prefix='deletion-ast-',dir=temporary_parent) as temporary:
   directory=Path(temporary)
   (directory/'entry.js').write_text("import('./child.mjs')")
   (directory/'child.mjs').write_text("import './leaf.js';")
   (directory/'leaf.js').write_text('export const value=1;')
   root=directory.relative_to(source).as_posix()
   script="const x=require('./tests/fixtures/studentDeletionSourceClosure'); process.stdout.write(JSON.stringify(x.collect(process.argv[1],[process.argv[2]])))"
   result=subprocess.run([str(node),'-e',script,str(source),root+'/entry.js'],cwd=source,
                         capture_output=True,text=True,timeout=10,
                         env={'PATH':str(node.parent),'NODE_OPTIONS':'--no-addons'})
   self.assertEqual(result.returncode,0,result.stderr[:2000])
   self.assertEqual(set(json.loads(result.stdout)),
                    {root+'/entry.js',root+'/child.mjs',root+'/leaf.js'})
   (directory/'child.mjs').write_text('require(computed)')
   rejected=subprocess.run([str(node),'-e',script,str(source),root+'/entry.js'],cwd=source,
                           capture_output=True,text=True,timeout=10,
                           env={'PATH':str(node.parent),'NODE_OPTIONS':'--no-addons'})
   self.assertNotEqual(rejected.returncode,0)
   self.assertIn('Executable dynamic source edge unresolved',rejected.stderr)
 def test_package_inventory_authenticates_scanner_and_parser_before_execution(self):
  from full_backend_auth_contract import validate_package
  root=Path(__file__).resolve().parents[2]
  node=root/'tasks/runtime/node/node_modules/node/bin/node'
  with tempfile.TemporaryDirectory(dir=root/'tasks/tmp') as temporary:
   parent=Path(temporary)/'package'
   source=parent/'source'
   source.mkdir(parents=True)
   manifest=parent/'manifest.json'
   manifest.write_text('{}')
   manifest.chmod(0o444)
   parent.chmod(0o555)
   try:
    with patch('full_backend_auth_contract.validate_manifest',return_value={'files':{}}), \
         patch('full_backend_auth_contract.inventory',side_effect=RuntimeError('complete inventory mismatch')), \
         patch('full_backend_auth_contract.validate_student_deletion_source_closure') as scanner:
     with self.assertRaisesRegex(RuntimeError,'complete inventory mismatch'):
      validate_package(source,manifest,hashlib.sha256(manifest.read_bytes()).hexdigest(),
                       node,hashlib.sha256(node.read_bytes()).hexdigest())
     scanner.assert_not_called()
   finally: parent.chmod(0o700)
 def test_mcp_rendered_lifecycle_closure_is_required(self):
  from full_backend_auth_contract import MCP_RENDERED_REQUIRED, validate_mcp_rendered_manifest
  self.assertIn('tests/fixtures/mcpRenderedAdminLifecycle.js',MCP_RENDERED_REQUIRED)
  value={'files':dict.fromkeys(MCP_RENDERED_REQUIRED,'a'*64)}
  validate_mcp_rendered_manifest(value,True)
  for missing in MCP_RENDERED_REQUIRED:
   partial={'files':{key:sha for key,sha in value['files'].items() if key!=missing}}
   with self.assertRaises(RuntimeError):validate_mcp_rendered_manifest(partial,True)
  validate_mcp_rendered_manifest({'files':{}},False)
 def test_secureshop_agent_host_source_closure_matches_offline_resolver(self):
  from full_backend_auth_contract import SECURESHOP_AGENT_HOST_SOURCE_CLOSURE
  source=Path(__file__).resolve().parents[2]
  node=shutil.which('node');self.assertIsNotNone(node)
  completed=subprocess.run(
   [node,str(source/'tests/fixtures/secureShopAgentHostSourceClosure.js'),str(source)],
   check=True,capture_output=True,text=True,timeout=30,
   env={**os.environ,'NODE_OPTIONS':'--no-addons'},
  )
  observed=json.loads(completed.stdout)
  self.assertEqual(len(observed['agents']),17)
  self.assertEqual(set(observed['files']),SECURESHOP_AGENT_HOST_SOURCE_CLOSURE)
  self.assertEqual(
   {(item['file'],item['kind']) for item in observed['dynamic']},
   {('server/agent-runtime/dpiPolicyBinding.js', 'literal-local-conditional'), ('agent-host/index.js', 'canonical-agent-registry'), ('db/postgres/initialize-application.js', 'canonical-postgres-repository-manifest'), ('agent-host/shared/vectorStore.js', 'shared-vector-store')},
  )
  self.assertIn('server/services/secureshop/vectorStore.js',observed['files'])
  self.assertIn('server/database/postgres/secureshopVectorRepository.js',observed['files'])
 def test_agent_host_manifest_and_literal_conditional_reject_unknown_sources_in_memory(self):
  source=Path(__file__).resolve().parents[2]
  script=r"""
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const root=process.argv[1],read=fs.readFileSync;
const {collectAgentHostSourceClosure}=require(path.join(root,'tests/fixtures/secureShopAgentHostSourceClosure.js'));
const file=path.join(root,'db/postgres/initialize-application.js'),original=read(file,'utf8');
const cases=[
 ['const repositories = Object.freeze([','let repositories = Object.freeze(['],
 ['const repositories = Object.freeze([','const repositories = (['],
 ["'sqlWorkshopDb'","'../sqlWorkshopDb'"],
 ['for (const [schema, , moduleName, method] of repositories)','for (const [schema, , other, method] of repositories)'],
 ['${moduleName}`','${method}`'],
 ['const requiredStoreManifest',"repositories[1][2]='otherModule'; const requiredStoreManifest"],
 ['const requiredStoreManifest','const alias=repositories; const requiredStoreManifest'],
 ['const requiredStoreManifest',"for(const tuple of repositories) tuple[2]='otherModule'; const requiredStoreManifest"],
 ['await require(`../../server/database/postgres/${moduleName}`)[method]();','{const moduleName="other"; await require(`../../server/database/postgres/${moduleName}`)[method]();}'],
 ['await require(`../../server/database/postgres/${moduleName}`)[method]();','{const [,,moduleName]=[null,null,"other"]; await require(`../../server/database/postgres/${moduleName}`)[method]();}'],
 ['await require(`../../server/database/postgres/${moduleName}`)[method]();','await (async function(moduleName){ return require(`../../server/database/postgres/${moduleName}`)[method](); })("other");']
];
for(const [from,to] of cases){assert.ok(original.includes(from),from);fs.readFileSync=function(p,...args){return path.resolve(String(p))===file?original.replace(from,to):read.call(this,p,...args);};try{assert.throws(()=>collectAgentHostSourceClosure(root),/manifest|repository|dynamic require/);}finally{fs.readFileSync=read;}}
const conditional=path.join(root,'server/agent-runtime/dpiPolicyBinding.js'),body=read(conditional,'utf8');
for(const replacement of ["decoder?'./dpiDecoderEvidence':computed", "decoder?'./dpiDecoderEvidence':'../../../../outside-closure'", "decoder?'./dpiDecoderEvidence':(other?'./dpiActorProof':'./dpiActorProof')"]){fs.readFileSync=function(p,...args){return path.resolve(String(p))===conditional?body.replace("decoder?'./dpiDecoderEvidence':'./dpiActorProof'",replacement):read.call(this,p,...args);};try{assert.throws(()=>collectAgentHostSourceClosure(root),/dynamic require|unresolved|escapes/);}finally{fs.readFileSync=read;}}
const actual=collectAgentHostSourceClosure(root);for(const f of ['server/agent-runtime/dpiDecoderEvidence.js','server/agent-runtime/dpiActorProof.js'])assert.ok(actual.files.includes(f));
"""
  subprocess.run([shutil.which('node'),'-e',script,str(source)],check=True,capture_output=True,text=True,timeout=30,env={**os.environ,'NODE_OPTIONS':'--no-addons'})
 def test_secureshop_rendered_closure_is_explicit_complete_and_exclusive(self):
  from full_backend_auth_contract import SECURESHOP_RENDERED_REQUIRED, validate_secureshop_rendered_manifest
  value={'files':dict.fromkeys(SECURESHOP_RENDERED_REQUIRED,'a'*64)}
  validate_secureshop_rendered_manifest(value,True,True)
  validate_secureshop_rendered_manifest({'files':{}},False,False)
  for missing in SECURESHOP_RENDERED_REQUIRED:
   partial={'files':{key:sha for key,sha in value['files'].items() if key!=missing}}
   with self.assertRaises(RuntimeError):validate_secureshop_rendered_manifest(partial,True,True)
  for rendered,mcp in [(False,False),(True,True)]:
   with self.assertRaises(RuntimeError):validate_secureshop_rendered_manifest(value,True,rendered,mcp)
 def fixture(self):return dict(version=1,scope='full_backend_auth',files={**{p:'a'*64 for p in REQUIRED|REVIEWED_MIGRATIONS},**EMBEDDING_ASSETS,**QUALIFIED_ADDITIONAL_MIGRATIONS},symlinks={},directories=[])
 def test_embedding_asset_identity_cannot_be_replaced(self):
  for name in EMBEDDING_ASSETS:
   value=self.fixture();value['files'][name]='f'*64
   with self.assertRaises(RuntimeError):validate_manifest(value)
 def test_qualified_migration_checksums_cannot_be_replaced(self):
  for name in QUALIFIED_ADDITIONAL_MIGRATIONS:
   value=self.fixture();value['files'][name]='f'*64
   with self.assertRaises(RuntimeError):validate_manifest(value)
 def test_exact_stores_and_migrations(self):
  self.assertEqual(len(STORES),16);self.assertEqual(len(set(x[0] for x in STORES)),16)
  validate_manifest(self.fixture())
  for name in ['db/postgres/identity-migrations/0062_candidate.sql','db/postgres/workshop-migrations/legacy_challenge/0004_candidate.sql']:
   value=self.fixture();value['files'][name]='a'*64
   with self.assertRaises(RuntimeError):validate_manifest(value)
  value=self.fixture();value['files'].pop(next(iter(REVIEWED_MIGRATIONS)))
  with self.assertRaises(RuntimeError):validate_manifest(value)
 def test_startup_import_closure_is_required_even_when_secureshop_disabled(self):
  for name in ['tests/fixtures/fullBackendSecureShopStartup.js','tests/fixtures/fullBackendSecureShopAdmission.js']:
   value=self.fixture();value['files'].pop(name)
   with self.assertRaises(RuntimeError):validate_manifest(value)
 def test_only_exact_upload_source_module_allowed(self):
  for relative,accepted in [('agent-host/agents/uploads/server.js',True),('agent-host/agents/uploads/tools/index.js',True),('agent-host/agents/uploads/private.txt',False),('server/uploads/private.txt',False)]:
   with tempfile.TemporaryDirectory() as temp:
    root=Path(temp).resolve()/'source';target=root/relative;target.parent.mkdir(parents=True);target.write_text('source')
    for entry in sorted(root.rglob('*'),reverse=True):entry.chmod(0o555 if entry.is_dir() else 0o444)
    root.chmod(0o555)
    try:
     if accepted:self.assertIn(relative,inventory(root)['files'])
     else:
      with self.assertRaises(RuntimeError):inventory(root)
    finally:
     root.chmod(0o755)
     for entry in root.rglob('*'):
      if entry.is_dir():entry.chmod(0o755)
 def test_capacity_layout(self):
  row={'HostConfig':{'Memory':536870912,'NanoCpus':2000000000,'PidsLimit':256,'Tmpfs':{'/var/lib/postgresql':'rw,size=1073741824'}},'Mounts':[],
       'NetworkSettings':{'Ports':{'5432/tcp':[{'HostIp':'127.0.0.1','HostPort':'54321'}]}}}
  self.assertEqual(validate_fullboot_layout(row),54321)
  row['HostConfig']['Tmpfs']['/var/lib/postgresql']='rw,size=268435456'
  with self.assertRaises(RuntimeError):validate_fullboot_layout(row)
 def test_mcp_indirect_requires_explicit_rendered_pinned_manifest(self):
  endpoints={'version':1,'postgres':{'host':'127.0.0.1','port':38090},'runner':{'host':'127.0.0.1','port':38091},'smtp':{'host':'127.0.0.1','port':38092},'mailpit':{'host':'127.0.0.1','port':38093},'model':{'host':'127.0.0.1','port':11434}}
  self.assertEqual(validate_mcp_indirect_configuration(True,True,MCP_MODEL_DIGEST,endpoints),endpoints)
  for bad in [dict(endpoints,model={'host':'localhost','port':11434}),dict(endpoints,runner={'host':'127.0.0.1','port':38090})]:
   with self.assertRaises(RuntimeError):validate_mcp_indirect_configuration(True,True,MCP_MODEL_DIGEST,bad)
  with self.assertRaises(RuntimeError):validate_mcp_indirect_configuration(True,False,MCP_MODEL_DIGEST,endpoints)
  with self.assertRaises(RuntimeError):validate_mcp_indirect_configuration(True,True,'a'*64,endpoints)
  self.assertIsNone(validate_mcp_indirect_configuration(False,False,None,None))

if __name__=='__main__':unittest.main()

class RenderedAdmission(unittest.TestCase):
 def test_browser_rejected_before_resources(self):
  from full_backend_auth_contract import validate_rendered, RENDERED_REQUIRED, RENDERED_SOURCE_FILES, BROWSER_SHA256
  validate_rendered({},False,None,None)
  with self.assertRaises(RuntimeError):validate_rendered({},False,'/unrequested',BROWSER_SHA256)
  with self.assertRaises(RuntimeError):validate_rendered({'files':{}},True,'/missing',BROWSER_SHA256)
  manifest={'files':dict.fromkeys(RENDERED_REQUIRED|RENDERED_SOURCE_FILES,'a'*64)}
  with self.assertRaises(RuntimeError):validate_rendered(manifest,True,'/missing',BROWSER_SHA256)

class FullMcpControlTests(unittest.TestCase):
 def test_exact_one_use_control(self):
  import os
  from full_backend_auth_contract import consume_full_mcp_control
  with tempfile.TemporaryDirectory() as temporary:
   root=Path(temporary).resolve();source=root/'package'/'source';source.mkdir(parents=True);evidence=root/'evidence';evidence.mkdir()
   control=root/'grant.json';expected={'mcp_indirect':True,'owner_handle':'42','model_digest':'a'*64}
   value=dict(expected,scope='full_backend_mcp_indirect',status='granted',allowedLaunches=1)
   control.write_text(json.dumps(value));os.chmod(control,0o600)
   with self.assertRaises(RuntimeError):consume_full_mcp_control(control,dict(expected,owner_handle='43'),source,evidence)
   self.assertEqual(json.loads(control.read_text())['status'],'granted')
   consume_full_mcp_control(control,expected,source,evidence)
   self.assertEqual(json.loads(control.read_text())['status'],'consumed')
   with self.assertRaises(RuntimeError):consume_full_mcp_control(control,expected,source,evidence)

class ExactDependencyLog(unittest.TestCase):
 def test_only_pinned_empty_dependency_log_is_admitted(self):
  for relative,content,allowed in [('client/node_modules/nwsapi/dist/lint.log',b'',True),('client/node_modules/nwsapi/dist/lint.log',b'not empty',False),('client/node_modules/nwsapi/dist/other.log',b'',False),('server/runtime.log',b'',False),('.env',b'',False)]:
   with self.subTest(relative=relative,content=content),tempfile.TemporaryDirectory() as temporary:
    root=Path(temporary).resolve()/'source';target=root/relative;target.parent.mkdir(parents=True);target.write_bytes(content);target.chmod(0o444)
    for directory,_,_ in os.walk(root,topdown=False):Path(directory).chmod(0o555)
    try:
     if allowed:self.assertIn(relative,inventory(root)['files'])
     else:
      with self.assertRaises(RuntimeError):inventory(root)
    finally:
     for directory,_,_ in os.walk(root):Path(directory).chmod(0o700)
