import ast, argparse, hashlib, json, os, re, subprocess, sys, types, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
OUTPUT={name:(ROOT/name).read_text() for name in ('tests/postgres/aclPermissionCurrentHostAdmission.js', 'tests/postgres/secureshopEnabledIndexStartup.integration.test.js', 'tests/fixtures/secureshopEnabledUsersBrowser.js', 'tests/postgres/acl_permission_execution.py', 'tests/postgres/acl_permission_current_host.py', 'tests/postgres/run_acl_permission_with_inspector.py', 'tests/postgres/run-acl-permission-current-host.py', 'tests/postgres/acl_permission_receipt.py')}
def functions(text,names,env):
 tree=ast.parse(text); selected=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
 assert len(selected)==len(names)
 exec(compile(ast.Module(body=selected,type_ignores=[]),'<actual-materialized>','exec'),env)
 return env

class Admission(unittest.TestCase):
 def test_parse_explicit_only(self):
  source=OUTPUT['tests/postgres/acl_permission_current_host.py']
  parse=functions(source,{'parse'},{'argparse':argparse,'re':re})['parse']
  tree=ast.parse((ROOT/'tests/postgres/run_admin_student_deletion_with_inspector.py').read_text())
  values=next(n.value.args[0] for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='REQUIRED_VALUES' for t in n.targets))
  keys=ast.literal_eval(values)
  args=['--run','--acl-permission-recovery']
  for key in keys:args += [key,'a'*12 if key=='--nonce' else 'b'*64]
  self.assertTrue(parse(args).acl_permission_recovery)
  for bad in (args[0:1]+args[2:],args+['--acl-permission-recovery'],args+['--arbitrary-env','X=1']):
   with self.assertRaises((SystemExit,RuntimeError)):parse(bad)
 def test_actual_nonce_store_planner(self):
  base=(ROOT/'tests/postgres/admin_student_deletion_current_host.py').read_text()
  full=ast.parse((ROOT/'tests/postgres/full_backend_auth_contract.py').read_text())
  stores=ast.literal_eval(next(n.value for n in full.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='STORES' for t in n.targets)))
  scope=functions(base,{'database_plan'},{'re':re,'STORES':stores})
  functions(OUTPUT['tests/postgres/acl_permission_execution.py'],{'store_urls'},scope)
  urls=scope['store_urls']('a'*12,54321);self.assertEqual(len(urls),33)
  self.assertTrue(all('@127.0.0.1:54321/dvaia_test_student_deletion_aaaaaaaaaaaa_' in u for u in urls.values()))
  for nonce,port in [('foreign',54321),('a'*12,0),('a'*12,True)]:
   with self.assertRaises(RuntimeError):scope['store_urls'](nonce,port)
 def test_original_bounds_and_confinement(self):
  fixture=OUTPUT['tests/postgres/secureshopEnabledIndexStartup.integration.test.js']
  execution=OUTPUT['tests/postgres/acl_permission_execution.py']
  inspector=OUTPUT['tests/postgres/run_acl_permission_with_inspector.py']
  self.assertIn('timeout:180000',fixture);self.assertIn('ownerDeadline = Date.now() + 180000',fixture)
  self.assertIn('deadline=min(deadline, time.monotonic() + 210)',execution)
  self.assertNotIn('copyIsolatedSource',execution);self.assertNotIn("'vite",execution)
  self.assertIn("if (!currentHost) assert.equal(fs.statSync(source).mode & 0o222, 0",fixture)
  self.assertIn("flags != {'--run', '--acl-permission-recovery'}",inspector)
  self.assertIn('(deny file-write*)',inspector);self.assertIn("writable = ('tasks/qualification', 'tasks/tmp')",inspector)
  self.assertIn('snapshot_after()',execution);self.assertIn("row['Config']['Labels'].get('dvaia.test.owner') != owner_token",execution)
 def test_actual_js_grant_and_foreign_stores(self):
  program=r'''
const fs=require('fs'),Module=require('module'),path=require('path'),assert=require('assert/strict');
const texts=JSON.parse(fs.readFileSync(0,'utf8'));for(const [n,s]of Object.entries(texts))if(n.endsWith('.js'))new(require('vm').Script)(s);
const filename=path.resolve('tests/postgres/aclPermissionCurrentHostAdmission.js'),mod=new Module(filename,module);mod.filename=filename;mod.paths=Module._nodeModulePaths(path.dirname(filename));mod._compile(texts['tests/postgres/aclPermissionCurrentHostAdmission.js'],filename);
const {validateGrant,validateStores}=mod.exports,repo=process.cwd(),nonce='a'.repeat(12),sha='b'.repeat(64),temp=repo+'/tasks/qualification/run-admin-acl-permission-'+nonce+'/runtime/tmp';
const env={ADMIN_ACL_PERMISSION_BUILD_SHA256:sha,ADMIN_ACL_PERMISSION_SNAPSHOT_SHA256:sha,ADMIN_ACL_PERMISSION_STORE_PLAN_SHA256:sha,DVAIA_CHROMIUM_ACTUAL_EXECUTABLE:'/physical/chrome'};
const grant={version:1,cohort:'admin-acl-permission-current-host',launcherPid:11,workerPid:12,nonce,workspace:repo,buildSha256:sha,snapshotSha256:sha,storePlanSha256:sha,outerSandbox:'repository-only',chromium:'/physical/chrome',profile:temp+'/dvaia-acl-permission-browser-'+nonce};
const context={env,paths:{temp},repo,launcherPid:11,workerPid:12};assert.equal(validateGrant(grant,context).admitted,true);
for(const delta of [{workerPid:99},{launcherPid:99},{workspace:'/foreign'},{cohort:'admin-student-deletion-current-host'},{snapshotSha256:'c'.repeat(64)},{outerSandbox:'none'}])assert.throws(()=>validateGrant({...grant,...delta},context));
const stores=require('./db/postgres/initialize-application').requiredStoreManifest;
const e={PG_TEST_DISPOSABLE:'yes',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',PG_POOL_BUDGET:'78'};
for(const row of stores)for(const [key,role]of [[row.runtimeVariable,'runtime'],[row.migrationVariable,'migration']])e[key]=`postgresql://dvaia_${row.schema}_${role}@127.0.0.1:54321/dvaia_test_student_deletion_${nonce}_${row.schema}`;
assert.equal(validateStores(e).length,16);const key=stores[0].runtimeVariable;
for(const replacement of [e[key].replace('127.0.0.1','remote.invalid'),e[key].replace(nonce,'d'.repeat(12)),e[key].replace('_runtime@','_migration@'),e[key]+'?x=1'])assert.throws(()=>validateStores({...e,[key]:replacement}));
console.log('actual grant and all sixteen nonce URL negatives pass');
'''
  result=subprocess.run(['/bin/bash','tasks/run-in-repository.sh','tasks/runtime/node/node_modules/node/bin/node','-e',program],cwd=ROOT,input=json.dumps(OUTPUT),capture_output=True,text=True,timeout=15)
  self.assertEqual(result.returncode,0,result.stderr)

if __name__=='__main__':unittest.main()
