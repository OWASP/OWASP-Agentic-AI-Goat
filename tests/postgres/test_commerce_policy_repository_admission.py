import ast,re,unittest,hashlib,json,os,stat,tempfile,types,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
class CommercePolicy(unittest.TestCase):
 def load(self):
  p=ROOT/'tests/postgres/run_standalone_commerce_with_inspector.py'
  tree=ast.parse(p.read_text());nodes=[n for n in tree.body if isinstance(n,(ast.Assign,ast.FunctionDef)) and (isinstance(n,ast.Assign) or n.name=='validate_arguments')]
  ns={'Path':Path,'re':re,'__file__':str(p)};exec(compile(ast.Module(body=nodes,type_ignores=[]),str(p),'exec'),ns);return ns
 def args(self,n):
  v={k:'value' for k in n['REQUIRED']};v.update({'--cohort':n['COHORT'],'--main-workspace':str(ROOT),'--evidence-parent':str(ROOT/'tasks/qualification')})
  for k in v:
   if k.endswith('-sha256'):v[k]='a'*64
  return ['--plan','--commerce-test-no-sandbox']+[x for pair in v.items() for x in pair]
 def test_no_renderer_unchanged(self):
  n=self.load();a=self.args(n);self.assertEqual(n['validate_arguments'](a,planning=True),a)
 def test_exact_optional(self):
  n=self.load();a=self.args(n)+['--policy-renderer-admission',str(ROOT/'tasks/qualification/commerce-policy-renderer/admission.json'),'--policy-renderer-admission-sha256','b'*64];self.assertEqual(n['validate_arguments'](a,planning=True),a)
 def test_denials(self):
  n=self.load();base=self.args(n)
  for extra in (['--policy-renderer-admission','/tmp/arbitrary'],['--policy-renderer-admission','/tmp/arbitrary','--policy-renderer-admission-sha256','b'*64],['--policy-renderer-admission',str(ROOT/'tasks/qualification/commerce-policy-renderer/admission.json'),'--policy-renderer-admission-sha256','bad']):
   with self.subTest(extra=extra),self.assertRaises(RuntimeError):n['validate_arguments'](base+extra,planning=True)
 def test_other_cohort_denied(self):
  n=self.load();a=self.args(n);a[a.index('--cohort')+1]=n['ACCOUNT_AVATAR_COHORT'];a+=['--policy-renderer-admission',str(ROOT/'tasks/qualification/commerce-policy-renderer/admission.json'),'--policy-renderer-admission-sha256','b'*64]
  with self.assertRaises(RuntimeError):n['validate_arguments'](a,planning=True)
 def test_actual_main_private_admission(self):
  p=ROOT/'tests/postgres/run-secureshop-agent-host-transport-main.py';tree=ast.parse(p.read_text());node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='policy_renderer_admission');ns={'Path':Path,'os':os,'stat':stat,'re':re,'hashlib':hashlib,'json':json,'POLICY_INSTRUCTION_BROWSER':'policy-instruction-browser'};exec(compile(ast.Module(body=[node],type_ignores=[]),str(p),'exec'),ns)
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp).resolve();p=root/'tasks/qualification/commerce-policy-renderer/admission.json';p.parent.mkdir(parents=True,mode=0o700)
   value={'version':1,'workspace':str(root),'home':str(root),'managedSha256':'a'*64,'stageSha256':'b'*64,'dockerExecutable':'/fixed/docker','dockerExecutableSha256':'c'*64};raw=json.dumps(value).encode();p.write_bytes(raw);p.chmod(0o600)
   a=types.SimpleNamespace(cohort='standalone-commerce-browser',current_host_profile='owned',policy_renderer_admission=str(p),policy_renderer_admission_sha256=hashlib.sha256(raw).hexdigest(),docker='/fixed/docker',docker_sha256='c'*64)
   self.assertEqual(ns['policy_renderer_admission'](a,root)['value'],value)
   a.cohort='account-avatar-browser'
   with self.assertRaises(RuntimeError):ns['policy_renderer_admission'](a,root)
   a.cohort='standalone-commerce-browser';p.chmod(0o644)
   with self.assertRaises(RuntimeError):ns['policy_renderer_admission'](a,root)
   p.chmod(0o600);a.policy_renderer_admission_sha256='f'*64
   with self.assertRaises(RuntimeError):ns['policy_renderer_admission'](a,root)
 def test_actual_js_path_fences(self):
  p=ROOT/'tests/fixtures/secureshopOwnedPolicyRendererAdmission.js'
  program="""const Module=require('node:module'),assert=require('node:assert/strict');let s='';process.stdin.on('data',x=>s+=x);process.stdin.on('end',()=>{const m=new Module(process.argv[1]);m.filename=process.argv[1];m.paths=Module._nodeModulePaths(require('node:path').dirname(m.filename));m._compile(s,m.filename);const root=process.argv[2],f=root+'/tasks/qualification/commerce-policy-renderer/admission.json',env={SECURESHOP_STANDALONE_COMMERCE_NATIVE:'1',PG_TEST_DISPOSABLE:'yes',NODE_ENV:'test',OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE:root};m.exports.rendererAdmissionPath(root,f,env);assert.throws(()=>m.exports.rendererAdmissionPath(root,f+'/other',env));assert.throws(()=>m.exports.rendererAdmissionPath(root,f,{...env,PG_TEST_DISPOSABLE:'no'}));assert.throws(()=>m.exports.rendererAdmissionPath(root,f,{...env,SECURESHOP_STANDALONE_COMMERCE_NATIVE:undefined}));});"""
  r=subprocess.run([str(ROOT/'tasks/runtime/node/node_modules/node/bin/node'),'-e',program,str(p),str(ROOT)],input=p.read_text(),text=True,capture_output=True,timeout=10);self.assertEqual(r.returncode,0,r.stderr)
 def test_actual_commerce_early_admission(self):
  p=ROOT/'tests/fixtures/secureshopCommerceBrowserAdmission.js'
  program="""const vm=require('node:vm'),assert=require('node:assert/strict'),path=require('node:path');let s='';process.stdin.on('data',x=>s+=x);process.stdin.on('end',async()=>{const start=s.indexOf('async function admitCommerceBrowser('),end=s.indexOf('  const run = path.dirname(evidencePath);',start);assert(start>0&&end>start);const fn=vm.runInNewContext('('+s.slice(start,end)+'return true;})',{assert,path,process,PREFIX:'SECURESHOP_COMMERCE_',COHORT:'standalone-commerce-browser',commerceVariant:v=>({cohort:v,selector:v==='standalone-commerce-browser'?'SECURESHOP_STANDALONE_COMMERCE_NATIVE':'SECURESHOP_ACCOUNT_AVATAR_NATIVE'})});const workspace=process.cwd(),filename=path.join(workspace,'tasks/qualification/commerce-policy-renderer/admission.json');const env={SECURESHOP_COMMERCE_TEST_NO_SANDBOX:'1',SECURESHOP_STANDALONE_COMMERCE_NATIVE:'1',PG_TEST_DISPOSABLE:'yes',NODE_ENV:'test',OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE:workspace};const options={workspace,variant:'standalone-commerce-browser'};assert.equal(await fn(env,options),true);assert.equal(await fn({...env,SECURESHOP_STANDALONE_COMMERCE_POLICY_RENDERER_ADMISSION:filename},options),true);await assert.rejects(fn({...env,SECURESHOP_STANDALONE_COMMERCE_POLICY_RENDERER_ADMISSION:'/tmp/other'},options));await assert.rejects(fn({...env,SECURESHOP_STANDALONE_COMMERCE_NATIVE:undefined,SECURESHOP_ACCOUNT_AVATAR_NATIVE:'1',SECURESHOP_STANDALONE_COMMERCE_POLICY_RENDERER_ADMISSION:filename},{...options,variant:'account-avatar-browser'}));});"""
  r=subprocess.run([str(ROOT/'tasks/runtime/node/node_modules/node/bin/node'),'-e',program],input=p.read_text(),text=True,capture_output=True,timeout=10,cwd=ROOT);self.assertEqual(r.returncode,0,r.stderr)
if __name__=='__main__':unittest.main()
