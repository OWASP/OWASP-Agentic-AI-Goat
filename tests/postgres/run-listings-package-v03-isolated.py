#!/usr/bin/env python3
"""Qualify one current-source Listings image, run V03 while it is live, then remove it."""
import argparse, hashlib, importlib.util, json, os, re, signal, subprocess, sys
from pathlib import Path
HERE=Path(__file__).resolve().parent; ROOT=HERE.parents[1]; sys.path.insert(0,str(HERE))
import listings_package_candidate as package
LAUNCHER=HERE/'run-secureshop-agent-host-transport-main.py'; SELF='tests/postgres/run-listings-package-v03-isolated.py'; HEX=re.compile(r'[a-f0-9]{64}')
def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod
def parser():
 p=argparse.ArgumentParser(allow_abbrev=False)
 for name in ('main-workspace','node','docker','docker-sha256','docker-host','docker-daemon','image-id','browser','browser-sha256','browser-root','ollama-model-sha256','v03-native-receipt','v03-native-receipt-sha256','v03-native-result','v03-native-result-sha256'):p.add_argument('--'+name,required=True)
 p.add_argument('--evidence-parent',required=True);p.add_argument('--plan',action='store_true');return p
def run_child(command,cwd,timeout=1800,grace=300):
 process=subprocess.Popen(command,cwd=cwd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
   text=True,start_new_session=True);timed_out=False
 try: output,error=process.communicate(timeout=timeout)
 except subprocess.TimeoutExpired:
  timed_out=True;os.killpg(process.pid,signal.SIGTERM)
  try: output,error=process.communicate(timeout=grace)
  except subprocess.TimeoutExpired:
   os.killpg(process.pid,signal.SIGKILL);output,error=process.communicate(timeout=30)
 return process.returncode,output,error,timed_out
def main(argv=None):
 a=parser().parse_args(argv);launcher=load(LAUNCHER,'v03_compound_launcher');source=launcher.validate_static(launcher.parse(['--main-workspace',a.main_workspace,'--node',a.node,'--docker',a.docker,'--docker-sha256',a.docker_sha256,'--docker-host',a.docker_host,'--docker-daemon',a.docker_daemon,'--cohort','listings-package']))
 def child(admission):
  if not isinstance(admission,dict) or set(admission)!={'imageId','imageTag','sourceSha256','runtimeDigest','evidence'} or any(not isinstance(admission.get(key),str) or not HEX.fullmatch(admission[key]) for key in ('sourceSha256','runtimeDigest')) or not re.fullmatch(r'sha256:[a-f0-9]{64}',admission.get('imageId','')):raise RuntimeError('Closed V03 package callback admission required')
  parent=Path(admission['evidence'])/'v03';parent.mkdir(mode=0o700)
  args=['--main-workspace',a.main_workspace,'--node',a.node,'--docker',a.docker,'--docker-sha256',a.docker_sha256,'--docker-host',a.docker_host,'--docker-daemon',a.docker_daemon,'--image-id',a.image_id,'--cohort',launcher.V03_OPTIMIZE_BROWSER,'--browser',a.browser,'--browser-sha256',a.browser_sha256,'--browser-root',a.browser_root,'--ollama-model-sha256',a.ollama_model_sha256,'--listings-image-id',admission['imageId'],'--listings-runtime-digest',admission['runtimeDigest'],'--v03-native-receipt',a.v03_native_receipt,'--v03-native-receipt-sha256',a.v03_native_receipt_sha256,'--v03-native-result',a.v03_native_result,'--v03-native-result-sha256',a.v03_native_result_sha256,'--evidence-parent',str(parent)]
  returncode,output,error,timed_out=run_child([sys.executable,str(LAUNCHER),*args],source)
  stdout=Path(admission['evidence'])/'v03.stdout';stderr=Path(admission['evidence'])/'v03.stderr'
  for path,value in ((stdout,output),(stderr,error)):
   if len(value.encode())>8*1024*1024:raise RuntimeError('V03 child output exceeds bound')
   with path.open('x',encoding='utf-8') as stream:os.chmod(path,0o600);stream.write(value)
  if timed_out: raise RuntimeError('V03 child timed out after graceful cleanup window')
  if returncode: raise RuntimeError('V03 child failed')
  rows=[]
  for line in output.splitlines():
   try:v=json.loads(line)
   except:continue
   if isinstance(v,dict) and set(v)=={'evidence','passed','cleanup'}:rows.append(v)
  if len(rows)!=1 or rows[0]['passed'] is not True:raise RuntimeError('V03 child receipt unavailable')
  result=Path(rows[0]['evidence'])/'result.json';return {'evidence':rows[0]['evidence'],'resultSha256':hashlib.sha256(result.read_bytes()).hexdigest()}
 package_args=launcher.parse(['--main-workspace',a.main_workspace,'--node',a.node,'--docker',a.docker,'--docker-sha256',a.docker_sha256,'--docker-host',a.docker_host,'--docker-daemon',a.docker_daemon,'--cohort','listings-package','--evidence-parent',a.evidence_parent]+(['--plan'] if a.plan else []))
 if a.plan:
  package.source_manifest(launcher,package_args,source,(SELF,));planned=launcher.parse(['--main-workspace',a.main_workspace,'--node',a.node,'--docker',a.docker,'--docker-sha256',a.docker_sha256,'--docker-host',a.docker_host,'--docker-daemon',a.docker_daemon,'--image-id',a.image_id,'--cohort',launcher.V03_OPTIMIZE_BROWSER,'--browser',a.browser,'--browser-sha256',a.browser_sha256,'--browser-root',a.browser_root,'--ollama-model-sha256',a.ollama_model_sha256,'--listings-image-id','sha256:'+'0'*64,'--listings-runtime-digest','0'*64,'--v03-native-receipt',a.v03_native_receipt,'--v03-native-receipt-sha256',a.v03_native_receipt_sha256,'--v03-native-result',a.v03_native_result,'--v03-native-result-sha256',a.v03_native_result_sha256,'--plan']);launcher.validate_static(planned);print(json.dumps({'cohort':'listings-package-v03','sourceCopy':False,'nativeStarted':False,'browserStarted':False}));return 0
 return package.qualify(launcher,package_args,source,after_package=child,additional_drivers=(SELF,))
if __name__=='__main__':raise SystemExit(main())
