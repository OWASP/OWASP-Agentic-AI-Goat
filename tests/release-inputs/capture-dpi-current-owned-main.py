"""Read-only DPI manifest/argv capture. Does not run the plan or allocate resources."""
import pathlib,json,hashlib,importlib.util,sys,os,re
P=pathlib.Path(__file__).resolve().parent;ROOT=P.parents[1]
def sha(p):
 with pathlib.Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def publish(path,value):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w')as f:json.dump(value,f,separators=(',',':'));f.write('\n');f.flush();os.fsync(f.fileno())
def main():
 if len(sys.argv)!=3 or not re.fullmatch(r'v[1-9][0-9]*',sys.argv[1]) or not re.fullmatch('[a-f0-9]{64}',sys.argv[2]):raise RuntimeError('Expected version and source capture SHA256')
 version=sys.argv[1];source=P/('dpi-current-owned-source-pins-'+version+'.json')
 if source.resolve()!=source or sha(source)!=sys.argv[2]:raise RuntimeError('Source capture identity mismatch')
 m=json.loads(source.read_text());pins=m['sourcePins']
 def verify():
  for rel,h in pins.items():
   p=ROOT/rel
   if pathlib.Path(rel).is_absolute() or '..'in pathlib.Path(rel).parts or p.resolve()!=p or sha(p)!=h:raise RuntimeError('Source pin mismatch')
 verify();sys.path.insert(0,str(ROOT/'tests/postgres'));spec=importlib.util.spec_from_file_location('dpi_owned_capture',ROOT/'tests/postgres/run-setup-database-phase-isolated.py');parent=importlib.util.module_from_spec(spec);spec.loader.exec_module(parent)
 lineage=P/'finflow-traversal-plan-argv-v2.json';old=json.loads(lineage.read_text())['planArgv'];value=lambda key:old[old.index(key)+1]
 runtime={}
 for key in ('node','docker'):
  f=pathlib.Path(value('--'+key));h=value('--'+key+'-sha256')
  if not f.is_absolute() or f.resolve()!=f or sha(f)!=h:raise RuntimeError('Runtime changed')
  runtime[key]={'path':str(f),'sha256':h}
 if '/node-v26.10.0-'not in runtime['node']['path']:raise RuntimeError('Current Node required')
 if sys.version_info[:2]!=(3,14) or sha(pathlib.Path(sys.executable).resolve())!=value('--python-sha256'):raise RuntimeError('Current Python changed')
 runtime['python']={'path':str(pathlib.Path(sys.executable).resolve()),'sha256':value('--python-sha256')}
 result={'cohort':'dpi-current-owned','mode':'actual-model','workspace':str(ROOT),'model':parent.POLICY_MODEL,'modelDigest':parent.POLICY_DIGEST,'inputSha256':parent.DPI_INPUT_SHA256,'budgets':parent.DPI_BUDGETS,'sourcePins':pins,'sourceCaptureSha256':sys.argv[2],'dynamicRequires':m['dynamicRequires'],'dynamicReviewRequired':True,'authorReports':m['authorReports'],'dependencyInventory':parent.inventory(ROOT/'node_modules'),'runtimePins':runtime,'mainEnvSha256':sha(ROOT/'.env')if(ROOT/'.env').exists()else None,'imageId':value('--image-id'),'runtimeLineage':{'path':str(lineage),'sha256':sha(lineage)},'actualExecution':False}
 verify();parent.validate_dpi_manifest(result)
 target=P/('dpi-current-owned-main-manifest-'+version+'.json');argv=P/('dpi-current-owned-plan-argv-'+version+'.json')
 if target.exists()or argv.exists():raise RuntimeError('Exclusive outputs already exist')
 publish(target,result)
 args=[runtime['python']['path'],'-B',str(ROOT/'tests/postgres/run-setup-database-phase-isolated.py'),'--package',str(ROOT),'--main-workspace','--scenario','dpi-current-owned','--manifest',str(target),'--manifest-sha256',sha(target)]
 for key in ('node','node-sha256','python-sha256','docker','docker-sha256','docker-host','docker-daemon','image-id'):args+=['--'+key,value('--'+key)]
 args+=['--plan'];publish(argv,{'planArgv':args})
 print(json.dumps({'manifest':str(target),'manifestSha256':sha(target),'argv':str(argv),'argvSha256':sha(argv),'sourceCount':len(pins),'dependencyCount':len(result['dependencyInventory']),'dynamicRequires':result['dynamicRequires'],'dynamicReviewRequired':True,'executed':False}))
if __name__=='__main__':main()
