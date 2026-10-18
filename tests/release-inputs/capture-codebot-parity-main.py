#!/usr/bin/env python3
"""Explicit read-only inventory capture; no app imports, build, browser or DB launch."""
import argparse,hashlib,importlib.util,json,os,sys
from pathlib import Path

def sha(p):
 with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

REQUIRED = {
 'tests/postgres/run-setup-database-phase-isolated.py',
 'tests/postgres/run-finflow-backup-browser-main.py',
 'tests/postgres/codeBotRenderedParityMainV1.js',
 'tests/fixtures/codeBotRenderedParityV1.js',
 'tests/codeBotRenderedParityV1.test.js',
 'tests/postgres/codebot_parity_launcher_test.py',
 'tests/postgres/codebot_capture_test.py',
 'tests/fixtures/secureshopAnalyticsBrowserOwner.js',
 'tests/fixtures/browserProcessOwnership.js',
 'tests/postgres/sql_nosql_process_ownership.py',
 'tests/postgres/sql_nosql_docker_ownership.py',
 'tests/postgres/ctf_setup_sidecars.py',
 'tests/release-inputs/record-current-frontend-build.py',
 'tests/release-inputs/capture-codebot-parity-main.py',
 'package.json','package-lock.json','client/package.json','client/package-lock.json','client/vite.config.mjs','client/index.html',
}

def profile_requirements(profile):
 if profile not in ('codebot','workshop-history','mcp-audit-content','mcp-indirect-supply-content','mcp-remaining-nine-content','ipi-email-five-content','ipi-rag-query-content','ipi-rag-upload-clean-content','ipi-email-trigger-actual'):raise ValueError('Closed capture profile required')
 if profile=='ipi-email-trigger-actual':return (REQUIRED|{'tests/release-inputs/capture-codebot-parity-source.cjs','tests/codebotCaptureRoots.test.js','tests/postgres/ipiEmailRenderedFixture.js','tests/ipiEmailRenderedQualificationContract.test.js','tests/fixtures/ipiEmailTriggerActualInput.json','tests/postgres/finflowBackupBrowserActualTransport.js','tests/ipiRagActualParentContract.test.js','server/agent-runtime/indirectEmailGraph.js','server/agent-runtime/indirectEmailDeliveryGraph.js','server/services/ipiEmailProvider.js'},['db/postgres/identity-migrations'])
 if profile in ('ipi-email-five-content','ipi-rag-query-content','ipi-rag-upload-clean-content','ipi-email-trigger-actual'):return (REQUIRED|{'tests/postgres/ipiEmailRenderedFixture.js','tests/ipiEmailRenderedQualificationContract.test.js'},['db/postgres/identity-migrations'])
 if profile in ('mcp-indirect-supply-content','mcp-remaining-nine-content'):return (REQUIRED|{'tests/fixtures/mcpAuditContentBrowser.js','tests/mcpAuditContentBrowser.test.js','server/database/postgres/mcpWorkshopDb.js','server/routes/mcpWorkshop.js','tests/codebotCaptureRoots.test.js'},['db/postgres/identity-migrations','db/postgres/workshop-migrations/mcp'])
 if profile=='mcp-audit-content':return (REQUIRED|{'tests/fixtures/mcpAuditContentBrowser.js','tests/mcpAuditContentBrowser.test.js','tests/fixtures/mcpAuditSeedUpgrade.js','tests/mcpAuditDefaults.test.js','tests/fixtures/mcpAuditPriorDefaults.json','server/database/postgres/mcpWorkshopDb.js','server/routes/mcpWorkshop.js','tests/codebotCaptureRoots.test.js'},['db/postgres/identity-migrations','db/postgres/workshop-migrations/mcp'])
 return (REQUIRED|({'tests/fixtures/workshopHistoryBrowserQualification.js','tests/workshopHistoryBrowserQualification.test.js','server/database/postgres/sqlWorkshopDb.js','server/database/postgres/nosqlWorkshopDb.js','server/services/ariaAgentService.js','server/services/novaAgentService.js','server/routes/sqlWorkshop.js','server/routes/nosqlWorkshop.js','server/agent-runtime/workshopGraph.js','server/agent-runtime/workshopResultPresentation.js','server/services/workshopObjectiveGrader.js','server/agent-runtime/workshopRouteHandlers.js','tests/codebotCaptureRoots.test.js'} if profile=='workshop-history' else set()), ['db/postgres/identity-migrations']+['db/postgres/workshop-migrations/'+store for store in (['aria','nova'] if profile=='workshop-history' else ['supply_chain'])])

def verify_pins(root,pins,profile='codebot'):
 required,directories=profile_requirements(profile)
 if not isinstance(pins,dict) or not pins or not required.issubset(pins):raise RuntimeError('Mandatory CodeBot source closure incomplete')
 for rel,value in pins.items():
  target=root/rel
  if Path(rel).is_absolute() or '..' in Path(rel).parts or target.is_symlink() or not target.resolve().is_relative_to(root) or sha(target)!=value:raise RuntimeError('Source changed')
 for directory in directories:
  if not {p.relative_to(root).as_posix() for p in (root/directory).glob('*.sql')}.issubset(pins):raise RuntimeError('Migration closure incomplete')

def main():
 p=argparse.ArgumentParser(allow_abbrev=False)
 for key in ['source-pins','source-pins-sha256','output','build-report','build-report-sha256']:p.add_argument('--'+key,required=True)
 for key in ['browser','browser-root','browser-sha256']:p.add_argument('--'+key)
 p.add_argument('--profile',choices=['codebot','workshop-history','mcp-audit-content','mcp-indirect-supply-content','mcp-remaining-nine-content','ipi-email-five-content','ipi-rag-query-content','ipi-rag-upload-clean-content','ipi-email-trigger-actual'],default='codebot')
 a=p.parse_args();root=Path(__file__).resolve().parents[2]
 if sha(a.source_pins)!=a.source_pins_sha256:raise RuntimeError('Source capture pin mismatch')
 source=json.loads(Path(a.source_pins).read_text());pins=source['sourcePins']
 build_report=Path(a.build_report).resolve(strict=True)
 if not build_report.is_relative_to(root/'tests/release-inputs') or sha(build_report)!=a.build_report_sha256:raise RuntimeError('Build report authority mismatch')
 build_rel=build_report.relative_to(root).as_posix()
 if pins.get(build_rel)!=a.build_report_sha256:raise RuntimeError('Build report must be source-pinned')
 def verify():
  if sha(a.source_pins)!=a.source_pins_sha256:raise RuntimeError('Source input map changed')
  verify_pins(root,pins,a.profile)
 verify()
 path=root/'tests/postgres/run-finflow-backup-browser-main.py'
 spec=importlib.util.spec_from_file_location('codebot_browser_capture',path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 node=Path('/Users/averma5/.dvaia/runtimes/node-v26.10.0-darwin-arm64/bin/node')
 expected_node='56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
 expected_python='b08b055365df6dcd3fff0b805b688428f0f6a01839303f22c0716780155c480d'
 if sha(node)!=expected_node or sha(Path(sys.executable).resolve())!=expected_python:raise RuntimeError('Runtime authority mismatch')
 browser_fields={}
 if a.profile=='ipi-email-trigger-actual':
  if any([a.browser,a.browser_root,a.browser_sha256]):raise RuntimeError('Email actual profile does not allocate a browser')
 else:
  if not all([a.browser,a.browser_root,a.browser_sha256]):raise RuntimeError('Browser authority required')
  browser=Path(a.browser);br=Path(a.browser_root)
  if browser.resolve()!=browser or br.resolve()!=br or not browser.is_relative_to(br) or sha(browser)!=a.browser_sha256:raise RuntimeError('Canonical browser authority mismatch')
  browser_fields={'browserRoot':str(br),'browserExecutable':str(browser),'browserInventory':m.inventory(br)}
 result={'cohort':'codebot-rendered-parity','mode':'model-free','workspace':str(root),'sourcePins':pins,'dependencyInventory':m.inventory(root/'node_modules'),'dynamicRequires':source.get('dynamicRequires',[]),'runtimePins':{'node':{'path':str(node),'sha256':expected_node},'python':{'path':str(Path(sys.executable).resolve()),'sha256':expected_python}},'actualExecution':False,**browser_fields}
 if a.profile=='ipi-email-trigger-actual':
  input_sha='fd9d30779361a1b66fe373f58a45ec748b64d3fb268cd05288bc3639c4ab73d4'
  if sha(root/'tests/fixtures/ipiEmailTriggerActualInput.json')!=input_sha:raise RuntimeError('Frozen email input changed')
  result.update(mode='actual-model',actualExecution=True,model='llama3.1:8b',modelDigest='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e',inputSha256=input_sha,cases=['setup','clean-control','attack'],wireBudget={'actor':16,'judge':28,'chat':44,'generate':0,'tags':1,'version':0,'metadata':1,'external':45},mailpitImage='sha256:98b916bd3c8d61f7633a52d3ea2f58d00620cb01ca57ab59edde68c347a95365')
 if a.profile!='codebot':result.update(cohort=a.profile,profile=a.profile)
 result.update(buildReport=build_rel,clientSourceInventory=m.inventory(root/'client/src'),clientPublicInventory=m.inventory(root/'client/public'),clientDependencyInventory=m.inventory(root/'client/node_modules'),clientBuildInventory=m.inventory(root/'client/build'))
 helper=root/'tests/postgres/run-finflow-backup-browser-main.py'
 if helper.relative_to(root).as_posix() not in pins:raise RuntimeError('Build admission helper must be pinned')
 spec=importlib.util.spec_from_file_location('codebot_build_capture',helper);admission=importlib.util.module_from_spec(spec);spec.loader.exec_module(admission)
 admission.validate_build_provenance(root,result)
 verify()
 output=Path(a.output)
 if output.parent.resolve()!=Path(__file__).resolve().parent:raise RuntimeError('Private main output required')
 with output.open('x') as f:
  os.fchmod(f.fileno(),0o600);json.dump(result,f,separators=(',',':'));f.write('\n');f.flush();os.fsync(f.fileno())
 fd=os.open(output.parent,os.O_RDONLY)
 try:os.fsync(fd)
 finally:os.close(fd)
 print(json.dumps({'manifest':str(output),'sha256':sha(output),'sourceFiles':len(pins),'dependencyEntries':len(result['dependencyInventory'])}))
if __name__=='__main__':main()
