#!/usr/bin/env python3
"""Zero-model product-target upload reset qualification over disposable PostgreSQL."""
import sys
sys.dont_write_bytecode = True
import argparse, hashlib, importlib.util, json
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
SHARED = ROOT / 'tests/postgres/run-persona-transition-main-isolated.py'
SHARED_SHA256 = 'c3e5618ad2ba9d107ddfc8d540654197e84a7692f99cd3fc197c3697b5f17a24'
FIXTURE = 'tests/postgres/secureshopBoundUploadProductReset.native.js'
FIXTURE_SHA256 = '143ec256001cc6a1dd8ae4538626b335e9d0146d23c9c763276a3a10b25fe081'
CLEANUP = 'server/services/secureshopCleanupComposition.js'
CLEANUP_SHA256 = '3185a0f3647be5815b3af9409411ff63aadbc59511c8188b319b0d86002efccf'
ADAPTER = 'server/services/secureshopBoundUploadResetAdapter.js'
ADAPTER_SHA256 = '3068510b942e6c9c800fac7b3807157210d095fa6fad63ebd76c2216519c6b70'
SELECTED_UPLOAD_SOURCES = ('server/services/secureshopV46TraversalWriter.js',
 'agent-host/agents/uploads/tools/index.js', 'agent-host/shared/vectorStore.js',
 'sidecars/sandbox-runner/secureshopFiles.js')
SUITE = 'bound-upload-product-reset'
PREFIX = 'PG_SECURESHOP_UPLOAD_PRODUCT_RESET_'
STORES = (('IDENTITY', 'identity'), ('AGENTS', 'secureshop_agents'), ('REVIEW', 'secureshop_review'))
SCOPE = ('real reserved product target, completed physical upload and orphan admission; canonical public launch reset '
 'must delete owned bytes, reconcile the orphan, record exact original-birth cleanup receipt, retire product target, '
 'preserve immutable upload rows and sibling target/bytes, fence stale authority, and replay without duplicate cleanup; '
 'controlled fixture only, no model/browser/Judge/credit claim')

def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def validate_sources():
 for relative, expected in ((FIXTURE,FIXTURE_SHA256),(CLEANUP,CLEANUP_SHA256),(ADAPTER,ADAPTER_SHA256),
                            (str(SHARED.relative_to(ROOT)),SHARED_SHA256)):
  if sha(ROOT/relative) != expected: raise RuntimeError('Upload product reset source pin mismatch: '+relative)
def configure(shared, *, run):
 shared.SUITES={SUITE:(FIXTURE,PREFIX,STORES,1)}
 shared.arguments=lambda:SimpleNamespace(suite=SUITE,fresh_cohort=None,run=run,plan=not run)
 original=shared.source_inventory
 def inventory(extra): return original([*extra,Path(__file__).resolve(),ROOT/'tests/postgres/test_secureshop_bound_upload_product_reset_launcher.py',
  *(ROOT/name for name in SELECTED_UPLOAD_SOURCES)])
 shared.source_inventory=inventory
 return shared
def main(argv=None):
 parser=argparse.ArgumentParser(description=__doc__);modes=parser.add_mutually_exclusive_group();modes.add_argument('--plan',action='store_true');modes.add_argument('--run',action='store_true');args=parser.parse_args(argv)
 validate_sources()
 if not args.run:
  print(json.dumps({'plan':True,'suite':SUITE,'fixture':FIXTURE,'fixtureSha256':FIXTURE_SHA256,
   'cleanupSha256':CLEANUP_SHA256,'adapterSha256':ADAPTER_SHA256,'sharedLauncherSha256':SHARED_SHA256,
   'stores':STORES,'expectedTests':1,'sourceCopies':False,'actualModel':False,'browser':False,
   'qualificationScope':SCOPE,'allocationStarted':False}));return 0
 spec=importlib.util.spec_from_file_location('upload_product_reset_owned_persona_launcher',SHARED)
 shared=importlib.util.module_from_spec(spec);spec.loader.exec_module(shared);return configure(shared,run=True).main()
if __name__=='__main__':sys.exit(main())
