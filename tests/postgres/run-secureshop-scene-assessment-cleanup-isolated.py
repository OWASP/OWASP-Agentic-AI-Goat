#!/usr/bin/env python3
"""Owned one-store V03 scene progress cleanup qualification."""
import sys
sys.dont_write_bytecode = True
import argparse, hashlib, importlib.util, json
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
SHARED = 'tests/postgres/run-persona-transition-main-isolated.py'
SHARED_SHA256 = '892ce14315b9d1af8cc8f0019dcca031e6d0bfbadf643321c1cf3c03addebb4f'
FIXTURE = 'tests/postgres/secureshopSceneAssessmentCleanup.integration.test.js'
FIXTURE_SHA256 = '52c846c5dc531c8d2047f967b76d983adff580981cb2fd9cb866f1fc9c0de8d0'
MIGRATION = 'db/postgres/identity-migrations/0152_secureshop_scene_assessment_cleanup.sql'
MIGRATION_SHA256 = '69ec4990c82ed1dd3e483c17c91a85050e712b5d4760b5bd47985832f9dcb7df'
CONTROL = 'tests/postgres/test_secureshop_scene_assessment_cleanup_launcher.py'
SUITE = 'scene-assessment-cleanup'
PREFIX = 'PG_SECURESHOP_SCENE_ASSESSMENT_'
STORES = (('IDENTITY', 'identity'),)
SCOPE = ('V03 exact packet-to-scene provenance and shared-scene reset retirement; fresh and populated 0152, '
 'second-run no-op, malformed unavailable history preservation, immutable evidence, unrelated progress, and '
 'concurrent late-contribution denial; owned disposable PostgreSQL only, no model, browser, Judge, or application database')

def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def pins(): return {name: expected for name, expected in (
    (SHARED, SHARED_SHA256), (FIXTURE, FIXTURE_SHA256), (MIGRATION, MIGRATION_SHA256))}
def installed(): return {name: (ROOT/name).is_file() and sha(ROOT/name) == expected
                         for name, expected in pins().items()}
def configured_source(source):
    environment = ("    env.update(NODE_ENV='test', PG_TEST_DISPOSABLE='yes', PLATFORM_DATABASE_ENGINE='postgres', WORKSHOP_DATABASE_ENGINE='postgres',\n"
      "               AI_PROVIDER='mock', AWS_EC2_METADATA_DISABLED='true', HF_HUB_OFFLINE='1', TRANSFORMERS_OFFLINE='1',\n"
      "               MCP_WORKSHOP_AUTOSTART='false', MCP_SIDECARS_AUTOSTART='false', SS_ENABLE='false')")
    if source.count(environment) != 1: raise RuntimeError('Shared isolated environment seam changed')
    source = source.replace(environment, environment + "\n    env.update(SECURESHOP_SCENE_ASSESSMENT_NATIVE='1', OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE=str(ROOT))")
    save = "    def save(): lifecycle.helpers.write_private_json(evidence/'result.json', result)"
    if source.count(save) != 1: raise RuntimeError('Shared isolated result seam changed')
    return source.replace(save,
      "    def save(): lifecycle.helpers.write_private_json(evidence/'result.json', {**result,'qualificationScope':SCENE_ASSESSMENT_SCOPE})")
def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);gate=parser.add_mutually_exclusive_group()
    gate.add_argument('--plan',action='store_true');gate.add_argument('--run',action='store_true');args=parser.parse_args(argv)
    state=installed()
    if not args.run:
        print(json.dumps({'plan':True,'allocationStarted':False,'suite':SUITE,'fixture':FIXTURE,
          'stores':STORES,'expectedTests':1,'sourcePins':pins(),'installedMatches':state,
          'qualificationScope':SCOPE,'sourceCopies':False,'actualModel':False,'browser':False,'judge':False}))
        return 0
    if not all(state.values()): raise RuntimeError('Scene assessment cleanup source pin mismatch; no allocation started')
    shared_path=ROOT/SHARED;spec=importlib.util.spec_from_file_location('scene_cleanup_owned_lifecycle',shared_path)
    module=importlib.util.module_from_spec(spec)
    exec(compile(configured_source(shared_path.read_text()),str(shared_path),'exec'),module.__dict__)
    module.SCENE_ASSESSMENT_SCOPE=SCOPE
    module.SUITES={SUITE:(FIXTURE,PREFIX,STORES,1)}
    module.arguments=lambda:SimpleNamespace(suite=SUITE,fresh_cohort=None,run=True,plan=False)
    original=module.source_inventory
    module.source_inventory=lambda extra:original([*extra,Path(__file__).resolve(),ROOT/CONTROL,ROOT/MIGRATION])
    return module.main()
if __name__=='__main__':sys.exit(main())
