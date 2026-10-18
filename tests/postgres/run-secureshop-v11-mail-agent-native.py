#!/usr/bin/env python3
"""Owned native PG qualification only; controlled provider, no model/browser calls."""
import sys
sys.dont_write_bytecode = True
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
SHARED = 'tests/postgres/run-persona-transition-main-isolated.py'
SHARED_SHA = 'a90145068bffab08475b058054b309ed44bb99e0eea8d6658b252b702f07eb1e'
FIXTURE = 'tests/postgres/secureshopV11MailAgentAssessmentNative.integration.test.js'
FIXTURE_SHA = 'e63cf61a67365fef010e4d9db62ae1d54c4c2131f410de56b8712d123af20e7a'
BACKEND_SHA = '49c7e860f8b577cb8f6ecb6ddb522de1325807248a3b1c22a231f3d02af53627'
REQUIRED_POSTIMAGES = {'server/agent-runtime/objectiveJudge.js': '796ea560c2b92e525d93cc0da437d89a3311a3a6e681600c9d81d2f59bce1fed', 'server/services/secureshopBoundRoleChat.js': 'd6d5cab84b7e39b799525bd9fde8f396272796d40d5dcda475d000e63bf7c8a7', 'server/services/secureshopMailAgentReadOriginalReader.js': 'cb9a84ed8cbab9fd27383a26a1190ab5b6135dfbb01186776dcd2059af6bab18', 'server/services/secureshopMailAgentReadEvidence.js': '001bf1ccc41837c163fa4eea18740513a79490db051498c8df74fb8bf5376870', 'server/services/secureshopMailAgentReadAssessment.js': '54b8d0a36d36f9bf69f426123e31255d1b5f1a15541164d4b99b885bf579f772', 'server/routes/secureshop/boundRoleChat.js': '243ea4d69ee56fd52bf869fc5687a7a9a82e6169602289274b7ed9f3247e7026', 'server/services/secureshopBoundReviewComposition.js': '4868bfec436e04ee70d0453c250cf1f9ec0819c78946bec5ead70e79b11d9f4a', 'server/services/secureshopAssessmentRecovery.js': 'a861941064a2bdb3ff3f5b7e94f0e1a676ca17b3cf0f08f9a779202c8abb5428', 'server/config/secureshopCurriculum.js': 'e173f9299a0c8941b39f4109627698af67b2e3071dfa224e12947702f94814be'}
STORES = (('FRESH','identity'),('POPULATED','identity'),('IDENTITY','identity'),
          ('AGENTS','secureshop_agents'),('COMMERCE','secureshop'),('REVIEW','secureshop_review'))

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def validate(root=ROOT):
    for relative, expected in [(SHARED,SHARED_SHA),(FIXTURE,FIXTURE_SHA)]:
        if not (root/relative).is_file() or sha(root/relative) != expected:
            raise RuntimeError('V11 qualification input changed: '+relative)
    return [name for name, expected in REQUIRED_POSTIMAGES.items()
            if not (root/name).is_file() or sha(root/name) != expected]

def main(argv=None):
    parser = argparse.ArgumentParser()
    gate = parser.add_mutually_exclusive_group()
    gate.add_argument('--plan',action='store_true')
    gate.add_argument('--run',action='store_true')
    args = parser.parse_args(argv)
    missing = validate()
    if not args.run:
        print(json.dumps({'plan':True,'fixture':FIXTURE,'fixtureSha256':FIXTURE_SHA,
            'backendPatchSha256':BACKEND_SHA,'sharedSha256':SHARED_SHA,'stores':STORES,
            'expectedTests':3,'prerequisitesReady':not missing,'pendingPostimages':missing,
            'sourceCopies':False,'allocationStarted':False,'actualModel':False,
            'actualJudge':False,'browser':False,'objectiveCredit':False}))
        return 0
    if missing:
        raise RuntimeError('Reviewed V11 backend not integrated: '+', '.join(missing))
    spec = importlib.util.spec_from_file_location('v11_owned_native_launcher',ROOT/SHARED)
    shared = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(shared)
    shared.SUITES = {'v11-mail-agent':(FIXTURE,'PG_SECURESHOP_V11_MAIL_AGENT_',STORES,3)}
    shared.arguments = lambda: SimpleNamespace(suite='v11-mail-agent',fresh_cohort=None,run=True,plan=False)
    original_inventory = shared.source_inventory
    shared.source_inventory = lambda extra: original_inventory([*extra,Path(__file__).resolve()])
    return shared.main()

if __name__ == '__main__':
    sys.exit(main())
