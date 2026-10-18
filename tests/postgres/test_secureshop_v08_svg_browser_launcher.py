import ast
import base64
import hashlib
import json
import unittest
from pathlib import Path

SOURCE = Path(__file__).with_name('run-secureshop-agent-host-transport-main.py')


def constants():
    tree = ast.parse(SOURCE.read_text())
    values = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                values[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                pass
    return values


class V08LauncherContractTest(unittest.TestCase):
    def test_v08_cohort_is_distinct_pinned_and_bounded(self):
        value = constants()
        assert value['V08_SVG_BROWSER'] == 'customer-avatar-upload-v08-svg-browser'
        assert value['V08_SVG_TEST'] == 'tests/postgres/secureshopCustomerCheckoutRendered.integration.test.js'
        assert value['V08_SVG_HELPER'] == 'tests/fixtures/secureshopAvatarUploadRenderedQualification.js'
        assert value['V08_SVG_EVIDENCE'] == 'tests/fixtures/secureshopV08ActualEvidence.js'
        assert value['V08_SVG_CANDIDATE'] == 'tests/fixtures/secureshopV08CandidateCatalog.js'
        assert value['V08_SVG_CONTRACT'] == 'tests/secureshopAvatarUploadRenderedQualification.test.js'
        assert len(value['V08_SVG_FLAGS']) == 22
        assert {'physicalSandboxPreview', 'exactBrowserEffect', 'fixedRouteIneligibleZeroEffect'} <= set(value['V08_SVG_FLAGS'])
        source = SOURCE.read_text()
        for phrase in ["SECURESHOP_V08_SVG_BROWSER_NATIVE='1'", 'SECURESHOP_V08_SVG_BROWSER_EVIDENCE_PATH',
                       'v08-original-evidence.json', 'customer-avatar-upload-v08-svg-browser.json',
                       'V08_SVG_TEST_SHA256', 'V08_SVG_HELPER_SHA256', 'V08_SVG_EVIDENCE_SHA256',
                       'V08_SVG_CANDIDATE_SHA256', 'validate_v08_svg_pins(source,digest)']:
            assert phrase in source
        assert "run_node(label,[args.node,'--test','--test-reporter=tap','--test-concurrency=1',V08_SVG_TEST],900)" in source

    def test_v08_receipt_binds_svg_bytes_raw_model_judge_and_cleanup(self):
        source = SOURCE.read_text()
        start = source.index('def v08_svg_browser_receipt')
        end = source.index('\ndef ', start + 4)
        body = source[start:end]
        for phrase in ["fixture.get('mime') != 'image/svg+xml'", "fixture.get('filename','').lower().endswith('.svg')",
                       "tools[0].get('name') != 'uploads.upload_avatar'", "tools[0].get('args') != {}",
                       "len(original.get('judgeTranscripts',[])) != 1", 'evidenceSha256',
                       'vulnerableActorCalls', 'fixedActorCalls', 'svgAssessmentPosts', 'genuineCredit']:
            assert phrase in body

    def test_v08_support_receipt_is_not_reinterpreted_as_v06(self):
        source = SOURCE.read_text()
        start = source.index('def v08_svg_support_receipt')
        end = source.index('\ndef ', start + 4)
        body = source[start:end]
        assert 'V08_SVG_FLAGS' in body
        assert "receipt['actualModelCalls'] != 4" in body
        assert "receipt['judgeCalls'] != 1" in body
        assert 'V06_UPLOAD_FLAGS' not in body

    def test_v08_plan_validates_every_pinned_source_before_provisioning(self):
        tree = ast.parse(SOURCE.read_text())
        function = next(node for node in tree.body
                        if isinstance(node, ast.FunctionDef) and node.name == 'validate_v08_svg_pins')
        value = constants()
        names = ['V08_SVG_TEST', 'V08_SVG_HELPER', 'V08_SVG_EVIDENCE', 'V08_SVG_CANDIDATE',
                 'V08_SVG_CONTRACT', 'V08_SVG_LAUNCHER_TEST']
        namespace = {name: value[name] for name in names}
        namespace.update({name + '_SHA256': value[name + '_SHA256'] for name in names})
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(SOURCE), 'exec'), namespace)
        expected = {value[name]: value[name + '_SHA256'] for name in names}
        observed = namespace['validate_v08_svg_pins'](
            Path('/owned'), lambda path: expected[path.relative_to('/owned').as_posix()])
        assert observed == tuple(value[name] for name in names)
        try:
            namespace['validate_v08_svg_pins'](
                Path('/owned'), lambda path: '0' * 64 if path.relative_to('/owned').as_posix() == value['V08_SVG_EVIDENCE']
                else expected[path.relative_to('/owned').as_posix()])
        except RuntimeError as error:
            assert str(error) == 'Pinned V08 source changed: ' + value['V08_SVG_EVIDENCE']
        else:
            raise AssertionError('V08 plan accepted changed evidence source')


if __name__ == "__main__":
    unittest.main()
