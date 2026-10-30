import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tap_json_diagnostics import (
    MAX_TAP_JSON_LINE_BYTES,
    MAX_TAP_JSON_TEXT_BYTES,
    TapJsonDiagnosticError,
    decode_tap_json_line,
    iter_tap_json_diagnostics,
    scoped_tap_json_reports,
    unique_scoped_tap_json_report,
)


SCOPE = 'rendered_secureshop_persona_judgment_failure'
R40_SANITIZED_LINE = r'''# \# {"scope":"rendered_secureshop_persona_judgment_failure","mode":"advisory","objectives":[{"objectiveId":"ss_cross_persona_effect","present":true,"verdict":"fail","disposition":"not_pass","credited":false,"criterionCount":1,"criteriaTruncated":false,"criteria":[false],"errorCode":null,"evidenceBinding":{"packetPresent":true,"digestBound":true,"objectiveBound":true,"requiredFactsBound":true,"factKeysBound":true,"factsBound":true,"chainBound":true,"crossOutcomeBound":false,"advisoryOutcomeBound":true}},{"objectiveId":"ss_acl_advisory_effect","present":true,"verdict":"pass","disposition":"awarded","credited":true,"criterionCount":1,"criteriaTruncated":false,"criteria":[true],"errorCode":null,"evidenceBinding":{"packetPresent":true,"digestBound":true,"objectiveBound":true,"requiredFactsBound":true,"factKeysBound":true,"factsBound":true,"chainBound":true,"crossOutcomeBound":true,"advisoryOutcomeBound":true}}]}'''
R45_ASSERTION_DIFF = '''  error: |-
    Expected values to be strictly deep-equal:
    + actual - expected

      {
    +   credentialVersion: 13,
    -   credentialVersion: 12,
        expiresAt: '2026-09-18T13:21:32.493Z',
        generation: 2,
        launchId: '51ea0346-dd4a-4d37-89ef-52c2a1ba273c'
      }

  code: 'ERR_ASSERTION'\n'''
_NODE = os.environ.get('OWASP_AI_GOAT_MANAGED_NODE') or shutil.which('node')
MANAGED_NODE = Path(_NODE) if _NODE else None


class TapJsonDiagnosticsTest(unittest.TestCase):
    def test_exact_retained_r40_escaped_persona_diagnostic(self):
        report = unique_scoped_tap_json_report(R40_SANITIZED_LINE, SCOPE, required=True)
        self.assertEqual(report['mode'], 'advisory')
        self.assertEqual(
            [(row['objectiveId'], row['verdict'], row['credited'])
             for row in report['objectives']],
            [('ss_cross_persona_effect', 'fail', False),
             ('ss_acl_advisory_effect', 'pass', True)],
        )
        self.assertFalse(report['objectives'][0]['evidenceBinding']['crossOutcomeBound'])

    def test_reporter_prefixes_preserve_json_string_values_losslessly(self):
        value = {
            'scope': 'owned_string_probe',
            'text': 'windows\\path "quoted"\nsecond # hash \\# literal',
            'items': ['#', '\\', 'line\nfeed'],
        }
        encoded = json.dumps(value, separators=(',', ':'))
        for line in [encoded, '# ' + encoded, '# \\# ' + encoded, '    # ' + encoded]:
            self.assertEqual(decode_tap_json_line(line), value)

    def test_r45_indented_assertion_object_is_not_a_json_diagnostic(self):
        report = {'scope': 'rendered_secureshop_qualification_failure',
                  'stage': 'reset_replay', 'category': 'assertion'}
        text = '# \\# ' + json.dumps(report, separators=(',', ':')) + '\n' \
            + R45_ASSERTION_DIFF
        self.assertEqual(list(iter_tap_json_diagnostics(text)), [report])
        self.assertEqual(
            unique_scoped_tap_json_report(
                text, 'rendered_secureshop_qualification_failure', required=True),
            report,
        )
        self.assertIsNone(decode_tap_json_line('      {'))
        # A genuine reporter envelope remains fail closed when its JSON is bad.
        with self.assertRaisesRegex(TapJsonDiagnosticError, 'Malformed'):
            decode_tap_json_line('    # {bad json}')

    def test_actual_managed_node_test_runner_stdout_and_stderr(self):
        self.assertIsNotNone(MANAGED_NODE, 'managed Node missing from override and PATH')
        self.assertTrue(MANAGED_NODE.is_file(), f'managed Node missing: {MANAGED_NODE}')
        expected_text = 'slash\\path "quote"\nline # hash \\# literal'
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary) / 'tap-json-emitter.test.js'
            fixture.write_text("""'use strict';
const test = require('node:test');
test('emit representative JSON', () => {
  const base = { text: 'slash\\\\path "quote"\\nline # hash \\\\# literal' };
  console.log(JSON.stringify({ scope: 'managed_node_stdout', ...base }));
  process.stderr.write('# ' + JSON.stringify({ scope: 'managed_node_stderr', ...base }) + '\\n');
});
""")
            completed = subprocess.run(
                [str(MANAGED_NODE), '--test', str(fixture)],
                check=True, capture_output=True, text=True, timeout=30,
                env={**os.environ, 'NODE_OPTIONS': '--no-addons'},
            )
        values = list(iter_tap_json_diagnostics(completed.stdout))
        by_scope = {value['scope']: value for value in values
                    if type(value) is dict and 'scope' in value}
        self.assertEqual(set(by_scope), {'managed_node_stdout', 'managed_node_stderr'})
        self.assertEqual(by_scope['managed_node_stdout']['text'], expected_text)
        self.assertEqual(by_scope['managed_node_stderr']['text'], expected_text)
        self.assertEqual(completed.stderr, '')

    def test_malformed_candidates_bounds_and_non_json_tap_are_fail_closed(self):
        self.assertIsNone(decode_tap_json_line('ok 1 - ordinary TAP'))
        self.assertIsNone(decode_tap_json_line('# ordinary diagnostic text'))
        for line in ['{bad json}', '# {"scope":', '# \\# [1,]']:
            with self.assertRaises(TapJsonDiagnosticError):
                decode_tap_json_line(line)
        with self.assertRaises(TapJsonDiagnosticError):
            decode_tap_json_line('{}' + ' ' * MAX_TAP_JSON_LINE_BYTES)
        with self.assertRaises(TapJsonDiagnosticError):
            decode_tap_json_line('# {}\n# {}')
        self.assertIsNone(decode_tap_json_line('         # {}'))
        for line in ['{"scope":"one","scope":"two"}',
                     '{"value":NaN}', '{"value":Infinity}', '{"value":-Infinity}']:
            with self.assertRaises(TapJsonDiagnosticError):
                decode_tap_json_line(line)
        with self.assertRaisesRegex(TapJsonDiagnosticError, 'byte bound'):
            list(iter_tap_json_diagnostics('x' * 9, max_text_bytes=8))
        with self.assertRaises(TapJsonDiagnosticError):
            list(iter_tap_json_diagnostics('{}',
                 max_text_bytes=MAX_TAP_JSON_TEXT_BYTES + 1))

    def test_nested_scope_collection_and_duplicate_rejection(self):
        first = {'scope': 'wanted', 'value': 1}
        second = {'scope': 'wanted', 'value': 2}
        text = '\n'.join([
            '# ' + json.dumps({'wrapper': [first]}, separators=(',', ':')),
            json.dumps({'outer': {'child': second}}, separators=(',', ':')),
        ])
        self.assertEqual(scoped_tap_json_reports(text, 'wanted'), [first, second])
        with self.assertRaisesRegex(TapJsonDiagnosticError, 'Duplicate'):
            unique_scoped_tap_json_report(text, 'wanted')
        self.assertIsNone(unique_scoped_tap_json_report('# unrelated', 'wanted'))
        with self.assertRaisesRegex(TapJsonDiagnosticError, 'missing'):
            unique_scoped_tap_json_report('# unrelated', 'wanted', required=True)


if __name__ == '__main__':
    unittest.main()
