"""Controlled V55 raw-call ordering checks; no native/model qualification."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from test_secureshop_mail_inline_browser_launcher import M, controlled_wire, packed, receipt, sha


REPAIR = ('The previous decision was not a valid single JSON object matching '
          'the requested schema. No tool was executed from that output. Return '
          'exactly one corrected decision, without commentary or additional objects.')
FINAL_REPAIR = ('The previous response did not match the required answer-only JSON '
                'schema. Return exactly one object with one nonempty answer string. '
                'Do not return a tool call or any other key.')


def repaired_wire(before):
    """Add one rejected physical Ollama response, retaining the accepted trace."""
    wire = controlled_wire()
    actor = wire['calls'][:-1]
    insert_at = 11 if before == 'summary' else 12
    retry = copy.deepcopy(actor[insert_at])
    retry['response'] = packed({'message': {'content': 'invalid decision'}, 'done': True})
    retry['responseBytes'] = retry['responseObservedBytes'] = len(retry['response'].encode())
    retry['responseSha256'] = sha(retry['response'])
    actor.insert(insert_at, retry)
    corrected = actor[insert_at + 1]
    request = json.loads(corrected['request'])
    request['messages'].extend([{'role': 'assistant', 'content': 'invalid decision'},
                                {'role': 'user', 'content': REPAIR if before == 'summary' else FINAL_REPAIR}])
    corrected['request'] = packed(request)
    corrected['requestBytes'] = len(corrected['request'].encode())
    corrected['requestSha256'] = sha(corrected['request'])
    for index, call in enumerate(actor, start=1):
        call['index'] = index
    wire['calls'] = actor + wire['calls'][-1:]
    expected = receipt()
    expected['actorCalls'] = 14
    return wire, expected


class ActorRepairProvenanceTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'original.json'

    def validate(self, wire, expected):
        self.path.write_text(packed(wire))
        self.path.chmod(0o600)
        return M.mail_inline_wire(self.path, expected, M.MAIL_INLINE_MODEL_SHA256)

    def test_unrepaired_order_is_admitted(self):
        self.validate(controlled_wire(), receipt())

    def test_decision_repair_between_read_and_summary_is_rejected(self):
        wire, expected = repaired_wire('summary')
        # The failed HTTP attempt has no published tool or trace. The accepted
        # summary still receives the original read observation and is saved.
        self.assertEqual(wire['proof'], controlled_wire()['proof'])
        summary = json.loads(wire['calls'][12]['request'])
        self.assertEqual(summary['messages'][-1]['content'], REPAIR)
        self.assertEqual(json.loads(wire['calls'][12]['response'])['message']['content'],
                         packed({'tool_calls': [{'agent': 'email', 'tool': 'summarize_thread', 'args': {}}]}))
        with self.assertRaisesRegex(RuntimeError, 'Original model did not uniquely select ordered mail tools'):
            self.validate(wire, expected)

    def test_final_response_repair_after_summary_does_not_require_adjacency(self):
        wire, expected = repaired_wire('final')
        self.validate(wire, expected)


if __name__ == '__main__':
    unittest.main()
