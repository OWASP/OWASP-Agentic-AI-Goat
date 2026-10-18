"""Nonallocating checks for the never-applied IDOR lesson purpose successor."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
ACTIVE = ROOT / 'db/postgres/workshop-migrations/secureshop_agents'
PREDECESSOR = ACTIVE / '0058_role_chat_turn_binding.sql'
DRAFT = ROOT / 'docs/secureshop/drafts/0086_idor_lesson_conversation_purpose.sql'
PURPOSE = 'secureshop_idor_lesson'


def purposes(text):
    match = re.search(r'conversation_purpose IN\s*\((.*?)\)\s*AND\s*'
                      r'\(authority_mode', text, re.S)
    if match is None:
        raise AssertionError('Closed purpose CHECK missing')
    return re.findall(r"'([^']+)'", match.group(1))


class IdorLessonPurposeDraftContract(unittest.TestCase):
    def test_preserves_exact_purposes_and_launch_bound_guard(self):
        old = PREDECESSOR.read_text()
        proposed = DRAFT.read_text()
        old_purposes = purposes(old)
        self.assertEqual(purposes(proposed), old_purposes + [PURPOSE])
        self.assertEqual(len(set(purposes(proposed))), len(purposes(proposed)))
        guard = "AND (authority_mode='launch_bound' OR conversation_purpose='general')"
        self.assertIn(guard, old)
        self.assertIn(guard, proposed)
        body = '\n'.join(line for line in proposed.splitlines()
                         if not line.lstrip().startswith('--'))
        self.assertEqual(body.count('ALTER TABLE secureshop_agents.agent_sessions'), 2)
        self.assertEqual(body.count('agent_sessions_conversation_purpose_shape'), 2)
        self.assertNotRegex(body, r'(?i)\b(UPDATE|DELETE|INSERT|GRANT|REVOKE|CREATE TABLE)\b')

    def test_promoted_next_filename_matches_reviewed_bytes(self):
        names = sorted(path.name for path in ACTIVE.glob('[0-9][0-9][0-9][0-9]_*.sql'))
        self.assertTrue(names[-1].startswith('0086_'))
        self.assertEqual((ACTIVE / DRAFT.name).read_bytes(), DRAFT.read_bytes())


if __name__ == '__main__':
    unittest.main()
