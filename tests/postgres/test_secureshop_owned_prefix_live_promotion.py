import ast
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from secureshop_owned_prefix_promotion_safety import parse_pg_boolean

SOURCE = Path(__file__).resolve().parents[2]
LAUNCHER = SOURCE / 'tests/postgres/run-secureshop-owned-prefix-live-promotion.py'
CONTINUATION = SOURCE / 'tests/postgres/run-secureshop-owned-prefix-live-continuation.py'


class SecureShopOwnedPrefixPromotionContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = LAUNCHER.read_text()
        ast.parse(cls.text)

    def test_exact_six_drafts_are_installed_in_reserved_order(self):
        expected = [
            '0051_secureshop_mcp_trust.sql',
            '0052_secureshop_controlled_ssrf.sql',
            '0053_codebot_request_journal.sql',
            '0011_secureshop_mcp_trust.sql',
            '0012_secureshop_controlled_ssrf.sql',
            '0013_secureshop_conversation_purpose.sql',
        ]
        promotion = self.text[self.text.index('def promote_reset_release():'):]
        positions = [promotion.index(name) for name in expected]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("details['count']!=prior['count']+3", self.text)
        self.assertIn("details['ledger'][:-3]!=prior['ledger']", self.text)

    def test_database_only_promotion_retains_activation_boundary(self):
        self.assertIn("'performed':False,'requiredBeforeActivation':True", self.text)
        self.assertNotIn('docker compose up', self.text)
        self.assertNotIn('MCP_OWNED_RESOURCES_ENABLED=true', self.text)

    def test_backup_restore_restart_and_repair_hold_are_preserved(self):
        for required in ('pg_dump', 'pg_restore', "signal.SIGHUP",
                         "watcherHeldForRepair", "all16LedgersVerified"):
            self.assertIn(required, self.text)

    def test_populated_agent_sessions_compare_all_old_fields_and_exact_new_default(self):
        self.assertIn("return \"to_jsonb(t) - 'conversation_purpose'\"", self.text)
        self.assertIn("'generalRows':purpose_before['rows'],'invalidRows':0", self.text)
        self.assertIn("'rows':purpose_before['rows']", self.text)
        self.assertNotIn("if key=='secureshop_agents.agent_sessions'", self.text)
        self.assertIn("present = parse_pg_boolean(raw_present)", self.text)

    def test_postgres_boolean_parser_is_strict_and_executable(self):
        self.assertIs(parse_pg_boolean('true'), True)
        self.assertIs(parse_pg_boolean('false'), False)
        for invalid in ('t', 'f', 'TRUE', '', None, 1):
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                parse_pg_boolean(invalid)

    def test_applied_prefix_continuation_never_reapplies_migrations(self):
        text = CONTINUATION.read_text()
        ast.parse(text)
        self.assertIn("prior_evidence=Path(args.prior_evidence).resolve()", text)
        self.assertIn("current_ledgers!=expected_ledgers", text)
        self.assertIn("if any(details['applied'] for details in replay.values())", text)
        self.assertIn("final_inventory!=current_inventory", text)
        self.assertNotIn('def promote_reset_release', text)
        self.assertNotIn('atomic_copy(', text)


if __name__ == '__main__':
    unittest.main()
