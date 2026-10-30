import hashlib
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REVIEW = ROOT / 'db/postgres/workshop-migrations/secureshop_review'
AGENTS = ROOT / 'db/postgres/workshop-migrations/secureshop_agents'

class RefundMigrationContract(unittest.TestCase):
    def test_exact_prefix_and_current_tail_are_explicit(self):
        review = sorted(p.name for p in REVIEW.glob('*.sql'))
        self.assertIn('0008_secureshop_bound_refund_requests.sql', review)
        self.assertIn('0009_secureshop_refund_cleanup_receipts.sql', review)
        self.assertIn('0010_secureshop_refund_cleanup_receipt_guard.sql', review)
        self.assertIn('0017_secureshop_refund_conversation_purpose.sql',
                      [p.name for p in AGENTS.glob('*.sql')])
        self.assertIn('UNIQUE (target_id,shop_user_id,order_id,operation_kind)',
                      (REVIEW / '0008_secureshop_bound_refund_requests.sql').read_text())
        self.assertIn('refund_cleanup_receipt_immutable',
                      (REVIEW / '0010_secureshop_refund_cleanup_receipt_guard.sql').read_text())

    def test_review_tail_hashes_are_pinned(self):
        expected = {
            '0008_secureshop_bound_refund_requests.sql': '7e2032c719fad96ae2cff4c7db403e791ee4ae2f20252cfb2cc3a377cd38a7a6',
            '0009_secureshop_refund_cleanup_receipts.sql': 'da3c90fd04961bd9b24a177cd761c1655586be66b43254f13ebbb8d3ae9549f5',
        }
        for name, digest in expected.items():
            self.assertEqual(hashlib.sha256((REVIEW / name).read_bytes()).hexdigest(), digest)

    def test_native_database_prefix_is_short_and_scoped(self):
        prefix = 'bound_refund'
        self.assertLessEqual(len(f'owasp_ai_goat_test_{prefix}_populated_review'), 63)
        self.assertLessEqual(len(f'owasp_ai_goat_test_{prefix}_fresh_review'), 63)

if __name__ == '__main__':
    unittest.main()
