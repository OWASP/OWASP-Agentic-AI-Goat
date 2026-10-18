-- Customer profile confirmations reuse the existing completed operation ledger.
-- Preserve all historical kinds, receipt bytes, guards and reset redaction.
ALTER TABLE secureshop_review.chat_commerce_operations
 DROP CONSTRAINT chat_commerce_operations_kind_check;
ALTER TABLE secureshop_review.chat_commerce_operations
 ADD CONSTRAINT chat_commerce_operations_kind_check CHECK
 (kind IN ('cart.add','cart.update','cart.remove','payment.create','checkout','address.create','address.update','profile.update'));
ALTER TABLE secureshop_review.chat_commerce_operations
 DROP CONSTRAINT chat_commerce_operations_state_payload;
ALTER TABLE secureshop_review.chat_commerce_operations
 ADD CONSTRAINT chat_commerce_operations_state_payload CHECK (
 (state='prepared' AND kind IN ('checkout','cart.add','cart.update','cart.remove')
  AND context_json IS NOT NULL AND request_json IS NOT NULL
  AND proposal_json IS NOT NULL AND proposal_sha256 IS NOT NULL
  AND result_json IS NULL AND result_sha256 IS NULL)
 OR (state='completed' AND context_json IS NOT NULL AND request_json IS NOT NULL
  AND result_json IS NOT NULL AND result_sha256 IS NOT NULL
  AND ((kind='checkout' AND proposal_json IS NOT NULL AND proposal_sha256 IS NOT NULL)
   OR (kind IN ('cart.add','cart.update','cart.remove')
    AND ((proposal_json IS NULL AND proposal_sha256 IS NULL)
     OR (proposal_json IS NOT NULL AND proposal_sha256 IS NOT NULL)))
   OR (kind IN ('payment.create','address.create','address.update','profile.update') AND proposal_json IS NULL AND proposal_sha256 IS NULL)))
 OR (state='redacted' AND context_json IS NULL AND request_json IS NULL
  AND proposal_json IS NULL AND result_json IS NULL));
