-- Cart tool decisions prepare immutable intent; only trusted confirmation applies it.
-- Preserve all historical completed receipts and the existing UUID family claim.
ALTER TABLE secureshop_review.chat_commerce_operations
 DROP CONSTRAINT chat_commerce_operations_check;
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
   OR (kind='payment.create' AND proposal_json IS NULL AND proposal_sha256 IS NULL)))
 OR (state='redacted' AND context_json IS NULL AND request_json IS NULL
  AND proposal_json IS NULL AND result_json IS NULL));
