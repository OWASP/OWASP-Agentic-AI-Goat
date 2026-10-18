-- Preserve v1 hash-only receipts byte-for-byte. Raw authored presentation uses
-- an additive immutable v2 document: full source bytes, original preparation,
-- and trusted execution epoch. No source is reconstructed from mutable products.
ALTER TABLE secureshop_review.owned_merchant_listing_create_receipts
  ADD COLUMN receipt_version smallint NOT NULL DEFAULT 1,
  ADD COLUMN source_document jsonb;
ALTER TABLE secureshop_review.owned_merchant_listing_create_receipts
  ADD CONSTRAINT owned_listing_create_source_version CHECK ((
    (receipt_version=1 AND source_document IS NULL)
    OR (receipt_version=2 AND source_document IS NOT NULL
      AND jsonb_typeof(source_document)='object'
      AND octet_length(source_document::text)<=131072
      AND source_document ?& ARRAY['version','kind','listing','authoredHtml','storedHtml','preparation','execution']
      AND source_document - ARRAY['version','kind','listing','authoredHtml','storedHtml','preparation','execution']='{}'::jsonb
      AND source_document->'version'='1'::jsonb
      AND source_document->>'kind'='merchant_authored_html'
      AND jsonb_typeof(source_document->'listing')='object'
      AND jsonb_typeof(source_document->'authoredHtml')='string'
      AND jsonb_typeof(source_document->'storedHtml')='string'
      AND jsonb_typeof(source_document->'preparation')='object'
      AND jsonb_typeof(source_document->'execution')='object')) IS TRUE);
-- Existing immutable trigger, operation-ID uniqueness, SELECT/INSERT grants and
-- target FK apply unchanged to both generations. No UPDATE grant is introduced.
