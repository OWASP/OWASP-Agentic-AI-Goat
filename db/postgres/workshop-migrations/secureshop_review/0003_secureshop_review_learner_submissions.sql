-- Draft forward migration. Apply after secureshop_review 0001 and 0002.
-- This keeps the review body and caller-selected author_id raw for the
-- teaching sinks while recording the authenticated shop persona separately.
ALTER TABLE secureshop_review.reviews
  ADD COLUMN source_kind text NOT NULL DEFAULT 'fixture'
    CHECK (source_kind IN ('fixture','learner')),
  ADD COLUMN source_version smallint NOT NULL DEFAULT 1 CHECK (source_version = 1),
  ADD COLUMN submission_id uuid,
  ADD COLUMN request_sha256 bytea,
  ADD COLUMN body_sha256 bytea,
  ADD COLUMN submitted_by_shop_user_id integer,
  ADD COLUMN submitted_by_shop_role text;

ALTER TABLE secureshop_review.reviews
  ADD CONSTRAINT review_submission_provenance_shape CHECK (
    (source_kind='fixture'
      AND submission_id IS NULL AND request_sha256 IS NULL AND body_sha256 IS NULL
      AND submitted_by_shop_user_id IS NULL AND submitted_by_shop_role IS NULL)
    OR
    (source_kind='learner'
      AND submission_id IS NOT NULL
      AND octet_length(request_sha256)=32 AND octet_length(body_sha256)=32
      AND submitted_by_shop_user_id >= 1
      AND submitted_by_shop_role IN ('customer','merchant','admin'))
  );

CREATE UNIQUE INDEX review_submission_id_by_target
  ON secureshop_review.reviews(target_id,submission_id)
  WHERE source_kind='learner';

CREATE OR REPLACE FUNCTION secureshop_review.guard_review_identity()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id OR NEW.target_id IS DISTINCT FROM OLD.target_id
     OR NEW.product_id IS DISTINCT FROM OLD.product_id OR NEW.author_id IS DISTINCT FROM OLD.author_id
     OR NEW.body IS DISTINCT FROM OLD.body OR NEW.rating IS DISTINCT FROM OLD.rating
     OR NEW.source_kind IS DISTINCT FROM OLD.source_kind
     OR NEW.source_version IS DISTINCT FROM OLD.source_version
     OR NEW.submission_id IS DISTINCT FROM OLD.submission_id
     OR NEW.request_sha256 IS DISTINCT FROM OLD.request_sha256
     OR NEW.body_sha256 IS DISTINCT FROM OLD.body_sha256
     OR NEW.submitted_by_shop_user_id IS DISTINCT FROM OLD.submitted_by_shop_user_id
     OR NEW.submitted_by_shop_role IS DISTINCT FROM OLD.submitted_by_shop_role
     OR NEW.created_at IS DISTINCT FROM OLD.created_at OR OLD.status <> 'pending'
     OR NEW.status NOT IN ('approved','rejected') THEN
    RAISE EXCEPTION 'review identity or decision is immutable' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;

-- Version 1 already commits both counts into receipt_sha256. Learner-created
-- rows make the actual deletion count greater than the immutable fixture seed.
ALTER TABLE secureshop_review.review_cleanup_receipts
  DROP CONSTRAINT review_cleanup_receipts_check;
ALTER TABLE secureshop_review.review_cleanup_receipts
  ADD CONSTRAINT review_cleanup_covers_seed
  CHECK (deleted_review_count >= seed_count AND deleted_review_count <= 256);

