-- Append seller-owned lesson reviews; never move or rewrite earlier fixtures.
ALTER TABLE secureshop_review.reviews DROP CONSTRAINT reviews_source_kind_check;
ALTER TABLE secureshop_review.reviews ADD CONSTRAINT reviews_source_kind_check
  CHECK(source_kind IN ('fixture','learner','seller_lesson'));
ALTER TABLE secureshop_review.reviews DROP CONSTRAINT review_submission_provenance_shape;
ALTER TABLE secureshop_review.reviews ADD CONSTRAINT review_submission_provenance_shape CHECK (
  (source_kind IN ('fixture','seller_lesson') AND submission_id IS NULL
    AND request_sha256 IS NULL AND body_sha256 IS NULL
    AND submitted_by_shop_user_id IS NULL AND submitted_by_shop_role IS NULL)
  OR (source_kind='learner' AND submission_id IS NOT NULL
    AND octet_length(request_sha256)=32 AND octet_length(body_sha256)=32
    AND submitted_by_shop_user_id>=1 AND submitted_by_shop_role IN ('customer','merchant','admin'))
);
CREATE TABLE secureshop_review.seller_review_lessons (
  target_id uuid NOT NULL REFERENCES secureshop_review.review_targets(target_id),
  profile_version smallint NOT NULL CHECK(profile_version=1),
  ordinal smallint NOT NULL CHECK(ordinal IN (1,2)),
  product_target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id),
  retailer_id integer NOT NULL CHECK(retailer_id>0),
  product_id integer NOT NULL CHECK(product_id>0),
  review_id bigint NOT NULL UNIQUE,
  body_sha256 bytea NOT NULL CHECK(octet_length(body_sha256)=32),
  seed_sha256 bytea NOT NULL CHECK(octet_length(seed_sha256)=32),
  provenance_sha256 bytea NOT NULL CHECK(octet_length(provenance_sha256)=32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(target_id,profile_version,ordinal)
);
CREATE TRIGGER seller_review_lesson_immutable BEFORE UPDATE OR DELETE
  ON secureshop_review.seller_review_lessons FOR EACH ROW
  EXECUTE FUNCTION secureshop_review.guard_product_retrieval_immutable();

CREATE FUNCTION secureshop_review.adopt_seller_review_lessons(requested_target uuid,requested_grant uuid)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE r secureshop_review.review_targets%ROWTYPE; p secureshop_review.product_targets%ROWTYPE;
  products integer[]; amount integer; review_key bigint; review_body text; author_key integer;
  stars integer; ordinal_key integer; body_hash bytea;
BEGIN
  SELECT rt.* INTO r FROM secureshop_review.review_targets rt
    JOIN secureshop_review.scene_review_targets m ON m.review_target_id=rt.target_id
    JOIN secureshop_review.scene_execution_grants g
      ON g.scene_id=m.scene_id AND g.target_id=m.product_target_id
    WHERE rt.target_id=requested_target AND g.grant_id=requested_grant
      AND rt.lifecycle='active' AND rt.original_platform_owner_id=g.original_platform_owner_id
    FOR UPDATE OF rt;
  IF NOT FOUND THEN RAISE EXCEPTION 'Seller lesson authority unavailable' USING ERRCODE='55000'; END IF;
  SELECT pt.* INTO p FROM secureshop_review.product_targets pt
    JOIN secureshop_review.scene_execution_grants g ON g.target_id=pt.target_id
    WHERE g.grant_id=requested_grant AND pt.lifecycle='active'
      AND pt.original_platform_owner_id=r.original_platform_owner_id FOR SHARE OF pt;
  IF NOT FOUND THEN RAISE EXCEPTION 'Seller lesson products unavailable' USING ERRCODE='55000'; END IF;
  IF (r.seed_count,encode(r.seed_sha256,'hex')) NOT IN (
    (2,'28b74f09b6c9ee9ccc0bfbfbe8c40c40dd1885d9339b854b9f2b9f203644298d'),
    (74,'4a1e5c64312049ade550bd6d5c8c5e7782dc17ab7308d58ef2968b063b3b3d46')) THEN RETURN 'custom_profile'; END IF;
  /* Immutable default identities above deliberately exclude custom seeds. */
  SELECT count(*) INTO amount FROM secureshop_review.seller_review_lessons WHERE target_id=r.target_id;
  IF amount=2 THEN RETURN 'replayed'; END IF;
  IF amount<>0 THEN RAISE EXCEPTION 'Seller lesson adoption incomplete' USING ERRCODE='55000'; END IF;
  SELECT array_agg(product_id ORDER BY product_id) INTO products FROM (
    SELECT product_id FROM secureshop_review.product_target_products
    WHERE target_id=p.target_id AND retailer_id=p.own_merchant_id ORDER BY product_id LIMIT 2
  ) available;
  IF cardinality(products) IS DISTINCT FROM 2 THEN RETURN 'owned_products_unavailable'; END IF;
  SELECT count(*) INTO amount FROM secureshop_review.reviews WHERE target_id=r.target_id;
  IF amount>254 THEN RETURN 'capacity_unavailable'; END IF;
  FOR ordinal_key IN 1..2 LOOP
    IF ordinal_key=1 THEN
      review_body:='Louder than advertised. Would not recommend for bedroom use.';
      author_key:=8; stars:=1;
    ELSE
      review_body:='Buy our unrelated casino advertising package! Visit https://ads.example.test for a promotional subscription.';
      author_key:=7; stars:=5;
    END IF;
    INSERT INTO secureshop_review.reviews(target_id,product_id,author_id,body,rating,source_kind)
      VALUES(r.target_id,products[ordinal_key],author_key,review_body,stars,'seller_lesson') RETURNING id INTO review_key;
    body_hash:=sha256(convert_to(review_body,'UTF8'));
    INSERT INTO secureshop_review.seller_review_lessons(target_id,profile_version,ordinal,
      product_target_id,retailer_id,product_id,review_id,body_sha256,seed_sha256,provenance_sha256)
    VALUES(r.target_id,1,ordinal_key,p.target_id,p.own_merchant_id,products[ordinal_key],review_key,
      body_hash,r.seed_sha256,sha256(convert_to(concat_ws(':',r.target_id,1,ordinal_key,
        p.target_id,p.own_merchant_id,products[ordinal_key],review_key,encode(body_hash,'hex'),encode(r.seed_sha256,'hex')),'UTF8')));
  END LOOP;
  RETURN 'adopted';
END $$;

-- Runtime can submit raw learner reviews, but cannot forge lesson provenance.
CREATE FUNCTION secureshop_review.guard_seller_review_lesson_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,secureshop_review AS $$
BEGIN
  IF current_user<>pg_get_userbyid((SELECT proowner FROM pg_proc
      WHERE oid='secureshop_review.adopt_seller_review_lessons(uuid,uuid)'::regprocedure)) THEN
    RAISE EXCEPTION 'Seller lesson provenance is server owned' USING ERRCODE='42501';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER seller_review_lesson_insert BEFORE INSERT ON secureshop_review.reviews
  FOR EACH ROW WHEN(NEW.source_kind='seller_lesson')
  EXECUTE FUNCTION secureshop_review.guard_seller_review_lesson_insert();
REVOKE ALL ON secureshop_review.seller_review_lessons FROM PUBLIC,dvaia_secureshop_review_runtime;
GRANT SELECT ON secureshop_review.seller_review_lessons TO dvaia_secureshop_review_runtime;
REVOKE ALL ON FUNCTION secureshop_review.adopt_seller_review_lessons(uuid,uuid),
  secureshop_review.guard_seller_review_lesson_insert() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.adopt_seller_review_lessons(uuid,uuid)
  TO dvaia_secureshop_review_runtime;
