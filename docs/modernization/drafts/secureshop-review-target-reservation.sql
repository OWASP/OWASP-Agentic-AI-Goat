-- Draft forward identity migration. Do not register in startup migrations yet.
-- Review reservations remain unresolved cleanup debt; this migration does not
-- add a completion setter, deletion grant, or provisioning claim.
ALTER TABLE identity.secureshop_target_reservations
  DROP CONSTRAINT secureshop_target_reservations_target_kind_check;
ALTER TABLE identity.secureshop_target_reservations
  ADD CONSTRAINT secureshop_target_reservations_target_kind_check
  CHECK (target_kind IN ('files','reviews'));
