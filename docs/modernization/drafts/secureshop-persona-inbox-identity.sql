-- DRAFT ONLY. Forward target-kind admission for the launch-bound persona inbox.
-- Never rewrite applied reservation/history migrations.
ALTER TABLE identity.secureshop_target_reservations
  DROP CONSTRAINT secureshop_target_reservations_target_kind_check;
ALTER TABLE identity.secureshop_target_reservations
  ADD CONSTRAINT secureshop_target_reservations_target_kind_check
  CHECK (target_kind IN ('files','reviews','products','persona_inbox'));

ALTER TABLE identity.secureshop_target_cleanup_history
  DROP CONSTRAINT secureshop_target_cleanup_history_target_kind_check;
ALTER TABLE identity.secureshop_target_cleanup_history
  ADD CONSTRAINT secureshop_target_cleanup_history_target_kind_check
  CHECK (target_kind IN ('files','reviews','products','persona_inbox'));
