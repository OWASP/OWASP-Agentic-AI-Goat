ALTER TABLE workshop_platform.objective_judgments
  DROP CONSTRAINT objective_judgments_disposition_check;

ALTER TABLE workshop_platform.objective_judgments
  ADD CONSTRAINT objective_judgments_disposition_check
  CHECK(disposition IN (
    'pending','not_pass','threshold_pending','awarded','already_complete',
    'stale_generation','hidden','mode_changed'
  ));
