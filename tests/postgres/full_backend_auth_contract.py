"""Import-inert frozen sixteen-store admission contract; no providers or launches."""
import json
import hashlib
import os
import re
from pathlib import Path
from sql_nosql_package_contract import digest, require, SHA, prepare_evidence_root

STORES = (('identity', 'IDENTITY'), ('aria', 'SQL_WORKSHOP'), ('nova', 'NOSQL_WORKSHOP'), ('xss', 'XSS_WORKSHOP'), ('mcp', 'MCP_WORKSHOP'), ('csrf', 'CSRF_WORKSHOP'), ('supply_chain', 'SUPPLY_CHAIN_WORKSHOP'), ('finflow', 'FINFLOW_WORKSHOP'), ('excessive_agency', 'EXCESSIVE_AGENCY'), ('ctf', 'CTF'), ('legacy_challenge', 'LEGACY_CHALLENGE'), ('sensitive_lookup', 'SENSITIVE_LOOKUP'), ('secureshop', 'SECURESHOP'), ('secureshop_agents', 'SECURESHOP_AGENTS'), ('session_disclosure', 'SESSION_DISCLOSURE'), ('secureshop_review', 'SECURESHOP_REVIEW'))
MCP_MODEL_DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'
REVIEWED_MIGRATIONS = {
    'db/postgres/maintenance-migrations/0001_maintenance_fence.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0043_mail_snapshot_integrity.sql',
    'db/postgres/identity-migrations/0001_identity.sql',
    'db/postgres/identity-migrations/0002_workshop_platform.sql',
    'db/postgres/identity-migrations/0003_account_flows.sql',
    'db/postgres/identity-migrations/0004_graph_runtime.sql',
    'db/postgres/identity-migrations/0005_attendee_email.sql',
    'db/postgres/identity-migrations/0006_graph_trace.sql',
    'db/postgres/identity-migrations/0007_objective_judgments.sql',
    'db/postgres/identity-migrations/0008_objective_evidence.sql',
    'db/postgres/identity-migrations/0009_grade_recovery.sql',
    'db/postgres/identity-migrations/0010_workshop_activity.sql',
    'db/postgres/identity-migrations/0011_dpi_practice_receipts.sql',
    'db/postgres/identity-migrations/0012_historical_import_provenance.sql',
    'db/postgres/identity-migrations/0013_import_batches.sql',
    'db/postgres/identity-migrations/0014_xss_legacy_admin.sql',
    'db/postgres/identity-migrations/0015_identity_auxiliary_provenance.sql',
    'db/postgres/identity-migrations/0016_graph_judge_trace_metadata.sql',
    'db/postgres/identity-migrations/0017_auxiliary_trigger_table_fields.sql',
    'db/postgres/identity-migrations/0018_graph_provisional_event.sql',
    'db/postgres/identity-migrations/0019_archive_owner_bindings.sql',
    'db/postgres/identity-migrations/0020_bootstrap_admin_permissions.sql',
    'db/postgres/identity-migrations/0022_activity_log_retention.sql',
    'db/postgres/identity-migrations/0023_workshop_teaching_content.sql',
    'db/postgres/identity-migrations/0024_codebot_javascript_objective.sql',
    'db/postgres/identity-migrations/0025_secureshop_launch_authority.sql',
    'db/postgres/identity-migrations/0026_secureshop_target_reservations.sql',
    'db/postgres/identity-migrations/0027_secureshop_target_admission.sql',
    'db/postgres/identity-migrations/0028_secureshop_review_target_reservation.sql',
    'db/postgres/identity-migrations/0029_secureshop_target_reconciliation.sql',
    'db/postgres/identity-migrations/0030_secureshop_instance_objective_contributions.sql',
    'db/postgres/identity-migrations/0031_secureshop_conversation_cleanup_checkpoint.sql',
    'db/postgres/identity-migrations/0032_secureshop_progress_cleanup_checkpoint.sql',
    'db/postgres/identity-migrations/0033_secureshop_product_target_reservation.sql',
    'db/postgres/identity-migrations/0034_secureshop_owner_reset.sql',
    'db/postgres/identity-migrations/0035_student_deletion_journal.sql',
    'db/postgres/identity-migrations/0036_dpi_teaching_scope.sql',
    'db/postgres/identity-migrations/0037_nosqli9_identity_content.sql',
    'db/postgres/identity-migrations/0038_student_deletion_finalizer.sql',
    'db/postgres/identity-migrations/0039_secureshop_cleanup_catalog_independence.sql',
    'db/postgres/identity-migrations/0040_legacy_upload_lifecycle.sql',
    'db/postgres/identity-migrations/0041_finflow_response_repair_copy.sql',
    'db/postgres/identity-migrations/0042_rag_upload_guidance.sql',
    'db/postgres/identity-migrations/0043_dpi_evidence_guidance.sql',
    'db/postgres/identity-migrations/0044_sensitive_info_aggregate_reset.sql',
    'db/postgres/identity-migrations/0045_secureshop_persona_inbox_identity.sql',
    'db/postgres/identity-migrations/0046_graph_judge_validation_code.sql',
    'db/postgres/identity-migrations/0047_secureshop_persona_inbox_catalog.sql',
    'db/postgres/identity-migrations/0048_workshop_catalog_field_provenance.sql',
    'db/postgres/identity-migrations/0049_workshop_catalog_persona_adoption.sql',
    'db/postgres/identity-migrations/0050_mcp_conversation_history.sql',
    'db/postgres/identity-migrations/0051_secureshop_mcp_trust.sql',
    'db/postgres/identity-migrations/0052_secureshop_controlled_ssrf.sql',
    'db/postgres/identity-migrations/0053_codebot_request_journal.sql',
    'db/postgres/identity-migrations/0054_finflow_log_policy_defaults.sql',
    'db/postgres/identity-migrations/0055_finflow_admin_artifact_defaults.sql',
    'db/postgres/identity-migrations/0056_finflow_authentic_curriculum_defaults.sql',
    'db/postgres/identity-migrations/0057_graph_agent_outcome.sql',
    'db/postgres/identity-migrations/0058_finflow_durable_log_overlay_tip.sql',
    'db/postgres/identity-migrations/0059_dpi_policy_trace_metadata.sql',
    'db/postgres/identity-migrations/0060_finflow_description_default.sql',
    'db/postgres/identity-migrations/0061_mcp_supply_chain_curriculum_defaults.sql',
    'db/postgres/identity-migrations/0065_ipi_email_artifacts.sql',
    'db/postgres/identity-migrations/0066_dpi_teaching_copy_alignment.sql',
    'db/postgres/identity-migrations/0067_graph_observability_metadata.sql',
    'db/postgres/identity-migrations/0069_sql_injection_postgres_copy_defaults.sql',
    'db/postgres/identity-migrations/0070_xss_scope_authority.sql',
    'db/postgres/identity-migrations/0071_xss_scope_bind_conflict_fix.sql',
    'db/postgres/identity-migrations/0072_xss_profile_reset_journal.sql',
    'db/postgres/identity-migrations/0073_xss_judgment_child_binding.sql',
    'db/postgres/identity-migrations/0074_xss_profile_reset_parent_supersession.sql',
    'db/postgres/identity-migrations/0075_xss_profile_reset_constraint_repair.sql',
    'db/postgres/identity-migrations/0076_xss_profile_reset_owner_lookup.sql',
    'db/postgres/identity-migrations/0077_xss_parent_reset_journal.sql',
    'db/postgres/identity-migrations/0078_xss_parent_reset_admission_fence.sql',
    'db/postgres/identity-migrations/0079_xss_deletion_redaction_recovery_filter.sql',
    'db/postgres/identity-migrations/0080_legacy_ai_private_history.sql',
    'db/postgres/identity-migrations/0081_finflow_admin_enum_multiturn_defaults.sql',
    'db/postgres/identity-migrations/0082_workshop_rag_sources.sql',
    'db/postgres/identity-migrations/0083_mcp_http_operations.sql',
    'db/postgres/identity-migrations/0084_admin_bulk_reset_cohort.sql',
    'db/postgres/identity-migrations/0085_admin_bulk_xss_replay.sql',
    'db/postgres/identity-migrations/0086_admin_bulk_secureshop_replay.sql',
    'db/postgres/identity-migrations/0088_admin_bulk_reset_scope_discovery.sql',
    'db/postgres/identity-migrations/0089_mcp_shadow_operations.sql',
    'db/postgres/identity-migrations/0090_secureshop_audit_query_operations.sql',
    'db/postgres/identity-migrations/0091_legacy_file_ssi_reset.sql',
    'db/postgres/identity-migrations/0092_secureshop_audit_sql_objective.sql',
    'db/postgres/identity-migrations/0093_admin_bulk_legacy_file_ssi_replay.sql',
    'db/postgres/identity-migrations/0094_secureshop_audit_sql_defaults.sql',
    'db/postgres/identity-migrations/0095_teaching_sessions.sql',
    'db/postgres/identity-migrations/0096_secureshop_audit_instruction_defaults.sql',
    'db/postgres/identity-migrations/0097_mcp_protected_reconciliation.sql',
    'db/postgres/identity-migrations/0098_persona_objective_judgments.sql',
    'db/postgres/identity-migrations/0099_bound_tool_policy_trace.sql',
    'db/postgres/identity-migrations/0100_secureshop_audit_target_snapshot.sql',
    'db/postgres/identity-migrations/0101_graph_response_source.sql',
    'db/postgres/identity-migrations/0102_graph_prompt_policy_snapshot.sql',
    'db/postgres/identity-migrations/0103_dpi_semantic_grading_qualification.sql',
    'db/postgres/identity-migrations/0104_ctf_authority_read_model.sql',
    'db/postgres/identity-migrations/0105_ctf_lifecycle_projection.sql',
    'db/postgres/identity-migrations/0106_ctf_authoritative_decisions.sql',
    'db/postgres/identity-migrations/0107_ctf_decision_projection.sql',
    'db/postgres/identity-migrations/0108_ctf_decision_recovery.sql',
    'db/postgres/identity-migrations/0109_ctf_current_publication.sql',
    'db/postgres/identity-migrations/0110_ctf_authority_bootstrap.sql',
    'db/postgres/identity-migrations/0111_ctf_operation_recovery.sql',
    'db/postgres/identity-migrations/0112_ctf_student_deletion.sql',
    'db/postgres/identity-migrations/0113_ctf_predefense_claim.sql',
    'db/postgres/identity-migrations/0114_ctf_blocked_predefense_command.sql',
    'db/postgres/identity-migrations/0115_ctf_delivery_activation.sql',
    'db/postgres/identity-migrations/0116_ctf_blocked_publication_lock.sql',
    'db/postgres/identity-migrations/0117_ctf_ordered_telemetry.sql',
    'db/postgres/identity-migrations/0118_ctf_predefense_registration_locator.sql',
    'db/postgres/identity-migrations/0119_ctf_response_diagnostics.sql',
    'db/postgres/identity-migrations/0120_ctf_completed_proposal_authorization.sql',
    'db/postgres/identity-migrations/0121_ctf_global_reset_deleted_tombstones.sql',
    'db/postgres/identity-migrations/0122_ctf_predefense_recovery.sql',
    'db/postgres/workshop-migrations/aria/0001_schema.sql',
    'db/postgres/workshop-migrations/aria/0002_import_history.sql',
    'db/postgres/workshop-migrations/aria/0003_import_metadata.sql',
    'db/postgres/workshop-migrations/csrf/0001_schema.sql',
    'db/postgres/workshop-migrations/csrf/0002_import_history.sql',
    'db/postgres/workshop-migrations/csrf/0003_owner_binding.sql',
    'db/postgres/workshop-migrations/ctf/0001_schema.sql',
    'db/postgres/workshop-migrations/ctf/0002_import_provenance.sql',
    'db/postgres/workshop-migrations/ctf/0003_stage_default_provenance.sql',
    'db/postgres/workshop-migrations/ctf/0004_system_prompt_default_provenance.sql',
    'db/postgres/workshop-migrations/ctf/0005_defense_style_default_provenance.sql',
    'db/postgres/workshop-migrations/ctf/0006_authority_projection_read_model.sql',
    'db/postgres/workshop-migrations/ctf/0007_ordered_projection_receipts.sql',
    'db/postgres/workshop-migrations/ctf/0008_authoritative_decision_delivery.sql',
    'db/postgres/workshop-migrations/ctf/0009_authority_bootstrap_fence.sql',
    'db/postgres/workshop-migrations/ctf/0010_student_deletion_delivery.sql',
    'db/postgres/workshop-migrations/ctf/0011_delivery_activation.sql',
    'db/postgres/workshop-migrations/ctf/0012_ordered_telemetry_receipts.sql',
    'db/postgres/workshop-migrations/excessive_agency/0001_schema.sql',
    'db/postgres/workshop-migrations/finflow/0001_schema.sql',
    'db/postgres/workshop-migrations/finflow/0002_legacy_sensitive.sql',
    'db/postgres/workshop-migrations/finflow/0003_import_provenance.sql',
    'db/postgres/workshop-migrations/finflow/0004_import_batches.sql',
    'db/postgres/workshop-migrations/finflow/0005_legacy_sensitive_archive.sql',
    'db/postgres/workshop-migrations/finflow/0006_owner_binding.sql',
    'db/postgres/workshop-migrations/finflow/0007_legacy_sensitive_import_provenance.sql',
    'db/postgres/workshop-migrations/finflow/0008_student_deletion.sql',
    'db/postgres/workshop-migrations/finflow/0009_sensitive_info_aggregate_reset.sql',
    'db/postgres/workshop-migrations/finflow/0010_traversal_targets.sql',
    'db/postgres/workshop-migrations/finflow/0011_durable_customer_backups.sql',
    'db/postgres/workshop-migrations/finflow/0012_durable_log_overlays.sql',
    'db/postgres/workshop-migrations/finflow/0013_legacy_file_ssi_cleanup.sql',
    'db/postgres/workshop-migrations/legacy_challenge/0001_schema.sql',
    'db/postgres/workshop-migrations/legacy_challenge/0002_import_provenance.sql',
    'db/postgres/workshop-migrations/legacy_challenge/0003_student_deletion.sql',
    'db/postgres/workshop-migrations/legacy_challenge/0004_private_history_source_cleanup.sql',
    'db/postgres/workshop-migrations/legacy_challenge/0005_private_history_boundary.sql',
    'db/postgres/workshop-migrations/mcp/0001_schema.sql',
    'db/postgres/workshop-migrations/mcp/0002_import_provenance.sql',
    'db/postgres/workshop-migrations/mcp/0003_owner_binding.sql',
    'db/postgres/workshop-migrations/mcp/0004_mcp_owned_resources.sql',
    'db/postgres/workshop-migrations/mcp/0005_mcp_http_child_leases.sql',
    'db/postgres/workshop-migrations/mcp/0006_mcp_shadow_child_leases.sql',
    'db/postgres/workshop-migrations/nova/0001_schema.sql',
    'db/postgres/workshop-migrations/nova/0002_paper_access.sql',
    'db/postgres/workshop-migrations/nova/0003_import_history.sql',
    'db/postgres/workshop-migrations/nova/0004_import_metadata.sql',
    'db/postgres/workshop-migrations/nova/0005_nosqli9_content.sql',
    'db/postgres/workshop-migrations/secureshop/0001_schema.sql',
    'db/postgres/workshop-migrations/secureshop/0002_import_history.sql',
    'db/postgres/workshop-migrations/secureshop/0003_local_product_assets.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0001_schema.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0002_vectors.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0003_import_history.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0004_embedding_identity.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0005_conversation_binding.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0006_secureshop_turn_admission.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0007_secureshop_conversation_generation_retirement.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0008_secureshop_bound_persona_sessions.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0009_secureshop_bound_persona_renewal.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0010_secureshop_persona_inbox.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0011_secureshop_mcp_trust.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0012_secureshop_controlled_ssrf.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0013_secureshop_conversation_purpose.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0014_secureshop_bound_session_inventory.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0015_secureshop_bound_password_overlay.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0016_secureshop_bound_api_keys.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0017_secureshop_refund_conversation_purpose.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0018_secureshop_product_assist_conversation_purpose.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0019_secureshop_product_manual_ingest_purpose.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0020_secureshop_bound_audit_events.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0021_secureshop_audit_run_storage.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0022_secureshop_audit_sql_purpose.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0023_secureshop_persona_authority_state.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0024_secureshop_bound_tool_policy.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0025_owned_user_lookup.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0026_password_reset.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0027_bound_prompt_policies.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0028_system_config_candidate.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0029_system_config_retirement_guard.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0030_bound_system_diagnostics.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0031_secureshop_analytics_purpose.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0032_analytics_request_admission.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0033_bound_pricing.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0034_analytics_mode_admission.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0035_owned_mcp_registry.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0036_owned_mcp_registry_publication.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0037_listing_conversation_purpose.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0038_bound_lab_mail.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0039_mail_reply_purpose.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0040_inventory_conversation_purpose.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0041_owned_mcp_invocation_journal.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0042_owned_mcp_invocation_recovery.sql',
    'db/postgres/workshop-migrations/secureshop_review/0001_schema.sql',
    'db/postgres/workshop-migrations/secureshop_review/0002_cleanup_receipts.sql',
    'db/postgres/workshop-migrations/secureshop_review/0003_secureshop_review_learner_submissions.sql',
    'db/postgres/workshop-migrations/secureshop_review/0004_secureshop_bound_product_target.sql',
    'db/postgres/workshop-migrations/secureshop_review/0005_secureshop_bound_commerce.sql',
    'db/postgres/workshop-migrations/secureshop_review/0006_secureshop_bound_account.sql',
    'db/postgres/workshop-migrations/secureshop_review/0007_secureshop_bound_merchant_listings.sql',
    'db/postgres/workshop-migrations/secureshop_review/0008_secureshop_bound_refund_requests.sql',
    'db/postgres/workshop-migrations/secureshop_review/0009_secureshop_refund_cleanup_receipts.sql',
    'db/postgres/workshop-migrations/secureshop_review/0010_secureshop_refund_cleanup_receipt_guard.sql',
    'db/postgres/workshop-migrations/secureshop_review/0011_secureshop_bound_product_retrieval.sql',
    'db/postgres/workshop-migrations/secureshop_review/0012_secureshop_bound_manual_ingest.sql',
    'db/postgres/workshop-migrations/secureshop_review/0013_secureshop_bound_audit_events.sql',
    'db/postgres/workshop-migrations/secureshop_review/0014_product_embedding_revisions.sql',
    'db/postgres/workshop-migrations/secureshop_review/0015_product_embedding_privacy_cleanup.sql',
    'db/postgres/workshop-migrations/secureshop_review/0016_manual_runtime_provenance.sql',
    'db/postgres/workshop-migrations/secureshop_review/0017_bound_system_rebuild_operations.sql',
    'db/postgres/workshop-migrations/secureshop_review/0018_bound_system_first_embedding_revision.sql',
    'db/postgres/workshop-migrations/secureshop_review/0019_bound_policy_retrieval_corpus.sql',
    'db/postgres/workshop-migrations/secureshop_review/0020_bound_owned_system_restart.sql',
    'db/postgres/workshop-migrations/secureshop_review/0021_bound_owned_system_restart_manager.sql',
    'db/postgres/workshop-migrations/secureshop_review/0022_owned_listing_operations.sql',
    'db/postgres/workshop-migrations/secureshop_review/0023_listing_declined_terminal.sql',
    'db/postgres/workshop-migrations/secureshop_review/0024_listing_rewrite_publication.sql',
    'db/postgres/workshop-migrations/secureshop_review/0025_bound_coupon_commerce.sql',
    'db/postgres/workshop-migrations/secureshop_review/0026_owned_inventory_operations.sql',
    'db/postgres/workshop-migrations/sensitive_lookup/0001_schema.sql',
    'db/postgres/workshop-migrations/sensitive_lookup/0002_student_deletion.sql',
    'db/postgres/workshop-migrations/session_disclosure/0001_schema.sql',
    'db/postgres/workshop-migrations/supply_chain/0001_schema.sql',
    'db/postgres/workshop-migrations/supply_chain/0002_import_provenance.sql',
    'db/postgres/workshop-migrations/supply_chain/0003_import_batches.sql',
    'db/postgres/workshop-migrations/supply_chain/0004_owner_binding.sql',
    'db/postgres/workshop-migrations/xss/0001_schema.sql',
    'db/postgres/workshop-migrations/xss/0002_email_builder.sql',
    'db/postgres/workshop-migrations/xss/0003_legacy_challenge_config.sql',
    'db/postgres/workshop-migrations/xss/0004_import_history.sql',
    'db/postgres/workshop-migrations/xss/0005_owner_binding.sql',
    'db/postgres/workshop-migrations/xss/0006_profile_model_origin.sql',
    'db/postgres/workshop-migrations/xss/0007_student_deletion.sql',
    'db/postgres/workshop-migrations/xss/0008_scoped_profile_reset_receipt.sql',
    'db/postgres/workshop-migrations/xss/0009_student_deletion_receipt_retention.sql',
    'db/postgres/workshop-migrations/xss/0010_profile_origin_child_scope.sql',
    'db/postgres/workshop-migrations/xss/0011_profile_origin_child_scope_not_null.sql',
    'db/postgres/workshop-migrations/xss/0012_scoped_profile_reset_retirement.sql',
    'db/postgres/workshop-migrations/xss/0013_scoped_profile_reset_owner_deletion_fence.sql',
    'db/postgres/workshop-migrations/xss/0014_parent_profile_reset_receipt.sql',
    'db/postgres/workshop-migrations/xss/0015_owner_deletion_write_fence.sql',
}
REQUIRED = {'package-lock.json', 'tests/postgres/run-full-backend-auth-isolated.py', 'db/postgres/initialize-application.js', 'tests/postgres/sql_nosql_process_ownership.py', 'tests/postgres/browser_process_ownership.py', 'tests/postgres/fullApplicationBackendAuth.integration.test.js', 'node_modules/express/package.json', 'package.json', 'node_modules/pg/package.json', 'tests/postgres/sql_nosql_package_contract.py', 'tests/fixtures/fullBackendBootControls.js', 'tests/fixtures/fullBackendMcpAdmission.js', 'tests/postgres/sql_nosql_docker_ownership.py', 'server/index.js', 'tests/postgres/full_backend_auth_contract.py'}

EMBEDDING_ASSETS = {'tests/fixtures/fullBackendModelCache/Xenova/all-MiniLM-L6-v2/config.json': '7135149f7cffa1a573466c6e4d8423ed73b62fd2332c575bf738a0d033f70df7', 'tests/fixtures/fullBackendModelCache/Xenova/all-MiniLM-L6-v2/onnx/model_quantized.onnx': 'afdb6f1a0e45b715d0bb9b11772f032c399babd23bfc31fed1c170afc848bdb1', 'tests/fixtures/fullBackendModelCache/Xenova/all-MiniLM-L6-v2/tokenizer.json': 'da0e79933b9ed51798a3ae27893d3c5fa4a201126cef75586296df9b4d2c62a0', 'tests/fixtures/fullBackendModelCache/Xenova/all-MiniLM-L6-v2/tokenizer_config.json': '9261e7d79b44c8195c1cada2b453e55b00aeb81e907a6664974b4d7776172ab3'}
REQUIRED |= set(EMBEDDING_ASSETS)

REQUIRED |= {
 'tests/fixtures/fullBackendSecureShopStartup.js',
 'tests/fixtures/fullBackendSecureShopAdmission.js',
 'server/services/studentDeletionRunDrain.js',
 'server/services/secureshopBoundReviewBatchAuthority.js',
 'server/services/secureshopBoundReviewFixtureProfiles.js',
 'server/services/legacyChallengeOwnerCleanup.js',
}

STUDENT_DELETION_SOURCE_ROOTS = {
 'server/services/studentDeletionApplication.js',
 'server/services/studentDeletionProduction.js',
 'server/services/studentDeletionComposition.js',
 'server/services/studentDeletionAdapters.js',
 'server/services/studentDeletionWorker.js',
 'server/services/studentDeletionStoreCleanup.js',
}
_LITERAL_REQUIRE = re.compile(r"require\(\s*['\"]([^'\"]+)['\"]\s*\)")
_LITERAL_ADAPTER_LOAD = re.compile(r"load\(\s*['\"]([^'\"]+)['\"]\s*\)")

def student_deletion_source_closure(source):
 """Resolve literal relative require/load edges from production deletion roots.

 Computed module names are intentionally outside this static claim and require
 a separately reviewed explicit root. Directory index resolution matches Node.
 """
 source=Path(source).resolve();pending=list(STUDENT_DELETION_SOURCE_ROOTS);observed=set()
 while pending:
  relative=pending.pop()
  if relative in observed:continue
  target=source/relative
  require(target.is_file() and not target.is_symlink(), 'student deletion source edge missing')
  observed.add(relative)
  if target.suffix!='.js':continue
  text=target.read_text();specifiers=_LITERAL_REQUIRE.findall(text)
  if relative=='server/services/studentDeletionAdapters.js':specifiers+=_LITERAL_ADAPTER_LOAD.findall(text)
  for specifier in specifiers:
   if not specifier.startswith('.'):continue
   base=(target.parent/specifier).resolve()
   candidates=(base,Path(str(base)+'.js'),Path(str(base)+'.json'),base/'index.js')
   imported=next((candidate for candidate in candidates if candidate.is_file()),None)
   require(imported is not None and imported.is_relative_to(source), 'student deletion relative import unresolved')
   imported_relative=imported.relative_to(source).as_posix()
   if imported_relative not in observed:pending.append(imported_relative)
 return frozenset(observed)

def validate_student_deletion_source_closure(source,manifest):
 closure=student_deletion_source_closure(source)
 require(closure <= set(manifest['files']), 'student deletion transitive source closure missing')
 return closure

def validate_mcp_indirect_configuration(enabled, rendered, model_digest, endpoints):
 if not enabled:
  require(model_digest is None and endpoints is None, 'MCP cohort arguments require explicit opt-in')
  return None
 require(rendered is True and model_digest == MCP_MODEL_DIGEST, 'pinned rendered MCP model required')
 require(type(endpoints) is dict and set(endpoints)=={'version','postgres','runner','smtp','mailpit','model'} and endpoints['version']==1, 'MCP endpoint manifest mismatch')
 ports=[]
 for name in ('postgres','runner','smtp','mailpit'):
  endpoint=endpoints[name]
  require(type(endpoint) is dict and set(endpoint)=={'host','port'} and endpoint['host']=='127.0.0.1'
          and type(endpoint['port']) is int and 1 <= endpoint['port'] <= 65535
          and endpoint['port'] not in {5432,1025,8025,8090,11434}, 'MCP endpoint mismatch')
  ports.append(endpoint['port'])
 model=endpoints['model']
 require(type(model) is dict and set(model)=={'host','port'} and model=={'host':'127.0.0.1','port':11434}
         and len(set(ports))==4 and 11434 not in ports, 'MCP model or endpoint collision')
 return endpoints

SOURCE_UPLOAD_PATHS = {'agent-host/agents/uploads/server.js', 'agent-host/agents/uploads', 'agent-host/agents/uploads/tools', 'agent-host/agents/uploads/tools/index.js'}

PINNED_EMPTY_DEPENDENCY_LOG = 'client/node_modules/nwsapi/dist/lint.log'
EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

def inventory(source):
    source = Path(source)
    require(source.is_absolute() and not source.is_symlink() and source.is_dir()
            and source.resolve() == source and not source.stat().st_mode & 0o222,
            'exact immutable source directory required')
    files, links, directories = {}, {}, []
    for entry in source.rglob('*'):
        relative = entry.relative_to(source).as_posix()
        require((relative==PINNED_EMPTY_DEPENDENCY_LOG and entry.is_file() and not entry.is_symlink() and digest(entry)==EMPTY_SHA256) or (not entry.name.startswith('.env') and not entry.name.endswith(('.db', '.db-wal', '.db-shm', '.db-journal', '.sqlite', '.sqlite3', '.log'))
                and (relative.startswith(('node_modules/', 'client/node_modules/')) or (not any(part in {'.git', '__pycache__', 'sensitive_files', 'workshop_data', 'uploads', 'logs', 'vector-indexes', 'build', 'dist', 'browser-profile', 'frontend-build'} for part in entry.relative_to(source).parts)) or relative in SOURCE_UPLOAD_PATHS)),
                'private/runtime material forbidden in source package')
        if entry.is_symlink():
            target = os.readlink(entry)
            require(relative.startswith(('node_modules/', 'client/node_modules/')) and not Path(target).is_absolute(), 'only relative dependency symlinks allowed')
            require(entry.resolve(strict=True).is_relative_to((source / ('client/node_modules' if relative.startswith('client/') else 'node_modules')).resolve()), 'external dependency symlink forbidden')
            links[relative] = target
        else:
            require(not entry.stat().st_mode & 0o222, 'writable frozen package entry forbidden')
            if entry.is_file():
                files[relative] = digest(entry)
            elif entry.is_dir():
                directories.append(relative)
            else:
                raise RuntimeError('special package entry forbidden')
    return dict(files=files, symlinks=links, directories=sorted(directories))


# Exact admitted additions: historical native-qualified pins plus source-reviewed
# CTF0123 (native qualification pending). Executable recovery0004 is excluded.
QUALIFIED_ADDITIONAL_MIGRATIONS = {
 'db/postgres/identity-migrations/0123_ctf_canonical_admin_policy.sql': 'e0ceab31af4c5bb1aa9d31f56743cd70875b23669bf29ec277937f5d9d94c235',
 'db/postgres/maintenance-migrations/0002_local_recovery.sql': 'c2ae8481c0375ed278b5c872d8f9b442239fb31868d8feb9021d9fbf71f0a673',
 'db/postgres/maintenance-migrations/0003_canonical_inprocess_recovery.sql': '49b9a13f24727e729604a37264de247e962f7f1ad2c30f021c7045791f5b29b7',
 'db/postgres/workshop-migrations/secureshop_review/0027_policy_embedding_lineage.sql': '99d92c1bddc2bf40f8d480e9eecc860ce5a08794f442e34fdb0c2a66c68cd0d0',
}
REVIEWED_MIGRATIONS.update(QUALIFIED_ADDITIONAL_MIGRATIONS)

DPI_PHASE_A_MIGRATION_DIGEST = 'bd38b2eb359ca3d611b683af0394b06da391f65f1b39b5185d28f3beaec72900'

def validate_manifest(manifest, *, profile=None):
 require(profile in (None, 'dpi-technique-phase-a'), 'unknown admission profile')
 require(type(manifest) is dict and set(manifest)=={'version','scope','files','symlinks','directories'}
         and type(manifest['version']) is int and manifest['version']==1
         and manifest['scope']=='full_backend_auth', 'manifest schema mismatch')
 require(REQUIRED <= set(manifest['files']), 'required source closure missing')
 require(all(manifest['files'].get(name)==sha for name,sha in EMBEDDING_ASSETS.items()), 'exact offline embedding assets required')
 actual={name for name in manifest['files'] if name.startswith('db/postgres/identity-migrations/') or name.startswith('db/postgres/workshop-migrations/') or name.startswith('db/postgres/maintenance-migrations/')}
 if profile == 'dpi-technique-phase-a':
  # Retained donor SQL is inert in this model-only profile. Bind every byte;
  # do not add newer unrelated migrations to make model admission succeed.
  sql={name:manifest['files'][name] for name in actual}
  require(hashlib.sha256(json.dumps(sql,sort_keys=True,separators=(',',':')).encode()).hexdigest()==DPI_PHASE_A_MIGRATION_DIGEST, 'exact Phase A retained migration inventory required')
 else:
  require(actual==REVIEWED_MIGRATIONS, 'exact reviewed migration closure required')
  require(all(manifest['files'].get(name)==sha for name,sha in QUALIFIED_ADDITIONAL_MIGRATIONS.items()), 'qualified migration checksum mismatch')
 return manifest

def validate_package(source, manifest_path, manifest_sha256, node, node_sha256, *, profile=None):
 source,manifest_path,node=map(Path,(source,manifest_path,node))
 require(source.name=='source' and manifest_path==source.parent/'manifest.json'
         and set(p.name for p in source.parent.iterdir())=={'source','manifest.json'}, 'exact source-plus-manifest required')
 require(not source.parent.is_symlink() and not source.parent.stat().st_mode & 0o222, 'immutable parent required')
 require(manifest_path.is_file() and not manifest_path.is_symlink() and not manifest_path.stat().st_mode & 0o222
         and SHA.fullmatch(manifest_sha256) and digest(manifest_path)==manifest_sha256, 'manifest identity mismatch')
 require(node.is_absolute() and node.is_file() and not node.is_symlink() and os.access(node,os.X_OK)
         and SHA.fullmatch(node_sha256) and digest(node)==node_sha256, 'Node identity mismatch')
 manifest=validate_manifest(json.loads(manifest_path.read_text()),profile=profile)
 validate_student_deletion_source_closure(source,manifest)
 require(all(manifest[key]==value for key,value in inventory(source).items()), 'complete inventory mismatch')
 require(all((source/key).stat().st_nlink==1 for key in manifest['files']), 'hardlinks forbidden')
 return manifest

def validate_fullboot_layout(row):
 from sql_nosql_docker_ownership import validate_container_layout
 # Reuse every identity/port/mount check with an isolated copy; shared cohorts
 # retain their exact 256 MiB contract.
 import copy
 candidate=copy.deepcopy(row)
 require(candidate.get('HostConfig',{}).get('Tmpfs')=={'/var/lib/postgresql':'rw,size=1073741824'}, 'full boot requires exact 1 GiB tmpfs')
 candidate['HostConfig']['Tmpfs']={'/var/lib/postgresql':'rw,size=268435456'}
 return validate_container_layout(candidate)

BROWSER_SHA256 = '51083e7cf58ba060a0160b8f447ea04c0e9bada00c30a047259bcfe1217b82c3'
RENDERED_REQUIRED = {
 'client/package.json','client/package-lock.json','client/index.html','client/vite.config.mjs','client/vite.opaque-frame-cors.mjs',
 'client/node_modules/vite/bin/vite.js','client/src/App.js',
 'tests/fixtures/fullBackendRenderedBranch.js','tests/fixtures/browserProcessOwnership.js','tests/fixtures/fullBackendRenderedAuth.js','tests/fixtures/validatedBrowserJsonCache.js',
 'tests/fixtures/fullBackendBrowserProxy.js','tests/fixtures/fullBackendBrowserForwardProxy.js','tests/fixtures/fullBackendBrowserNetworkPolicy.js',
}
def validate_rendered(manifest, rendered, browser, browser_sha256):
 if not rendered:
  require(browser is None and browser_sha256 is None, 'browser arguments require rendered mode')
  return
 require((RENDERED_REQUIRED | RENDERED_SOURCE_FILES) <= set(manifest['files']), 'rendered source closure missing')
 require({p for p in manifest['files'] if p.startswith(('client/src/','client/public/'))} == {p for p in RENDERED_SOURCE_FILES if p.startswith(('client/src/','client/public/'))}, 'unexpected client source inventory')
 require(browser is not None and browser_sha256==BROWSER_SHA256, 'pinned browser identity required')
 executable=Path(browser)
 require(executable.is_absolute() and executable.is_file() and not executable.is_symlink()
         and executable.resolve()==executable and os.access(executable,os.X_OK)
         and digest(executable)==browser_sha256, 'browser identity mismatch')

RENDERED_SOURCE_FILES = {'client/src/hooks/useChangePolling.js', 'client/src/pages/secureshop/components/ProductCard.jsx', 'client/src/pages/secureshop/bridge/uploads.mjs', 'client/src/hooks/useWorkshopHeartbeat.js', 'client/src/pages/secureshop/context/AuthContext.test.jsx', 'client/src/pages/secureshop/pages/Cart.jsx', 'client/src/pages/secureshop/components/Button.jsx', 'client/src/pages/secureshop/components/RoleSwitcher.jsx', 'client/src/pages/workshops/SupplyChainWorkshop.js', 'client/src/utils/loadAdminActivityUsers.js', 'client/src/pages/secureshop/pages/merchant/Reviews.jsx', 'client/src/pages/secureshop/components/Shell.toastContext.test.jsx', 'client/src/pages/challenges/directPromptInjectionVisibility.test.js', 'client/src/App.secureshopLifecycle.test.jsx', 'client/src/utils/loadAgentRunDetail.test.js', 'client/src/pages/secureshop/SecureShopApp.jsx', 'client/src/pages/challenges/CSRFWorkshop.js', 'client/src/components/observability/AgentRunInspector.test.js', 'client/src/pages/challenges/ExcessiveAgencyBolaLab.js', 'client/src/test/remarkGfmMock.js', 'client/src/pages/secureshop/utils/boundReviewRequests.mjs', 'client/src/components/observability/AgentRunInspector.js', 'client/src/utils/judgeFeedback.mjs', 'client/src/pages/secureshop/bridge/fetchAdapter.mjs', 'client/src/context/WorkshopConfigContext.js', 'client/src/pages/labs/AIAssistant.js', 'client/src/pages/secureshop/pages/Inbox.jsx', 'client/src/pages/secureshop/components/Card.jsx', 'client/src/pages/secureshop/components/Tabs.jsx', 'client/src/pages/secureshop/components/TopNav.jsx', 'client/src/pages/secureshop/components/Dialog.jsx', 'client/src/pages/ComprehensiveAdminDashboard.js', 'client/src/pages/WorkshopSignup.js', 'client/src/pages/workshops/NoSQLWorkshop.js', 'client/src/pages/secureshop/pages/merchant/Analytics.jsx', 'client/src/pages/secureshop/components/McpTrustLab.jsx', 'client/src/styles/WorkshopAuth.css', 'client/src/pages/challenges/MCPWorkshop.polling.test.js', 'client/src/pages/SessionDisclosureDemo.js', 'client/src/pages/secureshop/pages/Orders.jsx', 'client/src/pages/secureshop/bridge/compiler.mjs', 'client/src/utils/loadAgentRunDetail.js', 'client/src/index.css', 'client/src/pages/admin/ProgressAnalyticsPanel.js', 'client/src/pages/secureshop/bridge/handshake.mjs', 'client/public/font-licenses/fraunces-OFL.txt', 'client/src/pages/secureshop/pages/merchant/Listings.jsx', 'client/vite.review-renderer.config.mjs', 'client/public/font-licenses/jetbrains-mono-OFL.txt', 'client/src/utils/serializedReconciliation.js', 'client/src/context/WorkshopConfigContext.test.js', 'client/src/pages/secureshop/components/ControlledSsrfLab.jsx', 'client/src/pages/challenges/IndirectPromptInjectionChallenge.polling.test.js', 'client/public/favicon.svg', 'client/src/pages/secureshop/components/AgentAssist.test.js', 'client/src/pages/secureshop/FONT_LICENSES.md', 'client/src/pages/secureshop/components/reviewCardServerRenderer.jsx', 'client/src/pages/pollingConsumers.test.js', 'client/src/pages/WorkshopLogin.js', 'client/src/pages/workshops/SensitiveInfoWorkshop.mode.test.js', 'client/src/components/admin/AIProviderManagement.js', 'client/src/pages/secureshop/pages/Home.jsx', 'client/src/pages/secureshop/pages/Login.jsx', 'client/src/hooks/useReconciliationGuard.js', 'client/src/pages/challenges/MCPWorkshop.js', 'client/src/pages/secureshop/hooks/useAgentStream.js', 'client/src/pages/secureshop/components/Shell.jsx', 'client/src/utils/judgeFeedback.test.js', 'client/src/pages/AgentRunsPage.js', 'client/src/index.js', 'client/src/pages/secureshop/components/ControlledSsrfLab.test.jsx', 'client/src/pages/secureshop/bridge/operations.mjs', 'client/src/pages/workshops/SensitiveInfoWorkshop.js', 'client/src/pages/secureshop/pages/admin/Audit.jsx', 'client/src/pages/challenges/DirectPromptInjectionChallenge.test.js', 'client/src/utils/formatWorkshopTime.components.test.js', 'client/src/pages/secureshop/components/Input.jsx', 'client/src/pages/secureshop/components/AgentLane/Hop.jsx', 'client/src/pages/secureshop/components/Badge.jsx', 'client/src/utils/secureShopFetch.mjs', 'client/src/components/workshop/JudgeRetryButton.test.js', 'client/src/components/SolutionPanel.js', 'client/src/pages/secureshop/pages/Product.jsx', 'client/src/pages/secureshop/bridge/stateChannel.mjs', 'client/src/pages/secureshop/components/AgentLane/HopDetailSheet.jsx', 'client/src/pages/secureshop/components/Rating.jsx', 'client/src/utils/authenticatedSse.mjs', 'client/src/pages/ComprehensiveAdminDashboard.activity.test.js', 'client/src/utils/judgeFailureMessage.mjs', 'client/src/App.js', 'client/src/pages/UserActivity.js', 'client/src/pages/secureshop/pages/merchant/Reviews.test.jsx', 'client/src/pages/secureshop/bridge/stateStore.mjs', 'client/src/pages/secureshop/fonts.css', 'client/src/components/workshop/JudgeRetryButton.js', 'client/src/test/reactMarkdownMock.js', 'client/src/pages/secureshop/SecureShopWorkshop.test.jsx', 'client/src/pages/secureshop/components/PageTransition.jsx', 'client/src/pages/EditProfile.js', 'client/src/pages/secureshop/components/AgentAssist.jsx', 'client/src/utils/csrfDeepLink.mjs', 'client/src/utils/finflowWorkshopPresentation.mjs', 'client/src/pages/secureshop/SecureShopObjectives.test.jsx', 'client/src/pages/workshops/SensitiveInfoWorkshop.metadata.test.js', 'client/src/components/workshop/ObjectiveHelpModal.js', 'client/src/pages/secureshop/components/UploadZone.jsx', 'client/src/pages/secureshop/pages/Product.boundReviews.test.jsx', 'client/src/pages/secureshop/SecureShopWorkshop.jsx', 'client/src/pages/secureshop/components/PersonaInboxLab.jsx', 'client/src/components/HintPanel.js', 'client/src/components/admin/PromptInjectionHintEditorModal.js', 'client/src/pages/challenges/CSRFWorkshop.browserExecution.test.js', 'client/src/pages/challenges/directPromptInjectionState.js', 'client/src/pages/secureshop/utils/boundReviewRequests.test.js', 'client/src/pages/workshops/SQLNoSQLProgressCache.test.js', 'client/src/pages/secureshop/pages/Checkout.jsx', 'client/src/pages/secureshop/components/McpTrustLab.test.jsx', 'client/src/utils/csrfResponseGuard.mjs', 'client/src/components/workshop/WorkshopExperience.gallery.js', 'client/src/pages/secureshop/components/AgentLane/Turn.jsx', 'client/src/components/admin/StudentWorkshopView.js', 'client/src/context/ShopAuthContext.js', 'client/src/components/workshop/WorkshopExperience.test.js', 'client/src/components/VisibilityProtectedRoute.js', 'client/src/pages/secureshop/components/EmptyState.jsx', 'client/src/pages/secureshop/utils/reviewLifecycle.test.js', 'client/src/pages/challenges/ExcessiveAgencyBolaLab.hints.test.js', 'client/src/pages/secureshop/utils/shopStorage.mjs', 'client/src/pages/secureshop/bridge/runtime.mjs', 'client/src/pages/secureshop/theme.css', 'client/src/utils/authenticatedSse.test.js', 'client/src/utils/serializedReconciliation.test.js', 'client/src/components/ErrorBoundary.js', 'client/src/services/revisionPoller.js', 'client/src/pages/UserProfile.truthfulness.test.js', 'client/src/pages/WorkshopDashboard.js', 'client/src/pages/challenges/CSRFWorkshop.deepLink.test.js', 'client/src/pages/challenges/XSSWorkshop.visibility.test.js', 'client/src/pages/secureshop/pages/admin/AccessControl.jsx', 'client/src/pages/LandingPage.js', 'client/src/pages/secureshop/SecureShopWorkshopController.mjs', 'client/src/components/workshop/ObjectiveHelpModal.test.js', 'client/src/context/AuthContext.test.js', 'client/src/pages/challenges/ExcessiveAgencyBolaLab.toolActivity.test.js', 'client/src/pages/secureshop/pages/Catalog.jsx', 'client/src/pages/secureshop/context/ToastContext.jsx', 'client/src/pages/workshopReconciliation.test.js', 'client/src/components/workshop/experience.mjs', 'client/src/pages/secureshop/components/PersonaInboxLab.test.jsx', 'client/secureshop-frame.html', 'client/src/pages/ctfObjectives.js', 'client/src/pages/secureshop/frameEntry.jsx', 'client/src/pages/secureshop/pages/admin/Overview.jsx', 'client/src/pages/admin/CTFAdminPanel.solutions.test.js', 'client/src/pages/CTFLeaderboard.test.js', 'client/src/components/VisibilityProtectedRoute.integration.test.js', 'client/src/pages/CTFLeaderboard.js', 'client/src/pages/secureshop/context/CartContext.test.jsx', 'client/src/pages/secureshop/utils/assetUrl.mjs', 'client/src/pages/secureshop/components/AgentLane.jsx', 'client/src/components/VulnerabilityTemplate.js', 'client/src/pages/secureshop/SecureShopWorkshopController.test.js', 'client/src/pages/secureshop/components/ReviewCard.jsx', 'client/src/pages/secureshop/pages/merchant/Pricing.jsx', 'client/src/pages/secureshop/bridge/transport.mjs', 'client/src/pages/secureshop/pages/Register.jsx', 'client/src/pages/secureshop/pages/admin/Policies.jsx', 'client/src/utils/promptInjectionAdminCompatibility.js', 'client/src/pages/secureshop/utils/reviewLifecycle.mjs', 'client/src/utils/formatWorkshopTime.js', 'client/src/components/admin/PromptInjectionHintEditorModal.test.js', 'client/src/pages/challenges/directPromptInjectionVisibility.js', 'client/src/setupProxy.js', 'client/src/pages/workshops/SQLWorkshop.js', 'client/src/components/VisibilityProtectedRoute.test.js', 'client/src/pages/secureshop/pages/Landing.jsx', 'client/src/pages/secureshop/pages/NotFound.jsx', 'client/src/pages/ComprehensiveAdminDashboard.permissions.test.js', 'client/src/pages/UserProfile.js', 'client/src/pages/challenges/XSSWorkshop.js', 'client/src/components/workshop/useWorkshopResetController.js', 'client/src/pages/challenges/IndirectPromptInjectionChallenge.visibility.test.js', 'client/src/components/WorkshopNavbar.js', 'client/src/pages/SessionDisclosureDemo.test.js', 'client/src/pages/secureshop/components/RequireAuth.jsx', 'client/src/components/workshop/WorkshopExperience.js', 'client/src/utils/csrfDeepLink.test.js', 'client/src/pages/challenges/DirectPromptInjectionChallenge.js', 'client/src/pages/challenges/directPromptInjectionState.test.js', 'client/src/components/admin/ServerLogs.js', 'client/src/pages/secureshop/pages/admin/Users.jsx', 'client/src/pages/WorkshopChallenges.js', 'client/src/pages/secureshop/context/CartContext.jsx', 'client/public/font-licenses/inter-OFL.txt', 'client/src/pages/secureshop/pages/merchant/Inbox.jsx', 'client/src/pages/CTFChallenge.hints.test.js', 'client/src/pages/secureshop/context/AuthContext.jsx', 'client/src/pages/challenges/IndirectPromptInjectionChallenge.js', 'client/src/pages/secureshop/pages/Account.jsx', 'client/src/pages/CTFChallenge.js', 'client/src/pages/secureshop/pages/admin/System.jsx', 'client/src/pages/secureshop/pages/merchant/Overview.jsx', 'client/src/pages/secureshop/SecureShopObjectives.jsx', 'client/src/pages/workshops/SupplyChainWorkshop.idempotency.test.js', 'client/src/pages/admin/CTFAdminPanel.js', 'client/src/pages/secureshop/components/Footer.jsx', 'client/src/components/workshop/fixtures.mjs', 'client/src/utils/formatWorkshopTime.test.js', 'client/src/context/AuthContext.js', 'client/src/pages/secureshop/components/Spinner.jsx', 'client/src/pages/secureshop/components/OrderStatusChip.jsx', 'client/src/pages/secureshop/hooks/useAgentStream.test.js', 'client/src/pages/secureshop/pages/admin/MCP.jsx', 'client/src/setupTests.js', 'client/src/utils/loadAdminActivityUsers.test.js', 'client/src/pages/CTFDashboard.js'}


RENDERED_SOURCE_FILES.add('client/src/pages/CTFChallenge.feedback.test.js')
RENDERED_SOURCE_FILES.add('client/src/pages/secureshop/pages/Home.test.jsx')
RENDERED_SOURCE_FILES.add('client/src/pages/secureshop/pages/Catalog.test.jsx')
RENDERED_SOURCE_FILES.add('client/public/secureshop/product-placeholder.svg')
RENDERED_SOURCE_FILES.add('client/src/pages/secureshop/utils/legacyProductImageDefaults.json')
REQUIRED.add('server/services/secureshopFailureDiagnostic.js')

def consume_full_mcp_control(control, expected, source, evidence):
    """Bind the root's one-use authorization to every parsed cohort argument."""
    control = Path(control)
    if (not control.is_absolute() or control.resolve() != control or control.is_symlink()
            or not control.is_file() or control.stat().st_uid != os.getuid()
            or control.stat().st_mode & 0o077
            or any(control.is_relative_to(Path(boundary)) for boundary in [source.parent, evidence, Path(__file__).resolve().parents[2]])):
        raise RuntimeError('Private external full MCP control required')
    lock = control.with_name(control.name + '.consume-lock')
    lock.mkdir(mode=0o700)
    try:
        value = json.loads(control.read_text())
        if (type(value) is not dict or value.get('scope') != 'full_backend_mcp_indirect'
                or value.get('status') != 'granted' or type(value.get('allowedLaunches')) is not int
                or value['allowedLaunches'] != 1
                or any(value.get(key) != wanted for key, wanted in expected.items())):
            raise RuntimeError('Full MCP control binding mismatch')
        value.update(status='consumed', launcherPid=os.getpid())
        pending = control.with_name(control.name + '.pending')
        with pending.open('x') as output:
            os.chmod(pending, 0o600)
            json.dump(value, output, sort_keys=True)
            output.flush()
            os.fsync(output.fileno())
        os.replace(pending, control)
    finally:
        lock.rmdir()


MCP_RENDERED_REQUIRED = {
    'sidecars/sandbox-runner/mcpTargets.js',
    'sidecars/sandbox-runner/mcpProtectedState.js',
    'sidecars/sandbox-runner/mcpPackageCatalog.js',
    'tests/postgres/full_backend_mcp_resources.py',
    'tests/postgres/mcp_connected_baseline_contract.py',
    'tests/postgres/mcp_strict_runner_ownership.py',
    'sidecars/sandbox-runner/apparmor/dvaia-mcp-sandbox.apparmor.in',
    'tests/fixtures/fullBackendMcpAdmission.js',
    'tests/fixtures/fullBackendRenderedMcp.js',
    'tests/fixtures/mcpRenderedAdminLifecycle.js',
    'tests/fixtures/mcpRenderedLearner.js',
    'tests/fixtures/mcpRenderedNativeEvidence.js',
}

def validate_mcp_rendered_manifest(manifest, enabled):
    if enabled:
        require(MCP_RENDERED_REQUIRED <= set(manifest['files']), 'MCP rendered source closure missing')

SECURESHOP_RENDERED_REQUIRED = {
    'tests/fixtures/fullBackendAssessmentBrowser.js',
    'tests/postgres/mcp_connected_baseline_contract.py',
    'tests/postgres/full_backend_secureshop_contract.py',
    'tests/postgres/full_backend_secureshop_resources.py',
    'tests/fixtures/fullBackendRenderedSecureShop.js',
    'tests/fixtures/configureDurableNetworkMessages.js',
    'tests/fixtures/secureShopRenderedNativeEvidence.js',
    'tests/fixtures/renderedSecureShopSession.js',
    'tests/fixtures/renderedSecureShopReviewWorkflow.js',
    'tests/fixtures/renderedSecureShopBrowser.js',
    'tests/fixtures/renderedSecureShopPersona.js',
    'tests/fixtures/renderedSecureShopMcpTrust.js',
    'tests/fixtures/renderedSecureShopSsrf.js',
    'tests/fixtures/secureShopQualificationPreload.js',
    'tests/fixtures/secureShopEndpointCapabilities.js',
    'tests/fixtures/secureShopEndpointIpc.js',
    'tests/fixtures/secureShopAgentHostIpcSpawn.js',
    'tests/fixtures/secureShopEndpointBridge.js',
    'tests/fixtures/secureShopPostBindObserver.js',
    'tests/fixtures/secureShopStaticDynamicSocketGuard.js',
    'tests/fixtures/secureShopDynamicSocketGuard.js',
    'tests/fixtures/secureShopCatalogEvidence.js',
    'server/services/secureshop/agentHostSupervisor.js',
    'server/services/secureshopSsrfTargetPool.js',
    'server/services/secureshopSsrfOwnedTarget.js',
    'server/services/secureshopRecoverableToolError.js',
    'client/vite.review-renderer.config.mjs',
    'server/config/secureshopCurriculum.js',
}

def validate_secureshop_rendered_manifest(manifest, enabled, rendered, mcp_enabled=False):
    if not enabled:
        return
    require(rendered is True and mcp_enabled is False,
            'SecureShop requires an exclusive rendered cohort')
    require(SECURESHOP_RENDERED_REQUIRED <= set(manifest['files']),
            'SecureShop rendered source closure missing')

# Agent-host entrypoints are loaded from the canonical runtime registry.
SECURESHOP_RENDERED_REQUIRED |= {'agent-host/agents/product-search/tools/search.js', 'agent-host/agents/audit/server.js', 'agent-host/agents/analytics/server.js', 'agent-host/agents/support/server.js', 'agent-host/agents/summarizer/server.js', 'server/agent-runtime/mcpObservedActionPrompt.js', 'agent-host/shared/callerContext.js', 'agent-host/agents/summarizer/tools/summarize_reviews.js', 'agent-host/agents/email/server.js', 'agent-host/agents/listing/tools/optimize_images.js', 'agent-host/agents/summarizer/tools/summarize_file.js', 'agent-host/agents/policy/server.js', 'agent-host/agents/uploads/server.js', 'agent-host/agents/cart/server.js', 'agent-host/agents/support/tools/index.postgres.js', 'agent-host/agents/cart/tools/index.js', 'agent-host/agents/listing/tools/optimize_images.postgres.js', 'agent-host/agents/summarizer/tools/summarize_reviews.postgres.js', 'agent-host/agents/product-search/tools/search.postgres.js', 'agent-host/agents/system/server.js', 'agent-host/agents/product-search/server.js', 'agent-host/agents/pricing-strategy/server.js', 'agent-host/agents/cart/tools/index.postgres.js', 'agent-host/agents/review-moderator/server.js', 'agent-host/shared/graphServer.js', 'agent-host/agents/listing/server.js', 'agent-host/agents/summarizer/tools/explain_return_policy.js', 'agent-host/agents/support/tools/index.js', 'agent-host/agents/mcp-registry/server.js', 'agent-host/agents/user-management/server.js', 'agent-host/agents/inventory/server.js', 'agent-host/agents/price-advisor/server.js'}

# Exact transitive CommonJS closure from agent-host/index.js through all 17
# canonical agent entrypoints. The companion offline scanner rejects any new
# computed require until its finite targets have been reviewed here.
SECURESHOP_AGENT_HOST_SOURCE_CLOSURE = {
 'agent-host/agents/analytics/server.js',
 'agent-host/agents/analytics/tools/index.js',
 'agent-host/agents/analytics/tools/index.postgres.js',
 'agent-host/agents/audit/server.js',
 'agent-host/agents/audit/tools/index.js',
 'agent-host/agents/cart/server.js',
 'agent-host/agents/cart/tools/index.js',
 'agent-host/agents/cart/tools/index.postgres.js',
 'agent-host/agents/email/server.js',
 'agent-host/agents/email/tools/index.js',
 'agent-host/agents/email/tools/index.postgres.js',
 'agent-host/agents/inventory/server.js',
 'agent-host/agents/inventory/tools/index.js',
 'agent-host/agents/inventory/tools/index.postgres.js',
 'agent-host/agents/listing/server.js',
 'agent-host/agents/listing/tools/_llmRewrite.js',
 'agent-host/agents/listing/tools/_nunjucksSink.js',
 'agent-host/agents/listing/tools/create.js',
 'agent-host/agents/listing/tools/create.postgres.js',
 'agent-host/agents/listing/tools/import_bulk.js',
 'agent-host/agents/listing/tools/import_bulk.postgres.js',
 'agent-host/agents/listing/tools/optimize_images.js',
 'agent-host/agents/listing/tools/optimize_images.postgres.js',
 'agent-host/agents/listing/tools/update.js',
 'agent-host/agents/listing/tools/update.postgres.js',
 'agent-host/agents/mcp-registry/server.js',
 'agent-host/agents/mcp-registry/tools/index.js',
 'agent-host/agents/policy/server.js',
 'agent-host/agents/policy/tools/index.js',
 'agent-host/agents/policy/tools/index.postgres.js',
 'agent-host/agents/price-advisor/server.js',
 'agent-host/agents/price-advisor/tools/index.js',
 'agent-host/agents/price-advisor/tools/index.postgres.js',
 'agent-host/agents/pricing-strategy/server.js',
 'agent-host/agents/pricing-strategy/tools/index.js',
 'agent-host/agents/pricing-strategy/tools/index.postgres.js',
 'agent-host/agents/product-search/server.js',
 'agent-host/agents/product-search/tools/personalized_feed.js',
 'agent-host/agents/product-search/tools/personalized_feed.postgres.js',
 'agent-host/agents/product-search/tools/search.js',
 'agent-host/agents/product-search/tools/search.postgres.js',
 'agent-host/agents/product-search/tools/similar.js',
 'agent-host/agents/product-search/tools/similar.postgres.js',
 'agent-host/agents/review-moderator/server.js',
 'agent-host/agents/review-moderator/tools/index.js',
 'agent-host/agents/review-moderator/tools/index.postgres.js',
 'agent-host/agents/summarizer/server.js',
 'agent-host/agents/summarizer/tools/explain_return_policy.js',
 'agent-host/agents/summarizer/tools/summarize_file.js',
 'agent-host/agents/summarizer/tools/summarize_product.js',
 'agent-host/agents/summarizer/tools/summarize_product.postgres.js',
 'agent-host/agents/summarizer/tools/summarize_reviews.js',
 'agent-host/agents/summarizer/tools/summarize_reviews.postgres.js',
 'agent-host/agents/support/server.js',
 'agent-host/agents/support/tools/index.js',
 'agent-host/agents/support/tools/index.postgres.js',
 'agent-host/agents/system/server.js',
 'agent-host/agents/system/tools/index.js',
 'agent-host/agents/uploads/server.js',
 'agent-host/agents/uploads/tools/index.js',
 'agent-host/agents/user-management/server.js',
 'agent-host/agents/user-management/tools/index.js',
 'agent-host/agents/user-management/tools/index.postgres.js',
 'agent-host/index.js',
 'agent-host/shared/callerContext.js',
 'agent-host/shared/db.js',
 'agent-host/shared/graphServer.js',
 'agent-host/shared/trace.js',
 'agent-host/shared/vectorStore.js',
 'client/src/pages/secureshop/utils/legacyProductImageDefaults.json',
 'db/postgres/initialize-application.js',
 'db/postgres/migrate.js',
 'db/postgres/nosqlWorkshopFixtures.js',
 'db/postgres/provision-application.js',
 'db/postgres/provisioning-extension.js',
 'db/postgres/seeds/secureshop.json',
 'db/postgres/seeds/sensitiveLookup.json',
 'db/postgres/sqlWorkshopFixtures.js',
 'db/postgres/workshopChallengeFixtures.js',
 'scripts/application-data-root.js',
 'scripts/application-journal-bound-maintenance.js',
 'scripts/application-node-runtime.js',
 'scripts/install/ctf-authority-journal.js',
 'scripts/install/ctf-authority-setup.js',
 'scripts/launcher-control.js',
 'scripts/lib/application-maintenance-installation.js',
 'scripts/lib/application-maintenance-plan-configuration.js',
 'scripts/lib/application-maintenance-scope.js',
 'scripts/lib/setup-additive-environment-publication.js',
 'scripts/lib/setup-local-postgres-state.js',
 'scripts/lib/setup-local-process-identity.js',
 'scripts/local-docker-authority.js',
 'scripts/local-mailpit.js',
 'scripts/start-application.js',
 'server/agent-runtime/boundedSourceClassificationEvaluation.js',
 'server/agent-runtime/ctfDefenseGraph.js',
 'server/agent-runtime/ctfGuardianResult.js',
 'server/agent-runtime/ctfLanguageDecision.js',
 'server/agent-runtime/ctfStageJudge.js',
 'server/agent-runtime/dpiActorProof.js',
 'server/agent-runtime/dpiAnswerComparison.js',
 'server/agent-runtime/dpiAnswerEvaluation.js',
 'server/agent-runtime/dpiContentWitnessComparison.js',
 'server/agent-runtime/dpiContentWitnessV12Comparison.js',
 'server/agent-runtime/dpiDecoderEvidence.js',
 'server/agent-runtime/dpiExistentialComparison.js',
 'server/agent-runtime/dpiExistentialEvaluation.js',
 'server/agent-runtime/dpiObfuscationGraph.js',
 'server/agent-runtime/dpiPolicyBinding.js',
 'server/agent-runtime/dpiPolicyContract.js',
 'server/agent-runtime/dpiTaskContributionComparison.js',
 'server/agent-runtime/dpiTechniqueWitness.js',
 'server/agent-runtime/dpiTechniqueWitnessAudit.js',
 'server/agent-runtime/durableGeneration.js',
 'server/agent-runtime/exactQuoteResolver.js',
 'server/agent-runtime/finflowAdminCatalogSelection.js',
 'server/agent-runtime/inventoryStockComparison.js',
 'server/agent-runtime/inventoryStockEvaluation.js',
 'server/agent-runtime/judgeErrors.js',
 'server/agent-runtime/judgeExecutionTranscript.js',
 'server/agent-runtime/judgeProviderConfiguration.js',
 'server/agent-runtime/mailHeaderBoundarySelection.js',
 'server/agent-runtime/mailReplyAuthorityComparison.js',
 'server/agent-runtime/mailReplyAuthorityConsistentComparison.js',
 'server/agent-runtime/mailReplyCompactComparison.js',
 'server/agent-runtime/mailReplyComparison.js',
 'server/agent-runtime/mailReplyConditionalComparison.js',
 'server/agent-runtime/mailReplyEvaluation.js',
 'server/agent-runtime/mailReplyGroundedComparison.js',
 'server/agent-runtime/mailReplyKeyedComparison.js',
 'server/agent-runtime/mailReplySeparatedAuthorityComparison.js',
 'server/agent-runtime/mailReplySourceComparison.js',
 'server/agent-runtime/mailReplySparseComparison.js',
 'server/agent-runtime/mailReplyWholeComparison.js',
 'server/agent-runtime/modelAnalysisGraph.js',
 'server/agent-runtime/objectiveJudge.js',
 'server/agent-runtime/ownerWorkflowHttpError.js',
 'server/agent-runtime/ownerWorkflowRoutes.js',
 'server/agent-runtime/pricingDirectiveGroupVerifier.js',
 'server/agent-runtime/pricingEvidenceCatalogue.js',
 'server/agent-runtime/pricingEvidenceSelectionVerifier.js',
 'server/agent-runtime/pricingQuoteGroupVerifier.js',
 'server/agent-runtime/pricingSemanticDecompositionVerifier.js',
 'server/agent-runtime/providers/finalResponseContract.js',
 'server/agent-runtime/providers/langchainProvider.js',
 'server/agent-runtime/providers/modelScheduler.js',
 'server/agent-runtime/ragDirectiveGroupVerifier.js',
 'server/agent-runtime/ragEvidenceSelectionVerifier.js',
 'server/agent-runtime/ragSemanticDecompositionVerifier.js',
 'server/agent-runtime/ragTypedActionDefense.js',
 'server/agent-runtime/referenceComparisonVerifier.js',
 'server/agent-runtime/reviewModerationComparison.js',
 'server/agent-runtime/reviewModerationEvaluation.js',
 'server/agent-runtime/sourceComparisonLegacyVerifier.js',
 'server/agent-runtime/sourceComparisonVerifier.js',
 'server/config/legacyFileSsiCurriculum.js',
 'server/config/secureshopCurriculum.js',
 'server/config/workshopCatalog.js',
 'server/config/xssEmailBuilderCurriculum.js',
 'server/data/csrfWorkshopSolutions.js',
 'server/data/ctfDefaults.js',
 'server/data/excessiveAgencySolutions.js',
 'server/data/indirectPromptInjectionSolutions.js',
 'server/data/legacyChallengeSeeds.js',
 'server/data/legacyVulnerabilitySettings.js',
 'server/data/mcpWorkshopSolutions.js',
 'server/data/nosqlInjectionWorkshopSolutions.js',
 'server/data/postgres/nosqlInjectionWorkshopSolutions.js',
 'server/data/postgres/sqlInjectionWorkshopSolutions.js',
 'server/data/promptInjectionSolutions.js',
 'server/data/secureshopAgentSeeds.js',
 'server/data/sensitiveInfoSolutions.js',
 'server/data/sqlInjectionWorkshopSolutions.js',
 'server/data/supplyChainSolutions.js',
 'server/data/workshopHints.js',
 'server/data/xssWorkshopSolutions.js',
 'server/database/excessiveAgencyLabDb.js',
 'server/database/postgres/applicationMaintenanceControl.js',
 'server/database/postgres/applicationMaintenanceInprocessControl.js',
 'server/database/postgres/applicationMaintenanceRecoveryControl.js',
 'server/database/postgres/applicationMaintenanceRecoveryProof.js',
 'server/database/postgres/applicationMaintenanceReplayEncoding.js',
 'server/database/postgres/applicationMaintenanceStoreInspection.js',
 'server/database/postgres/catalogDefaultProvenance.js',
 'server/database/postgres/csrfWorkshopDb.js',
 'server/database/postgres/ctfAuthorityBootstrapImport.js',
 'server/database/postgres/ctfAuthorityBootstrapRepository.js',
 'server/database/postgres/ctfDb.js',
 'server/database/postgres/ctfDecisionProjectionRepository.js',
 'server/database/postgres/ctfDecisionRepository.js',
 'server/database/postgres/ctfDeliveryActivation.js',
 'server/database/postgres/ctfDeliveryActivationOperator.js',
 'server/database/postgres/ctfLifecycleRepository.js',
 'server/database/postgres/ctfStageDefaultProvenance.js',
 'server/database/postgres/ctfTelemetryRepository.js',
 'server/database/postgres/excessiveAgencyLabDb.js',
 'server/database/postgres/identityRepository.js',
 'server/database/postgres/identityValidation.js',
 'server/database/postgres/index.js',
 'server/database/postgres/legacyChallengeDb.js',
 'server/database/postgres/legacySensitiveStore.js',
 'server/database/postgres/mcpWorkshopDb.js',
 'server/database/postgres/nosqlWorkshopDb.js',
 'server/database/postgres/poolBudget.js',
 'server/database/postgres/secureshopAgentsDb.js',
 'server/database/postgres/secureshopBoundReviewRepository.js',
 'server/database/postgres/secureshopCommerceDb.js',
 'server/database/postgres/secureshopInitialization.js',
 'server/database/postgres/secureshopPools.js',
 'server/database/postgres/secureshopReviewDb.js',
 'server/database/postgres/secureshopReviewDecisionReceipt.js',
 'server/database/postgres/secureshopSeed.js',
 'server/database/postgres/secureshopVectorRepository.js',
 'server/database/postgres/sensitiveInfoWorkshopDb.js',
 'server/database/postgres/sensitiveLookupDb.js',
 'server/database/postgres/sessionDisclosureDb.js',
 'server/database/postgres/sqlWorkshopDb.js',
 'server/database/postgres/supplyChainWorkshopDb.js',
 'server/database/postgres/workshopPlatformSeed.js',
 'server/database/postgres/workshopPlatformSeedCore.js',
 'server/database/postgres/workshopPlatformSupport.js',
 'server/database/postgres/workshopSupport.js',
 'server/database/postgres/xssEmailStore.js',
 'server/database/postgres/xssProfileOriginRepository.js',
 'server/database/postgres/xssScopedProfileResetRepository.js',
 'server/database/postgres/xssWorkshopDb.js',
 'server/database/xssWorkshopStore.js',
 'server/middleware/ctfHintConfigInput.js',
 'server/middleware/llmLogger.js',
 'server/services/applicationMaintenanceExecutionAdmission.js',
 'server/services/applicationMaintenanceInprocessAdmission.js',
 'server/services/applicationMaintenanceInprocessSources.json',
 'server/services/applicationMaintenanceInprocessWorkflow.js',
 'server/services/applicationMaintenanceLease.js',
 'server/services/csrfReconProof.js',
 'server/services/ctfAuthorityBootstrap.js',
 'server/services/ctfDecisionProjectionContract.js',
 'server/services/ctfDecisionService.js',
 'server/services/ctfDefenseLayers.js',
 'server/services/ctfDeletionContract.js',
 'server/services/ctfHintState.js',
 'server/services/ctfLifecycleCommands.js',
 'server/services/ctfPredefenseContract.js',
 'server/services/ctfProjectionResults.js',
 'server/services/ctfResponseDiagnostics.js',
 'server/services/ctfTelemetryContract.js',
 'server/services/dpiDecodedRequest.js',
 'server/services/legacyAiTeachingHistoryReadiness.js',
 'server/services/mcp/ownedManagedConfiguration.js',
 'server/services/multiProviderAIService.js',
 'server/services/platformSigningConfiguration.js',
 'server/services/promptInjectionCTF.js',
 'server/services/secureshop/assetPaths.js',
 'server/services/secureshop/traceBuffer.js',
 'server/services/secureshop/vectorStore.js',
 'server/services/secureshopBoundReviewBatchAuthority.js',
 'server/services/secureshopBoundReviewModeration.js',
 'server/services/secureshopConversationBinding.js',
 'server/services/secureshopConversationPurpose.js',
 'server/services/secureshopCouponContract.js',
 'server/services/secureshopInventoryContract.js',
 'server/services/secureshopInventoryEvidence.js',
 'server/services/secureshopLoopEvidence.js',
 'server/services/secureshopMailHeaderEvidence.js',
 'server/services/secureshopMailSenderIdentity.js',
 'server/services/secureshopMcpSchemaDigest.js',
 'server/services/secureshopPasswordResetKeys.js',
 'server/services/secureshopPricingActivation.js',
 'server/services/secureshopPricingHttpClient.js',
 'server/services/secureshopPricingManagedConfiguration.js',
 'server/services/secureshopPricingPackage.js',
 'server/services/secureshopQualifiedManagedConfiguration.js',
 'server/services/secureshopRealModelTrace.js',
 'server/services/secureshopReviewRunProjection.js',
 'server/services/secureshopSystemConfigActivation.js',
 'server/services/secureshopSystemConfigClient.js',
 'server/services/secureshopSystemDiagnosticActivation.js',
 'server/services/secureshopSystemDiagnosticClient.js',
 'server/services/secureshopSystemManagedConfiguration.js',
 'server/services/secureshopSystemManagedEnvironment.js',
 'server/services/secureshopSystemRestartActivation.js',
 'server/services/secureshopSystemRestartClient.js',
 'server/services/secureshopSystemRestartContract.js',
 'server/utils/logger.js',
 'server/utils/requestContext.js',
 'sidecars/sandbox-runner/owned-pricing-http/input.js',
 'sidecars/sandbox-runner/owned-pricing-http/wire.js',
 'sidecars/sandbox-runner/owned-system/contract.js',
 'sidecars/sandbox-runner/owned-system/diagnostic-contract.js',
 'sidecars/sandbox-runner/owned-system/diagnostic-result.js',
 'sidecars/sandbox-runner/owned-system/diagnostic-wire.js',
 'sidecars/sandbox-runner/owned-system/health-contract.js',
 'sidecars/sandbox-runner/owned-system/receipt.js',
 'sidecars/sandbox-runner/owned-system/restart-contract.js',
 'sidecars/sandbox-runner/owned-system/restart-wire.js',
}

SECURESHOP_RENDERED_REQUIRED |= SECURESHOP_AGENT_HOST_SOURCE_CLOSURE | {
 'tests/fixtures/secureShopAgentHostSourceClosure.js',
}

# Exact inherited client closure from the qualified hc1402rc donor.
# Keep validate_rendered exact set equality: unlisted additions remain denied.
RENDERED_SOURCE_FILES |= {
 'client/src/components/CtfRecoveryNotice.js',
 'client/src/components/admin/StudentWorkshopView.csrfParity.test.js',
 'client/src/components/workshop/CsrfResponseText.js',
 'client/src/components/workshop/CsrfResponseText.test.js',
 'client/src/components/workshop/CsrfRetrievedWidget.js',
 'client/src/components/workshop/CsrfRetrievedWidget.test.js',
 'client/src/components/workshop/useWorkshopResetController.test.js',
 'client/src/hooks/useAdminActiveUserCount.js',
 'client/src/hooks/useAdminActiveUserCount.test.js',
 'client/src/pages/ComprehensiveAdminDashboard.bulkReset.test.js',
 'client/src/pages/ComprehensiveAdminDashboard.secureshopSolutions.test.js',
 'client/src/pages/ComprehensiveAdminDashboard.studentDetails.test.js',
 'client/src/pages/WorkshopLogin.test.js',
 'client/src/pages/challenges/MCPWorkshop.shadowSource.test.js',
 'client/src/pages/secureshop/bridge/mailReferences.mjs',
 'client/src/pages/secureshop/bridge/transport.test.js',
 'client/src/pages/secureshop/components/ProductDescription.jsx',
 'client/src/pages/secureshop/components/UploadZone.lifecycle.test.jsx',
 'client/src/pages/secureshop/components/productDescriptionServerRenderer.jsx',
 'client/src/pages/secureshop/pages/Account.addresses.test.jsx',
 'client/src/pages/secureshop/pages/Account.apiKeys.test.jsx',
 'client/src/pages/secureshop/pages/Account.sessions.test.jsx',
 'client/src/pages/secureshop/pages/Cart.totals.test.jsx',
 'client/src/pages/secureshop/pages/Checkout.summary.test.jsx',
 'client/src/pages/secureshop/pages/Inbox.test.jsx',
 'client/src/pages/secureshop/pages/Login.destination.test.jsx',
 'client/src/pages/secureshop/pages/MailAssessment.jsx',
 'client/src/pages/secureshop/pages/MailAssessment.test.jsx',
 'client/src/pages/secureshop/pages/MailCapabilityStatus.jsx',
 'client/src/pages/secureshop/pages/MailCapabilityStatus.test.jsx',
 'client/src/pages/secureshop/pages/Orders.lifecycle.test.jsx',
 'client/src/pages/secureshop/pages/Product.related.test.jsx',
 'client/src/pages/secureshop/pages/admin/AccessControl.errors.test.jsx',
 'client/src/pages/secureshop/pages/admin/AdminFailures.test.jsx',
 'client/src/pages/secureshop/pages/admin/AdminReadFailures.test.jsx',
 'client/src/pages/secureshop/pages/admin/Audit.boundSummary.test.jsx',
 'client/src/pages/secureshop/pages/admin/Audit.errors.test.jsx',
 'client/src/pages/secureshop/pages/admin/BoundSystemRestart.jsx',
 'client/src/pages/secureshop/pages/admin/BoundSystemRestart.test.jsx',
 'client/src/pages/secureshop/pages/admin/Overview.errors.test.jsx',
 'client/src/pages/secureshop/pages/admin/PasswordResetPanel.jsx',
 'client/src/pages/secureshop/pages/admin/PasswordResetPanel.test.jsx',
 'client/src/pages/secureshop/pages/admin/Policies.operations.test.jsx',
 'client/src/pages/secureshop/pages/admin/System.boundConfig.test.jsx',
 'client/src/pages/secureshop/pages/admin/System.boundDiagnostic.test.jsx',
 'client/src/pages/secureshop/pages/admin/System.boundRebuild.test.jsx',
 'client/src/pages/secureshop/pages/admin/System.staleResponse.test.jsx',
 'client/src/pages/secureshop/pages/admin/Users.errors.test.jsx',
 'client/src/pages/secureshop/pages/admin/aclOperation.js',
 'client/src/pages/secureshop/pages/admin/policyOperation.js',
 'client/src/pages/secureshop/pages/admin/policyOperation.test.js',
 'client/src/pages/secureshop/pages/admin/systemConfigOperation.mjs',
 'client/src/pages/secureshop/pages/admin/systemConfigRecovery.js',
 'client/src/pages/secureshop/pages/admin/systemConfigRecovery.test.js',
 'client/src/pages/secureshop/pages/admin/systemDiagnosticRecovery.js',
 'client/src/pages/secureshop/pages/admin/systemRebuildOperation.mjs',
 'client/src/pages/secureshop/pages/admin/systemRebuildRecovery.js',
 'client/src/pages/secureshop/pages/admin/systemRestartOperation.mjs',
 'client/src/pages/secureshop/pages/admin/systemRestartRecovery.js',
 'client/src/pages/secureshop/pages/admin/userAdminOperation.js',
 'client/src/pages/secureshop/pages/mailRequests.js',
 'client/src/pages/secureshop/pages/mailRequests.test.jsx',
 'client/src/pages/secureshop/pages/merchant/Analytics.errors.test.jsx',
 'client/src/pages/secureshop/pages/merchant/Inbox.test.jsx',
 'client/src/pages/secureshop/pages/merchant/InboxDisclosure.test.jsx',
 'client/src/pages/secureshop/pages/merchant/InventoryPanel.jsx',
 'client/src/pages/secureshop/pages/merchant/InventoryPanel.test.jsx',
 'client/src/pages/secureshop/pages/merchant/Listings.manualUpload.test.jsx',
 'client/src/pages/secureshop/pages/merchant/Overview.test.jsx',
 'client/src/pages/secureshop/pages/merchant/Pricing.bound.test.jsx',
 'client/src/pages/secureshop/pages/merchant/Pricing.errors.test.jsx',
 'client/src/pages/secureshop/pages/merchant/PricingRecoveryReferences.jsx',
 'client/src/pages/secureshop/pages/merchant/analytics.css',
 'client/src/pages/secureshop/pages/merchant/analyticsChart.mjs',
 'client/src/pages/secureshop/pages/merchant/analyticsRecovery.mjs',
 'client/src/pages/secureshop/pages/merchant/inventoryReference.mjs',
 'client/src/pages/secureshop/pages/merchant/listingsReferences.mjs',
 'client/src/pages/secureshop/pages/merchant/pricingOperation.mjs',
 'client/src/pages/secureshop/pages/merchant/pricingRecovery.mjs',
 'client/src/pages/secureshop/pages/merchant/useBoundAnalytics.js',
 'client/src/pages/secureshop/pages/merchant/useBoundAnalytics.test.jsx',
 'client/src/pages/secureshop/pages/merchant/useBoundInventory.js',
 'client/src/pages/secureshop/pages/merchant/useBoundInventory.test.jsx',
 'client/src/pages/secureshop/pages/merchant/useBoundListings.js',
 'client/src/pages/secureshop/pages/merchant/useBoundListings.test.jsx',
 'client/src/pages/secureshop/pages/merchant/useBoundPricing.js',
 'client/src/pages/secureshop/utils/agentStreamProtocol.mjs',
 'client/src/pages/secureshop/utils/couponReference.mjs',
 'client/src/pages/secureshop/utils/loginDestination.mjs',
 'client/src/pages/secureshop/utils/loginDestination.test.mjs',
 'client/src/pages/secureshop/utils/manualReviewOperation.mjs',
 'client/src/pages/secureshop/utils/refundRequest.bridge.test.js',
 'client/src/pages/secureshop/utils/refundRequest.mjs',
 'client/src/pages/secureshop/utils/refundRequest.test.js',
 'client/src/pages/workshops/LegacyFileSsiWorkshop.js',
 'client/src/pages/workshops/LegacyFileSsiWorkshopPage.js',
 'client/src/pages/workshops/__tests__/LegacyFileSsiWorkshop.test.js',
 'client/src/services/ctfRecovery.js',
 'client/src/services/ctfRecovery.test.js',
 'client/src/services/useCtfRecovery.js',
 'client/src/services/useCtfRecovery.test.js',
 'client/src/utils/adminBulkReset.js',
 'client/src/utils/adminBulkReset.test.js',
 'client/src/utils/legacyFileSsiController.mjs',
 'client/src/utils/legacyFileSsiSnapshot.mjs',
}

# Reviewed active-family admin source and its controlled regression.
RENDERED_SOURCE_FILES |= {'client/src/utils/adminExerciseLoading.js', 'client/src/pages/ComprehensiveAdminDashboard.exerciseLoading.test.js'}

# Reviewed platform authority projections; historical client entries remain required.
RENDERED_SOURCE_FILES |= {
 'client/src/utils/platformAdmin.js',
 'client/src/utils/platformAdmin.test.js',
 'client/src/App.platformAdmin.test.jsx',
}
