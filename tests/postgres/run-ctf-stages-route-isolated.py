#!/usr/bin/env python3
"""Run authentic mounted CTF stages in an owned frozen copy and disposable PG18."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import selectors
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from urllib.parse import quote


POSTGRES_IMAGE_ID = "sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280"
MAX_LOG_BYTES = 16 * 1024 * 1024
CONTAINER_OWNER_LABEL = "org.owasp-ai-goat.ctf-stages-runner"
CONTAINER_NONCE_LABEL = "org.owasp-ai-goat.ctf-stages-nonce"
SOURCE_DIRECTORIES = ("server", "db", "tests", "docs")
SOURCE_FILES = ("package.json", "package-lock.json")
CURRENT_PUBLICATION_SOURCE_PINS = {
    "tests/postgres/ctfAuthenticatedPublicationCurrent.integration.test.js": "4f71ba707d2b8d48b4197169769785090f5faa49535951826e431bd197369d3c",
    "db/postgres/identity-migrations/0155_ctf_authenticated_publication_stale.sql": "030c1c3d87152de08756a5f40f46249b0909d6cb08a604fe5f6e177b50cbff59",
}
DENIED_NAMES = frozenset({".git", "node_modules", "build", "logs", "uploads",
    "sensitive_files", "workshop_data", "vector-indexes", "coverage", ".cache", "__pycache__"})
DENIED_SUFFIXES = (".db", ".db-wal", ".db-shm", ".db-journal", ".sqlite", ".sqlite3", ".log")


class OwnedSignalExit(SystemExit):
    pass


def parse_args(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--docker-host", required=True)
    parser.add_argument("--docker-cli", required=True)
    parser.add_argument("--docker-cli-sha256", required=True)
    parser.add_argument("--image-id", help="Explicit installed PostgreSQL 18 image for repository-only cohorts")
    parser.add_argument("--node", required=True)
    parser.add_argument("--node-sha256", required=True)
    parser.add_argument("--source-manifest-sha256", required=True)
    parser.add_argument("--dependency-manifest-sha256", required=True)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--application-maintenance-lease", action="store_true", help="Empty disposable identity stores; session lease behavior only")
    selection.add_argument("--ctf-authority-bootstrap", action="store_true", help="Migration-only bootstrap preparation; no activation or model")
    selection.add_argument("--ctf-blocked-publication", action="store_true", help="Unmounted blocked publication; no model")
    selection.add_argument("--ctf-authority-runtime", action="store_true", help="Isolated assembled authority runtime; controlled input guard only")
    selection.add_argument("--ctf-production-runtime", action="store_true", help="Isolated production adapters with owned synthetic provider transport")
    selection.add_argument("--ctf-publication-current", action="store_true", help="Current-source 0155 publication: valid populated predecessor, no-op, then canonical reset")
    parser.add_argument("--browser-executable")
    parser.add_argument("--browser-sha256")
    parser.add_argument("--client-source-sha256")
    parser.add_argument("--client-dependency-sha256")
    parser.add_argument("--client-build-sha256")
    parser.add_argument("--client-build-output-sha256")
    parser.add_argument("--client-build-report-sha256")
    parser.add_argument("--client-build-report")
    parser.add_argument("--client-build-input-sha256")
    parser.add_argument("--client-build-recorder-sha256")
    parser.add_argument("--content-source-manifest-sha256")
    parser.add_argument("--docker-daemon-id")
    parser.add_argument("--stage6-candidate-sha256")
    selection.add_argument("--ctf-recovery-rendered", action="store_true", help="Real challenge component, controlled transport and owned pinned browser")
    selection.add_argument("--ctf-ten-content", action="store_true", help="Main-workspace prebuilt CTF stages 1-10 content projection; no source copy")
    selection.add_argument("--ctf-config-rendered", action="store_true", help="Separate prebuilt CTF configuration rendered cohort; no source copy or model")
    selection.add_argument("--ctf-preview-rendered", action="store_true", help="Separate prebuilt CTF preview rendered cohort; no source copy or credit")
    selection.add_argument("--ctf-learner-entry-hint-rendered", action="store_true", help="Separate prebuilt learner registration/start/hint rendered cohort; no source copy or credit")
    selection.add_argument("--ctf-learner-attempt-gate-rendered", action="store_true", help="Separate prebuilt learner default-three-attempt rendered cohort; controlled transport only")
    selection.add_argument("--ctf-fixed-practice-rendered", action="store_true", help="Separate prebuilt fixed-practice rendered cohort; controlled provider only")
    selection.add_argument("--ctf-full-reset-rendered", action="store_true", help="Separate prebuilt Full CTF Reset rendered cohort; no model, credit, or source copy")
    selection.add_argument("--ctf-stage6-current-main", action="store_true", help="Current-main owned Stage 6 actual actor and earned rendered qualification; no source copy")
    selection.add_argument("--ctf-predefense-recovery", action="store_true", help="Assembled application deterministic recovery component only")
    selection.add_argument("--ctf-authority-application", action="store_true", help="Isolated HTTP application with owned synthetic provider transport")
    selection.add_argument("--ctf-stage6-adoption", action="store_true", help="Paired active-authority Stage 6 instructor adoption; no model")
    selection.add_argument("--ctf-teaching-content", action="store_true", help="Main-workspace CTF teaching-content authority qualification; no model or source copy")
    selection.add_argument("--ctf-telemetry", action="store_true", help="Isolated ordered heartbeat qualification")
    selection.add_argument("--ctf-delivery-provision-case", choices=("fresh-reuse", "completion-failure"))
    selection.add_argument("--ctf-delivery-activation", action="store_true", help="Isolated delivery activation qualification only")
    selection.add_argument("--ctf-registration-locator", action="store_true", help="Isolated claim-bound registration locator qualification")
    selection.add_argument("--ctf-response-diagnostics", action="store_true", help="Isolated immutable response diagnostics qualification")
    selection.add_argument("--ctf-admin-read", action="store_true", help="Isolated claim-bound registration locator qualification")
    selection.add_argument("--ctf-blocked-predefense", action="store_true", help="Unmounted predefense orchestration; no live model")
    selection.add_argument("--ctf-worker-lifecycle", action="store_true", help="Unmounted projection worker lifecycle; no model")
    selection.add_argument("--ctf-predefense", action="store_true", help="Unmounted predefense claim and authorization; no model")
    selection.add_argument("--ctf-student-deletion", action="store_true", help="Unmounted ordered student deletion; no model")
    selection.add_argument("--ctf-admin-response", action="store_true", help="Unmounted admin current response matrix; no model")
    selection.add_argument("--ctf-current-read", action="store_true", help="Unmounted authenticated current reads; no model")
    selection.add_argument("--ctf-current-response", action="store_true", help="Current authenticated response projection; no model")
    selection.add_argument("--ctf-operation-recovery", action="store_true", help="Authenticated lifecycle receipt read; no model")
    selection.add_argument("--ctf-current-publication", action="store_true", help="Current publication authority guards; no model")
    selection.add_argument("--ctf-decision-recovery", action="store_true", help="Unmounted decision recovery SQL and delivery; no model")
    selection.add_argument("--ctf-decision-projection", action="store_true", help="Actual authoritative decision delivery; no model")
    selection.add_argument("--ctf-decision-schema", action="store_true", help="Unmounted authoritative decision SQL; no model")
    selection.add_argument("--ctf-projection-worker", action="store_true", help="Actual two-store lifecycle worker; no model")
    selection.add_argument("--ctf-lifecycle-schema", action="store_true", help="CTF 2B SQL-only disposable qualification; no model")
    selection.add_argument("--authority-schema-only", action="store_true",
                           help="Inert authority schema, four disposable stores; no model")
    selection.add_argument("--session-fence-only", action="store_true",
                           help="Real JWT/disposable PG with synthetic guardian and Judge; no model")
    selection.add_argument("--stage-end", type=int, choices=range(2, 11))
    parser.add_argument("--target-stage", type=int, choices=range(6, 11),
                        help="Qualify exactly one later stage with explicit unearned prerequisites")
    parser.add_argument("--candidate-set", choices=["instructor", "reviewer-boundary-v1", "stage6-fixed-v1"], default="instructor")
    parser.add_argument("--run", action="store_true", help="Root-controlled execution gate")
    args = parser.parse_args(argv)
    if args.target_stage is not None:
        if args.stage_end is not None:
            parser.error("--target-stage cannot be combined with --stage-end")
        selected = [action.dest for action in selection._group_actions
                    if action.dest != "stage_end" and getattr(args, action.dest, None)]
        if selected and selected != ["ctf_stage6_current_main"]:
            parser.error("--target-stage cannot be combined with this selector")
    if args.ctf_publication_current or args.ctf_ten_content or args.ctf_config_rendered or args.ctf_preview_rendered or args.ctf_learner_entry_hint_rendered or args.ctf_learner_attempt_gate_rendered or args.ctf_fixed_practice_rendered or args.ctf_full_reset_rendered:
        if not args.image_id or len(args.image_id) != 71 or not args.image_id.startswith("sha256:") \
                or any(character not in "0123456789abcdef" for character in args.image_id[7:]):
            parser.error("repository-only cohort requires an exact installed image SHA-256")
    elif args.image_id:
        parser.error("--image-id is only accepted by repository-only cohorts")
    if args.ctf_publication_current:
        if not all((args.content_source_manifest_sha256, args.docker_daemon_id)):
            parser.error("Current publication requires source and Docker daemon identity pins")
        if any((args.browser_executable, args.browser_sha256, args.client_source_sha256,
                args.client_dependency_sha256, args.client_build_sha256,
                args.client_build_output_sha256, args.client_build_report_sha256,
                args.client_build_report, args.client_build_input_sha256,
                args.client_build_recorder_sha256, args.stage6_candidate_sha256)):
            parser.error("Current publication is DB-only and forbids browser, build, and model candidate pins")
    if (args.ctf_publication_current or args.ctf_operation_recovery or args.ctf_recovery_rendered or args.ctf_ten_content or args.ctf_config_rendered or args.ctf_preview_rendered or args.ctf_learner_entry_hint_rendered or args.ctf_learner_attempt_gate_rendered or args.ctf_fixed_practice_rendered or args.ctf_full_reset_rendered or args.ctf_predefense_recovery or args.application_maintenance_lease or args.ctf_authority_application or args.ctf_stage6_adoption or args.ctf_teaching_content or args.ctf_production_runtime or args.ctf_response_diagnostics or args.ctf_authority_runtime or args.ctf_admin_read or args.ctf_registration_locator or args.ctf_delivery_provision_case or args.ctf_telemetry or args.ctf_delivery_activation or args.session_fence_only or args.authority_schema_only or args.ctf_lifecycle_schema or args.ctf_projection_worker or args.ctf_decision_schema or args.ctf_decision_projection or args.ctf_decision_recovery or args.ctf_current_publication or args.ctf_authority_bootstrap or args.ctf_current_response or args.ctf_student_deletion or args.ctf_admin_response or args.ctf_predefense or args.ctf_blocked_publication or args.ctf_blocked_predefense or args.ctf_worker_lifecycle or args.ctf_current_read) and args.candidate_set != "instructor":
        parser.error("session-fence-only does not accept model candidate sets")
    if args.ctf_stage6_adoption or args.ctf_teaching_content:
        if not all((args.content_source_manifest_sha256, args.docker_daemon_id)):
            parser.error("Main-workspace authority qualification requires current source and Docker daemon pins")
        if any((args.browser_executable, args.browser_sha256, args.client_source_sha256,
                args.client_dependency_sha256, args.client_build_sha256,
                args.client_build_output_sha256, args.client_build_report_sha256,
                args.client_build_report, args.client_build_input_sha256,
                args.client_build_recorder_sha256, args.stage6_candidate_sha256)):
            parser.error("Main-workspace authority qualification forbids browser, build, and model candidate pins")
    elif args.ctf_recovery_rendered or args.ctf_ten_content or args.ctf_config_rendered or args.ctf_preview_rendered or args.ctf_learner_entry_hint_rendered or args.ctf_learner_attempt_gate_rendered or args.ctf_fixed_practice_rendered or args.ctf_full_reset_rendered or args.ctf_stage6_current_main:
        if not all((args.browser_executable, args.browser_sha256, args.client_source_sha256, args.client_dependency_sha256)):
            parser.error("rendered/content selector requires explicit browser path and source/dependency digests")
        if (args.ctf_ten_content or args.ctf_config_rendered or args.ctf_preview_rendered or args.ctf_learner_entry_hint_rendered or args.ctf_learner_attempt_gate_rendered or args.ctf_fixed_practice_rendered or args.ctf_full_reset_rendered or args.ctf_stage6_current_main) and not all((args.client_build_sha256, args.client_build_output_sha256)):
            parser.error("ctf-ten-content requires parent and recorder prebuilt client/build manifest digests")
        if (args.ctf_ten_content or args.ctf_config_rendered or args.ctf_preview_rendered or args.ctf_learner_entry_hint_rendered or args.ctf_learner_attempt_gate_rendered or args.ctf_fixed_practice_rendered or args.ctf_full_reset_rendered or args.ctf_stage6_current_main) and not all((args.client_build_report, args.client_build_report_sha256, args.client_build_input_sha256, args.client_build_recorder_sha256)):
            parser.error("ctf-ten-content requires build report, input, and recorder digests")
        if (args.ctf_ten_content or args.ctf_config_rendered or args.ctf_preview_rendered or args.ctf_learner_entry_hint_rendered or args.ctf_learner_attempt_gate_rendered or args.ctf_fixed_practice_rendered or args.ctf_full_reset_rendered or args.ctf_stage6_current_main) and not all((args.content_source_manifest_sha256, args.docker_daemon_id)):
            parser.error("ctf-ten-content requires content source manifest and daemon identity pins")
    elif not args.ctf_publication_current and any((args.browser_executable, args.browser_sha256, args.client_source_sha256, args.client_dependency_sha256, args.client_build_sha256, args.client_build_output_sha256, args.client_build_report_sha256, args.client_build_report, args.client_build_input_sha256, args.client_build_recorder_sha256, args.content_source_manifest_sha256, args.docker_daemon_id)):
        parser.error("browser pin is only accepted by rendered selector")
    if args.ctf_stage6_current_main:
        if args.target_stage != 6 or args.candidate_set != "stage6-fixed-v1" or not args.stage6_candidate_sha256 or len(args.stage6_candidate_sha256) != 64 or any(c not in "0123456789abcdef" for c in args.stage6_candidate_sha256):
            parser.error("Stage 6 current-main requires target 6, closed fixed candidate, and exact SHA-256")
    elif args.candidate_set == "stage6-fixed-v1" or args.stage6_candidate_sha256:
        parser.error("Stage 6 fixed candidate requires current-main selector")
    if (args.ctf_config_rendered or args.ctf_preview_rendered or args.ctf_learner_entry_hint_rendered or args.ctf_learner_attempt_gate_rendered or args.ctf_fixed_practice_rendered or args.ctf_full_reset_rendered) and (args.stage_end is not None or args.target_stage is not None):
        parser.error("Separate rendered cohort forbids stage target overrides")
    return args


def qualification_selection(args, nonce):
    """Closed execution contract shared by launcher and resource-free controls."""
    if args.application_maintenance_lease:
        return {"mode": "application_maintenance_lease", "stageEnd": None,
            "test": "tests/postgres/applicationMaintenanceLease.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_lease_{index}_{nonce}" for index in (1, 2)),
            "childSeconds": 180, "workSeconds": 300, "cleanupSeconds": 120,
            "tmpfsBytes": 268435456,
            "environment": {"APPLICATION_MAINTENANCE_LEASE_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_authority_bootstrap:
        return {"mode": "ctf_authority_bootstrap_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfAuthorityBootstrap.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_bootstrap_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_AUTHORITY_BOOTSTRAP_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_blocked_publication:
        return {"mode": "ctf_blocked_publication_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfBlockedPublication.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_blockpub_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_BLOCKED_PUBLICATION_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_recovery_rendered:
        return {"mode": "ctf_recovery_rendered_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfAuthorityApplication.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_app_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 480, "workSeconds": 660, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_RECOVERY_RENDERED_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_ten_content:
        return {"mode": "ctf_ten_content_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfAuthorityApplication.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_app_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 480, "workSeconds": 660, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_TEN_CONTENT_ISOLATED": "1", "CTF_RECOVERY_RENDERED_ISOLATED": "1",
                "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_config_rendered:
        return {"mode": "ctf_config_rendered_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfAuthorityApplication.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_config_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 480, "workSeconds": 360, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_CONFIG_RENDERED_ISOLATED": "1", "CTF_RECOVERY_RENDERED_ISOLATED": "1",
                "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_preview_rendered:
        return {"mode": "ctf_preview_rendered_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfAuthorityApplication.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_preview_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 480, "workSeconds": 360, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_PREVIEW_RENDERED_ISOLATED": "1", "CTF_RECOVERY_RENDERED_ISOLATED": "1",
                "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_learner_entry_hint_rendered:
        return {"mode": "ctf_learner_entry_hint_rendered_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfAuthorityApplication.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_learner_entry_hint_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 480, "workSeconds": 180, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_LEARNER_ENTRY_HINT_RENDERED_ISOLATED": "1", "CTF_RECOVERY_RENDERED_ISOLATED": "1",
                "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_learner_attempt_gate_rendered:
        return {"mode": "ctf_learner_attempt_gate_rendered_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfAuthorityApplication.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_learner_attempt_gate_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 480, "workSeconds": 360, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_LEARNER_ATTEMPT_GATE_RENDERED_ISOLATED": "1", "CTF_RECOVERY_RENDERED_ISOLATED": "1",
                "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_fixed_practice_rendered:
        return {"mode": "ctf_fixed_practice_rendered_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfAuthorityApplication.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_fixed_practice_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 480, "workSeconds": 120, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_FIXED_PRACTICE_RENDERED_ISOLATED": "1", "CTF_RECOVERY_RENDERED_ISOLATED": "1",
                "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_full_reset_rendered:
        return {"mode": "ctf_full_reset_rendered_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfFullResetRendered.integration.test.js",
            "databases": (f"owasp_ai_goat_test_ctf_full_reset_identity_{nonce}",
                f"owasp_ai_goat_test_ctf_full_reset_store_{nonce}"),
            "childSeconds": 480, "workSeconds": 660, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_FULL_RESET_RENDERED_ISOLATED": "1",
                "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_stage6_current_main:
        return {"mode": "ctf_stage6_current_main_actual", "stageEnd": 6,
            "test": "tests/postgres/ctfStagesRoute.integration.test.js",
            "databases": ("owasp_ai_goat_test_ctf_stages_identity", "owasp_ai_goat_test_ctf_stages_store"),
            "childSeconds": 1500, "workSeconds": 1680, "cleanupSeconds": 120,
            "environment": {"CTF_STAGES_ROUTE_ISOLATED": "1", "RUN_LIVE_CTF_WORKFLOW": "1",
                "CTF_STAGE_END": "6", "CTF_TARGET_STAGE": "6", "CTF_CANDIDATE_SET": "stage6-fixed-v1",
                "CTF_STAGE6_CANDIDATE_SHA256": args.stage6_candidate_sha256,
                "CTF_STAGE6_EARNED_RENDERED": "1", "AI_PROVIDER": "ollama",
                "JUDGE_PROVIDER": "ollama", "OLLAMA_BASE_URL": "http://127.0.0.1:11434",
                "OLLAMA_MODEL": "llama3.1:8b", "JUDGE_MODEL": "llama3.1:8b",
                "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_predefense_recovery:
        return {"mode": "ctf_predefense_recovery_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfAuthorityApplication.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_app_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_PREDEFENSE_RECOVERY_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_stage6_adoption:
        return {"mode": "ctf_stage6_adoption_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfAuthorityApplication.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_app_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_AUTHORITY_APPLICATION_ISOLATED": "1",
                "CTF_STAGE6_ADOPTION_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_teaching_content:
        return {"mode": "ctf_teaching_content_main", "stageEnd": None,
            "test": "tests/postgres/ctfAuthorityApplication.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_app_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_TEACHING_CONTENT_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_authority_application:
        return {"mode": "ctf_authority_application_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfAuthorityApplication.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_app_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_AUTHORITY_APPLICATION_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_production_runtime:
        return {"mode": "ctf_production_runtime_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfProductionRuntime.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_prod_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_PRODUCTION_RUNTIME_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_publication_current:
        return {"mode": "ctf_publication_current_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfAuthenticatedPublicationCurrent.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_publication_current_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 300, "workSeconds": 480, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_PUBLICATION_CURRENT_NATIVE": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_authority_runtime:
        return {"mode": "ctf_authority_runtime_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfAuthorityRuntime.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_runtime_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_AUTHORITY_RUNTIME_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_telemetry:
        return {"mode": "ctf_telemetry_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfTelemetry.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_telemetry_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_TELEMETRY_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_delivery_provision_case:
        return {"mode": "ctf_delivery_provision_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfDeliveryProvision.integration.test.js", "databases": (),
            "provisionCase": args.ctf_delivery_provision_case,
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 1073741824,
            "environment": {"CTF_DELIVERY_PROVISION_ISOLATED": "1", "PG_PROVISION_FRESH_CLUSTER": "yes",
                "CTF_DELIVERY_PROVISION_CASE": args.ctf_delivery_provision_case, "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_delivery_activation:
        return {"mode": "ctf_delivery_activation_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfDeliveryActivation.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_activation_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_DELIVERY_ACTIVATION_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_registration_locator:
        return {"mode": "ctf_registration_locator_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfRegistrationLocator.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_locator_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_REGISTRATION_LOCATOR_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_response_diagnostics:
        return {"mode": "ctf_response_diagnostics_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfResponseDiagnostics.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_diagnostics_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_RESPONSE_DIAGNOSTICS_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_admin_read:
        return {"mode": "ctf_admin_read_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfAdminRead.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_adminread_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_ADMIN_READ_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_blocked_predefense:
        return {"mode": "ctf_blocked_predefense_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfBlockedPredefense.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_blockpre_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_BLOCKED_PREDEFENSE_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_worker_lifecycle:
        return {"mode": "ctf_worker_lifecycle_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfProjectionWorkerLifecycle.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_worklife_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_WORKER_LIFECYCLE_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_predefense:
        return {"mode": "ctf_predefense_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfPredefense.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_predef_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_PREDEFENSE_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_student_deletion:
        return {"mode": "ctf_student_deletion_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfStudentDeletion.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_delete_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_DELETION_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_admin_response:
        return {"mode": "ctf_admin_response_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfAdminResponse.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_opread_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_ADMIN_RESPONSE_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_current_read:
        return {"mode": "ctf_current_read_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfCurrentRead.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_read_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_CURRENT_READ_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_current_response:
        return {"mode": "ctf_current_response_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfCurrentResponse.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_opread_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_CURRENT_RESPONSE_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_current_publication:
        return {"mode": "ctf_current_publication_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfCurrentPublication.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_publication_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_CURRENT_PUBLICATION_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_decision_recovery:
        return {"mode": "ctf_decision_recovery_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfDecisionRecovery.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_decision_recovery_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_DECISION_RECOVERY_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_operation_recovery:
        return {"mode": "ctf_operation_recovery_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfOperationRecovery.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_opread_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_OPERATION_RECOVERY_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_decision_projection:
        return {"mode": "ctf_decision_projection_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfDecisionProjection.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_decision_projection_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_DECISION_PROJECTION_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_decision_schema:
        return {"mode": "ctf_decision_schema_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfAuthoritativeDecision.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_decision_{state}_{kind}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_DECISION_SCHEMA_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_projection_worker:
        return {"mode": "ctf_projection_worker_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfProjectionWorker.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_worker_{state}_{kind}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_PROJECTION_WORKER_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_lifecycle_schema:
        return {"mode": "ctf_lifecycle_schema_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfLifecycleProjection.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_lifecycle_{state}_{kind}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_LIFECYCLE_SCHEMA_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.authority_schema_only:
        return {"mode": "authority_schema_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfAuthorityReadModel.integration.test.js",
            "databases": tuple(f"owasp_ai_goat_test_ctf_authority_{state}_{kind}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_AUTHORITY_SCHEMA_ISOLATED": "1",
                "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.session_fence_only:
        return {"mode": "session_fence_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfAdmittedSessionFence.integration.test.js",
            "databases": (f"owasp_ai_goat_test_ctf_session_identity_{nonce}",
                          f"owasp_ai_goat_test_ctf_session_store_{nonce}"),
            "childSeconds": 180, "workSeconds": 300, "cleanupSeconds": 120,
            "environment": {"CTF_SESSION_FENCE_ISOLATED": "1", "AI_PROVIDER": "mock",
                "JUDGE_PROVIDER": "mock", "AWS_EC2_METADATA_DISABLED": "true"}}
    stage_end = args.stage_end or args.target_stage or 4
    return {"mode": "independent_target" if args.target_stage else "sequential_prefix",
        "stageEnd": stage_end, "test": "tests/postgres/ctfStagesRoute.integration.test.js",
        "databases": ("owasp_ai_goat_test_ctf_stages_identity", "owasp_ai_goat_test_ctf_stages_store"),
        "childSeconds": 700 if stage_end <= 4 else 1900,
        "workSeconds": None, "cleanupSeconds": None,
        "environment": {"CTF_STAGES_ROUTE_ISOLATED": "1", "RUN_LIVE_CTF_WORKFLOW": "1",
            "CTF_STAGE_END": str(stage_end), "CTF_CANDIDATE_SET": args.candidate_set,
            **({"CTF_TARGET_STAGE": str(args.target_stage)} if args.target_stage else {}),
            "AI_PROVIDER": "ollama", "JUDGE_PROVIDER": "ollama",
            "OLLAMA_BASE_URL": "http://127.0.0.1:11434", "OLLAMA_MODEL": "llama3.1:8b",
            "JUDGE_MODEL": "llama3.1:8b", "AWS_EC2_METADATA_DISABLED": "true"}}


def provision_case(selection):
    return selection.get("provisionCase")


def create_provision_secret(root, nonce):
    file = root / ("provision-" + nonce + ".env")
    password = uuid.uuid4().hex + uuid.uuid4().hex
    descriptor = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write("POSTGRES_PASSWORD=" + password + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    info = file.lstat()
    return {"path": file, "dev": info.st_dev, "ino": info.st_ino, "uid": info.st_uid}, password


def remove_provision_secret(secret):
    file = secret["path"]
    info = file.lstat()
    if file.is_symlink() or (info.st_dev, info.st_ino, info.st_uid) != (secret["dev"], secret["ino"], secret["uid"]):
        raise RuntimeError("Owned provisioning secret identity changed")
    file.unlink()
    if file.exists() or file.is_symlink():
        raise RuntimeError("Owned provisioning secret removal failed")


def delivery_role(selection):
    return "dvaia_ctf_delivery" if selection["mode"] in ("ctf_publication_current_controlled", "ctf_delivery_activation_controlled", "ctf_telemetry_controlled", "ctf_authority_runtime_controlled", "ctf_production_runtime_controlled", "ctf_authority_application_controlled", "ctf_stage6_adoption_controlled", "ctf_teaching_content_main", "ctf_predefense_recovery_controlled", "ctf_recovery_rendered_controlled", "ctf_ten_content_controlled", "ctf_config_rendered_controlled", "ctf_preview_rendered_controlled", "ctf_learner_entry_hint_rendered_controlled", "ctf_learner_attempt_gate_rendered_controlled", "ctf_fixed_practice_rendered_controlled", "ctf_full_reset_rendered_controlled") else None


def delivery_database(selection, database):
    return delivery_role(selection) is not None and database in selection["databases"][1::2]


def database_environment(selection, urls):
    if selection["mode"] == "ctf_publication_current_controlled":
        result = {}
        for database, (state, kind) in zip(selection["databases"],
                ((state, kind) for state in ("FRESH", "POPULATED") for kind in ("IDENTITY", "CTF")), strict=True):
            for role in ("runtime", "migration"):
                result[f"PG_CTF_PUBLICATION_CURRENT_{state}_{kind}_{role.upper()}_URL"] = urls[database][role]
        for state, database in zip(("FRESH", "POPULATED"), selection["databases"][1::2], strict=True):
            result[f"PG_CTF_PUBLICATION_CURRENT_{state}_CTF_DELIVERY_URL"] = urls[database]["delivery"]
        return result
    if selection["mode"] == "ctf_full_reset_rendered_controlled":
        identity, ctf = selection["databases"]
        return {"IDENTITY_DATABASE_URL": urls[identity]["runtime"],
            "IDENTITY_MIGRATION_DATABASE_URL": urls[identity]["migration"],
            "CTF_DATABASE_URL": urls[ctf]["runtime"],
            "CTF_MIGRATION_DATABASE_URL": urls[ctf]["migration"],
            "CTF_DELIVERY_DATABASE_URL": urls[ctf]["delivery"]}
    if selection["mode"] == "application_maintenance_lease":
        return {f"PG_APPLICATION_LEASE_{index}_{role.upper()}_URL": urls[database][role]
            for index, database in enumerate(selection["databases"], 1) for role in ("runtime", "migration")}
    if selection["mode"] == "ctf_fixed_practice_rendered_controlled":
        result = {}
        for database, (state, kind) in zip(selection["databases"],
                ((state, kind) for state in ("FRESH", "POPULATED") for kind in ("IDENTITY", "CTF")), strict=True):
            for role in ("runtime", "migration"):
                result[f"PG_CTF_AUTHORITY_APPLICATION_{state}_{kind}_{role.upper()}_URL"] = urls[database][role]
        for state, database in zip(("FRESH", "POPULATED"), selection["databases"][1::2], strict=True):
            result[f"PG_CTF_AUTHORITY_APPLICATION_{state}_CTF_DELIVERY_URL"] = urls[database]["delivery"]
        return result
    if selection["mode"] in ("ctf_operation_recovery_controlled", "ctf_recovery_rendered_controlled", "ctf_ten_content_controlled", "ctf_config_rendered_controlled", "ctf_preview_rendered_controlled", "ctf_learner_entry_hint_rendered_controlled", "ctf_learner_attempt_gate_rendered_controlled", "ctf_fixed_practice_rendered_controlled", "ctf_predefense_recovery_controlled", "ctf_authority_application_controlled", "ctf_stage6_adoption_controlled", "ctf_teaching_content_main", "ctf_production_runtime_controlled", "ctf_response_diagnostics_controlled", "ctf_authority_runtime_controlled", "ctf_admin_read_controlled", "ctf_registration_locator_controlled", "ctf_telemetry_controlled", "ctf_delivery_activation_controlled", "ctf_blocked_publication_controlled", "ctf_current_read_controlled", "ctf_worker_lifecycle_controlled", "ctf_blocked_predefense_controlled", "ctf_predefense_controlled", "ctf_admin_response_controlled", "ctf_student_deletion_controlled", "ctf_current_response_controlled", "authority_schema_controlled", "ctf_lifecycle_schema_controlled", "ctf_projection_worker_controlled", "ctf_decision_schema_controlled", "ctf_decision_projection_controlled", "ctf_decision_recovery_controlled", "ctf_current_publication_controlled", "ctf_authority_bootstrap_controlled"):
        result = {}
        for database, (state, kind) in zip(selection["databases"],
                ((state, kind) for state in ("FRESH", "POPULATED") for kind in ("IDENTITY", "CTF")), strict=True):
            for role in ("runtime", "migration"):
                prefix = {"ctf_operation_recovery_controlled": "PG_CTF_OPERATION_RECOVERY", "ctf_recovery_rendered_controlled": "PG_CTF_AUTHORITY_APPLICATION", "ctf_ten_content_controlled": "PG_CTF_AUTHORITY_APPLICATION", "ctf_config_rendered_controlled": "PG_CTF_AUTHORITY_APPLICATION", "ctf_preview_rendered_controlled": "PG_CTF_AUTHORITY_APPLICATION", "ctf_learner_entry_hint_rendered_controlled": "PG_CTF_AUTHORITY_APPLICATION", "ctf_learner_attempt_gate_rendered_controlled": "PG_CTF_AUTHORITY_APPLICATION", "ctf_predefense_recovery_controlled": "PG_CTF_AUTHORITY_APPLICATION", "ctf_authority_application_controlled": "PG_CTF_AUTHORITY_APPLICATION", "ctf_stage6_adoption_controlled": "PG_CTF_AUTHORITY_APPLICATION", "ctf_teaching_content_main": "PG_CTF_AUTHORITY_APPLICATION", "ctf_production_runtime_controlled": "PG_CTF_PRODUCTION_RUNTIME", "ctf_response_diagnostics_controlled": "PG_CTF_RESPONSE_DIAGNOSTICS", "ctf_authority_runtime_controlled": "PG_CTF_AUTHORITY_RUNTIME", "ctf_admin_read_controlled": "PG_CTF_ADMIN_READ", "ctf_registration_locator_controlled": "PG_CTF_REGISTRATION_LOCATOR", "ctf_telemetry_controlled": "PG_CTF_TELEMETRY", "ctf_delivery_activation_controlled": "PG_CTF_ACTIVATION", "ctf_blocked_publication_controlled": "PG_CTF_BLOCKED_PUBLICATION", "ctf_current_read_controlled": "PG_CTF_CURRENT_READ", "ctf_worker_lifecycle_controlled": "PG_CTF_WORKER_LIFECYCLE", "ctf_blocked_predefense_controlled": "PG_CTF_BLOCKED_PREDEFENSE", "ctf_predefense_controlled": "PG_CTF_PREDEFENSE", "ctf_admin_response_controlled": "PG_CTF_OPERATION_RECOVERY", "ctf_student_deletion_controlled": "PG_CTF_DELETION", "ctf_current_response_controlled": "PG_CTF_OPERATION_RECOVERY", "ctf_authority_bootstrap_controlled": "PG_CTF_BOOTSTRAP", "ctf_current_publication_controlled": "PG_CTF_CURRENT_PUBLICATION", "ctf_decision_recovery_controlled": "PG_CTF_DECISION_RECOVERY", "ctf_decision_projection_controlled": "PG_CTF_DECISION_PROJECTION", "ctf_decision_schema_controlled": "PG_CTF_DECISION", "ctf_projection_worker_controlled": "PG_CTF_WORKER", "ctf_lifecycle_schema_controlled": "PG_CTF_LIFECYCLE", "authority_schema_controlled": "PG_CTF_AUTHORITY"}[selection["mode"]]
                result[f"{prefix}_{state}_{kind}_{role.upper()}_URL"] = urls[database][role]
        if selection["mode"] in ("ctf_delivery_activation_controlled", "ctf_telemetry_controlled", "ctf_authority_runtime_controlled", "ctf_production_runtime_controlled", "ctf_authority_application_controlled", "ctf_stage6_adoption_controlled", "ctf_teaching_content_main", "ctf_predefense_recovery_controlled", "ctf_recovery_rendered_controlled", "ctf_ten_content_controlled", "ctf_config_rendered_controlled", "ctf_preview_rendered_controlled", "ctf_learner_entry_hint_rendered_controlled", "ctf_learner_attempt_gate_rendered_controlled"):
            for state, database in zip(("FRESH", "POPULATED"), selection["databases"][1::2], strict=True):
                result[f"{prefix}_{state}_CTF_DELIVERY_URL"] = urls[database]["delivery"]
        return result
    identity, ctf = selection["databases"]
    return {"IDENTITY_DATABASE_URL": urls[identity]["runtime"],
        "IDENTITY_MIGRATION_DATABASE_URL": urls[identity]["migration"],
        "CTF_DATABASE_URL": urls[ctf]["runtime"],
        "CTF_MIGRATION_DATABASE_URL": urls[ctf]["migration"]}


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def validate_executable(path, expected_sha256, label):
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file() or sha256(candidate) != expected_sha256:
        raise RuntimeError(f"{label} pin mismatch")
    return candidate.resolve()


def write_private_json(path, value):
    path = Path(path)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def open_private_log(path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(descriptor, "w", encoding="utf-8")


def _container_id(value):
    value = str(value or "").strip()
    if value.startswith("sha256:"):
        value = value[7:]
    return value if len(value) == 64 and all(c in "0123456789abcdef" for c in value.lower()) else None


def inspect_owned_container(intent, docker, base_env, *, runner=subprocess.run, target=None):
    target = target or intent.get("containerId") or intent["name"]
    inspected = runner(docker + ["inspect", target], env=base_env,
                       capture_output=True, text=True, timeout=30)
    if inspected.returncode != 0:
        raise RuntimeError(f"Owned container inspection failed: {target}")
    try:
        rows = json.loads(inspected.stdout)
        row = rows[0]
        config = row["Config"]
        labels = config.get("Labels") or {}
        actual_id = _container_id(row.get("Id"))
        if not actual_id or row.get("Name") != f"/{intent['name']}":
            raise ValueError("container identity mismatch")
        if actual_id != _container_id(intent.get("containerId") or actual_id):
            raise ValueError("container id mismatch")
        if config.get("Image") != intent["image"]:
            raise ValueError("container image mismatch")
        if labels.get(CONTAINER_OWNER_LABEL) != intent["owner"] or labels.get(CONTAINER_NONCE_LABEL) != intent["nonce"]:
            raise ValueError("container ownership label mismatch")
    except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Unowned or malformed container: {target}") from error
    return actual_id


def stream_child_output(child, output_path, *, deadline, max_bytes=MAX_LOG_BYTES,
                        monotonic=time.monotonic, selector_factory=selectors.DefaultSelector):
    if child.stdout is None:
        raise RuntimeError("Owned child stdout pipe was not created")
    selector = selector_factory()
    selector.register(child.stdout, selectors.EVENT_READ)
    total = 0
    with open_private_log(output_path) as output:
        while True:
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise TimeoutError("Owned CTF child exceeded its deadline")
            events = selector.select(min(0.25, remaining))
            for key, _ in events:
                chunk = key.fileobj.read1(min(65536, max_bytes + 1 - total))
                if chunk:
                    total += len(chunk)
                    if total > max_bytes:
                        raise RuntimeError("CTF stages private TAP exceeds the size limit")
                    output.buffer.write(chunk)
                    output.flush()
                else:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
            if child.poll() is not None and not selector.get_map():
                break
        output.flush()
        os.fsync(output.fileno())
    selector.close()
    return child.wait(timeout=1), total


def record_child_result(state, result_path, code, size):
    state["result"] = {"path": str(result_path), "bytes": size,
        "sha256": sha256(result_path), "returncode": code}
    if code:
        raise RuntimeError(f"CTF stages route integration failed ({code})")


def ignored(_directory, names):
    return [name for name in names if name in DENIED_NAMES or name.startswith(".env")
            or name.endswith(DENIED_SUFFIXES)]


def inventory(root):
    result = {}
    for name in SOURCE_FILES:
        path = Path(root) / name
        result[name] = {"kind": "file", "sha256": sha256(path),
            "bytes": path.stat().st_size}
    for directory in SOURCE_DIRECTORIES:
        base = Path(root) / directory
        for path in sorted(base.rglob("*")):
            relative = path.relative_to(root).as_posix()
            parts = path.relative_to(base).parts
            if any(part in DENIED_NAMES or part.startswith(".env")
                   or part.endswith(DENIED_SUFFIXES) for part in parts):
                continue
            if path.is_symlink():
                result[relative] = {"kind": "symlink", "target": os.readlink(path)}
            elif path.is_file():
                result[relative] = {"kind": "file", "sha256": sha256(path),
                    "bytes": path.stat().st_size}
    return result


def content_source_inventory(root):
    """Inventory the full mounted application closure for the ten-content child."""
    result = inventory(root)
    for directory in ("agent-host", "scripts", "sidecars"):
        base = Path(root) / directory
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            relative = path.relative_to(root).as_posix()
            parts = path.relative_to(base).parts
            if any(part in DENIED_NAMES or part.startswith(".env")
                   or part.endswith(DENIED_SUFFIXES) for part in parts):
                continue
            if path.is_symlink():
                result[relative] = {"kind": "symlink", "target": os.readlink(path)}
            elif path.is_file():
                result[relative] = {"kind": "file", "sha256": sha256(path),
                    "bytes": path.stat().st_size}
    return result


def assert_current_publication_source(root):
    for relative, expected in CURRENT_PUBLICATION_SOURCE_PINS.items():
        source = Path(root) / relative
        if source.is_symlink() or not source.is_file() or sha256(source) != expected:
            raise RuntimeError(f"Current publication source pin mismatch: {relative}")


def manifest_digest(entries):
    encoded = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def dependency_inventory(root):
    result = {}
    root = Path(root)
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            result[relative] = {"kind": "symlink", "target": os.readlink(path)}
        elif path.is_file():
            result[relative] = {"kind": "file", "sha256": sha256(path),
                "bytes": path.stat().st_size}
    return result


def verified_dependency_snapshot(root, expected_sha256):
    entries = dependency_inventory(root)
    actual = manifest_digest(entries)
    if actual != expected_sha256:
        raise RuntimeError("Dependency manifest pin mismatch")
    return {"count": len(entries), "sha256": actual}


def copy_frozen_source(source, workspace, expected_sha256):
    before = inventory(source)
    actual = manifest_digest(before)
    if actual != expected_sha256:
        raise RuntimeError("Source manifest pin mismatch")
    for directory in SOURCE_DIRECTORIES:
        shutil.copytree(source / directory, workspace / directory, ignore=ignored, symlinks=True)
    for name in SOURCE_FILES:
        shutil.copy2(source / name, workspace / name)
    after = inventory(workspace)
    if before != after:
        raise RuntimeError("Frozen CTF source copy differs from the reviewed source")
    (workspace / "node_modules").symlink_to(source / "node_modules", target_is_directory=True)
    for path in sorted(workspace.rglob("*"), reverse=True):
        if path.is_symlink():
            continue
        os.chmod(path, 0o500 if path.is_dir() else 0o400)
    os.chmod(workspace, 0o500)
    return {"count": len(after), "sha256": actual}


def client_inventory(root):
    result = {}
    for item in sorted(Path(root).rglob("*")):
        parts = item.relative_to(root).parts
        if any(p in DENIED_NAMES or p.startswith(".env") or p.endswith(DENIED_SUFFIXES) for p in parts):
            continue
        if item.is_symlink():
            raise RuntimeError("Client source symlink is not permitted")
        if item.is_file():
            result[item.relative_to(root).as_posix()] = {"sha256": sha256(item), "bytes": item.stat().st_size}
    return result


def copy_rendered_client(source, workspace, source_digest, dependency_digest):
    client = source / "client"
    expected = client_inventory(client)
    if manifest_digest(expected) != source_digest:
        raise RuntimeError("Client source manifest pin mismatch")
    dependencies = verified_dependency_snapshot(client / "node_modules", dependency_digest)
    # Root-owned workspace is read-only for other selectors; only this closed
    # rendered mode needs a temporary build entry in its disposable client root.
    workspace.chmod(0o700)
    destination = workspace / "client"
    shutil.copytree(client, destination, ignore=ignored)
    if client_inventory(destination) != expected:
        raise RuntimeError("Rendered client copy mismatch")
    destination.chmod(0o700)
    (destination / "node_modules").symlink_to(client / "node_modules", target_is_directory=True)
    workspace.chmod(0o500)
    return {"sourceSha256": source_digest, "sourceCount": len(expected), "dependencies": dependencies}


def validate_prebuilt_build(source, expected_sha256):
    build = Path(source) / "client" / "build"
    if not build.is_dir() or build.is_symlink():
        raise RuntimeError("Prebuilt client/build directory is unavailable")
    entries = client_inventory(build)
    actual = manifest_digest(entries)
    if actual != expected_sha256:
        raise RuntimeError("Prebuilt client/build manifest pin mismatch")
    return {"path": str(build), "sha256": actual, "count": len(entries)}


def validate_repo_build_provenance(report, source, report_path, *, npm_path=Path("/opt/homebrew/lib/node_modules/npm/bin/npm-cli.js")):
    source = Path(source)
    report_path = Path(report_path)
    expected_build = source / "client/build"
    expected_node = source / "tasks/runtime/node/node_modules/node/bin/node"
    qualified_parent = source / "tasks/qualification"
    run_directory = report_path.parent
    if report.get("repositoryOnly") is not True or report.get("workspace") != str(source) \
            or report.get("outputRoot") != str(expected_build) \
            or report.get("command") != [str(expected_node), str(npm_path),
                                           "--prefix", "client", "run", "build"] \
            or qualified_parent.is_symlink() or qualified_parent.resolve() != qualified_parent \
            or run_directory.parent != qualified_parent or not run_directory.name.startswith("frontend-build-") \
            or run_directory.is_symlink() or run_directory.resolve() != run_directory \
            or report_path.is_symlink() or report_path.resolve() != report_path:
        raise RuntimeError("CTF ten-content requires repository-only qualified build provenance")
    for directory in (qualified_parent, run_directory):
        if not directory.is_dir() or directory.stat().st_uid != os.getuid() or directory.stat().st_mode & 0o077:
            raise RuntimeError("CTF ten-content build evidence directory is not private")
    pins = report.get("runtimePins") or {}
    for key, path in (("node", expected_node), ("npm", npm_path)):
        if path.is_symlink() or path.resolve() != path or not path.is_file() \
                or pins.get(key) != {"path": str(path), "sha256": sha256(path)}:
            raise RuntimeError("CTF ten-content build runtime pin mismatch")


def validate_stage6_repository_build_location(report, report_path, source, module):
    source = Path(source)
    report_path = Path(report_path)
    parent = report_path.parent
    qualification = source / "tasks/qualification"
    output_root = Path(report.get("outputRoot", ""))
    if (report.get("inputMode") != "private-repository-v1"
            or report.get("repositoryOnly") is not True
            or report.get("workspace") != str(source)
            or report.get("command") != module.private_command(module.REPO_NODE)
            or report.get("runtimePins") != {
                "node": {"path": str(module.REPO_NODE), "sha256": sha256(module.REPO_NODE)},
                "npm": {"path": str(module.REVIEWED_NPM), "sha256": sha256(module.REVIEWED_NPM)}}
            or qualification.is_symlink() or qualification.resolve() != qualification
            or qualification.stat().st_uid != os.getuid()
            or qualification.stat().st_mode & 0o077
            or parent.parent != qualification
            or not parent.name.startswith("frontend-build-")
            or parent.is_symlink() or parent.resolve() != parent
            or parent.stat().st_uid != os.getuid()
            or parent.stat().st_mode & 0o077
            or output_root != parent / "output/application"
            or output_root.is_symlink() or output_root.resolve() != output_root):
        raise RuntimeError("Stage 6 repository-private build location mismatch")
    return output_root


def validate_frontend_build_report(source, report_path, report_sha256, input_sha256, build_output_sha256, recorder_sha256, *, private_external=False, repository_required=False, require_installed_match=True):
    report_path = Path(report_path)
    if report_path.is_symlink() or not report_path.is_file() or sha256(report_path) != report_sha256:
        raise RuntimeError("Frontend build report pin mismatch")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report.get("qualified") is not True or report.get("beforeAfterInputsEqual") is not True:
        raise RuntimeError("Frontend build report is not qualified")
    if report.get("buildInputInventorySha256") != input_sha256 or report.get("clientBuildInventorySha256") != build_output_sha256:
        raise RuntimeError("Frontend build report input/output provenance mismatch")
    artifacts = report.get("artifacts") or {}
    required = ("inputs-before.json", "inputs-after.json", "output.json")
    for name in required:
        artifact = report_path.parent / name
        if not artifact.is_file() or artifact.is_symlink() or sha256(artifact) != artifacts.get(name):
            raise RuntimeError(f"Frontend build artifact mismatch: {name}")
    recorder = Path(source) / "tests/release-inputs/record-current-frontend-build.py"
    if recorder.is_symlink() or not recorder.is_file() or sha256(recorder) != recorder_sha256:
        raise RuntimeError("Frontend build recorder pin mismatch")
    spec = importlib.util.spec_from_file_location("owasp_ai_goat_frontend_build_receipt", recorder)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if private_external:
        output_root = Path(report.get("outputRoot", ""))
        if repository_required:
            output_root = validate_stage6_repository_build_location(report, report_path, source, module)
        else:
            if report.get("inputMode") != "private-external-v1":
                raise RuntimeError("Stage 6 requires the exact private-external build mode")
            if not output_root.is_absolute() or output_root.resolve() != output_root or output_root.is_relative_to(source) or output_root.is_symlink():
                raise RuntimeError("Stage 6 external build root is not canonical and isolated")
        current_inputs = module.private_inputs(Path(source))
    else:
        validate_repo_build_provenance(report, source, report_path)
        current_inputs = module.inputs(Path(source))
    before = json.loads((report_path.parent / "inputs-before.json").read_text(encoding="utf-8"))
    after = json.loads((report_path.parent / "inputs-after.json").read_text(encoding="utf-8"))
    if current_inputs != before or current_inputs != after or module.fingerprint(current_inputs) != input_sha256:
        raise RuntimeError("Frontend build inputs do not match the qualified report")
    output = json.loads((report_path.parent / "output.json").read_text(encoding="utf-8"))
    build_directory = output_root if private_external else Path(source) / "client/build"
    if module.fingerprint(module.inventory(build_directory)) != build_output_sha256 or output != module.inventory(build_directory):
        raise RuntimeError("Prebuilt client/build output does not match the qualified report")
    if private_external:
        for directory, key in (("node_modules", "rootDependencyInventorySha256"),
                ("client/src", "clientSourceInventorySha256"),
                ("client/public", "clientPublicInventorySha256"),
                ("client/node_modules", "clientDependencyInventorySha256")):
            if module.fingerprint(module.inventory(Path(source) / directory)) != report.get(key):
                raise RuntimeError("Stage 6 private build input inventory mismatch")
        if require_installed_match and module.fingerprint(module.inventory(Path(source) / "client/build")) != build_output_sha256:
            raise RuntimeError("Installed client/build differs from admitted private output")
    return report


def dotenv_inventory(root):
    """Record private dotenv files without reading their contents into logs."""
    result = {}
    root = Path(root)
    for path in sorted(root.rglob(".env*")):
        if path.is_file() and not path.is_symlink():
            result[path.relative_to(root).as_posix()] = {
                "sha256": sha256(path), "bytes": path.stat().st_size}
    return result


def docker_daemon_identity(docker, env, *, runner=subprocess.run):
    probe = runner(docker + ["info", "--format", "{{json .}}"], env=env,
                   capture_output=True, text=True, timeout=30, check=True)
    try:
        value = json.loads(probe.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("Docker daemon identity is not valid JSON") from error
    daemon_id = str(value.get("ID") or value.get("DockerRootDir") or "").strip()
    if not daemon_id:
        raise RuntimeError("Docker daemon identity is unavailable")
    return {"id": daemon_id, "serverVersion": str(value.get("ServerVersion") or "")}


def validate_current_host_postgres_image(docker, image_id, env, *, runner=subprocess.run):
    result = runner(docker + ["image", "inspect", image_id, "--format", "{{json .}}"],
                    env=env, capture_output=True, text=True, timeout=30, check=True)
    try:
        row = json.loads(result.stdout)
        variables = row["Config"]["Env"]
        postgres_major = [entry for entry in variables if entry == "PG_MAJOR=18"]
        postgres_version = [entry for entry in variables if entry.startswith("PG_VERSION=18.")]
        if row["Id"] != image_id or row["Os"] != "linux" or row["Architecture"] != "arm64" \
                or len(postgres_major) != 1 or len(postgres_version) != 1:
            raise ValueError("Installed image identity or PostgreSQL platform/version mismatch")
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("Pinned current-host PostgreSQL image is unavailable or incompatible") from error
    return {"id": image_id, "os": "linux", "architecture": "arm64",
            "postgresMajor": "18", "postgresVersion": postgres_version[0][len("PG_VERSION="):]}


def validate_ten_content_receipt(path, *, state=None):
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("CTF ten-content receipt is missing")
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("CTF ten-content receipt is unreadable") from error
    if receipt.get("version") != 1 or receipt.get("profile") != "ctf-ten-content":
        raise RuntimeError("CTF ten-content receipt profile mismatch")
    for key in ("modelCalls", "judgeCalls", "genuineCredit"):
        if receipt.get(key) != 0:
            raise RuntimeError(f"CTF ten-content receipt has nonzero {key}")
    if receipt.get("controlledProjectionCount") != 55:
        raise RuntimeError("CTF ten-content controlled projection count mismatch")
    if receipt.get("prerequisiteProjectionCount") != 45 or receipt.get("displayProjectionCount") != 10:
        raise RuntimeError("CTF ten-content prerequisite/display projection mismatch")
    if receipt.get("controlledProjectionCountPerStore") != 55 or receipt.get("controlledProjectionCountTotal") != 110:
        raise RuntimeError("CTF ten-content per-store projection count mismatch")
    if receipt.get("projectionStoreCount") != 2:
        raise RuntimeError("CTF ten-content store count mismatch")
    cases = receipt.get("cases")
    if not isinstance(cases, list) or len(cases) != 10:
        raise RuntimeError("CTF ten-content case count mismatch")
    for index, case in enumerate(cases, 1):
        if case.get("stage") != index or not all(case.get(key) is True for key in ("label", "hints", "adminSolution")):
            raise RuntimeError(f"CTF ten-content stage {index} projection mismatch")
    for key in ("hintGate", "adminMutation", "progressParity", "restored", "siblingPreserved", "sessionDenied", "ownerReset", "immutablePreserved", "browserRetired", "populatedReadback"):
        if receipt.get(key) is not True:
            raise RuntimeError(f"CTF ten-content receipt missing {key}")
    if not isinstance(receipt.get("browserActions"), int) or isinstance(receipt.get("browserActions"), bool) or receipt["browserActions"] < 0 or receipt["browserActions"] > 1600:
        raise RuntimeError("CTF ten-content browser action bound exceeded")
    if not isinstance(receipt.get("apiRequests"), int) or isinstance(receipt.get("apiRequests"), bool) or receipt["apiRequests"] < 0 or receipt["apiRequests"] > 1200:
        raise RuntimeError("CTF ten-content API request bound exceeded")
    if receipt.get("unexpectedApiPaths") != []:
        raise RuntimeError("CTF ten-content unexpected API paths observed")
    if receipt.get("populatedReadback") is not True:
        raise RuntimeError("CTF ten-content populated readback is missing")
    return receipt


def validate_blocklist_q05_receipt(path):
    """Admit only the separate rendered admin blocklist facet, never content credit."""
    path = Path(path)
    if path.is_symlink() or path.resolve() != path or not path.is_file():
        raise RuntimeError("CTF blocklist Q05 receipt is missing or noncanonical")
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("CTF blocklist Q05 receipt is unreadable") from error
    expected = {"version", "profile", "modelCalls", "judgeCalls", "postCounts",
        "browserPostCounts", "cancelPostCounts", "facts", "dialogTimeAba",
        "pendingAba", "unexpectedApiPaths", "siblingPreserved", "stage"}
    if not isinstance(receipt, dict) or set(receipt) != expected or receipt["version"] != 1 \
            or type(receipt["version"]) is not int or receipt["profile"] != "ctf-blocklist-q05" \
            or receipt["stage"] != "complete":
        raise RuntimeError("CTF blocklist Q05 receipt profile/schema mismatch")
    if any(type(receipt[name]) is not int or receipt[name] != 0 for name in ("modelCalls", "judgeCalls")):
        raise RuntimeError("CTF blocklist Q05 model/Judge calls are not zero")
    def counts(value, technique, payload):
        return type(value) is dict and set(value) == {"technique", "payload"} \
            and type(value["technique"]) is int and type(value["payload"]) is int \
            and value["technique"] == technique and value["payload"] == payload
    def zero_phases(value):
        return type(value) is dict and set(value) == {"browser", "server"} \
            and counts(value["browser"], 0, 0) and counts(value["server"], 0, 0)
    if not counts(receipt["postCounts"], 1, 1):
        raise RuntimeError("CTF blocklist Q05 POST counts mismatch")
    if not counts(receipt["browserPostCounts"], 1, 1) or not zero_phases(receipt["cancelPostCounts"]):
        raise RuntimeError("CTF blocklist Q05 browser/cancel POST counts mismatch")
    facts = ("cancelNoPost", "cancelStoresUnchanged", "techniqueClearedBothStores",
             "payloadClearedBothStores", "pendingAbaNoStaleUiOrRecovery")
    if type(receipt["facts"]) is not dict or set(receipt["facts"]) != set(facts) \
            or any(receipt["facts"][name] is not True for name in facts):
        raise RuntimeError("CTF blocklist Q05 evidence facet failed")
    dialog = receipt["dialogTimeAba"]
    if type(dialog) is not dict or set(dialog) != {"noPost", "eventsObserved", "postCounts"} \
            or dialog["noPost"] is not True or type(dialog["eventsObserved"]) is not int \
            or dialog["eventsObserved"] != 2 or not zero_phases(dialog["postCounts"]):
        raise RuntimeError("CTF blocklist Q05 dialog-time ABA failed")
    pending = receipt["pendingAba"]
    if type(pending) is not dict or set(pending) != {"responseReleased", "componentRetired", "eventsObserved"} \
            or pending["responseReleased"] is not True or type(pending["componentRetired"]) is not bool \
            or type(pending["eventsObserved"]) is not int or pending["eventsObserved"] != 2:
        raise RuntimeError("CTF blocklist Q05 pending ABA evidence mismatch")
    if receipt["unexpectedApiPaths"] != [] or receipt["siblingPreserved"] is not True:
        raise RuntimeError("CTF blocklist Q05 API/sibling boundary failed")
    return receipt


def validate_participant_reset_q05_receipt(path):
    """Admit the distinct rendered participant-reset proof without content credit."""
    path = Path(path)
    if path.name != "ctf-participant-reset-q05-result.json" or path.is_symlink() \
            or path.resolve() != path or not path.is_file():
        raise RuntimeError("CTF participant reset Q05 receipt is missing or noncanonical")
    parent = path.parent
    parent_info, info = parent.lstat(), path.lstat()
    if parent.is_symlink() or parent.resolve() != parent \
            or not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.getuid() \
            or stat.S_IMODE(parent_info.st_mode) != 0o700 \
            or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() \
            or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 16384:
        raise RuntimeError("CTF participant reset Q05 receipt is not private")
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError("CTF participant reset Q05 receipt is unreadable") from error
    expected = {"version", "profile", "modelCalls", "judgeCalls", "targetId",
        "browserPosts", "serverPosts", "facts", "operationId", "commitAckLost",
        "firstOperationReadLost", "firstOperationReadStatus", "firstOperationReadFinished",
        "operationReadDrops", "browserReadFailureObserved", "parkedBeforeCheck",
        "originalPostStatus", "outbox", "sameIdGets", "unexpectedApiPaths",
        "generationBefore", "generationAfter", "stage"}
    if type(receipt) is not dict or set(receipt) != expected \
            or type(receipt["version"]) is not int or receipt["version"] != 2 \
            or receipt["profile"] != "ctf-participant-reset-q05" \
            or receipt["stage"] != "complete":
        raise RuntimeError("CTF participant reset Q05 receipt profile/schema mismatch")
    for key, value in (("modelCalls", 0), ("judgeCalls", 0), ("targetId", 3010),
                       ("browserPosts", 1), ("serverPosts", 1),
                       ("operationReadDrops", 1), ("originalPostStatus", 202)):
        if type(receipt[key]) is not int or receipt[key] != value:
            raise RuntimeError(f"CTF participant reset Q05 {key} mismatch")
    facts = ("cancelNoPost", "cancelStateUnchanged", "modalAbaNoPost",
             "modalAbaStateUnchanged", "currentProgressClearedBothStores",
             "registrationRetained", "sharedPayloadPreserved", "siblingPreserved",
             "sameIdRecoveryNoSecondPost")
    if type(receipt["facts"]) is not dict or set(receipt["facts"]) != set(facts) \
            or any(receipt["facts"][key] is not True for key in facts):
        raise RuntimeError("CTF participant reset Q05 effect/authority proof failed")
    operation_id = receipt["operationId"]
    if type(operation_id) is not str or not re.fullmatch(
            r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", operation_id):
        raise RuntimeError("CTF participant reset Q05 operation reference invalid")
    if receipt["commitAckLost"] is not True or receipt["firstOperationReadLost"] is not True \
            or receipt["firstOperationReadFinished"] is not True \
            or receipt["browserReadFailureObserved"] is not True \
            or receipt["parkedBeforeCheck"] is not True \
            or type(receipt["firstOperationReadStatus"]) is not int \
            or receipt["firstOperationReadStatus"] not in (200, 202) \
            or type(receipt["sameIdGets"]) is not int or receipt["sameIdGets"] < 2 \
            or receipt["unexpectedApiPaths"] != []:
        raise RuntimeError("CTF participant reset Q05 recovery proof failed")
    if type(receipt["outbox"]) is not dict or set(receipt["outbox"]) != {"operationId", "kind", "ownerId"} \
            or receipt["outbox"] != {"operationId": operation_id,
                                      "kind": "owner_reset", "ownerId": "3010"}:
        raise RuntimeError("CTF participant reset Q05 outbox join failed")
    before, after = receipt["generationBefore"], receipt["generationAfter"]
    if type(before) is not str or type(after) is not str \
            or not re.fullmatch(r"0|[1-9][0-9]*", before) \
            or not re.fullmatch(r"[1-9][0-9]*", after) or int(after) != int(before) + 1:
        raise RuntimeError("CTF participant reset Q05 owner generation mismatch")
    return receipt


def validate_participant_remove_q05_receipt(path):
    """Admit only the separate rendered remove/re-registration facet, without recovery or credit claims."""
    path = Path(path)
    if path.name != "ctf-participant-remove-q05-result.json" or not path.is_absolute() \
            or path.is_symlink() or path.resolve() != path or not path.is_file():
        raise RuntimeError("CTF participant remove Q05 receipt is missing or noncanonical")
    parent = path.parent
    parent_info, path_info = parent.lstat(), path.lstat()
    if parent.is_symlink() or parent.resolve() != parent \
            or not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.getuid() \
            or stat.S_IMODE(parent_info.st_mode) != 0o700 \
            or not stat.S_ISREG(path_info.st_mode) or path_info.st_uid != os.getuid() \
            or stat.S_IMODE(path_info.st_mode) != 0o600 or path_info.st_nlink != 1 \
            or not 0 < path_info.st_size <= 16384:
        raise RuntimeError("CTF participant remove Q05 receipt is not private")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        if opened.st_dev != path_info.st_dev or opened.st_ino != path_info.st_ino \
                or opened.st_nlink != 1 or opened.st_size != path_info.st_size:
            raise RuntimeError("CTF participant remove Q05 receipt changed while opening")
        chunks, size = [], 0
        while True:
            chunk = os.read(descriptor, min(4096, 16385 - size))
            if not chunk:
                break
            size += len(chunk)
            if size > 16384:
                raise RuntimeError("CTF participant remove Q05 receipt exceeded bound")
            chunks.append(chunk)
        if size != opened.st_size or os.fstat(descriptor).st_size != opened.st_size:
            raise RuntimeError("CTF participant remove Q05 receipt changed while reading")
    finally:
        os.close(descriptor)
    def unique_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate receipt key")
            value[key] = item
        return value
    try:
        receipt = json.loads(b"".join(chunks).decode("utf-8"), object_pairs_hook=unique_pairs)
    except (UnicodeError, ValueError) as error:
        raise RuntimeError("CTF participant remove Q05 receipt is unreadable") from error
    expected = {"version", "profile", "modelCalls", "judgeCalls", "targetId",
        "oldParticipantId", "newParticipantId", "mountedActorId", "mountedSessionId",
        "comparisonActorId", "learnerSessionId", "preRemovalRows", "browserPosts",
        "removeOutboxCount", "originalPostStatus", "facts", "dialogTimeAba",
        "removeOutbox", "registrationOutbox", "generationBefore", "generationRemoved",
        "generationReregistered", "unexpectedApiPaths", "stage"}
    if type(receipt) is not dict or set(receipt) != expected \
            or type(receipt["version"]) is not int or receipt["version"] != 1 \
            or receipt["profile"] != "ctf-participant-remove-q05" \
            or receipt["stage"] != "complete":
        raise RuntimeError("CTF participant remove Q05 receipt profile/schema mismatch")
    for key, value in (("modelCalls", 0), ("judgeCalls", 0), ("targetId", 3010),
                       ("oldParticipantId", 3010), ("browserPosts", 1),
                       ("removeOutboxCount", 1)):
        if type(receipt[key]) is not int or receipt[key] != value:
            raise RuntimeError(f"CTF participant remove Q05 {key} mismatch")
    new_participant = receipt["newParticipantId"]
    if type(new_participant) is not int or not 0 < new_participant <= 2147483647 \
            or new_participant == receipt["oldParticipantId"]:
        raise RuntimeError("CTF participant remove Q05 fresh participant invalid")
    if type(receipt["originalPostStatus"]) is not int or receipt["originalPostStatus"] not in (200, 202):
        raise RuntimeError("CTF participant remove Q05 original POST status invalid")
    positive_id = lambda value: type(value) is str and re.fullmatch(r"[1-9][0-9]*", value) \
        and int(value) <= 9223372036854775807
    for key in ("mountedActorId", "mountedSessionId", "comparisonActorId", "learnerSessionId"):
        if not positive_id(receipt[key]):
            raise RuntimeError("CTF participant remove Q05 authority identity invalid")
    if receipt["mountedActorId"] == receipt["comparisonActorId"]:
        raise RuntimeError("CTF participant remove Q05 comparison actor not distinct")
    row_keys = {"participant", "progress", "attempts", "technique", "leaderboard",
                "events", "sessions", "binding", "currentIdentityProgress"}
    rows = receipt["preRemovalRows"]
    if type(rows) is not dict or set(rows) != row_keys \
            or any(type(rows[key]) is not int or rows[key] < 0 for key in row_keys) \
            or rows["participant"] != 1 or rows["binding"] != 1 \
            or any(rows[key] < 1 for key in ("progress", "leaderboard", "events", "sessions", "currentIdentityProgress")):
        raise RuntimeError("CTF participant remove Q05 pre-removal rows invalid")
    facts = {"cancelNoPost", "cancelStateUnchanged", "modalAbaNoPost",
             "modalAbaStateUnchanged", "removedCurrentCtfState", "oldRegistrationInactive",
             "historicalIdentityRetained", "sharedPayloadPreserved", "siblingPreserved",
             "reregisteredFresh", "noMutationReplay"}
    if type(receipt["facts"]) is not dict or set(receipt["facts"]) != facts \
            or any(receipt["facts"][key] is not True for key in facts):
        raise RuntimeError("CTF participant remove Q05 effect/authority proof failed")
    if type(receipt["dialogTimeAba"]) is not dict \
            or set(receipt["dialogTimeAba"]) != {"noPost", "eventsObserved"} \
            or receipt["dialogTimeAba"]["noPost"] is not True \
            or type(receipt["dialogTimeAba"]["eventsObserved"]) is not int \
            or receipt["dialogTimeAba"]["eventsObserved"] != 2:
        raise RuntimeError("CTF participant remove Q05 dialog-time ABA failed")
    uuid_pattern = r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"
    remove = receipt["removeOutbox"]
    if type(remove) is not dict or set(remove) != {"operationId", "kind", "ownerId", "actorId", "sessionId"} \
            or type(remove["operationId"]) is not str \
            or not re.fullmatch(uuid_pattern, remove["operationId"]) \
            or remove["kind"] != "owner_remove" or remove["ownerId"] != "3010" \
            or remove["actorId"] != receipt["mountedActorId"] \
            or remove["sessionId"] != receipt["mountedSessionId"]:
        raise RuntimeError("CTF participant remove Q05 outbox binding failed")
    register = receipt["registrationOutbox"]
    if type(register) is not dict or set(register) != {"operationId", "kind", "ownerId", "actorId", "sessionId", "disposition", "oldParticipantId"} \
            or type(register["operationId"]) is not str \
            or not re.fullmatch(uuid_pattern, register["operationId"]) \
            or register["operationId"] == remove["operationId"] \
            or register["kind"] != "register" or register["ownerId"] != "3010" \
            or register["actorId"] != "3010" \
            or register["sessionId"] != receipt["learnerSessionId"] \
            or register["disposition"] != "reactivate" or register["oldParticipantId"] != "3010":
        raise RuntimeError("CTF participant remove Q05 re-registration binding failed")
    generations = []
    for key in ("generationBefore", "generationRemoved", "generationReregistered"):
        value = receipt[key]
        if type(value) is not str or not re.fullmatch(r"0|[1-9][0-9]*", value) \
                or int(value) > 9223372036854775807:
            raise RuntimeError("CTF participant remove Q05 generation invalid")
        generations.append(int(value))
    if generations[1] != generations[0] + 1 or generations[2] != generations[1] + 1:
        raise RuntimeError("CTF participant remove Q05 generation transition invalid")
    if receipt["unexpectedApiPaths"] != []:
        raise RuntimeError("CTF participant remove Q05 unexpected API path")
    return receipt


def validate_participant_ban_q05_receipt(path):
    """Admit the separate physical Ban/Unban facet, without operation-recovery claims."""
    path = Path(path)
    if path.name != "ctf-participant-ban-q05-result.json" or not path.is_absolute() \
            or path.is_symlink() or path.resolve() != path or not path.is_file():
        raise RuntimeError("CTF participant Ban Q05 receipt is missing or noncanonical")
    parent = path.parent
    parent_info, path_info = parent.lstat(), path.lstat()
    if parent.is_symlink() or parent.resolve() != parent \
            or not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.getuid() \
            or stat.S_IMODE(parent_info.st_mode) != 0o700 \
            or not stat.S_ISREG(path_info.st_mode) or path_info.st_uid != os.getuid() \
            or stat.S_IMODE(path_info.st_mode) != 0o600 or path_info.st_nlink != 1 \
            or not 0 < path_info.st_size <= 16384:
        raise RuntimeError("CTF participant Ban Q05 receipt is not private")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        if opened.st_dev != path_info.st_dev or opened.st_ino != path_info.st_ino \
                or opened.st_nlink != 1 or opened.st_size != path_info.st_size:
            raise RuntimeError("CTF participant Ban Q05 receipt changed while opening")
        chunks, size = [], 0
        while True:
            chunk = os.read(descriptor, min(4096, 16385 - size))
            if not chunk:
                break
            size += len(chunk)
            if size > 16384:
                raise RuntimeError("CTF participant Ban Q05 receipt exceeded bound")
            chunks.append(chunk)
        if size != opened.st_size or os.fstat(descriptor).st_size != opened.st_size:
            raise RuntimeError("CTF participant Ban Q05 receipt changed while reading")
    finally:
        os.close(descriptor)
    def unique_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate receipt key")
            value[key] = item
        return value
    try:
        receipt = json.loads(b"".join(chunks).decode("utf-8"), object_pairs_hook=unique_pairs)
    except (UnicodeError, ValueError) as error:
        raise RuntimeError("CTF participant Ban Q05 receipt is unreadable") from error
    expected = {"version", "profile", "modelCalls", "judgeCalls", "targetId",
        "browserPostCounts", "serverOperationCounts", "cancelPostCounts",
        "abaPostCounts", "abaEvents", "observedPaths", "flags", "facts",
        "unexpectedApiPaths", "stage"}
    if type(receipt) is not dict or set(receipt) != expected \
            or type(receipt["version"]) is not int or receipt["version"] != 1 \
            or receipt["profile"] != "ctf-participant-ban-unban-q05" \
            or receipt["stage"] != "complete":
        raise RuntimeError("CTF participant Ban Q05 receipt profile/schema mismatch")
    for key, value in (("modelCalls", 0), ("judgeCalls", 0), ("targetId", 3011)):
        if type(receipt[key]) is not int or receipt[key] != value:
            raise RuntimeError(f"CTF participant Ban Q05 {key} mismatch")
    def counts(value, ban, unban):
        return type(value) is dict and set(value) == {"ban", "unban"} \
            and type(value["ban"]) is int and type(value["unban"]) is int \
            and value["ban"] == ban and value["unban"] == unban
    if not counts(receipt["browserPostCounts"], 1, 1) \
            or not counts(receipt["serverOperationCounts"], 1, 1) \
            or not counts(receipt["cancelPostCounts"], 0, 0) \
            or not counts(receipt["abaPostCounts"], 0, 0) \
            or not counts(receipt["abaEvents"], 2, 2):
        raise RuntimeError("CTF participant Ban Q05 request/authority counts mismatch")
    if type(receipt["observedPaths"]) is not dict \
            or receipt["observedPaths"] != {
                "ban": "/api/ctf/admin/participants/3011/ban",
                "unban": "/api/ctf/admin/participants/3011/unban"}:
        raise RuntimeError("CTF participant Ban Q05 observed browser route mismatch")
    if type(receipt["flags"]) is not dict or set(receipt["flags"]) != {"before", "afterBan", "afterUnban"} \
            or receipt["flags"]["before"] is not False \
            or receipt["flags"]["afterBan"] is not True \
            or receipt["flags"]["afterUnban"] is not False:
        raise RuntimeError("CTF participant Ban Q05 durable flags mismatch")
    facts = {"cancelNoPost", "cancelStateUnchanged", "abaNoPost", "abaStateUnchanged",
        "banDurableBothStores", "unbanDurableBothStores", "reloadBan", "reloadUnban",
        "targetEvidencePreserved", "platformPreserved", "siblingPreserved",
        "operationsApplied", "noSecondPost"}
    if type(receipt["facts"]) is not dict or set(receipt["facts"]) != facts \
            or any(receipt["facts"][key] is not True for key in facts) \
            or type(receipt["unexpectedApiPaths"]) is not list \
            or receipt["unexpectedApiPaths"]:
        raise RuntimeError("CTF participant Ban Q05 effect or API boundary failed")
    return receipt


def validate_teaching_save_q05_receipt(path):
    """Admit only the separate rendered teaching save and explicit content-equivalent restore."""
    path = Path(path)
    if path.name != "ctf-teaching-save-q05-result.json" or not path.is_absolute() \
            or path.is_symlink() or path.resolve() != path or not path.is_file():
        raise RuntimeError("CTF teaching save Q05 receipt is missing or noncanonical")
    parent = path.parent
    parent_info, path_info = parent.lstat(), path.lstat()
    if parent.is_symlink() or parent.resolve() != parent \
            or not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.getuid() \
            or stat.S_IMODE(parent_info.st_mode) != 0o700 \
            or not stat.S_ISREG(path_info.st_mode) or path_info.st_uid != os.getuid() \
            or stat.S_IMODE(path_info.st_mode) != 0o600 or path_info.st_nlink != 1 \
            or not 0 < path_info.st_size <= 16384:
        raise RuntimeError("CTF teaching save Q05 receipt is not private")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        if opened.st_dev != path_info.st_dev or opened.st_ino != path_info.st_ino \
                or opened.st_nlink != 1 or opened.st_size != path_info.st_size:
            raise RuntimeError("CTF teaching save Q05 receipt changed while opening")
        chunks, size = [], 0
        while True:
            chunk = os.read(descriptor, min(4096, 16385 - size))
            if not chunk:
                break
            size += len(chunk)
            if size > 16384:
                raise RuntimeError("CTF teaching save Q05 receipt exceeded bound")
            chunks.append(chunk)
        if size != opened.st_size or os.fstat(descriptor).st_size != opened.st_size:
            raise RuntimeError("CTF teaching save Q05 receipt changed while reading")
    finally:
        os.close(descriptor)
    def unique_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate receipt key")
            value[key] = item
        return value
    try:
        receipt = json.loads(b"".join(chunks).decode("utf-8"), object_pairs_hook=unique_pairs)
    except (UnicodeError, ValueError) as error:
        raise RuntimeError("CTF teaching save Q05 receipt is unreadable") from error
    expected = {"version", "profile", "modelCalls", "judgeCalls", "targetStageId",
        "siblingStageId", "mountedActorId", "mountedSessionId", "observedPath",
        "browserPuts", "fixtureDeniedPuts", "fixtureRestorePuts", "dialogTimeAba",
        "confirmed", "restore", "facts", "excluded", "unexpectedApiPaths", "stage"}
    if type(receipt) is not dict or set(receipt) != expected \
            or type(receipt["version"]) is not int or receipt["version"] != 1 \
            or receipt["profile"] != "ctf-teaching-save-q05" or receipt["stage"] != "complete":
        raise RuntimeError("CTF teaching save Q05 receipt profile/schema mismatch")
    for key, value in (("modelCalls", 0), ("judgeCalls", 0), ("targetStageId", 2),
                       ("siblingStageId", 3), ("browserPuts", 1),
                       ("fixtureDeniedPuts", 1), ("fixtureRestorePuts", 1)):
        if type(receipt[key]) is not int or receipt[key] != value:
            raise RuntimeError(f"CTF teaching save Q05 {key} mismatch")
    positive_decimal = lambda value: type(value) is str and re.fullmatch(r"[1-9][0-9]*", value) \
        and int(value) <= 9223372036854775807
    for key in ("mountedActorId", "mountedSessionId"):
        if not positive_decimal(receipt[key]):
            raise RuntimeError("CTF teaching save Q05 mounted authority identity invalid")
    if receipt["observedPath"] != "/api/ctf/admin/stages/2/content":
        raise RuntimeError("CTF teaching save Q05 observed browser route mismatch")
    dialog = receipt["dialogTimeAba"]
    if type(dialog) is not dict or set(dialog) != {"eventsObserved", "noPut"} \
            or type(dialog["eventsObserved"]) is not int or dialog["eventsObserved"] != 2 \
            or dialog["noPut"] is not True:
        raise RuntimeError("CTF teaching save Q05 dialog authority proof failed")
    uuid_pattern = r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"
    operation_keys = {"originalStatus", "resolvedStatus", "sameIdGets", "operationId",
        "sequence", "browserAckOperationId", "ackMessage"}
    def operation(value, *, restore=False):
        keys = operation_keys | ({"scope"} if restore else set())
        if type(value) is not dict or set(value) != keys \
                or (restore and value["scope"] != "content-equivalence-only") \
                or type(value["originalStatus"]) is not int \
                or value["originalStatus"] not in (200, 202) \
                or type(value["resolvedStatus"]) is not int or value["resolvedStatus"] != 200 \
                or type(value["sameIdGets"]) is not int \
                or not 0 <= value["sameIdGets"] <= 1024 \
                or type(value["operationId"]) is not str \
                or not re.fullmatch(uuid_pattern, value["operationId"]) \
                or not positive_decimal(value["sequence"]):
            raise RuntimeError("CTF teaching save Q05 operation proof invalid")
        if value["originalStatus"] == 200:
            if value["sameIdGets"] != 0 or value["browserAckOperationId"] is not None \
                    or value["ackMessage"] != "Stage updated":
                raise RuntimeError("CTF teaching save Q05 direct ACK mismatch")
        elif value["sameIdGets"] < 1 \
                or value["browserAckOperationId"] != value["operationId"] \
                or value["ackMessage"] is not None:
            raise RuntimeError("CTF teaching save Q05 same-ID recovery mismatch")
        return value
    confirmed = operation(receipt["confirmed"])
    restored = operation(receipt["restore"], restore=True)
    if confirmed["operationId"] == restored["operationId"] \
            or int(restored["sequence"]) <= int(confirmed["sequence"]):
        raise RuntimeError("CTF teaching save Q05 restore operation is not independent")
    facts = {"cancelNoPut", "cancelNoEffect", "dialogAbaNoPut", "dialogAbaNoEffect",
        "confirmedOnePhysicalPut", "physicalRequestFiveFieldsAndBearer", "fiveFieldsExact",
        "canonicalProjectionApplied", "actorSessionBound", "learnerMutationDenied",
        "guardianAndScoringUnchanged", "siblingPreserved", "adminHintsAndSolutionVisible",
        "learnerObjectiveVisible", "learnerRawHintsAndSolutionAbsent", "restoreContentEquivalent",
        "restorationGuardianAndScoringUnchanged"}
    if type(receipt["facts"]) is not dict or set(receipt["facts"]) != facts \
            or any(receipt["facts"][key] is not True for key in facts) \
            or receipt["excluded"] != ["byte-identical-undo", "provenance-rollback"] \
            or type(receipt["unexpectedApiPaths"]) is not list \
            or receipt["unexpectedApiPaths"]:
        raise RuntimeError("CTF teaching save Q05 effect, scope, or API boundary failed")
    return receipt


def validate_advanced_stage_save_q05_receipt(path):
    """Admit only the separate rendered Advanced Save facet, never content credit."""
    path = Path(path)
    if path.name != "ctf-advanced-stage-save-q05-result.json" or not path.is_absolute() \
            or path.is_symlink() or path.resolve() != path or not path.is_file():
        raise RuntimeError("CTF advanced stage save Q05 receipt is missing or noncanonical")
    parent = path.parent
    parent_info, path_info = parent.lstat(), path.lstat()
    if parent.is_symlink() or parent.resolve() != parent \
            or not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.getuid() \
            or stat.S_IMODE(parent_info.st_mode) != 0o700 \
            or not stat.S_ISREG(path_info.st_mode) or path_info.st_uid != os.getuid() \
            or stat.S_IMODE(path_info.st_mode) != 0o600 or path_info.st_nlink != 1 \
            or not 0 < path_info.st_size <= 16384:
        raise RuntimeError("CTF advanced stage save Q05 receipt is not private")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        if opened.st_dev != path_info.st_dev or opened.st_ino != path_info.st_ino \
                or opened.st_nlink != 1 or opened.st_size != path_info.st_size:
            raise RuntimeError("CTF advanced stage save Q05 receipt changed while opening")
        chunks, size = [], 0
        while True:
            chunk = os.read(descriptor, min(4096, 16385 - size))
            if not chunk:
                break
            size += len(chunk)
            if size > 16384:
                raise RuntimeError("CTF advanced stage save Q05 receipt exceeded bound")
            chunks.append(chunk)
        if size != opened.st_size or os.fstat(descriptor).st_size != opened.st_size:
            raise RuntimeError("CTF advanced stage save Q05 receipt changed while reading")
    finally:
        os.close(descriptor)
    def unique_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate receipt key")
            value[key] = item
        return value
    try:
        receipt = json.loads(b"".join(chunks).decode("utf-8"), object_pairs_hook=unique_pairs)
    except (UnicodeError, ValueError) as error:
        raise RuntimeError("CTF advanced stage save Q05 receipt is unreadable") from error
    exact = lambda value, keys: type(value) is dict and set(value) == set(keys)
    positive_decimal = lambda value: type(value) is str and re.fullmatch(r"[1-9][0-9]*", value) \
        and int(value) <= 9223372036854775807
    fields = {"version", "profile", "targetStageId", "siblingStageId", "mountedActorId",
        "mountedSessionId", "observedPath", "browserPuts", "fixtureRestorePuts", "dialogTimeAba",
        "confirmed", "restore", "facts", "excluded", "unexpectedApiPaths", "stage", "modelCalls", "judgeCalls"}
    if not exact(receipt, fields) or type(receipt["version"]) is not int or receipt["version"] != 1 \
            or receipt["profile"] != "ctf-advanced-stage-save-q05" or receipt["stage"] != "complete" \
            or type(receipt["targetStageId"]) is not int or receipt["targetStageId"] != 2 \
            or type(receipt["siblingStageId"]) is not int or receipt["siblingStageId"] != 3 \
            or receipt["observedPath"] != "/api/ctf/admin/stages/2" \
            or not positive_decimal(receipt["mountedActorId"]) \
            or not positive_decimal(receipt["mountedSessionId"]):
        raise RuntimeError("CTF advanced stage save Q05 receipt profile/schema mismatch")
    for key, value in (("modelCalls", 0), ("judgeCalls", 0), ("browserPuts", 1),
                       ("fixtureRestorePuts", 1)):
        if type(receipt[key]) is not int or receipt[key] != value:
            raise RuntimeError(f"CTF advanced stage save Q05 {key} mismatch")
    if not exact(receipt["dialogTimeAba"], {"eventsObserved", "noPut"}) \
            or type(receipt["dialogTimeAba"]["eventsObserved"]) is not int \
            or receipt["dialogTimeAba"]["eventsObserved"] != 2 \
            or receipt["dialogTimeAba"]["noPut"] is not True:
        raise RuntimeError("CTF advanced stage save Q05 dialog authority proof failed")
    uuid_pattern = r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"
    operation_keys = {"originalStatus", "resolvedStatus", "sameIdGets", "operationId",
        "sequence", "browserAckOperationId", "ackMessage"}
    def operation(value, *, restore=False):
        keys = operation_keys | ({"scope"} if restore else set())
        if not exact(value, keys) or (restore and value["scope"] != "content-equivalence-only") \
                or type(value["originalStatus"]) is not int or value["originalStatus"] not in (200, 202) \
                or type(value["resolvedStatus"]) is not int or value["resolvedStatus"] != 200 \
                or type(value["sameIdGets"]) is not int or not 0 <= value["sameIdGets"] <= 1024 \
                or type(value["operationId"]) is not str or not re.fullmatch(uuid_pattern, value["operationId"]) \
                or not positive_decimal(value["sequence"]):
            raise RuntimeError("CTF advanced stage save Q05 operation proof invalid")
        if value["originalStatus"] == 200:
            if value["sameIdGets"] != 0 or value["browserAckOperationId"] is not None \
                    or value["ackMessage"] != "Stage updated":
                raise RuntimeError("CTF advanced stage save Q05 direct ACK mismatch")
        elif value["sameIdGets"] < 1 or value["browserAckOperationId"] != value["operationId"] \
                or value["ackMessage"] is not None:
            raise RuntimeError("CTF advanced stage save Q05 same-ID recovery mismatch")
        return value
    confirmed = operation(receipt["confirmed"])
    restored = operation(receipt["restore"], restore=True)
    if confirmed["operationId"] == restored["operationId"] \
            or int(restored["sequence"]) <= int(confirmed["sequence"]):
        raise RuntimeError("CTF advanced stage save Q05 restore operation is not independent")
    facts = {"cancelNoPut", "cancelNoEffect", "dialogAbaNoPut", "dialogAbaNoEffect",
        "confirmedOnePhysicalPut", "nineFieldsAndCapturedBearer", "canonicalProjectionApplied",
        "policyAndScoreChanged", "siblingPreserved", "restoreContentEquivalent", "noModelOrJudge"}
    if not exact(receipt["facts"], facts) or any(receipt["facts"][key] is not True for key in facts) \
            or receipt["excluded"] != ["byte-identical-undo", "provenance-rollback", "model-qualification"] \
            or type(receipt["unexpectedApiPaths"]) is not list or receipt["unexpectedApiPaths"]:
        raise RuntimeError("CTF advanced stage save Q05 effect, exclusion, or API boundary failed")
    return receipt


def validate_stage_active_q05_receipt(path):
    """Admit only the separate rendered Stage Active facet, never content credit."""
    path = Path(path)
    if path.name != "ctf-stage-active-q05-result.json" or not path.is_absolute() \
            or path.is_symlink() or path.resolve() != path or not path.is_file():
        raise RuntimeError("CTF stage active Q05 receipt is missing or noncanonical")
    parent = path.parent
    parent_info, path_info = parent.lstat(), path.lstat()
    if parent.is_symlink() or parent.resolve() != parent \
            or not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.getuid() \
            or stat.S_IMODE(parent_info.st_mode) != 0o700 \
            or not stat.S_ISREG(path_info.st_mode) or path_info.st_uid != os.getuid() \
            or stat.S_IMODE(path_info.st_mode) != 0o600 or path_info.st_nlink != 1 \
            or not 0 < path_info.st_size <= 16384:
        raise RuntimeError("CTF stage active Q05 receipt is not private")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        if opened.st_dev != path_info.st_dev or opened.st_ino != path_info.st_ino \
                or opened.st_nlink != 1 or opened.st_size != path_info.st_size:
            raise RuntimeError("CTF stage active Q05 receipt changed while opening")
        chunks, size = [], 0
        while True:
            chunk = os.read(descriptor, min(4096, 16385 - size))
            if not chunk:
                break
            size += len(chunk)
            if size > 16384:
                raise RuntimeError("CTF stage active Q05 receipt exceeded bound")
            chunks.append(chunk)
        if size != opened.st_size or os.fstat(descriptor).st_size != opened.st_size:
            raise RuntimeError("CTF stage active Q05 receipt changed while reading")
    finally:
        os.close(descriptor)
    def unique_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate receipt key")
            value[key] = item
        return value
    try:
        receipt = json.loads(b"".join(chunks).decode("utf-8"), object_pairs_hook=unique_pairs)
    except (UnicodeError, ValueError) as error:
        raise RuntimeError("CTF stage active Q05 receipt is unreadable") from error
    exact = lambda value, keys: type(value) is dict and set(value) == set(keys)
    positive_decimal = lambda value: type(value) is str and re.fullmatch(r"[1-9][0-9]*", value) \
        and int(value) <= 9223372036854775807
    fields = {"version", "profile", "targetStageId", "siblingStageId", "mountedActorId",
        "mountedSessionId", "originalActive", "confirmedActive", "observedPath", "browserPuts",
        "fixtureRestorePuts", "dialogTimeAba", "confirmed", "restore", "facts", "excluded",
        "unexpectedApiPaths", "stage", "modelCalls", "judgeCalls"}
    if not exact(receipt, fields) or type(receipt["version"]) is not int or receipt["version"] != 1 \
            or receipt["profile"] != "ctf-stage-active-q05" or receipt["stage"] != "complete" \
            or type(receipt["targetStageId"]) is not int or receipt["targetStageId"] != 2 \
            or type(receipt["siblingStageId"]) is not int or receipt["siblingStageId"] != 3 \
            or type(receipt["originalActive"]) is not int or receipt["originalActive"] != 1 \
            or type(receipt["confirmedActive"]) is not int or receipt["confirmedActive"] != 0 \
            or receipt["observedPath"] != "/api/ctf/admin/stages/2" \
            or not positive_decimal(receipt["mountedActorId"]) \
            or not positive_decimal(receipt["mountedSessionId"]):
        raise RuntimeError("CTF stage active Q05 receipt profile/schema mismatch")
    for key, value in (("modelCalls", 0), ("judgeCalls", 0), ("browserPuts", 1),
                       ("fixtureRestorePuts", 1)):
        if type(receipt[key]) is not int or receipt[key] != value:
            raise RuntimeError(f"CTF stage active Q05 {key} mismatch")
    if not exact(receipt["dialogTimeAba"], {"eventsObserved", "noPut"}) \
            or type(receipt["dialogTimeAba"]["eventsObserved"]) is not int \
            or receipt["dialogTimeAba"]["eventsObserved"] != 2 \
            or receipt["dialogTimeAba"]["noPut"] is not True:
        raise RuntimeError("CTF stage active Q05 dialog authority proof failed")
    uuid_pattern = r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"
    operation_keys = {"originalStatus", "resolvedStatus", "sameIdGets", "operationId",
        "sequence", "browserAckOperationId", "ackMessage"}
    def operation(value, *, restore=False):
        keys = operation_keys | ({"scope"} if restore else set())
        if not exact(value, keys) or (restore and value["scope"] != "content-equivalence-only") \
                or type(value["originalStatus"]) is not int or value["originalStatus"] not in (200, 202) \
                or type(value["resolvedStatus"]) is not int or value["resolvedStatus"] != 200 \
                or type(value["sameIdGets"]) is not int or not 0 <= value["sameIdGets"] <= 32 \
                or type(value["operationId"]) is not str or not re.fullmatch(uuid_pattern, value["operationId"]) \
                or not positive_decimal(value["sequence"]):
            raise RuntimeError("CTF stage active Q05 operation proof invalid")
        if value["originalStatus"] == 200:
            if value["sameIdGets"] != 0 or value["browserAckOperationId"] is not None \
                    or value["ackMessage"] != "Stage updated":
                raise RuntimeError("CTF stage active Q05 direct ACK mismatch")
        elif value["sameIdGets"] < 1 or value["browserAckOperationId"] != value["operationId"] \
                or value["ackMessage"] is not None:
            raise RuntimeError("CTF stage active Q05 same-ID recovery mismatch")
        return value
    confirmed = operation(receipt["confirmed"])
    restored = operation(receipt["restore"], restore=True)
    if confirmed["operationId"] == restored["operationId"] \
            or int(restored["sequence"]) <= int(confirmed["sequence"]):
        raise RuntimeError("CTF stage active Q05 restore operation is not independent")
    facts = {"cancelNoPut", "cancelNoEffect", "dialogAbaNoPut", "dialogAbaNoEffect",
        "confirmedOnePhysicalPut", "capturedBearerAndBody", "canonicalProjectionApplied",
        "targetAvailabilityChanged", "nonAvailabilityFieldsUnchanged", "siblingPreserved",
        "restoreContentEquivalent", "noModelOrJudge"}
    if not exact(receipt["facts"], facts) or any(receipt["facts"][key] is not True for key in facts) \
            or receipt["excluded"] != ["byte-identical-undo", "provenance-rollback", "model-qualification"] \
            or type(receipt["unexpectedApiPaths"]) is not list or receipt["unexpectedApiPaths"]:
        raise RuntimeError("CTF stage active Q05 effect, exclusion, or API boundary failed")
    return receipt


def validate_stage_delete_q05_receipt(path):
    """Admit only the separate rendered Stage Delete facet, never content credit."""
    path = Path(path)
    if path.name != "ctf-stage-delete-q05-result.json" or not path.is_absolute() \
            or path.is_symlink() or path.resolve() != path or not path.is_file():
        raise RuntimeError("CTF stage delete Q05 receipt is missing or noncanonical")
    parent = path.parent
    parent_info, path_info = parent.lstat(), path.lstat()
    if parent.is_symlink() or parent.resolve() != parent \
            or not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.getuid() \
            or stat.S_IMODE(parent_info.st_mode) != 0o700 \
            or not stat.S_ISREG(path_info.st_mode) or path_info.st_uid != os.getuid() \
            or stat.S_IMODE(path_info.st_mode) != 0o600 or path_info.st_nlink != 1 \
            or not 0 < path_info.st_size <= 16384:
        raise RuntimeError("CTF stage delete Q05 receipt is not private")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        if opened.st_dev != path_info.st_dev or opened.st_ino != path_info.st_ino \
                or opened.st_nlink != 1 or opened.st_size != path_info.st_size:
            raise RuntimeError("CTF stage delete Q05 receipt changed while opening")
        chunks, size = [], 0
        while True:
            chunk = os.read(descriptor, min(4096, 16385 - size))
            if not chunk:
                break
            size += len(chunk)
            if size > 16384:
                raise RuntimeError("CTF stage delete Q05 receipt exceeded bound")
            chunks.append(chunk)
        if size != opened.st_size or os.fstat(descriptor).st_size != opened.st_size:
            raise RuntimeError("CTF stage delete Q05 receipt changed while reading")
    finally:
        os.close(descriptor)
    def unique_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate receipt key")
            value[key] = item
        return value
    try:
        receipt = json.loads(b"".join(chunks).decode("utf-8"), object_pairs_hook=unique_pairs)
    except (UnicodeError, ValueError) as error:
        raise RuntimeError("CTF stage delete Q05 receipt is unreadable") from error
    exact = lambda value, keys: type(value) is dict and set(value) == set(keys)
    positive_decimal = lambda value: type(value) is str and re.fullmatch(r"[1-9][0-9]*", value) \
        and int(value) <= 9223372036854775807
    safe_positive = lambda value: type(value) is int and 0 < value <= 9007199254740991
    fields = {"version", "profile", "stageNumber", "stageOrder", "targetStageId",
        "mountedActorId", "mountedSessionId", "learnerActorId", "learnerSessionId",
        "observedPath", "browserDeletes", "setup", "confirmed", "dialogTimeAba",
        "preProgressRows", "preEventRows", "facts", "excluded", "unexpectedApiPaths",
        "stage", "modelCalls", "judgeCalls"}
    if not exact(receipt, fields) or type(receipt["version"]) is not int or receipt["version"] != 1 \
            or receipt["profile"] != "ctf-stage-delete-q05" or receipt["stage"] != "complete" \
            or type(receipt["stageNumber"]) is not int or receipt["stageNumber"] != 11 \
            or type(receipt["stageOrder"]) is not int or receipt["stageOrder"] != 0 \
            or type(receipt["targetStageId"]) is not int or not 10 < receipt["targetStageId"] <= 2147483647 \
            or receipt["observedPath"] != f"/api/ctf/admin/stages/{receipt['targetStageId']}" \
            or receipt["learnerActorId"] != "3011" \
            or any(not positive_decimal(receipt[key]) for key in ("mountedActorId", "mountedSessionId", "learnerActorId", "learnerSessionId")):
        raise RuntimeError("CTF stage delete Q05 receipt profile/schema mismatch")
    for key, value in (("modelCalls", 0), ("judgeCalls", 0), ("browserDeletes", 1)):
        if type(receipt[key]) is not int or receipt[key] != value:
            raise RuntimeError(f"CTF stage delete Q05 {key} mismatch")
    if not exact(receipt["dialogTimeAba"], {"eventsObserved", "noDelete"}) \
            or type(receipt["dialogTimeAba"]["eventsObserved"]) is not int \
            or receipt["dialogTimeAba"]["eventsObserved"] != 2 \
            or receipt["dialogTimeAba"]["noDelete"] is not True:
        raise RuntimeError("CTF stage delete Q05 dialog authority proof failed")
    if not safe_positive(receipt["preProgressRows"]) or not safe_positive(receipt["preEventRows"]):
        raise RuntimeError("CTF stage delete Q05 nonvacuous learner state is missing")
    uuid_pattern = r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"
    operation_keys = {"originalStatus", "resolvedStatus", "sameIdGets", "operationId", "sequence", "browserAckOperationId", "ackMessage"}
    def operation(value, message):
        if not exact(value, operation_keys) \
                or type(value["originalStatus"]) is not int or value["originalStatus"] not in (200, 202) \
                or type(value["resolvedStatus"]) is not int or value["resolvedStatus"] != 200 \
                or type(value["sameIdGets"]) is not int or not 0 <= value["sameIdGets"] <= 32 \
                or type(value["operationId"]) is not str or not re.fullmatch(uuid_pattern, value["operationId"]) \
                or not positive_decimal(value["sequence"]):
            raise RuntimeError("CTF stage delete Q05 operation proof invalid")
        if value["originalStatus"] == 200:
            if value["sameIdGets"] != 0 or value["browserAckOperationId"] is not None or value["ackMessage"] != message:
                raise RuntimeError("CTF stage delete Q05 direct ACK mismatch")
        elif value["sameIdGets"] < 1 or value["browserAckOperationId"] != value["operationId"] or value["ackMessage"] is not None:
            raise RuntimeError("CTF stage delete Q05 same-ID recovery mismatch")
        return value
    if not exact(receipt["setup"], {"create", "start"}):
        raise RuntimeError("CTF stage delete Q05 setup schema mismatch")
    created = operation(receipt["setup"]["create"], "Stage created")
    started = operation(receipt["setup"]["start"], "Stage started successfully")
    deleted = operation(receipt["confirmed"], "Stage deleted")
    if len({created["operationId"], started["operationId"], deleted["operationId"]}) != 3 \
            or not int(created["sequence"]) < int(started["sequence"]) < int(deleted["sequence"]):
        raise RuntimeError("CTF stage delete Q05 operation history is not independent")
    facts = {"cancelNoDelete", "cancelNoEffect", "dialogAbaNoDelete", "dialogAbaNoEffect", "confirmedOnePhysicalDelete", "capturedBearerAndEmptyBody", "canonicalCreateAndStart", "progressAndEventPopulated", "canonicalDeleteProjection", "progressAndEventCascaded", "identityBindingTombstoned", "canonicalTenAndSiblingPreserved", "historyPreserved", "noModelOrJudge"}
    if not exact(receipt["facts"], facts) or any(receipt["facts"][key] is not True for key in facts) \
            or receipt["excluded"] != ["attempts-nonvacuity", "judgment-deletion", "model-qualification", "byte-identical-database-undo"] \
            or type(receipt["unexpectedApiPaths"]) is not list or receipt["unexpectedApiPaths"]:
        raise RuntimeError("CTF stage delete Q05 effect, exclusion, or API boundary failed")
    return receipt


def validate_config_q05_receipt(path):
    """Admit only the separate 15-key rendered Config facet, never content credit."""
    path = Path(path)
    if path.name != "ctf-config-q05-result.json" or not path.is_absolute() or path.is_symlink() \
            or path.resolve() != path or not path.is_file():
        raise RuntimeError("CTF config Q05 receipt is missing or noncanonical")
    parent = path.parent
    parent_info, path_info = parent.lstat(), path.lstat()
    if parent.is_symlink() or parent.resolve() != parent or not stat.S_ISDIR(parent_info.st_mode) \
            or parent_info.st_uid != os.getuid() or stat.S_IMODE(parent_info.st_mode) != 0o700 \
            or not stat.S_ISREG(path_info.st_mode) or path_info.st_uid != os.getuid() \
            or stat.S_IMODE(path_info.st_mode) != 0o600 or path_info.st_nlink != 1 \
            or not 0 < path_info.st_size <= 65536:
        raise RuntimeError("CTF config Q05 receipt is not private")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_nlink, opened.st_size) != (path_info.st_dev, path_info.st_ino, 1, path_info.st_size):
            raise RuntimeError("CTF config Q05 receipt changed while opening")
        data = os.read(descriptor, 65537)
        if len(data) != opened.st_size or len(data) > 65536 or os.fstat(descriptor).st_size != opened.st_size:
            raise RuntimeError("CTF config Q05 receipt changed while reading")
    finally:
        os.close(descriptor)
    def unique_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate receipt key")
            value[key] = item
        return value
    try:
        receipt = json.loads(data.decode("utf-8"), object_pairs_hook=unique_pairs)
    except (UnicodeError, ValueError) as error:
        raise RuntimeError("CTF config Q05 receipt is unreadable") from error
    keys = ["ctf_enabled", "ctf_visible_to_students", "student_leaderboard_visible", "public_leaderboard_visible", "ctf_registration_open", "ctf_max_participants", "ctf_time_limit", "leaderboard_update_interval", "ctf_nav_visible", "ctf_show_technique_feedback", "ctf_show_attempt_counter", "ctf_hint_gating_attempts", "ctf_hint_cost_1", "ctf_hint_cost_2", "ctf_hint_cost_3"]
    exact = lambda value, expected: type(value) is dict and set(value) == set(expected)
    positive_decimal = lambda value: type(value) is str and re.fullmatch(r"[1-9][0-9]*", value) and int(value) <= 9223372036854775807
    top = {"version", "profile", "mountedActorId", "mountedSessionId", "keys", "cases", "facts", "excluded", "unexpectedApiPaths", "browserActions", "apiRequests", "stage", "modelCalls", "judgeCalls"}
    if not exact(receipt, top) or type(receipt["version"]) is not int or receipt["version"] != 1 \
            or receipt["profile"] != "ctf-config-q05" or receipt["stage"] != "complete" \
            or receipt["keys"] != keys or not positive_decimal(receipt["mountedActorId"]) \
            or not positive_decimal(receipt["mountedSessionId"]):
        raise RuntimeError("CTF config Q05 receipt profile/schema mismatch")
    for key, value in (("modelCalls", 0), ("judgeCalls", 0)):
        if type(receipt[key]) is not int or receipt[key] != value:
            raise RuntimeError(f"CTF config Q05 {key} mismatch")
    for key in ("browserActions", "apiRequests"):
        if type(receipt[key]) is not int or not 1 <= receipt[key] <= 1200:
            raise RuntimeError(f"CTF config Q05 {key} bound exceeded")
    uuid_pattern = r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"
    operation_keys = {"originalStatus", "resolvedStatus", "sameIdGets", "operationId", "sequence", "browserAckOperationId", "ackMessage"}
    def operation(value, *, restore=False):
        expected = operation_keys | ({"scope", "contentEquivalent"} if restore else set())
        if not exact(value, expected) or (restore and (value["scope"] != "content-equivalence-only" or value["contentEquivalent"] is not True)) \
                or type(value["originalStatus"]) is not int or value["originalStatus"] not in (200, 202) \
                or type(value["resolvedStatus"]) is not int or value["resolvedStatus"] != 200 \
                or type(value["sameIdGets"]) is not int or not 0 <= value["sameIdGets"] <= 32 \
                or type(value["operationId"]) is not str or not re.fullmatch(uuid_pattern, value["operationId"]) \
                or not positive_decimal(value["sequence"]):
            raise RuntimeError("CTF config Q05 operation proof invalid")
        if value["originalStatus"] == 200:
            if value["sameIdGets"] != 0 or value["browserAckOperationId"] is not None or value["ackMessage"] != "Configuration updated successfully":
                raise RuntimeError("CTF config Q05 direct ACK mismatch")
        elif value["sameIdGets"] < 1 or value["browserAckOperationId"] != value["operationId"] or value["ackMessage"] is not None:
            raise RuntimeError("CTF config Q05 same-ID recovery mismatch")
        return value
    case_keys = {"key", "previous", "proposed", "cancel", "dialogTimeAba", "confirmed", "durable", "restore", "siblingPreserved"}
    durable = {"canonicalProjectionApplied", "actorSessionBound", "dbValueMatches", "adminGetMatches", "publicGetMatches"}
    operations = []
    if type(receipt["cases"]) is not list or len(receipt["cases"]) != len(keys):
        raise RuntimeError("CTF config Q05 case count mismatch")
    for expected_key, case in zip(keys, receipt["cases"], strict=True):
        if not exact(case, case_keys) or case["key"] != expected_key or type(case["previous"]) is not str \
                or type(case["proposed"]) is not str or case["previous"] == case["proposed"] \
                or not exact(case["cancel"], {"noPost", "unchanged"}) \
                or case["cancel"]["noPost"] is not True or case["cancel"]["unchanged"] is not True \
                or not exact(case["dialogTimeAba"], {"eventsObserved", "noPost", "unchanged"}) \
                or type(case["dialogTimeAba"]["eventsObserved"]) is not int or case["dialogTimeAba"]["eventsObserved"] != 2 \
                or case["dialogTimeAba"]["noPost"] is not True or case["dialogTimeAba"]["unchanged"] is not True \
                or not exact(case["durable"], durable) or any(case["durable"][key] is not True for key in durable) \
                or case["siblingPreserved"] is not True:
            raise RuntimeError("CTF config Q05 case boundary failed")
        operations.extend((operation(case["confirmed"]), operation(case["restore"], restore=True)))
    if len({row["operationId"] for row in operations}) != 30 or any(int(a["sequence"]) >= int(b["sequence"]) for a, b in zip(operations, operations[1:])):
        raise RuntimeError("CTF config Q05 operation history is not independent")
    facts = {"cancelNoPost", "dialogAbaNoPost", "onePhysicalPostPerKey", "canonicalProjectionReadback", "distinctRestoreOperations", "siblingStageProgressHistoryPreserved", "noPreview", "noMutationRetry", "noModelJudgeOrCredit"}
    if not exact(receipt["facts"], facts) or any(receipt["facts"][key] is not True for key in facts) \
            or receipt["excluded"] != ["byte-identical-undo", "provenance-rollback", "model-qualification", "original-55-content"] \
            or type(receipt["unexpectedApiPaths"]) is not list or receipt["unexpectedApiPaths"]:
        raise RuntimeError("CTF config Q05 effect, exclusion, or API boundary failed")
    return receipt


def validate_preview_q05_receipt(path):
    """Admit only the Stage 1 preview UI facet, never provider qualification or credit."""
    path = Path(path)
    if path.name != "ctf-preview-q05-result.json" or not path.is_absolute() or path.is_symlink() \
            or path.resolve() != path or not path.is_file():
        raise RuntimeError("CTF preview Q05 receipt is missing or noncanonical")
    parent = path.parent
    parent_info, path_info = parent.lstat(), path.lstat()
    if parent.is_symlink() or parent.resolve() != parent or not stat.S_ISDIR(parent_info.st_mode) \
            or parent_info.st_uid != os.getuid() or stat.S_IMODE(parent_info.st_mode) != 0o700 \
            or not stat.S_ISREG(path_info.st_mode) or path_info.st_uid != os.getuid() \
            or stat.S_IMODE(path_info.st_mode) != 0o600 or path_info.st_nlink != 1 \
            or not 0 < path_info.st_size <= 65536:
        raise RuntimeError("CTF preview Q05 receipt is not private")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_nlink, opened.st_size) != (path_info.st_dev, path_info.st_ino, 1, path_info.st_size):
            raise RuntimeError("CTF preview Q05 receipt changed while opening")
        data = os.read(descriptor, 65537)
        if len(data) != opened.st_size or len(data) > 65536 or os.fstat(descriptor).st_size != opened.st_size:
            raise RuntimeError("CTF preview Q05 receipt changed while reading")
    finally:
        os.close(descriptor)
    def unique_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate receipt key")
            value[key] = item
        return value
    try:
        receipt = json.loads(data.decode("utf-8"), object_pairs_hook=unique_pairs)
    except (UnicodeError, ValueError) as error:
        raise RuntimeError("CTF preview Q05 receipt is unreadable") from error
    exact = lambda value, expected: type(value) is dict and set(value) == set(expected)
    positive_decimal = lambda value: type(value) is str and re.fullmatch(r"[1-9][0-9]*", value) and int(value) <= 9223372036854775807
    top = {"version", "profile", "targetStageId", "siblingStageId", "mountedActorId", "mountedSessionId", "cases", "providerDiagnostics", "storeWitness", "facts", "excluded", "unexpectedApiPaths", "browserActions", "apiRequests", "stage", "judgeCalls", "genuineCredit"}
    if not exact(receipt, top) or type(receipt["version"]) is not int or receipt["version"] != 1 \
            or receipt["profile"] != "ctf-preview-q05" or receipt["stage"] != "complete" \
            or type(receipt["targetStageId"]) is not int or receipt["targetStageId"] != 1 \
            or type(receipt["siblingStageId"]) is not int or receipt["siblingStageId"] != 2 \
            or not positive_decimal(receipt["mountedActorId"]) or not positive_decimal(receipt["mountedSessionId"]):
        raise RuntimeError("CTF preview Q05 receipt profile/schema mismatch")
    for key in ("browserActions", "apiRequests"):
        if type(receipt[key]) is not int or not 1 <= receipt[key] <= 1200:
            raise RuntimeError(f"CTF preview Q05 {key} bound exceeded")
    if type(receipt["judgeCalls"]) is not int or receipt["judgeCalls"] != 0 \
            or type(receipt["genuineCredit"]) is not int or receipt["genuineCredit"] != 0:
        raise RuntimeError("CTF preview Q05 judge/credit mismatch")
    provider = {"kind", "physicalStarted", "completed", "clientAborted", "maxPhysicalCalls"}
    if not exact(receipt["providerDiagnostics"], provider) or receipt["providerDiagnostics"]["kind"] != "controlled-synthetic-transport" \
            or any(type(receipt["providerDiagnostics"][key]) is not int for key in provider - {"kind"}) \
            or receipt["providerDiagnostics"]["physicalStarted"] != 2 \
            or receipt["providerDiagnostics"]["completed"] != 1 \
            or receipt["providerDiagnostics"]["clientAborted"] != 1 \
            or receipt["providerDiagnostics"]["maxPhysicalCalls"] != 2 \
            or receipt["providerDiagnostics"]["physicalStarted"] != receipt["providerDiagnostics"]["completed"] + receipt["providerDiagnostics"]["clientAborted"]:
        raise RuntimeError("CTF preview Q05 provider diagnostics mismatch")
    base_case = {"browserPosts", "serverPosts", "providerStarts", "uiPublished", "stateInvariant"}
    cases = receipt["cases"]
    if not exact(cases, {"cancel", "dialogAba", "singleFlight", "postDispatchClose"}):
        raise RuntimeError("CTF preview Q05 case schema mismatch")
    for name in ("cancel", "dialogAba"):
        expected = base_case | ({"eventsObserved"} if name == "dialogAba" else set())
        case = cases[name]
        if not exact(case, expected) or any(case[key] != 0 or type(case[key]) is not int for key in ("browserPosts", "serverPosts", "providerStarts")) \
                or case["uiPublished"] is not False or case["stateInvariant"] is not True \
                or (name == "dialogAba" and (type(case["eventsObserved"]) is not int or case["eventsObserved"] != 2)):
            raise RuntimeError("CTF preview Q05 predispatch boundary failed")
    single = cases["singleFlight"]
    if not exact(single, base_case | {"status"}) or any(type(single[key]) is not int or single[key] != 1 for key in ("browserPosts", "serverPosts", "providerStarts")) \
            or single["uiPublished"] is not True or single["stateInvariant"] is not True \
            or type(single["status"]) is not int or single["status"] != 200:
        raise RuntimeError("CTF preview Q05 singleflight proof invalid")
    close = cases["postDispatchClose"]
    if not exact(close, base_case | {"clientAborted"}) or any(type(close[key]) is not int or close[key] != 1 for key in ("browserPosts", "serverPosts", "providerStarts")) \
            or close["uiPublished"] is not False or close["stateInvariant"] is not True or close["clientAborted"] is not True:
        raise RuntimeError("CTF preview Q05 abort proof invalid")
    witness = {"targetStageUnchanged", "siblingStageUnchanged", "progressUnchanged", "attemptsUnchanged", "judgmentsUnchanged", "historyUnchanged", "outboxUnchanged"}
    facts = {"cancelNoPostOrProvider", "dialogAbaNoPostOrProvider", "singleFlightOnePostOneProvider", "closeAbortsProviderWithoutPublication", "stage1NoLanguageOrOutputDefense", "allDurableStateUnchanged", "noObjectiveJudgeOrCredit", "providerDiagnosticsNotQualification"}
    if not exact(receipt["storeWitness"], witness) or any(receipt["storeWitness"][key] is not True for key in witness) \
            or not exact(receipt["facts"], facts) or any(receipt["facts"][key] is not True for key in facts) \
            or receipt["excluded"] != ["model-qualification", "objective-judge", "gameplay-credit", "outbox-operation-recovery"] \
            or type(receipt["unexpectedApiPaths"]) is not list or receipt["unexpectedApiPaths"]:
        raise RuntimeError("CTF preview Q05 effect, exclusion, or API boundary failed")
    return receipt


def validate_learner_entry_hint_q05_receipt(path):
    """Admit only FRESH learner registration/start/hint evidence, never scoring or credit."""
    path = Path(path)
    if path.name != "ctf-learner-entry-hint-q05-result.json" or not path.is_absolute() or path.is_symlink() \
            or path.resolve() != path or not path.is_file():
        raise RuntimeError("CTF learner-entry-hint Q05 receipt is missing or noncanonical")
    parent = path.parent
    parent_info, path_info = parent.lstat(), path.lstat()
    if parent.is_symlink() or parent.resolve() != parent or not stat.S_ISDIR(parent_info.st_mode) \
            or parent_info.st_uid != os.getuid() or stat.S_IMODE(parent_info.st_mode) != 0o700 \
            or not stat.S_ISREG(path_info.st_mode) or path_info.st_uid != os.getuid() \
            or stat.S_IMODE(path_info.st_mode) != 0o600 or path_info.st_nlink != 1 \
            or not 0 < path_info.st_size <= 65536:
        raise RuntimeError("CTF learner-entry-hint Q05 receipt is not private")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_nlink, opened.st_size) != (path_info.st_dev, path_info.st_ino, 1, path_info.st_size):
            raise RuntimeError("CTF learner-entry-hint Q05 receipt changed while opening")
        data = os.read(descriptor, 65537)
        if len(data) != opened.st_size or len(data) > 65536 or os.fstat(descriptor).st_size != opened.st_size:
            raise RuntimeError("CTF learner-entry-hint Q05 receipt changed while reading")
    finally:
        os.close(descriptor)
    def unique_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate receipt key")
            value[key] = item
        return value
    try:
        receipt = json.loads(data.decode("utf-8"), object_pairs_hook=unique_pairs)
    except (UnicodeError, ValueError) as error:
        raise RuntimeError("CTF learner-entry-hint Q05 receipt is unreadable") from error
    exact = lambda value, expected: type(value) is dict and set(value) == set(expected)
    positive_decimal = lambda value: type(value) is str and re.fullmatch(r"[1-9][0-9]*", value) and int(value) <= 9223372036854775807
    uuid_pattern = r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"
    top = {"version", "profile", "actorId", "sessionId", "participantId", "stageId", "siblingOwnerId", "prerequisite", "browserPosts", "serverPosts", "operations", "startOperationIds", "hintDialog", "facts", "storeWitness", "unexpectedApiPaths", "browserActions", "apiRequests", "modelCalls", "judgeCalls", "genuineCredit", "excluded", "stage"}
    if not exact(receipt, top) or type(receipt["version"]) is not int or receipt["version"] != 1 \
            or receipt["profile"] != "ctf-learner-entry-hint-q05" or receipt["stage"] != "complete" \
            or type(receipt["stageId"]) is not int or receipt["stageId"] != 1 \
            or type(receipt["siblingOwnerId"]) is not int or receipt["siblingOwnerId"] != 1001 \
            or any(not positive_decimal(receipt[key]) for key in ("actorId", "sessionId", "participantId")) \
            or receipt["prerequisite"] != {"hintGate": "0", "source": "pre-bootstrap-config", "defaultAttemptGateProven": False}:
        raise RuntimeError("CTF learner-entry-hint Q05 receipt profile/schema mismatch")
    counts = {"register", "start", "hint"}
    if not exact(receipt["browserPosts"], counts) or receipt["serverPosts"] != receipt["browserPosts"] \
            or any(type(receipt["browserPosts"][key]) is not int for key in counts) \
            or receipt["browserPosts"]["register"] != 1 or receipt["browserPosts"]["hint"] != 1 \
            or not 1 <= receipt["browserPosts"]["start"] <= 3:
        raise RuntimeError("CTF learner-entry-hint Q05 physical request counts invalid")
    operation_keys = {"originalStatus", "resolvedStatus", "sameIdGets", "operationId", "sequence"}
    def operation(value):
        if not exact(value, operation_keys) or type(value["originalStatus"]) is not int or value["originalStatus"] not in (200, 202) \
                or type(value["resolvedStatus"]) is not int or value["resolvedStatus"] != 200 \
                or type(value["sameIdGets"]) is not int or not 0 <= value["sameIdGets"] <= 32 \
                or type(value["operationId"]) is not str or not re.fullmatch(uuid_pattern, value["operationId"]) \
                or not positive_decimal(value["sequence"]):
            raise RuntimeError("CTF learner-entry-hint Q05 operation proof invalid")
        if (value["originalStatus"] == 200) != (value["sameIdGets"] == 0):
            raise RuntimeError("CTF learner-entry-hint Q05 recovery proof invalid")
    if not exact(receipt["operations"], counts):
        raise RuntimeError("CTF learner-entry-hint Q05 operation schema mismatch")
    for key in ("register", "start", "hint"):
        operation(receipt["operations"][key])
    operations = receipt["operations"]
    if not int(operations["register"]["sequence"]) < int(operations["start"]["sequence"]) < int(operations["hint"]["sequence"]):
        raise RuntimeError("CTF learner-entry-hint Q05 operation order invalid")
    starts = receipt["startOperationIds"]
    if type(starts) is not list or len(starts) != receipt["browserPosts"]["start"] \
            or len(set(starts)) != len(starts) or any(type(value) is not str or not re.fullmatch(uuid_pattern, value) for value in starts) \
            or starts[0] != operations["start"]["operationId"] \
            or len({operations[key]["operationId"] for key in counts} | set(starts)) != len(starts) + 2:
        raise RuntimeError("CTF learner-entry-hint Q05 start-operation proof invalid")
    dialog = {"cancelPosts", "abaPosts", "abaEventsObserved", "cancelStateUnchanged", "abaStateUnchanged"}
    if not exact(receipt["hintDialog"], dialog) or receipt["hintDialog"] != {"cancelPosts": 0, "abaPosts": 0, "abaEventsObserved": 2, "cancelStateUnchanged": True, "abaStateUnchanged": True}:
        raise RuntimeError("CTF learner-entry-hint Q05 dialog boundary invalid")
    witness = {"ownerRegistered", "stageStarted", "oneHintPurchased", "costApplied", "siblingBeforeNonempty", "siblingUnchanged", "attemptsUnchanged", "judgmentsUnchanged", "siblingLeaderboardUnchanged"}
    facts = {"physicalJoin", "physicalStageCard", "automaticStart", "hintCancelNoPost", "hintAbaNoPost", "onePhysicalHintPurchase", "actorSessionOutboxBound", "canonicalProjectionBound", "durableProgressBound", "nonemptySiblingPreserved", "noScoredAttemptOrCredit"}
    if not exact(receipt["storeWitness"], witness) or any(receipt["storeWitness"][key] is not True for key in witness) \
            or not exact(receipt["facts"], facts) or any(receipt["facts"][key] is not True for key in facts) \
            or receipt["excluded"] != ["default-attempt-gate", "scored-attempt", "fixed-practice", "model-qualification", "objective-judge", "gameplay-credit"] \
            or type(receipt["unexpectedApiPaths"]) is not list or receipt["unexpectedApiPaths"] \
            or any(type(receipt[key]) is not int or receipt[key] != 0 for key in ("modelCalls", "judgeCalls", "genuineCredit")):
        raise RuntimeError("CTF learner-entry-hint Q05 effect/exclusion boundary invalid")
    for key in ("browserActions", "apiRequests"):
        if type(receipt[key]) is not int or not 1 <= receipt[key] <= 400:
            raise RuntimeError(f"CTF learner-entry-hint Q05 {key} bound exceeded")
    return receipt


def validate_fixed_practice_q05_receipt(path):
    """Admit only bounded, controlled fixed-practice evidence with canonical stale fences."""
    path = Path(path)
    if path.name != "ctf-fixed-practice-q05-result.json" or not path.is_absolute() \
            or path.is_symlink() or path.resolve() != path or not path.is_file():
        raise RuntimeError("CTF fixed-practice Q05 receipt is missing or noncanonical")
    parent = path.parent
    parent_info, path_info = parent.lstat(), path.lstat()
    if parent.is_symlink() or parent.resolve() != parent or not stat.S_ISDIR(parent_info.st_mode) \
            or parent_info.st_uid != os.getuid() or stat.S_IMODE(parent_info.st_mode) != 0o700 \
            or not stat.S_ISREG(path_info.st_mode) or path_info.st_uid != os.getuid() \
            or stat.S_IMODE(path_info.st_mode) != 0o600 or path_info.st_nlink != 1 \
            or not 0 < path_info.st_size <= 65536:
        raise RuntimeError("CTF fixed-practice Q05 receipt is not private")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_nlink, opened.st_size) != (path_info.st_dev, path_info.st_ino, 1, path_info.st_size):
            raise RuntimeError("CTF fixed-practice Q05 receipt changed while opening")
        data = os.read(descriptor, 65537)
        if len(data) != opened.st_size or len(data) > 65536 or os.fstat(descriptor).st_size != opened.st_size:
            raise RuntimeError("CTF fixed-practice Q05 receipt changed while reading")
    finally:
        os.close(descriptor)
    def unique_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate receipt key")
            value[key] = item
        return value
    try:
        receipt = json.loads(data.decode("utf-8"), object_pairs_hook=unique_pairs)
    except (UnicodeError, ValueError) as error:
        raise RuntimeError("CTF fixed-practice Q05 receipt is unreadable") from error
    exact = lambda value, expected: type(value) is dict and set(value) == set(expected)
    def exact_value(value, expected):
        if type(expected) is dict:
            return type(value) is dict and set(value) == set(expected) and all(exact_value(value[key], item) for key, item in expected.items())
        if type(expected) is list:
            return type(value) is list and len(value) == len(expected) and all(exact_value(value[index], item) for index, item in enumerate(expected))
        return type(value) is type(expected) and value == expected
    positive_decimal = lambda value: type(value) is str and re.fullmatch(r"[1-9][0-9]*", value) and int(value) <= 9223372036854775807
    uuid_pattern = r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"
    top = {"version", "profile", "actorId", "sessionId", "participantId", "stageId", "siblingOwnerId", "cases", "providerDiagnostics", "storeWitness", "facts", "excluded", "cleanup", "authorityOperations", "unexpectedApiPaths", "browserActions", "apiRequests", "stage", "judgeCalls", "genuineCredit"}
    if not exact(receipt, top) or type(receipt["version"]) is not int or receipt["version"] != 1 \
            or receipt["profile"] != "ctf-fixed-practice-q05" or receipt["stage"] != "complete" \
            or type(receipt["stageId"]) is not int or receipt["stageId"] != 1 \
            or receipt["actorId"] != "2403" or any(not positive_decimal(receipt[key]) for key in ("sessionId", "participantId", "siblingOwnerId")) \
            or any(type(receipt[key]) is not int or receipt[key] != 0 for key in ("judgeCalls", "genuineCredit")):
        raise RuntimeError("CTF fixed-practice Q05 receipt profile/schema mismatch")
    cases = {"modeSelection", "submit", "staleBeforeDispatch", "staleBeforeProvider", "staleAfterDispatch"}
    expected_cases = {
        "modeSelection": {"browserPosts": 0, "serverPosts": 0, "providerStarts": 0, "responsePublished": False, "stateInvariant": True},
        "submit": {"browserPosts": 1, "serverPosts": 1, "providerStarts": 1, "responsePublished": True, "status": 200, "scoringEligible": False, "protectedContextIncluded": False, "serverSecretProvided": False},
        "staleBeforeDispatch": {"browserPosts": 0, "serverPosts": 0, "providerStarts": 0, "responsePublished": False, "stateInvariant": True},
        "staleBeforeProvider": {"browserPosts": 1, "serverPosts": 1, "providerStarts": 0, "responsePublished": False, "status": 409, "stateInvariant": True},
        "staleAfterDispatch": {"browserPosts": 1, "serverPosts": 1, "providerStarts": 1, "responsePublished": False, "status": 409, "stateInvariant": True},
    }
    if not exact(receipt["cases"], cases) or not exact_value(receipt["cases"], expected_cases):
        raise RuntimeError("CTF fixed-practice Q05 case proof invalid")
    provider = {"kind", "physicalStarted", "completed", "staleAfterDispatch", "maxPhysicalCalls"}
    if not exact(receipt["providerDiagnostics"], provider) or not exact_value(receipt["providerDiagnostics"], {"kind": "controlled-synthetic-provider", "physicalStarted": 2, "completed": 1, "staleAfterDispatch": 1, "maxPhysicalCalls": 2}):
        raise RuntimeError("CTF fixed-practice Q05 provider budget invalid")
    phases = ("pre-provider-stale", "pre-provider-restore", "post-provider-stale", "post-provider-restore")
    operations = receipt["authorityOperations"]
    if type(operations) is not list or len(operations) != len(phases):
        raise RuntimeError("CTF fixed-practice Q05 authority operation count invalid")
    seen, previous, authority_actor, authority_session = set(), 0, None, None
    operation_keys = {"phase", "operationId", "sequence", "actorId", "sessionId", "stageId"}
    for phase, operation in zip(phases, operations, strict=True):
        if not exact(operation, operation_keys) or operation["phase"] != phase \
                or type(operation["operationId"]) is not str or not re.fullmatch(uuid_pattern, operation["operationId"]) \
                or not positive_decimal(operation["sequence"]) or not positive_decimal(operation["actorId"]) \
                or not positive_decimal(operation["sessionId"]) or type(operation["stageId"]) is not int or operation["stageId"] != 1 \
                or operation["operationId"] in seen or int(operation["sequence"]) <= previous:
            raise RuntimeError("CTF fixed-practice Q05 authority operation proof invalid")
        if authority_actor is None:
            authority_actor, authority_session = operation["actorId"], operation["sessionId"]
            if authority_actor == receipt["actorId"] or authority_session == receipt["sessionId"]:
                raise RuntimeError("CTF fixed-practice Q05 authority identity aliases learner")
        elif (operation["actorId"], operation["sessionId"]) != (authority_actor, authority_session):
            raise RuntimeError("CTF fixed-practice Q05 authority identity is not consistently bound")
        seen.add(operation["operationId"]); previous = int(operation["sequence"])
    witness = {"attemptsUnchanged", "progressUnchanged", "judgmentsUnchanged", "leaderboardUnchanged", "authorityOutboxExact", "siblingBeforeNonempty", "siblingUnchanged", "controlledFixtureCleaned"}
    facts = {"visibleFixedModeDisclosureBeforeSubmit", "modeSelectionNoDispatch", "oneBoundPracticePost", "staleBeforeDispatchNoProviderOrPublication", "staleBeforeProviderNoProviderOrPublication", "staleAfterDispatchNoPublication", "unscoredPublicContextBoundary", "noAttemptProgressJudgeLeaderboardCreditWrites", "noAutomaticRetryOrOperationRecovery", "nonemptySiblingPreserved", "canonicalAuthorityStalenessBound", "onlyExpectedAuthorityOutboxMutations", "controlledProviderNotQualification"}
    if not exact(receipt["storeWitness"], witness) or any(receipt["storeWitness"][key] is not True for key in witness) \
            or not exact(receipt["facts"], facts) or any(receipt["facts"][key] is not True for key in facts) \
            or not exact(receipt["cleanup"], {"providerDrained", "ownedBrowserHandles", "ownedStoreHandles"}) \
            or not exact_value(receipt["cleanup"], {"providerDrained": True, "ownedBrowserHandles": 0, "ownedStoreHandles": 0}) \
            or receipt["excluded"] != ["native-browser-proof", "actual-model-qualification", "objective-judge", "gameplay-credit", "operation-id-recovery", "automatic-retry"] \
            or type(receipt["unexpectedApiPaths"]) is not list or receipt["unexpectedApiPaths"]:
        raise RuntimeError("CTF fixed-practice Q05 effect/exclusion boundary invalid")
    for key in ("browserActions", "apiRequests"):
        if type(receipt[key]) is not int or not 1 <= receipt[key] <= 240:
            raise RuntimeError(f"CTF fixed-practice Q05 {key} bound exceeded")
    return receipt


def validate_learner_attempt_gate_q05_receipt(path):
    """Admit only the controlled three-attempt learner gate evidence, never model credit."""
    path = Path(path)
    if path.name != "ctf-learner-attempt-gate-q05-result.json" or not path.is_absolute() \
            or path.is_symlink() or path.resolve() != path or not path.is_file():
        raise RuntimeError("CTF learner-attempt-gate Q05 receipt is missing or noncanonical")
    parent = path.parent
    parent_info, path_info = parent.lstat(), path.lstat()
    if parent.is_symlink() or parent.resolve() != parent or not stat.S_ISDIR(parent_info.st_mode) \
            or parent_info.st_uid != os.getuid() or stat.S_IMODE(parent_info.st_mode) != 0o700 \
            or not stat.S_ISREG(path_info.st_mode) or path_info.st_uid != os.getuid() \
            or stat.S_IMODE(path_info.st_mode) != 0o600 or path_info.st_nlink != 1 \
            or not 0 < path_info.st_size <= 65536:
        raise RuntimeError("CTF learner-attempt-gate Q05 receipt is not private")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_nlink, opened.st_size) != (path_info.st_dev, path_info.st_ino, 1, path_info.st_size):
            raise RuntimeError("CTF learner-attempt-gate Q05 receipt changed while opening")
        data = os.read(descriptor, 65537)
        if len(data) != opened.st_size or len(data) > 65536 or os.fstat(descriptor).st_size != opened.st_size:
            raise RuntimeError("CTF learner-attempt-gate Q05 receipt changed while reading")
    finally:
        os.close(descriptor)
    def unique_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate receipt key")
            value[key] = item
        return value
    try:
        receipt = json.loads(data.decode("utf-8"), object_pairs_hook=unique_pairs)
    except (UnicodeError, ValueError) as error:
        raise RuntimeError("CTF learner-attempt-gate Q05 receipt is unreadable") from error
    exact = lambda value, expected: type(value) is dict and set(value) == set(expected)
    positive_decimal = lambda value: type(value) is str and re.fullmatch(r"[1-9][0-9]*", value) and int(value) <= 9223372036854775807
    uuid_pattern = r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"
    top = {"version", "profile", "transport", "actorId", "sessionId", "participantId", "stageId", "siblingOwnerId", "gate", "attempts", "browserPosts", "serverPosts", "lifecycle", "reset", "providerCalls", "storeWitness", "facts", "excluded", "unexpectedApiPaths", "browserActions", "apiRequests", "genuineCredit", "stage"}
    if not exact(receipt, top) or type(receipt["version"]) is not int or receipt["version"] != 1 \
            or receipt["profile"] != "ctf-learner-attempt-gate-q05" or receipt["transport"] != "controlled-synthetic" \
            or receipt["stage"] != "complete" or type(receipt["stageId"]) is not int or receipt["stageId"] != 1 \
            or type(receipt["siblingOwnerId"]) is not int or receipt["siblingOwnerId"] != 1001 \
            or receipt["actorId"] != "2402" or not positive_decimal(receipt["sessionId"]) \
            or not positive_decimal(receipt["participantId"]) or receipt["participantId"] == "1001" \
            or type(receipt["genuineCredit"]) is not int or receipt["genuineCredit"] != 0:
        raise RuntimeError("CTF learner-attempt-gate Q05 receipt profile/schema mismatch")
    gate = {"configured", "initialAttempts", "initialHintVisible", "deniedStatus", "deniedError", "deniedOutboxDelta", "deniedProgressUnchanged", "deniedProviderCalls", "afterAttempts", "afterThirdHintVisible"}
    gate_rows = [{"count": 1, "hintVisible": False, "status": "in_progress"}, {"count": 2, "hintVisible": False, "status": "in_progress"}, {"count": 3, "hintVisible": True, "status": "in_progress"}]
    if not exact(receipt["gate"], gate) \
            or any(type(receipt["gate"][key]) is not int for key in ("configured", "initialAttempts", "deniedStatus", "deniedOutboxDelta", "deniedProviderCalls")) \
            or any(receipt["gate"][key] is not expected for key, expected in (("initialHintVisible", False), ("deniedProgressUnchanged", True), ("afterThirdHintVisible", True))) \
            or receipt["gate"]["configured"] != 3 or receipt["gate"]["initialAttempts"] != 0 \
            or receipt["gate"]["deniedStatus"] != 409 or receipt["gate"]["deniedError"] != "Hint availability changed; refresh stage status" \
            or receipt["gate"]["deniedOutboxDelta"] != 0 or receipt["gate"]["deniedProviderCalls"] != 0 \
            or type(receipt["gate"]["afterAttempts"]) is not list or len(receipt["gate"]["afterAttempts"]) != 3 \
            or any(not exact(row, {"count", "hintVisible", "status"}) or type(row["count"]) is not int \
                   or row["hintVisible"] is not expected["hintVisible"] or row["status"] != expected["status"] or row["count"] != expected["count"]
                   for row, expected in zip(receipt["gate"]["afterAttempts"], gate_rows, strict=True)):
        raise RuntimeError("CTF learner-attempt-gate Q05 default gate proof invalid")
    attempts = receipt["attempts"]
    attempt_keys = {"ordinal", "runId", "admissionId", "decisionId", "requestStatus", "publicationStatus", "verdict", "accepted", "guardianCalls", "judgeCalls", "sameIdGets", "recoveryResumePosts", "recoveryAuthorizePosts", "ownerSessionBound", "decisionApplied", "publicationCurrent", "noProviderReplay"}
    if type(attempts) is not list or len(attempts) != 3:
        raise RuntimeError("CTF learner-attempt-gate Q05 attempt count invalid")
    identifiers = {key: [] for key in ("runId", "admissionId", "decisionId")}
    judge_total = resume_total = authorize_total = 0
    for ordinal, attempt in enumerate(attempts, 1):
        if not exact(attempt, attempt_keys) or type(attempt["ordinal"]) is not int or attempt["ordinal"] != ordinal \
                or any(type(attempt[key]) is not str or not re.fullmatch(uuid_pattern, attempt[key]) for key in identifiers) \
                or type(attempt["requestStatus"]) is not int or attempt["requestStatus"] != 202 \
                or type(attempt["publicationStatus"]) is not int or attempt["publicationStatus"] != 200 \
                or attempt["verdict"] != "fail" or attempt["accepted"] is not False \
                or type(attempt["guardianCalls"]) is not int or attempt["guardianCalls"] != 1 or type(attempt["judgeCalls"]) is not int or not 1 <= attempt["judgeCalls"] <= 2 \
                or type(attempt["sameIdGets"]) is not int or not 1 <= attempt["sameIdGets"] <= 32 \
                or type(attempt["recoveryResumePosts"]) is not int or not 0 <= attempt["recoveryResumePosts"] <= 1 \
                or type(attempt["recoveryAuthorizePosts"]) is not int or not 0 <= attempt["recoveryAuthorizePosts"] <= 1 \
                or any(attempt[key] is not True for key in ("ownerSessionBound", "decisionApplied", "publicationCurrent", "noProviderReplay")):
            raise RuntimeError("CTF learner-attempt-gate Q05 attempt proof invalid")
        for key in identifiers:
            identifiers[key].append(attempt[key])
        judge_total += attempt["judgeCalls"]
        resume_total += attempt["recoveryResumePosts"]
        authorize_total += attempt["recoveryAuthorizePosts"]
    if any(len(set(values)) != 3 for values in identifiers.values()):
        raise RuntimeError("CTF learner-attempt-gate Q05 operation identifiers are not distinct")
    posts = {"register", "start", "attempt", "hint", "resume", "authorize"}
    if not exact(receipt["browserPosts"], posts) or not exact(receipt["serverPosts"], posts) \
            or any(type(receipt["browserPosts"][key]) is not int or type(receipt["serverPosts"][key]) is not int for key in posts) \
            or receipt["browserPosts"]["register"] != 1 or receipt["browserPosts"]["start"] != 1 \
            or receipt["browserPosts"]["attempt"] != 3 or receipt["browserPosts"]["hint"] != 0 \
            or receipt["browserPosts"]["resume"] != resume_total or receipt["browserPosts"]["authorize"] != authorize_total \
            or receipt["serverPosts"] != {**receipt["browserPosts"], "hint": 1}:
        raise RuntimeError("CTF learner-attempt-gate Q05 physical request counts invalid")
    lifecycle_keys = {"operationId", "sequence", "originalStatus"}
    if not exact(receipt["lifecycle"], {"register", "start"}):
        raise RuntimeError("CTF learner-attempt-gate Q05 lifecycle schema invalid")
    for key in ("register", "start"):
        value = receipt["lifecycle"][key]
        if not exact(value, lifecycle_keys) or type(value["operationId"]) is not str \
                or not re.fullmatch(uuid_pattern, value["operationId"]) or not positive_decimal(value["sequence"]) \
                or type(value["originalStatus"]) is not int or value["originalStatus"] not in (200, 202):
            raise RuntimeError("CTF learner-attempt-gate Q05 lifecycle proof invalid")
    if receipt["lifecycle"]["register"]["operationId"] == receipt["lifecycle"]["start"]["operationId"] \
            or int(receipt["lifecycle"]["register"]["sequence"]) >= int(receipt["lifecycle"]["start"]["sequence"]):
        raise RuntimeError("CTF learner-attempt-gate Q05 lifecycle order invalid")
    reset_keys = {"operationId", "sequence", "originalStatus", "deniedStatus", "deniedError", "generationBefore", "generationAfter"}
    reset = receipt["reset"]
    nonnegative_decimal = lambda value: type(value) is str and re.fullmatch(r"0|[1-9][0-9]*", value)
    if not exact(reset, reset_keys) or type(reset["operationId"]) is not str or not re.fullmatch(uuid_pattern, reset["operationId"]) \
            or not positive_decimal(reset["sequence"]) or type(reset["originalStatus"]) is not int or reset["originalStatus"] not in (200, 202) \
            or type(reset["deniedStatus"]) is not int or reset["deniedStatus"] != 409 \
            or reset["deniedError"] != "CTF request is no longer current" \
            or not nonnegative_decimal(reset["generationBefore"]) or not positive_decimal(reset["generationAfter"]) \
            or int(reset["generationAfter"]) != int(reset["generationBefore"]) + 1:
        raise RuntimeError("CTF learner-attempt-gate Q05 reset fence invalid")
    if int(receipt["lifecycle"]["start"]["sequence"]) >= int(reset["sequence"]):
        raise RuntimeError("CTF learner-attempt-gate Q05 reset order invalid")
    provider = {"guardian", "judge", "total"}
    if not exact(receipt["providerCalls"], provider) \
            or any(type(receipt["providerCalls"][key]) is not int for key in provider) \
            or receipt["providerCalls"]["guardian"] != 3 \
            or receipt["providerCalls"]["judge"] != judge_total or not 3 <= judge_total <= 6 \
            or receipt["providerCalls"]["total"] != 3 + judge_total or receipt["providerCalls"]["total"] > 9:
        raise RuntimeError("CTF learner-attempt-gate Q05 provider budget invalid")
    witness = {"progressAttemptsThree", "threeAttemptRows", "threeJudgmentRows", "noCompletion", "noHintPurchased", "identityBindingCurrent", "siblingBeforeNonempty", "siblingUnchanged", "resetReferenceFenced", "historicalEvidenceRetained"}
    facts = {"physicalJoinAndStart", "defaultGateIsThree", "lockedHintBeforeAttempts", "canonicalHintDenialBeforeAttempts", "threePhysicalScoredSubmissions", "sameReferenceRecoveryNoResubmit", "gateUnlockOnlyAfterThirdAttempt", "mountedSessionBound", "canonicalAttemptProjectionBound", "nonemptySiblingUnchanged", "noActualModelOrGenuineCreditClaim"}
    if not exact(receipt["storeWitness"], witness) or any(receipt["storeWitness"][key] is not True for key in witness) \
            or not exact(receipt["facts"], facts) or any(receipt["facts"][key] is not True for key in facts) \
            or receipt["excluded"] != ["actual-model-qualification", "guaranteed-secret-extraction", "genuine-gameplay-credit", "fixed-practice", "post-reset-credit"] \
            or type(receipt["unexpectedApiPaths"]) is not list or receipt["unexpectedApiPaths"]:
        raise RuntimeError("CTF learner-attempt-gate Q05 effect/exclusion boundary invalid")
    for key in ("browserActions", "apiRequests"):
        if type(receipt[key]) is not int or not 1 <= receipt[key] <= 800:
            raise RuntimeError(f"CTF learner-attempt-gate Q05 {key} bound exceeded")
    return receipt


def validate_full_reset_q05_receipt(path):
    """Admit only terminal, nonvacuous standalone Full Reset evidence, never content credit."""
    path = Path(path)
    if path.name != "ctf-full-reset-q05-result.json" or not path.is_absolute() \
            or path.is_symlink() or path.resolve() != path or not path.is_file():
        raise RuntimeError("CTF Full Reset Q05 receipt is missing or noncanonical")
    parent = path.parent
    parent_info, path_info = parent.lstat(), path.lstat()
    if parent.is_symlink() or parent.resolve() != parent \
            or not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.getuid() \
            or stat.S_IMODE(parent_info.st_mode) != 0o700 \
            or not stat.S_ISREG(path_info.st_mode) or path_info.st_uid != os.getuid() \
            or stat.S_IMODE(path_info.st_mode) != 0o600 or path_info.st_nlink != 1 \
            or not 0 < path_info.st_size <= 16384:
        raise RuntimeError("CTF Full Reset Q05 receipt is not private")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        if opened.st_dev != path_info.st_dev or opened.st_ino != path_info.st_ino \
                or opened.st_nlink != 1 or opened.st_size != path_info.st_size:
            raise RuntimeError("CTF Full Reset Q05 receipt changed while opening")
        chunks, size = [], 0
        while True:
            chunk = os.read(descriptor, min(4096, 16385 - size))
            if not chunk:
                break
            size += len(chunk)
            if size > 16384:
                raise RuntimeError("CTF Full Reset Q05 receipt exceeded bound")
            chunks.append(chunk)
        if size != opened.st_size or os.fstat(descriptor).st_size != opened.st_size:
            raise RuntimeError("CTF Full Reset Q05 receipt changed while reading")
    finally:
        os.close(descriptor)
    def unique_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate receipt key")
            value[key] = item
        return value
    try:
        receipt = json.loads(b"".join(chunks).decode("utf-8"), object_pairs_hook=unique_pairs)
    except (UnicodeError, ValueError) as error:
        raise RuntimeError("CTF Full Reset Q05 receipt is unreadable") from error
    exact = lambda value, keys: type(value) is dict and set(value) == set(keys)
    positive_decimal = lambda value: type(value) is str and re.fullmatch(r"[1-9][0-9]*", value) \
        and int(value) <= 9223372036854775807
    safe_count = lambda value: type(value) is int and 0 < value <= 9007199254740991
    cleared = ("ctf_attempts", "ctf_progress", "ctf_technique_blocklist",
        "ctf_leaderboard", "ctf_events", "ctf_sessions", "ctf_payload_blocklist", "ctf_participants")
    retained = ("ctf_stages", "ctf_config", "ctf_stage_teaching_content", "ctf_bans", "ctf_judgments")
    immutable_bootstrap = ("sessions", "pages", "imports")
    mutable_identity_memory = ("technique", "payload")
    fields = ("version", "profile", "modelCalls", "judgeCalls", "actorId", "sessionId",
        "path", "dialogAbaEventsObserved", "requestCounts", "responseStage", "serverResponse",
        "operation", "pre", "facts", "excluded", "unexpectedApiPaths", "stage")
    if not exact(receipt, fields) or type(receipt["version"]) is not int or receipt["version"] != 2 \
            or receipt["profile"] != "ctf-full-reset-q05" or receipt["stage"] != "complete" \
            or receipt["path"] != "/api/ctf/admin/reset" \
            or not positive_decimal(receipt["actorId"]) or not positive_decimal(receipt["sessionId"]):
        raise RuntimeError("CTF Full Reset Q05 receipt profile/schema mismatch")
    for key, value in (("modelCalls", 0), ("judgeCalls", 0), ("dialogAbaEventsObserved", 2)):
        if type(receipt[key]) is not int or receipt[key] != value:
            raise RuntimeError("CTF Full Reset Q05 model/ABA count mismatch")
    counts = {"wrongToken": 0, "cancel": 0, "dialogAba": 0, "browserPost": 1,
        "serverPost": 1, "browserFailed": 1, "browserFinished": 0, "serverFinished": 1}
    if not exact(receipt["requestCounts"], counts) \
            or any(type(receipt["requestCounts"][key]) is not int \
                or receipt["requestCounts"][key] != value for key, value in counts.items()):
        raise RuntimeError("CTF Full Reset Q05 physical request counts mismatch")
    response_stage = {"paused": 1, "failed": 1, "continued": 0}
    if not exact(receipt["responseStage"], response_stage) \
            or any(type(receipt["responseStage"][key]) is not int \
                or receipt["responseStage"][key] != value for key, value in response_stage.items()):
        raise RuntimeError("CTF Full Reset Q05 lost-response stage mismatch")
    server = receipt["serverResponse"]
    if not exact(server, ("status", "body", "lossPhase")) or type(server["status"]) is not int \
            or server["status"] not in (200, 202) \
            or server["lossPhase"] != "after-real-http-response-before-browser-consumption":
        raise RuntimeError("CTF Full Reset Q05 server response boundary mismatch")
    operation = receipt["operation"]
    uuid_pattern = r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"
    if not exact(operation, ("operationId", "sequence", "removedParticipants", "sameIdHarnessGets")) \
            or type(operation["operationId"]) is not str \
            or not re.fullmatch(uuid_pattern, operation["operationId"]) \
            or not positive_decimal(operation["sequence"]) \
            or not safe_count(operation["removedParticipants"]) \
            or type(operation["sameIdHarnessGets"]) is not int \
            or not 0 <= operation["sameIdHarnessGets"] <= 1024:
        raise RuntimeError("CTF Full Reset Q05 canonical operation invalid")
    if server["status"] == 200:
        if not exact(server["body"], ("message",)) \
                or server["body"]["message"] != "CTF reset successfully" \
                or operation["sameIdHarnessGets"] != 0:
            raise RuntimeError("CTF Full Reset Q05 direct response mismatch")
    elif not exact(server["body"], ("message", "operationId", "pending", "success")) \
            or server["body"]["message"] != "CTF operation is pending. No completion is being reported." \
            or server["body"]["operationId"] != operation["operationId"] \
            or server["body"]["pending"] is not True or server["body"]["success"] is not False \
            or operation["sameIdHarnessGets"] < 1:
        raise RuntimeError("CTF Full Reset Q05 same-ID harness readback mismatch")
    before = receipt["pre"]
    if not exact(before, ("clearedRows", "retainedRows", "immutableBootstrapRows", "mutableIdentityMemoryRows")) \
            or not exact(before["clearedRows"], cleared) or not exact(before["retainedRows"], retained) \
            or not exact(before["immutableBootstrapRows"], immutable_bootstrap) \
            or not exact(before["mutableIdentityMemoryRows"], mutable_identity_memory) \
            or any(not safe_count(count) for count in before["clearedRows"].values()) \
            or any(not safe_count(count) for count in before["retainedRows"].values()) \
            or any(not safe_count(count) for count in before["immutableBootstrapRows"].values()) \
            or any(not safe_count(count) for count in before["mutableIdentityMemoryRows"].values()) \
            or operation["removedParticipants"] != before["clearedRows"]["ctf_participants"]:
        raise RuntimeError("CTF Full Reset Q05 nonvacuous table witness mismatch")
    facts = ("wrongTokenNoPost", "cancelNoPost", "cancelNoEffect", "dialogAbaNoPost",
        "dialogAbaNoEffect", "onePhysicalPost", "capturedAuthorityAndBody",
        "canonicalOperationApplied", "removedCountMatches", "mutableCtfCleared",
        "mutableIdentityMemoryCleared",
        "retainedCtfUnchanged", "historicalIdentityEvidencePreserved",
        "platformAndWorkshopSiblingPreserved", "unknownUiNoReference", "noAutomaticRetry")
    excluded = ["browser-acknowledged-success", "browser-operation-id-recovery",
        "ctf-sibling-preservation", "ban-deletion", "judgment-deletion",
        "immutable-evidence-deletion", "model-grading", "full-Q05-denominator"]
    if not exact(receipt["facts"], facts) \
            or any(receipt["facts"][key] is not True for key in facts) \
            or receipt["excluded"] != excluded \
            or type(receipt["unexpectedApiPaths"]) is not list \
            or receipt["unexpectedApiPaths"]:
        raise RuntimeError("CTF Full Reset Q05 effect, exclusion, or API boundary failed")
    return receipt


def process_inventory():
    """Load the existing Darwin identity/session/birth inspector without a new runtime."""
    helper = Path(__file__).with_name("darwin_process_inventory.py")
    spec = importlib.util.spec_from_file_location("ctf_stages_process_inventory", helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def native_owned_group_members(pgid, *, uid=None):
    return process_inventory().owned_group_members(pgid, uid=uid)


def native_leader_birth(pgid, session_id, uid):
    row = process_inventory().LibProc().identity(pgid)
    if row is None or row.pid != pgid or row.pgid != pgid or row.uid != uid \
            or os.getsid(pgid) != session_id:
        raise RuntimeError("Original process-group leader birth is unavailable")
    return row.start_sec, row.start_usec


def capture_launch_birth(child):
    if sys.platform != "darwin":
        return None
    return native_leader_birth(child.pid, child._owned_sid, child._owned_uid)


def validate_ctf_browser_birth(record, child, browser, profile, *, kind="ctf_ten_content_browser", api=None,
                               getsid=os.getsid):
    """Independently bind the CTF child's claimed Chrome birth before ACK."""
    if kind not in ("ctf_ten_content_browser", "ctf_config_browser", "ctf_preview_browser", "ctf_learner_entry_hint_browser", "ctf_learner_attempt_gate_browser", "ctf_fixed_practice_browser", "ctf_full_reset_browser"):
        raise RuntimeError("Unrecognized CTF browser birth kind")
    module = process_inventory()
    api = module.LibProc() if api is None else api
    if not isinstance(record, dict) or set(record) != {"schemaVersion", "processes"} \
            or record["schemaVersion"] != 2 or not isinstance(record["processes"], list) \
            or len(record["processes"]) != 1:
        raise RuntimeError("CTF browser birth record schema mismatch")
    row = record["processes"][0]
    expected = {"kind", "pid", "parentPid", "uid", "pgid", "sessionId",
                "birth", "executablePath", "executableSha256"}
    if not isinstance(row, dict) or set(row) != expected \
            or row["kind"] != kind \
            or row["parentPid"] != child.pid or row["uid"] != os.getuid() \
            or row["pgid"] != child.pid or row["sessionId"] != child.pid \
            or row["executablePath"] != str(browser) \
            or row["executableSha256"] != sha256(browser) \
            or type(row["pid"]) is not int or row["pid"] <= 1 \
            or not isinstance(row["birth"], list) or len(row["birth"]) != 2 \
            or any(type(part) is not int or part < 0 for part in row["birth"]) \
            or row["birth"][0] <= 0 or row["birth"][1] >= 1000000:
        raise RuntimeError("CTF browser birth record identity mismatch")
    original_parent_birth = getattr(child, "_owned_birth", None)
    def parent():
        current = api.identity(child.pid)
        if current is None or (current.start_sec, current.start_usec) != original_parent_birth \
                or current.uid != os.getuid() or current.ruid != os.getuid() \
            or current.status == module.SZOMB:
            raise RuntimeError("CTF browser parent birth changed")
    parent()
    first = api.identity(row["pid"])
    if first is None or (first.pid, first.ppid, first.uid, first.ruid, first.pgid,
            first.start_sec, first.start_usec) != (row["pid"], child.pid,
            os.getuid(), os.getuid(), child.pid, *row["birth"]) \
            or first.status == module.SZOMB or getsid(row["pid"]) != child.pid:
        raise RuntimeError("CTF browser live birth unavailable")
    arguments = api.arguments(row["pid"])
    if not arguments or arguments[0] != str(browser) \
            or arguments.count(f"--user-data-dir={profile}") != 1:
        raise RuntimeError("CTF browser executable/profile mismatch")
    second = api.identity(row["pid"])
    parent()
    if second is None or (second.pid, second.ppid, second.uid, second.ruid,
            second.pgid, second.start_sec, second.start_usec) != (first.pid,
            first.ppid, first.uid, first.ruid, first.pgid, first.start_sec,
            first.start_usec) or second.status == module.SZOMB:
        raise RuntimeError("CTF browser birth changed during admission")
    return row


def acknowledge_ctf_browser(record_path, ack_path, child, browser, profile, *,
                            kind="ctf_ten_content_browser",
                            stop, deadline, sleep=time.sleep):
    while time.monotonic() < deadline and not stop.is_set():
        if record_path.exists() or record_path.is_symlink():
            with record_path.open("rb") as input_file:
                info = os.fstat(input_file.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() \
                        or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 4096:
                    raise RuntimeError("Private CTF browser birth record required")
                raw = input_file.read(4097)
                after = os.fstat(input_file.fileno())
            current = record_path.lstat()
            if len(raw) != info.st_size or (info.st_dev, info.st_ino, info.st_size,
                    info.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size,
                    after.st_mtime_ns) or (info.st_dev, info.st_ino) != (current.st_dev,
                    current.st_ino):
                raise RuntimeError("CTF browser birth record changed during admission")
            record = json.loads(raw)
            row = validate_ctf_browser_birth(record, child, browser, profile, kind=kind)
            write_private_json(ack_path, {"schemaVersion": 1,
                "recordSha256": hashlib.sha256(raw).hexdigest(), "parentPid": child.pid,
                "browserPid": row["pid"], "profile": str(profile)})
            return row
        sleep(0.025)
    raise RuntimeError("CTF browser birth record was not independently acknowledged")


def ctf_complete_roster(*, profile=None, pgid=None, records=None):
    """Deny qualification when any current-user process argv is unreadable."""
    rows = process_inventory().process_records(include_arguments=True) if records is None else records()
    if not isinstance(rows, list) or not any(row.get("pid") == os.getpid() for row in rows):
        raise RuntimeError("CTF complete process roster omitted launcher")
    if profile is not None:
        for row in rows:
            arguments = row.get("arguments")
            if row.get("pid") == pgid or row.get("pgid") == pgid \
                    or row.get("sessionId") == pgid \
                    or arguments is not None and str(profile) in "\0".join(arguments):
                raise RuntimeError("CTF browser profile/group remains in process roster")
    return True


def child_test_command(node, test, *, ten_content=False):
    return [str(node), "--test", *(["--test-isolation=none"] if ten_content else []),
            "--test-reporter=tap", str(test)]


def ten_content_run_parent(source):
    """Admit only the existing private repository qualification directory."""
    source = Path(source)
    tasks = source / "tasks"
    parent = tasks / "qualification"
    if source.resolve() != source or tasks.is_symlink() or not tasks.is_dir() \
            or parent.is_symlink() or parent.resolve() != parent:
        raise RuntimeError("Ten-content run parent is not canonical repository storage")
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() \
            or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError("Ten-content run parent is not private repository storage")
    return parent


def ten_content_short_tmp_parent(source):
    parent = Path(source) / "tasks/tmp"
    info = parent.lstat()
    if parent.is_symlink() or parent.resolve() != parent \
            or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise RuntimeError("CTF Chrome short temporary parent is not repository-owned")
    # Reserve space for Chromium's own socket basename; this bounds only the
    # private TMP root, not an unobserved internal socket path.
    if len(str(parent).encode()) + len("/c-") + 8 > 80:
        raise RuntimeError("CTF Chrome private temporary root is too long")
    return parent


def process_group_exists(pgid, *, runner=subprocess.run, env=None):
    if sys.platform == "darwin" and runner is subprocess.run:
        return bool(native_owned_group_members(pgid))
    result = runner(["ps", "-axo", "pgid=,stat="], env=env, capture_output=True,
                    text=True, timeout=10)
    if result.returncode != 0:
        raise RuntimeError(f"Owned process-group probe failed: {pgid}")
    return any(fields and fields[0] == str(pgid)
               for fields in (line.split() for line in result.stdout.splitlines()))


def assert_group_identity(pgid, session_id, uid, *, runner=subprocess.run, env=None,
                          getsid=os.getsid, birth=None):
    """Reject unknown/foreign membership before signaling the owned group."""
    if not isinstance(session_id, int) or session_id <= 1 or not isinstance(uid, int):
        raise RuntimeError("Owned process identity was not captured")
    if sys.platform == "darwin" and runner is subprocess.run and getsid is os.getsid:
        if session_id != pgid:
            raise RuntimeError("Refusing to signal foreign process session")
        members = native_owned_group_members(pgid, uid=uid)
        if members and (not isinstance(birth, tuple) or len(birth) != 2
                        or native_leader_birth(pgid, session_id, uid) != birth):
            raise RuntimeError("Original process-group leader birth changed")
        return
    result = runner(["ps", "-axo", "pid=,pgid=,uid="], env=env,
                    capture_output=True, text=True, timeout=10)
    if result.returncode != 0:
        raise RuntimeError("Owned process identity probe failed")
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) != 3:
            raise RuntimeError("Malformed process identity probe")
        try:
            pid, group, owner = map(int, fields)
        except ValueError as error:
            raise RuntimeError("Malformed process identity probe") from error
        if group != pgid:
            continue
        if owner != uid:
            raise RuntimeError("Refusing to signal foreign process owner")
        try:
            current_session = getsid(pid)
        except ProcessLookupError:
            continue
        if current_session != session_id:
            raise RuntimeError("Refusing to signal foreign process session")


def stop_group(child, *, env=None, group_exists=process_group_exists, killpg=os.killpg,
               monotonic=time.monotonic, sleep=time.sleep, term_seconds=8, kill_seconds=3,
               check_identity=assert_group_identity):
    pgid = getattr(child, "_owned_pgid", None)
    if not isinstance(pgid, int) or pgid <= 1:
        raise RuntimeError("Owned process group was not captured")
    birth = getattr(child, "_owned_birth", None)
    if sys.platform == "darwin" and (not isinstance(birth, tuple) or len(birth) != 2
                                      or any(type(value) is not int or value < 0 for value in birth)):
        raise RuntimeError("Original process-group launch birth is unavailable")
    child.poll()
    if group_exists(pgid, env=env):
        try:
            check_identity(pgid, child._owned_sid, child._owned_uid, env=env, birth=birth)
            killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = monotonic() + term_seconds
        while monotonic() < deadline:
            child.poll()
            if not group_exists(pgid, env=env):
                break
            sleep(0.1)
    if group_exists(pgid, env=env):
        try:
            check_identity(pgid, child._owned_sid, child._owned_uid, env=env, birth=birth)
            killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        deadline = monotonic() + kill_seconds
        while monotonic() < deadline:
            child.poll()
            if not group_exists(pgid, env=env):
                break
            sleep(0.1)
    if child.poll() is None:
        try:
            child.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
    child.poll()
    if group_exists(pgid, env=env):
        raise RuntimeError(f"Owned process group remains: {pgid}")
    return child.returncode


def cleanup_containers(intents, docker, base_env, logs_root=None, *, runner=subprocess.run):
    rows, errors = [], []
    for intent in reversed(intents):
        row = dict(intent)
        if logs_root is not None and intent.get("creationAttempted"):
            # Container diagnostics are optional.  Do not make cleanup depend on
            # an unbounded docker-logs stream; retain an explicit omission record.
            row["privateLog"] = {"status": "omitted", "reason": "bounded cleanup path"}
        try:
            present = True
            if not intent.get("containerId"):
                discovery = runner(docker + ["inspect", intent["name"]], env=base_env,
                                    capture_output=True, text=True, timeout=30)
                if discovery.returncode == 1:
                    present = False
                elif discovery.returncode != 0:
                    raise RuntimeError(f"Owned container discovery failed: {intent['name']}")
                else:
                    rows_found = json.loads(discovery.stdout)
                    discovered_id = _container_id(rows_found[0].get("Id"))
                    if not discovered_id:
                        raise RuntimeError(f"Owned container id was not returned: {intent['name']}")
                    intent["containerId"] = discovered_id
                    inspect_owned_container(intent, docker, base_env, runner=runner)
            else:
                inspect_owned_container(intent, docker, base_env, runner=runner)
            if present:
                removed = runner(docker + ["rm", "--force", intent["containerId"]], env=base_env,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
                if removed.returncode not in (0, 1):
                    raise RuntimeError(f"Owned container removal failed: {intent['name']}")
        except Exception as error:
            errors.append(error)
        try:
            probe = runner(docker + ["ps", "-a", "--no-trunc",
                "--format", "{{.ID}}\t{{.Names}}"],
                env=base_env, capture_output=True, text=True, timeout=30)
            if probe.returncode != 0:
                raise RuntimeError(f"Owned container absence probe failed: {intent['name']}")
            rows_found = [line.split("\t", 1) for line in probe.stdout.splitlines() if line.strip()]
            if any((len(parts) != 2 or parts[0] == intent.get("containerId") or
                    parts[1] == intent["name"]) for parts in rows_found):
                raise RuntimeError(f"Owned container absence verification failed: {intent['name']}")
            row["containerId"] = intent.get("containerId")
            row["cleanup"] = "absent_verified"
        except Exception as error:
            row["cleanup"] = "failed"
            row["error"] = f"{type(error).__name__}: {error}"
            errors.append(error)
        rows.append(row)
    return rows, errors


def child_identity(child):
    return {"name": child._owned_name, "pid": child.pid, "pgid": child._owned_pgid,
            "sid": child._owned_sid, "uid": child._owned_uid,
            "birth": getattr(child, "_owned_birth", None)}


def finalize_owned(children, logs, container_intents, docker, base_env, cleanup_receipt,
                   container_logs_root=None, *, require_quiescent_before_container_cleanup=False,
                   quiescence_check=None):
    errors, process_rows = [], []
    stop_unverified = False
    for child in reversed(children):
        row = child_identity(child)
        try:
            row["returncode"] = stop_group(child, env=base_env)
            row["cleanup"] = "absent_verified"
        except Exception as error:
            row["returncode"] = child.poll()
            row["cleanup"] = "failed"
            row["error"] = f"{type(error).__name__}: {error}"
            errors.append(error)
            stop_unverified = True
        process_rows.append(row)
    if require_quiescent_before_container_cleanup and not stop_unverified:
        try:
            if quiescence_check is None:
                raise RuntimeError("Full Reset complete child/browser roster check is missing")
            quiescence_check()
        except Exception as error:
            errors.append(error)
            stop_unverified = True
    for handle in reversed(logs):
        try:
            handle.close()
        except Exception as error:
            errors.append(error)
    if require_quiescent_before_container_cleanup and stop_unverified:
        # The exact owned DB intent remains available for a later verified
        # cleanup.  Retiring it now could destroy the only backing evidence
        # while an unverified browser or child still observes the state.
        container_rows = [dict(intent, cleanup="retained_quiescence_unverified")
            for intent in reversed(container_intents)]
    else:
        container_rows, container_errors = cleanup_containers(
            container_intents, docker, base_env, container_logs_root)
        errors.extend(container_errors)
    try:
        write_private_json(cleanup_receipt, {"schemaVersion": 1,
            "processes": sorted(process_rows, key=lambda row: row["name"]),
            "containers": sorted(container_rows, key=lambda row: row["name"])})
    except Exception as error:
        errors.append(error)
    return errors


def add_cleanup_errors(primary, errors):
    if not errors:
        return
    details = "; ".join(f"{type(error).__name__}: {error}" for error in errors)
    if primary is not None:
        primary.add_note(f"Owned cleanup errors: {details}")
        return
    raise RuntimeError(f"Owned cleanup failed: {details}")


def main_no_copy_selection(args):
    return args.ctf_publication_current or args.ctf_ten_content or args.ctf_config_rendered or args.ctf_preview_rendered or args.ctf_learner_entry_hint_rendered or args.ctf_learner_attempt_gate_rendered or args.ctf_fixed_practice_rendered or args.ctf_full_reset_rendered or args.ctf_stage6_current_main or args.ctf_stage6_adoption or args.ctf_teaching_content


def main_no_copy_environment(runtime, *, repository_only=False):
    directories = ("tmp", "cache", "config", "docker-config") if repository_only else ("home", "tmp", "cache")
    for name in directories:
        directory = runtime / name
        if directory.is_symlink():
            raise RuntimeError("Main-workspace runtime directory is a symlink")
        directory.mkdir(mode=0o700, exist_ok=True)
        if directory.resolve() != directory or directory.stat().st_uid != os.getuid() \
                or directory.stat().st_mode & 0o077:
            raise RuntimeError("Main-workspace runtime directory is not private")
    result = {"TMPDIR": str(runtime / "tmp"), "XDG_CACHE_HOME": str(runtime / "cache")}
    if repository_only:
        result.update(TMP=str(runtime / "tmp"), TEMP=str(runtime / "tmp"),
                      XDG_CONFIG_HOME=str(runtime / "config"),
                      DOCKER_CONFIG=str(runtime / "docker-config"),
                      PUPPETEER_CACHE_DIR=str(runtime / "cache"))
    else:
        result["HOME"] = str(runtime / "home")
    return result


def run_qualification(args):
    source = Path(__file__).resolve().parents[2]
    if args.ctf_publication_current:
        assert_current_publication_source(source)  # Exact fixture and migration before allocation.
    rendered_private = args.ctf_ten_content or args.ctf_config_rendered or args.ctf_preview_rendered or args.ctf_learner_entry_hint_rendered or args.ctf_learner_attempt_gate_rendered or args.ctf_fixed_practice_rendered or args.ctf_full_reset_rendered
    repository_private = rendered_private or args.ctf_publication_current
    if rendered_private:
        ctf_complete_roster()  # Before allocating an owned run or browser.
        short_tmp_parent = ten_content_short_tmp_parent(source)
    node = validate_executable(args.node, args.node_sha256, "Managed Node")
    browser = validate_executable(args.browser_executable, args.browser_sha256, "Owned browser") if (args.ctf_recovery_rendered or rendered_private or args.ctf_stage6_current_main) else None
    docker_cli = validate_executable(args.docker_cli, args.docker_cli_sha256, "Docker CLI")
    image_id = args.image_id if repository_private else POSTGRES_IMAGE_ID
    run_parent = ten_content_run_parent(source) if repository_private else None
    root = Path(tempfile.mkdtemp(prefix="owasp-ai-goat-ctf-stages-route-",
        dir=run_parent)).resolve()
    os.chmod(root, 0o700)
    browser_tmp = None
    if rendered_private:
        browser_tmp = Path(tempfile.mkdtemp(prefix="f-" if args.ctf_full_reset_rendered or args.ctf_fixed_practice_rendered else "a-" if args.ctf_learner_attempt_gate_rendered else "l-" if args.ctf_learner_entry_hint_rendered else "p-" if args.ctf_preview_rendered else "g-" if args.ctf_config_rendered else "c-", dir=short_tmp_parent)).resolve()
        os.chmod(browser_tmp, 0o700)
    workspace = root / "source"
    workspace.mkdir(mode=0o700)
    runtime = root / "runtime"
    runtime.mkdir(mode=0o700)
    rendered_evidence = root / "rendered-evidence"  # Deterministic even if provisioning fails early.
    main_no_copy = main_no_copy_selection(args)
    private_build_report = args.ctf_stage6_current_main
    test_workspace = runtime if main_no_copy else workspace
    app_logs = root / "application-logs"
    app_logs.mkdir(mode=0o700)
    base_env = {key: os.environ[key] for key in ("PATH",) if key in os.environ}
    if main_no_copy:
        base_env.update(main_no_copy_environment(runtime, repository_only=repository_private))
    else:
        base_env.update({key: os.environ[key] for key in ("HOME", "TMPDIR") if key in os.environ})
    docker = [str(docker_cli), "--host", args.docker_host]
    nonce = uuid.uuid4().hex[:12]
    container = f"owasp-ai-goat-ctf-stages-{nonce}"
    container_intents = [{"name": container, "nonce": nonce, "owner": CONTAINER_OWNER_LABEL,
        "image": image_id,
        "creationAttempted": False}]
    children, logs = [], []
    container_intent_path = root / "container-intent.json"
    child_intent_path = root / "child-process-intent.json"
    cleanup_receipt = root / "cleanup.json"
    ownership_path = root / "ownership.json"
    result_path = root / "result.tap"
    primary = None
    provision_secret = None
    receipt_path = None
    blocklist_receipt_path = None
    participant_reset_receipt_path = None
    participant_remove_receipt_path = None
    participant_ban_receipt_path = None
    advanced_stage_save_receipt_path = None
    stage_active_receipt_path = None
    stage_delete_receipt_path = None
    config_receipt_path = None
    preview_receipt_path = None
    learner_entry_hint_receipt_path = None
    learner_attempt_gate_receipt_path = None
    fixed_practice_receipt_path = None
    teaching_save_receipt_path = None
    full_reset_receipt_path = None
    browser_monitor_stop = threading.Event()
    browser_monitor = {"thread": None, "row": None, "error": None}
    signal_state = {"finalizing": False, "signum": None}

    def interrupted(signum, _frame):
        signal_state["signum"] = signum
        if not signal_state["finalizing"]:
            raise OwnedSignalExit(128 + signum)

    previous_signals = {signal.SIGTERM: signal.signal(signal.SIGTERM, interrupted),
                        signal.SIGINT: signal.signal(signal.SIGINT, interrupted)}

    def run(command, **kwargs):
        kwargs.setdefault("timeout", 60)
        kwargs.setdefault("env", base_env)
        return subprocess.run(command, check=True, **kwargs)

    selection = qualification_selection(args, nonce)
    stage_end = selection["stageEnd"]
    qualification_mode = selection["mode"]
    state = {"schemaVersion": 1, "runStatus": "preparing", "stageEnd": stage_end,
        "targetStage": args.target_stage, "qualificationMode": qualification_mode,
        "evidence": str(root), "managedNode": {"path": str(node), "sha256": args.node_sha256},
        "dockerCli": {"path": str(docker_cli), "sha256": args.docker_cli_sha256,
            "host": args.docker_host}, "postgresImageId": image_id,
        "container": container, "nonce": nonce}
    write_private_json(container_intent_path, {"schemaVersion": 1,
        "containers": container_intents})
    write_private_json(ownership_path, state)

    previous_alarm = None
    dotenv_before = dotenv_inventory(source) if main_no_copy else None
    if selection["workSeconds"]:
        def deadline_expired(_signum, _frame):
            raise TimeoutError("Owned session-fence phase deadline exceeded")
        previous_alarm = signal.signal(signal.SIGALRM, deadline_expired)
        signal.setitimer(signal.ITIMER_REAL, selection["workSeconds"])
    state["bounds"] = {key: selection[key] for key in ("childSeconds", "workSeconds", "cleanupSeconds")}
    try:
        if main_no_copy:
            state["daemon"] = docker_daemon_identity(docker, base_env)
            if state["daemon"]["id"] != args.docker_daemon_id:
                raise RuntimeError("Docker daemon identity does not match the admitted pin")
        state["dependencies"] = verified_dependency_snapshot(
            source / "node_modules", args.dependency_manifest_sha256)
        if main_no_copy:
            source_entries = content_source_inventory(source)
            if manifest_digest(source_entries) != args.content_source_manifest_sha256:
                raise RuntimeError("Source manifest pin mismatch")
            state["source"] = {"count": len(source_entries), "sha256": args.content_source_manifest_sha256, "mode": "main-workspace-no-copy"}
            if not (args.ctf_publication_current or args.ctf_stage6_adoption or args.ctf_teaching_content):
                client_source_entries = client_inventory(source / "client")
                if manifest_digest(client_source_entries) != args.client_source_sha256:
                    raise RuntimeError("Client source manifest pin mismatch")
                state["clientSource"] = {"count": len(client_source_entries), "sha256": args.client_source_sha256}
                state["clientDependencies"] = verified_dependency_snapshot(
                    source / "client" / "node_modules", args.client_dependency_sha256)
                if rendered_private:
                    report_path = Path(args.client_build_report)
                    if report_path.is_symlink() or not report_path.is_file() or sha256(report_path) != args.client_build_report_sha256:
                        raise RuntimeError("Frontend build report pin mismatch")
                    report_mode = json.loads(report_path.read_text(encoding="utf-8")).get("inputMode")
                    if report_mode != "legacy":
                        raise RuntimeError("CTF ten-content requires repository-only installed build report")
                    private_build_report = False
                state["buildReport"] = validate_frontend_build_report(source, args.client_build_report,
                    args.client_build_report_sha256, args.client_build_input_sha256,
                    args.client_build_output_sha256, args.client_build_recorder_sha256,
                    private_external=private_build_report, repository_required=bool(args.ctf_stage6_current_main), require_installed_match=not rendered_private)
                state["clientBuild"] = validate_prebuilt_build(source, args.client_build_sha256)
            source_inventory_path = runtime / "content-source-inventory.json"
            write_private_json(source_inventory_path, source_entries)
            state["contentSourceInventory"] = {"path": str(source_inventory_path),
                "sha256": sha256(source_inventory_path)}
        else:
            state["source"] = copy_frozen_source(source, workspace, args.source_manifest_sha256)
        if browser is not None:
            if main_no_copy:
                state["client"] = {"sourceSha256": args.client_source_sha256, "mode": "main-workspace-build"}
            else:
                state["client"] = copy_rendered_client(source, workspace, args.client_source_sha256, args.client_dependency_sha256)
            state["browser"] = {"path": str(browser), "sha256": args.browser_sha256}
        state["runStatus"] = "source_frozen"
        write_private_json(ownership_path, state)
        if repository_private:
            state["postgresImage"] = validate_current_host_postgres_image(docker, image_id, base_env)
        else:
            image = run(docker + ["image", "inspect", image_id, "--format", "{{.Id}}"],
                        capture_output=True, text=True).stdout.strip()
            if image != image_id:
                raise RuntimeError("Pinned PostgreSQL image is unavailable")
        container_intents[0]["creationAttempted"] = True
        write_private_json(container_intent_path, {"schemaVersion": 1,
            "containers": container_intents})
        if provision_case(selection):
            provision_secret, admin_password = create_provision_secret(root, nonce)
            authentication = ["--env-file", str(provision_secret["path"]), "-e", "POSTGRES_HOST_AUTH_METHOD=scram-sha-256",
                "-e", "POSTGRES_INITDB_ARGS=--wal-segsize=1 --auth-host=scram-sha-256"]
        else:
            authentication = ["-e", "POSTGRES_HOST_AUTH_METHOD=trust", "-e", "POSTGRES_INITDB_ARGS=--wal-segsize=1"]
        created = run(docker + ["run", "--detach", "--pull", "never", "--name", container,
            "--label", f"{CONTAINER_OWNER_LABEL}={CONTAINER_OWNER_LABEL}",
            "--label", f"{CONTAINER_NONCE_LABEL}={nonce}",
            "--tmpfs", f"/var/lib/postgresql:rw,size={selection.get('tmpfsBytes', 268435456)}",
            "-e", "POSTGRES_USER=ctf_stages_admin", *authentication, "-p", "127.0.0.1::5432",
            image_id, "-c", "shared_buffers=16MB", "-c", "max_connections=40",
            "-c", "max_wal_size=16MB", "-c", "min_wal_size=4MB"], capture_output=True, text=True)
        created_id = _container_id(created.stdout)
        if created_id:
            container_intents[0]["containerId"] = created_id
        inspect_owned_container(container_intents[0], docker, base_env, runner=subprocess.run)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            probe = subprocess.run(docker + ["exec", container, "pg_isready", "-h", "127.0.0.1", "-p", "5432", "-U", "ctf_stages_admin"],
                env=base_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            if probe.returncode == 0:
                break
            time.sleep(0.25)
        else:
            raise RuntimeError("Owned PostgreSQL container did not become ready")
        port = int(run(docker + ["port", container, "5432"], capture_output=True,
                       text=True).stdout.strip().rsplit(":", 1)[1])
        psql = docker + ["exec", container, "psql", "-U", "ctf_stages_admin",
            "-d", "postgres", "-v", "ON_ERROR_STOP=1"]
        if not provision_case(selection):
            roles = ("dvaia_identity_migration", "dvaia_identity_runtime",
                     "dvaia_ctf_migration", "dvaia_ctf_runtime")
            for role in roles + ((delivery_role(selection),) if delivery_role(selection) else ()):
                run(psql + ["-c", f"CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"], stdout=subprocess.DEVNULL)
            databases = tuple((database, roles[(index % 2) * 2], roles[(index % 2) * 2 + 1])
                for index, database in enumerate(selection["databases"]))
            urls = {}
            for database, migration, runtime_role in databases:
                run(psql + ["-c", f"CREATE DATABASE {database} OWNER {migration}"], stdout=subprocess.DEVNULL)
                run(psql + ["-c", f"REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{runtime_role}"], stdout=subprocess.DEVNULL)
                urls[database] = {"migration": f"postgresql://{quote(migration)}@127.0.0.1:{port}/{database}",
                    "runtime": f"postgresql://{quote(runtime_role)}@127.0.0.1:{port}/{database}"}
                if delivery_database(selection, database):
                    run(psql + ["-c", f"GRANT CONNECT ON DATABASE {database} TO dvaia_ctf_delivery"], stdout=subprocess.DEVNULL)
                    urls[database]["delivery"] = f"postgresql://dvaia_ctf_delivery@127.0.0.1:{port}/{database}"
        env = dict(base_env, NODE_ENV="test", PG_TEST_DISPOSABLE="yes",
            PLATFORM_DATABASE_ENGINE="postgres",
            WORKSHOP_DATABASE_ENGINE="postgres",
            JWT_SECRET=uuid.uuid4().hex + uuid.uuid4().hex,
            LOGS_DIR=str(app_logs), OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=str(root if repository_private else test_workspace))
        if args.ctf_publication_current:
            env["OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE"] = str(source)
        if provision_case(selection):
            env["PG_ADMIN_DATABASE_URL"] = f"postgresql://ctf_stages_admin:{admin_password}@127.0.0.1:{port}/postgres"
        else:
            env.update(database_environment(selection, urls))
        env.update(selection["environment"])
        if browser is not None:
            rendered_evidence.mkdir(mode=0o700)
            env.update(PUPPETEER_EXECUTABLE_PATH=str(browser), CTF_RENDERED_EVIDENCE=str(rendered_evidence))
            if main_no_copy:
                env.update(ANALYTICS_BROWSER_EXECUTABLE=str(browser), ANALYTICS_BROWSER_SHA256=args.browser_sha256)
        if args.ctf_stage6_current_main:
            env.update(CTF_STAGE6_EVIDENCE_ROOT=str(root),
                CTF_STAGE6_BUILD_DIRECTORY=str(Path(state["buildReport"]["outputRoot"]).resolve()),
                OWASP_AI_GOAT_CONTENT_DENY_DOTENV="1")
        if rendered_private:
            if args.ctf_full_reset_rendered:
                full_reset_receipt_path = runtime / "ctf-full-reset-q05-result.json"
            elif args.ctf_config_rendered:
                config_receipt_path = runtime / "ctf-config-q05-result.json"
            elif args.ctf_preview_rendered:
                preview_receipt_path = runtime / "ctf-preview-q05-result.json"
            elif args.ctf_learner_entry_hint_rendered:
                learner_entry_hint_receipt_path = runtime / "ctf-learner-entry-hint-q05-result.json"
            elif args.ctf_learner_attempt_gate_rendered:
                learner_attempt_gate_receipt_path = runtime / "ctf-learner-attempt-gate-q05-result.json"
            elif args.ctf_fixed_practice_rendered:
                fixed_practice_receipt_path = runtime / "ctf-fixed-practice-q05-result.json"
            else:
                receipt_path = runtime / "ctf-ten-content-result.json"
                blocklist_receipt_path = runtime / "ctf-blocklist-q05-result.json"
                participant_reset_receipt_path = runtime / "ctf-participant-reset-q05-result.json"
                participant_remove_receipt_path = runtime / "ctf-participant-remove-q05-result.json"
                participant_ban_receipt_path = runtime / "ctf-participant-ban-q05-result.json"
                advanced_stage_save_receipt_path = runtime / "ctf-advanced-stage-save-q05-result.json"
                stage_active_receipt_path = runtime / "ctf-stage-active-q05-result.json"
                stage_delete_receipt_path = runtime / "ctf-stage-delete-q05-result.json"
                teaching_save_receipt_path = runtime / "ctf-teaching-save-q05-result.json"
            browser_stem = "full-reset-browser" if args.ctf_full_reset_rendered else "fixed-practice-browser" if args.ctf_fixed_practice_rendered else "learner-attempt-gate-browser" if args.ctf_learner_attempt_gate_rendered else "learner-entry-hint-browser" if args.ctf_learner_entry_hint_rendered else "preview-browser" if args.ctf_preview_rendered else "config-browser" if args.ctf_config_rendered else "content-browser"
            browser_record = rendered_evidence / f"{browser_stem}-birth.json"
            browser_ack = rendered_evidence / f"{browser_stem}-ack.json"
            env.update(CTF_CONTENT_SOURCE_ROOT=str(source),
                       CTF_CONTENT_RUNTIME_DIRECTORY=str(runtime),
                       CTF_CONTENT_SOURCE_INVENTORY=str(source_inventory_path),
                       CTF_CONTENT_SOURCE_INVENTORY_SHA256=sha256(source_inventory_path),
                       CTF_CONTENT_SOURCE_MANIFEST_SHA256=args.content_source_manifest_sha256,
                       CTF_CONTENT_BUILD_DIRECTORY=str(Path(state["buildReport"]["outputRoot"]).resolve() if private_build_report else source / "client" / "build"),
                       CTF_CONTENT_BUILD_SHA256=args.client_build_sha256,
                       CTF_CONTENT_BUILD_OUTPUT_SHA256=args.client_build_output_sha256,
                       CTF_CONTENT_BUILD_REPORT_SHA256=args.client_build_report_sha256,
                       CTF_CONTENT_BUILD_REPORT=args.client_build_report,
                       CTF_CONTENT_BUILD_INPUT_INVENTORY_SHA256=args.client_build_input_sha256,
                       CTF_CONTENT_BUILD_RECORDER_SHA256=args.client_build_recorder_sha256,
                       CTF_CONTENT_CLIENT_SOURCE_SHA256=args.client_source_sha256,
                       CTF_CONTENT_CLIENT_DEPENDENCY_SHA256=args.client_dependency_sha256,
                       SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT=str(source / "tests/postgres/secureshop_darwin_browser_birth.py"),
                       SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON=str(Path(sys.executable).resolve()),
                       OWASP_AI_GOAT_CONTENT_DENY_DOTENV="1")
            if args.ctf_full_reset_rendered:
                env.update(CTF_FULL_RESET_SOURCE_ROOT=str(source),
                           CTF_FULL_RESET_RUNTIME_DIRECTORY=str(runtime),
                           CTF_FULL_RESET_Q05_RECEIPT=str(full_reset_receipt_path),
                           CTF_FULL_RESET_BROWSER_NATIVE="1",
                           CTF_FULL_RESET_BROWSER_RECORD=str(browser_record),
                           CTF_FULL_RESET_BROWSER_ACK=str(browser_ack),
                           CTF_FULL_RESET_BROWSER_TMP=str(browser_tmp))
            else:
                if args.ctf_learner_entry_hint_rendered:
                    env.update(CTF_LEARNER_ENTRY_HINT_Q05_RECEIPT=str(learner_entry_hint_receipt_path),
                               CTF_LEARNER_ENTRY_HINT_MAX_BROWSER_ACTIONS="400", CTF_LEARNER_ENTRY_HINT_MAX_API_REQUESTS="400",
                               CTF_LEARNER_ENTRY_HINT_DEADLINE_MS="180000", CTF_LEARNER_ENTRY_HINT_BROWSER_NATIVE="1",
                               CTF_LEARNER_ENTRY_HINT_BROWSER_RECORD=str(browser_record),
                               CTF_LEARNER_ENTRY_HINT_BROWSER_ACK=str(browser_ack),
                               CTF_LEARNER_ENTRY_HINT_BROWSER_TMP=str(browser_tmp))
                elif args.ctf_learner_attempt_gate_rendered:
                    env.update(CTF_LEARNER_ATTEMPT_GATE_Q05_RECEIPT=str(learner_attempt_gate_receipt_path),
                               CTF_LEARNER_ATTEMPT_GATE_MAX_BROWSER_ACTIONS="800", CTF_LEARNER_ATTEMPT_GATE_MAX_API_REQUESTS="800",
                               CTF_LEARNER_ATTEMPT_GATE_MAX_GUARDIAN_CALLS="3", CTF_LEARNER_ATTEMPT_GATE_MAX_JUDGE_CALLS="6",
                               CTF_LEARNER_ATTEMPT_GATE_MAX_PROVIDER_CALLS="9", CTF_LEARNER_ATTEMPT_GATE_DEADLINE_MS="360000",
                               CTF_LEARNER_ATTEMPT_GATE_BROWSER_NATIVE="1", CTF_LEARNER_ATTEMPT_GATE_BROWSER_RECORD=str(browser_record),
                               CTF_LEARNER_ATTEMPT_GATE_BROWSER_ACK=str(browser_ack),
                               CTF_LEARNER_ATTEMPT_GATE_BROWSER_TMP=str(browser_tmp))
                elif args.ctf_fixed_practice_rendered:
                    env.update(CTF_FIXED_PRACTICE_Q05_RECEIPT=str(fixed_practice_receipt_path),
                               CTF_FIXED_PRACTICE_MAX_BROWSER_ACTIONS="240", CTF_FIXED_PRACTICE_MAX_API_REQUESTS="240",
                               CTF_FIXED_PRACTICE_MAX_PROVIDER_CALLS="2", CTF_FIXED_PRACTICE_DEADLINE_MS="120000",
                               CTF_FIXED_PRACTICE_BROWSER_NATIVE="1", CTF_FIXED_PRACTICE_BROWSER_RECORD=str(browser_record),
                               CTF_FIXED_PRACTICE_BROWSER_ACK=str(browser_ack), CTF_FIXED_PRACTICE_BROWSER_TMP=str(browser_tmp))
                elif args.ctf_preview_rendered:
                    env.update(CTF_PREVIEW_Q05_RECEIPT=str(preview_receipt_path),
                               CTF_PREVIEW_MAX_BROWSER_ACTIONS="1200", CTF_PREVIEW_MAX_API_REQUESTS="1200",
                               CTF_PREVIEW_MAX_PROVIDER_CALLS="2", CTF_PREVIEW_DEADLINE_MS="360000",
                               CTF_PREVIEW_BROWSER_NATIVE="1", CTF_PREVIEW_BROWSER_RECORD=str(browser_record),
                               CTF_PREVIEW_BROWSER_ACK=str(browser_ack), CTF_PREVIEW_BROWSER_TMP=str(browser_tmp))
                elif args.ctf_config_rendered:
                    env.update(CTF_CONFIG_Q05_RECEIPT=str(config_receipt_path),
                               CTF_CONFIG_MAX_BROWSER_ACTIONS="1200", CTF_CONFIG_MAX_API_REQUESTS="1200",
                               CTF_CONFIG_DEADLINE_MS="360000", CTF_CONFIG_BROWSER_NATIVE="1",
                               CTF_CONFIG_BROWSER_RECORD=str(browser_record),
                               CTF_CONFIG_BROWSER_ACK=str(browser_ack),
                               CTF_CONFIG_BROWSER_TMP=str(browser_tmp))
                else:
                    env.update(CTF_TEN_CONTENT_RECEIPT=str(receipt_path),
                           CTF_BLOCKLIST_Q05_RECEIPT=str(blocklist_receipt_path),
                           CTF_PARTICIPANT_RESET_Q05_RECEIPT=str(participant_reset_receipt_path),
                           CTF_PARTICIPANT_BAN_Q05_RECEIPT=str(participant_ban_receipt_path),
                           CTF_ADVANCED_STAGE_SAVE_Q05_RECEIPT=str(advanced_stage_save_receipt_path),
                           CTF_STAGE_ACTIVE_Q05_RECEIPT=str(stage_active_receipt_path),
                           CTF_STAGE_DELETE_Q05_RECEIPT=str(stage_delete_receipt_path),
                           CTF_TEACHING_SAVE_Q05_RECEIPT=str(teaching_save_receipt_path),
                           CTF_TEN_CONTENT_BROWSER_NATIVE="1",
                           CTF_CONTENT_BROWSER_RECORD=str(browser_record),
                           CTF_CONTENT_BROWSER_ACK=str(browser_ack),
                           CTF_CONTENT_BROWSER_TMP=str(browser_tmp))
        child_test = str(source / selection["test"]) if main_no_copy else selection["test"]
        child = subprocess.Popen(child_test_command(node, child_test,
            ten_content=rendered_private), cwd=test_workspace, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        child._owned_name = "ctf_stages_route_test"
        child._owned_pgid = child.pid
        child._owned_sid = child.pid  # start_new_session=True
        child._owned_uid = os.getuid()
        children.append(child)
        try:
            child._owned_birth = capture_launch_birth(child)
        except BaseException:
            write_private_json(child_intent_path, {"schemaVersion": 1,
                "processes": [child_identity(item) for item in children]})
            raise
        write_private_json(child_intent_path, {"schemaVersion": 1,
            "processes": [child_identity(item) for item in children]})
        state["runStatus"] = "running"
        state["child"] = child_identity(child)
        write_private_json(ownership_path, state)
        deadline = time.monotonic() + selection["childSeconds"]
        if rendered_private:
            profile_name = "full-reset-profile" if args.ctf_full_reset_rendered else "fixed-practice-profile" if args.ctf_fixed_practice_rendered else "learner-attempt-gate-profile" if args.ctf_learner_attempt_gate_rendered else "learner-entry-hint-profile" if args.ctf_learner_entry_hint_rendered else "preview-profile" if args.ctf_preview_rendered else "config-profile" if args.ctf_config_rendered else "content-profile"
            birth_kind = "ctf_full_reset_browser" if args.ctf_full_reset_rendered else "ctf_fixed_practice_browser" if args.ctf_fixed_practice_rendered else "ctf_learner_attempt_gate_browser" if args.ctf_learner_attempt_gate_rendered else "ctf_learner_entry_hint_browser" if args.ctf_learner_entry_hint_rendered else "ctf_preview_browser" if args.ctf_preview_rendered else "ctf_config_browser" if args.ctf_config_rendered else "ctf_ten_content_browser"
            def observe_browser():
                try:
                    browser_monitor["row"] = acknowledge_ctf_browser(
                        browser_record, browser_ack, child, browser,
                        rendered_evidence / profile_name, kind=birth_kind,
                        stop=browser_monitor_stop,
                        deadline=deadline)
                except BaseException as error:
                    browser_monitor["error"] = error
            browser_monitor["thread"] = threading.Thread(
                target=observe_browser, name="ctf-rendered-browser-birth", daemon=False)
            browser_monitor["thread"].start()
        code, size = stream_child_output(child, result_path, deadline=deadline)
        record_child_result(state, result_path, code, size)
        if rendered_private:
            browser_monitor["thread"].join(timeout=1)
            if browser_monitor["thread"].is_alive() or browser_monitor["error"] is not None \
                    or browser_monitor["row"] is None:
                raise RuntimeError("CTF browser birth was not independently acknowledged")
            state["browserBirth"] = browser_monitor["row"]
            if args.ctf_full_reset_rendered:
                state["fullResetQ05Receipt"] = validate_full_reset_q05_receipt(full_reset_receipt_path)
            elif args.ctf_learner_entry_hint_rendered:
                state["learnerEntryHintQ05Receipt"] = validate_learner_entry_hint_q05_receipt(learner_entry_hint_receipt_path)
            elif args.ctf_learner_attempt_gate_rendered:
                state["learnerAttemptGateQ05Receipt"] = validate_learner_attempt_gate_q05_receipt(learner_attempt_gate_receipt_path)
            elif args.ctf_fixed_practice_rendered:
                state["fixedPracticeQ05Receipt"] = validate_fixed_practice_q05_receipt(fixed_practice_receipt_path)
            elif args.ctf_preview_rendered:
                state["previewQ05Receipt"] = validate_preview_q05_receipt(preview_receipt_path)
            elif args.ctf_config_rendered:
                state["configQ05Receipt"] = validate_config_q05_receipt(config_receipt_path)
            else:
                state["contentReceipt"] = validate_ten_content_receipt(receipt_path, state="FRESH")
                state["blocklistQ05Receipt"] = validate_blocklist_q05_receipt(blocklist_receipt_path)
                state["participantResetQ05Receipt"] = validate_participant_reset_q05_receipt(participant_reset_receipt_path)
                state["participantRemoveQ05Receipt"] = validate_participant_remove_q05_receipt(participant_remove_receipt_path)
                state["participantBanQ05Receipt"] = validate_participant_ban_q05_receipt(participant_ban_receipt_path)
                state["advancedStageSaveQ05Receipt"] = validate_advanced_stage_save_q05_receipt(advanced_stage_save_receipt_path)
                state["stageActiveQ05Receipt"] = validate_stage_active_q05_receipt(stage_active_receipt_path)
                state["stageDeleteQ05Receipt"] = validate_stage_delete_q05_receipt(stage_delete_receipt_path)
                state["teachingSaveQ05Receipt"] = validate_teaching_save_q05_receipt(teaching_save_receipt_path)
        else:
            verified_dependency_snapshot(source / "node_modules",
                                         args.dependency_manifest_sha256)
        state["runStatus"] = "test_pass"
    except BaseException as error:
        primary = error
        state["failure"] = {"type": type(error).__name__, "message": str(error)[:512]}
    finally:
        browser_monitor_stop.set()
        if browser_monitor["thread"] is not None:
            browser_monitor["thread"].join(timeout=2)
            if browser_monitor["thread"].is_alive() and primary is None:
                primary = RuntimeError("CTF browser birth observer remained active")
        if main_no_copy:
            postflight_errors = []
            def postflight(label, check):
                nonlocal primary
                try:
                    check()
                except BaseException as error:
                    postflight_errors.append(f"{label}: {error}")
                    if primary is None:
                        primary = error
            postflight("source", lambda: (_ for _ in ()).throw(RuntimeError("Source manifest changed during ten-content run"))
                if manifest_digest(content_source_inventory(source)) != args.content_source_manifest_sha256 else None)
            postflight("root-dependencies", lambda: verified_dependency_snapshot(source / "node_modules", args.dependency_manifest_sha256))
            if not (args.ctf_publication_current or args.ctf_stage6_adoption or args.ctf_teaching_content):
                postflight("client", lambda: (_ for _ in ()).throw(RuntimeError("Client source changed during ten-content run"))
                    if manifest_digest(client_inventory(source / "client")) != args.client_source_sha256 else None)
                postflight("client-dependencies", lambda: verified_dependency_snapshot(source / "client" / "node_modules", args.client_dependency_sha256))
                postflight("build", lambda: validate_prebuilt_build(source, args.client_build_sha256))
                postflight("build-report", lambda: validate_frontend_build_report(source, args.client_build_report,
                    args.client_build_report_sha256, args.client_build_input_sha256,
                    args.client_build_output_sha256, args.client_build_recorder_sha256,
                    private_external=private_build_report, repository_required=bool(args.ctf_stage6_current_main), require_installed_match=not rendered_private))
                postflight("browser", lambda: validate_executable(browser, args.browser_sha256, "Owned browser"))
            postflight("dotenv", lambda: (_ for _ in ()).throw(RuntimeError("Private dotenv inventory changed"))
                if dotenv_inventory(source) != dotenv_before else None)
            if args.ctf_full_reset_rendered:
                postflight("full-reset-receipt", lambda: validate_full_reset_q05_receipt(full_reset_receipt_path))
            elif args.ctf_learner_entry_hint_rendered:
                postflight("learner-entry-hint-receipt", lambda: validate_learner_entry_hint_q05_receipt(learner_entry_hint_receipt_path))
            elif args.ctf_learner_attempt_gate_rendered:
                postflight("learner-attempt-gate-receipt", lambda: validate_learner_attempt_gate_q05_receipt(learner_attempt_gate_receipt_path))
            elif args.ctf_fixed_practice_rendered:
                postflight("fixed-practice-receipt", lambda: validate_fixed_practice_q05_receipt(fixed_practice_receipt_path))
            elif args.ctf_preview_rendered:
                postflight("preview-receipt", lambda: validate_preview_q05_receipt(preview_receipt_path))
            elif args.ctf_config_rendered:
                postflight("config-receipt", lambda: validate_config_q05_receipt(config_receipt_path))
            elif args.ctf_ten_content:
                postflight("receipt", lambda: validate_ten_content_receipt(receipt_path))
                postflight("blocklist-receipt", lambda: validate_blocklist_q05_receipt(blocklist_receipt_path))
                postflight("participant-reset-receipt", lambda: validate_participant_reset_q05_receipt(participant_reset_receipt_path))
                postflight("participant-remove-receipt", lambda: validate_participant_remove_q05_receipt(participant_remove_receipt_path))
                postflight("participant-ban-receipt", lambda: validate_participant_ban_q05_receipt(participant_ban_receipt_path))
                postflight("advanced-stage-save-receipt", lambda: validate_advanced_stage_save_q05_receipt(advanced_stage_save_receipt_path))
                postflight("stage-active-receipt", lambda: validate_stage_active_q05_receipt(stage_active_receipt_path))
                postflight("stage-delete-receipt", lambda: validate_stage_delete_q05_receipt(stage_delete_receipt_path))
                postflight("teaching-save-receipt", lambda: validate_teaching_save_q05_receipt(teaching_save_receipt_path))
            postflight("daemon", lambda: (_ for _ in ()).throw(RuntimeError("Docker daemon identity changed during ten-content run"))
                if docker_daemon_identity(docker, base_env).get("id") != args.docker_daemon_id else None)
            if postflight_errors:
                state["postflightErrors"] = postflight_errors
            else:
                state["terminalPostflight"] = "source-client-build-dependencies-browser-receipt-daemon-checked"
        signal_state["finalizing"] = True
        if selection["cleanupSeconds"]:
            signal.setitimer(signal.ITIMER_REAL, selection["cleanupSeconds"])
        try:
            cleanup_errors = finalize_owned(children, logs, container_intents, docker, base_env,
                cleanup_receipt, root,
                require_quiescent_before_container_cleanup=args.ctf_full_reset_rendered,
                quiescence_check=(lambda: ctf_complete_roster(
                    profile=rendered_evidence / "full-reset-profile",
                    pgid=children[0].pid if children else -1)) if args.ctf_full_reset_rendered else None)
        except BaseException as cleanup_error:
            cleanup_errors = [cleanup_error]
        finally:
            if previous_alarm is not None:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, previous_alarm)
        if rendered_private:
            try:
                if cleanup_errors:
                    raise RuntimeError("CTF group/container cleanup was not verified")
                profile = rendered_evidence / ("full-reset-profile" if args.ctf_full_reset_rendered else "fixed-practice-profile" if args.ctf_fixed_practice_rendered else "learner-attempt-gate-profile" if args.ctf_learner_attempt_gate_rendered else "learner-entry-hint-profile" if args.ctf_learner_entry_hint_rendered else "preview-profile" if args.ctf_preview_rendered else "config-profile" if args.ctf_config_rendered else "content-profile")
                ctf_complete_roster(profile=profile,
                                    pgid=children[0].pid if children else -1)
                for directory in (profile, browser_tmp):
                    if directory.exists() or directory.is_symlink():
                        info = directory.lstat()
                        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() \
                                or stat.S_IMODE(info.st_mode) != 0o700 \
                                or directory.resolve() != directory:
                            raise RuntimeError("CTF browser profile/tmp cleanup target changed")
                        shutil.rmtree(directory)
                state["browserProfileCleanup"] = "complete-roster-absent-and-private-directories-removed"
            except BaseException as error:
                cleanup_errors.append(error)
                state["browserProfileCleanup"] = "unverified-retained"
        for signum, previous in previous_signals.items():
            signal.signal(signum, previous)
        if provision_secret is not None:
            try:
                remove_provision_secret(provision_secret)
                state["privateEnvironmentCleanup"] = "exact_identity_removed"
            except BaseException as error:
                cleanup_errors.append(error)
                state["privateEnvironmentCleanup"] = "failed"
        cleanup = None
        try:
            cleanup = json.loads(cleanup_receipt.read_text())
        except Exception:
            pass
        state["cleanup"] = cleanup
        state["runStatus"] = "terminal_pass_cleaned" if primary is None and not cleanup_errors else "terminal_fail"
        write_private_json(ownership_path, state)
        if primary is None and signal_state["signum"] is not None:
            primary = OwnedSignalExit(128 + signal_state["signum"])
        print(f"Owned CTF evidence retained at {root}", flush=True)
        add_cleanup_errors(primary, cleanup_errors)
    if primary is not None:
        raise primary


def main(argv=None):
    args = parse_args(argv)
    if not args.run:
        print("plan: no workspace, container, database, browser, model, or application mutation")
        return 0
    run_qualification(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
