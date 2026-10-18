#!/usr/bin/env python3
"""Run authentic mounted CTF stages in an owned frozen copy and disposable PG18."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import selectors
import subprocess
import tempfile
import time
import uuid
from urllib.parse import quote


POSTGRES_IMAGE_ID = "sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280"
MAX_LOG_BYTES = 16 * 1024 * 1024
CONTAINER_OWNER_LABEL = "org.dvaia.ctf-stages-runner"
CONTAINER_NONCE_LABEL = "org.dvaia.ctf-stages-nonce"
SOURCE_DIRECTORIES = ("server", "db", "tests", "docs")
SOURCE_FILES = ("package.json", "package-lock.json")
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
    selection.add_argument("--target-stage", type=int, choices=range(6, 11),
                           help="Qualify exactly one later stage with explicit unearned prerequisites")
    parser.add_argument("--candidate-set", choices=["instructor", "reviewer-boundary-v1", "stage6-fixed-v1"], default="instructor")
    parser.add_argument("--run", action="store_true", help="Root-controlled execution gate")
    args = parser.parse_args(argv)
    if (args.ctf_operation_recovery or args.ctf_recovery_rendered or args.ctf_ten_content or args.ctf_predefense_recovery or args.application_maintenance_lease or args.ctf_authority_application or args.ctf_stage6_adoption or args.ctf_teaching_content or args.ctf_production_runtime or args.ctf_response_diagnostics or args.ctf_authority_runtime or args.ctf_admin_read or args.ctf_registration_locator or args.ctf_delivery_provision_case or args.ctf_telemetry or args.ctf_delivery_activation or args.session_fence_only or args.authority_schema_only or args.ctf_lifecycle_schema or args.ctf_projection_worker or args.ctf_decision_schema or args.ctf_decision_projection or args.ctf_decision_recovery or args.ctf_current_publication or args.ctf_authority_bootstrap or args.ctf_current_response or args.ctf_student_deletion or args.ctf_admin_response or args.ctf_predefense or args.ctf_blocked_publication or args.ctf_blocked_predefense or args.ctf_worker_lifecycle or args.ctf_current_read) and args.candidate_set != "instructor":
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
    elif args.ctf_recovery_rendered or args.ctf_ten_content or args.ctf_stage6_current_main:
        if not all((args.browser_executable, args.browser_sha256, args.client_source_sha256, args.client_dependency_sha256)):
            parser.error("rendered/content selector requires explicit browser path and source/dependency digests")
        if (args.ctf_ten_content or args.ctf_stage6_current_main) and not all((args.client_build_sha256, args.client_build_output_sha256)):
            parser.error("ctf-ten-content requires parent and recorder prebuilt client/build manifest digests")
        if (args.ctf_ten_content or args.ctf_stage6_current_main) and not all((args.client_build_report, args.client_build_report_sha256, args.client_build_input_sha256, args.client_build_recorder_sha256)):
            parser.error("ctf-ten-content requires build report, input, and recorder digests")
        if (args.ctf_ten_content or args.ctf_stage6_current_main) and not all((args.content_source_manifest_sha256, args.docker_daemon_id)):
            parser.error("ctf-ten-content requires content source manifest and daemon identity pins")
    elif any((args.browser_executable, args.browser_sha256, args.client_source_sha256, args.client_dependency_sha256, args.client_build_sha256, args.client_build_output_sha256, args.client_build_report_sha256, args.client_build_report, args.client_build_input_sha256, args.client_build_recorder_sha256, args.content_source_manifest_sha256, args.docker_daemon_id)):
        parser.error("browser pin is only accepted by rendered selector")
    if args.ctf_stage6_current_main:
        if args.target_stage != 6 or args.candidate_set != "stage6-fixed-v1" or not args.stage6_candidate_sha256 or len(args.stage6_candidate_sha256) != 64 or any(c not in "0123456789abcdef" for c in args.stage6_candidate_sha256):
            parser.error("Stage 6 current-main requires target 6, closed fixed candidate, and exact SHA-256")
    elif args.candidate_set == "stage6-fixed-v1" or args.stage6_candidate_sha256:
        parser.error("Stage 6 fixed candidate requires current-main selector")
    return args


def qualification_selection(args, nonce):
    """Closed execution contract shared by launcher and resource-free controls."""
    if args.application_maintenance_lease:
        return {"mode": "application_maintenance_lease", "stageEnd": None,
            "test": "tests/postgres/applicationMaintenanceLease.integration.test.js",
            "databases": tuple(f"dvaia_test_lease_{index}_{nonce}" for index in (1, 2)),
            "childSeconds": 180, "workSeconds": 300, "cleanupSeconds": 120,
            "tmpfsBytes": 268435456,
            "environment": {"APPLICATION_MAINTENANCE_LEASE_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_authority_bootstrap:
        return {"mode": "ctf_authority_bootstrap_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfAuthorityBootstrap.integration.test.js",
            "databases": tuple(f"dvaia_test_ctf_bootstrap_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_AUTHORITY_BOOTSTRAP_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_blocked_publication:
        return {"mode": "ctf_blocked_publication_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfBlockedPublication.integration.test.js",
            "databases": tuple(f"dvaia_test_ctf_blockpub_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_BLOCKED_PUBLICATION_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_recovery_rendered:
        return {"mode": "ctf_recovery_rendered_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfAuthorityApplication.integration.test.js",
            "databases": tuple(f"dvaia_test_ctf_app_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 480, "workSeconds": 660, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_RECOVERY_RENDERED_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_ten_content:
        return {"mode": "ctf_ten_content_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfAuthorityApplication.integration.test.js",
            "databases": tuple(f"dvaia_test_ctf_app_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 480, "workSeconds": 660, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_TEN_CONTENT_ISOLATED": "1", "CTF_RECOVERY_RENDERED_ISOLATED": "1",
                "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_stage6_current_main:
        return {"mode": "ctf_stage6_current_main_actual", "stageEnd": 6,
            "test": "tests/postgres/ctfStagesRoute.integration.test.js",
            "databases": ("dvaia_test_ctf_stages_identity", "dvaia_test_ctf_stages_store"),
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
            "databases": tuple(f"dvaia_test_ctf_app_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_PREDEFENSE_RECOVERY_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_stage6_adoption:
        return {"mode": "ctf_stage6_adoption_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfAuthorityApplication.integration.test.js",
            "databases": tuple(f"dvaia_test_ctf_app_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_AUTHORITY_APPLICATION_ISOLATED": "1",
                "CTF_STAGE6_ADOPTION_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_teaching_content:
        return {"mode": "ctf_teaching_content_main", "stageEnd": None,
            "test": "tests/postgres/ctfAuthorityApplication.integration.test.js",
            "databases": tuple(f"dvaia_test_ctf_app_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_TEACHING_CONTENT_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_authority_application:
        return {"mode": "ctf_authority_application_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfAuthorityApplication.integration.test.js",
            "databases": tuple(f"dvaia_test_ctf_app_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_AUTHORITY_APPLICATION_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_production_runtime:
        return {"mode": "ctf_production_runtime_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfProductionRuntime.integration.test.js",
            "databases": tuple(f"dvaia_test_ctf_prod_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_PRODUCTION_RUNTIME_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_authority_runtime:
        return {"mode": "ctf_authority_runtime_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfAuthorityRuntime.integration.test.js",
            "databases": tuple(f"dvaia_test_ctf_runtime_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_AUTHORITY_RUNTIME_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_telemetry:
        return {"mode": "ctf_telemetry_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfTelemetry.integration.test.js",
            "databases": tuple(f"dvaia_test_ctf_telemetry_{state[0]}_{kind[0]}_{nonce}"
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
            "databases": tuple(f"dvaia_test_ctf_activation_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_DELIVERY_ACTIVATION_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_registration_locator:
        return {"mode": "ctf_registration_locator_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfRegistrationLocator.integration.test.js",
            "databases": tuple(f"dvaia_test_ctf_locator_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_REGISTRATION_LOCATOR_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_response_diagnostics:
        return {"mode": "ctf_response_diagnostics_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfResponseDiagnostics.integration.test.js",
            "databases": tuple(f"dvaia_test_ctf_diagnostics_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_RESPONSE_DIAGNOSTICS_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_admin_read:
        return {"mode": "ctf_admin_read_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfAdminRead.integration.test.js",
            "databases": tuple(f"dvaia_test_ctf_adminread_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_ADMIN_READ_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_blocked_predefense:
        return {"mode": "ctf_blocked_predefense_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfBlockedPredefense.integration.test.js",
            "databases": tuple(f"dvaia_test_ctf_blockpre_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_BLOCKED_PREDEFENSE_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_worker_lifecycle:
        return {"mode": "ctf_worker_lifecycle_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfProjectionWorkerLifecycle.integration.test.js",
            "databases": tuple(f"dvaia_test_ctf_worklife_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_WORKER_LIFECYCLE_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_predefense:
        return {"mode": "ctf_predefense_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfPredefense.integration.test.js",
            "databases": tuple(f"dvaia_test_ctf_predef_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_PREDEFENSE_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_student_deletion:
        return {"mode": "ctf_student_deletion_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfStudentDeletion.integration.test.js",
            "databases": tuple(f"dvaia_test_ctf_delete_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_DELETION_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_admin_response:
        return {"mode": "ctf_admin_response_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfAdminResponse.integration.test.js",
            "databases": tuple(f"dvaia_test_ctf_opread_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_ADMIN_RESPONSE_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_current_read:
        return {"mode": "ctf_current_read_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfCurrentRead.integration.test.js",
            "databases": tuple(f"dvaia_test_ctf_read_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_CURRENT_READ_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_current_response:
        return {"mode": "ctf_current_response_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfCurrentResponse.integration.test.js",
            "databases": tuple(f"dvaia_test_ctf_opread_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_CURRENT_RESPONSE_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_current_publication:
        return {"mode": "ctf_current_publication_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfCurrentPublication.integration.test.js",
            "databases": tuple(f"dvaia_test_ctf_publication_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_CURRENT_PUBLICATION_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_decision_recovery:
        return {"mode": "ctf_decision_recovery_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfDecisionRecovery.integration.test.js",
            "databases": tuple(f"dvaia_test_ctf_decision_recovery_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_DECISION_RECOVERY_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_operation_recovery:
        return {"mode": "ctf_operation_recovery_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfOperationRecovery.integration.test.js",
            "databases": tuple(f"dvaia_test_ctf_opread_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_OPERATION_RECOVERY_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_decision_projection:
        return {"mode": "ctf_decision_projection_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfDecisionProjection.integration.test.js",
            "databases": tuple(f"dvaia_test_ctf_decision_projection_{state[0]}_{kind[0]}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_DECISION_PROJECTION_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_decision_schema:
        return {"mode": "ctf_decision_schema_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfAuthoritativeDecision.integration.test.js",
            "databases": tuple(f"dvaia_test_ctf_decision_{state}_{kind}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_DECISION_SCHEMA_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_projection_worker:
        return {"mode": "ctf_projection_worker_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfProjectionWorker.integration.test.js",
            "databases": tuple(f"dvaia_test_ctf_worker_{state}_{kind}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_PROJECTION_WORKER_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.ctf_lifecycle_schema:
        return {"mode": "ctf_lifecycle_schema_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfLifecycleProjection.integration.test.js",
            "databases": tuple(f"dvaia_test_ctf_lifecycle_{state}_{kind}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_LIFECYCLE_SCHEMA_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.authority_schema_only:
        return {"mode": "authority_schema_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfAuthorityReadModel.integration.test.js",
            "databases": tuple(f"dvaia_test_ctf_authority_{state}_{kind}_{nonce}"
                for state in ("fresh", "populated") for kind in ("identity", "ctf")),
            "childSeconds": 240, "workSeconds": 420, "cleanupSeconds": 120,
            "tmpfsBytes": 536870912,
            "environment": {"CTF_AUTHORITY_SCHEMA_ISOLATED": "1",
                "AWS_EC2_METADATA_DISABLED": "true"}}
    if args.session_fence_only:
        return {"mode": "session_fence_controlled", "stageEnd": None,
            "test": "tests/postgres/ctfAdmittedSessionFence.integration.test.js",
            "databases": (f"dvaia_test_ctf_session_identity_{nonce}",
                          f"dvaia_test_ctf_session_store_{nonce}"),
            "childSeconds": 180, "workSeconds": 300, "cleanupSeconds": 120,
            "environment": {"CTF_SESSION_FENCE_ISOLATED": "1", "AI_PROVIDER": "mock",
                "JUDGE_PROVIDER": "mock", "AWS_EC2_METADATA_DISABLED": "true"}}
    stage_end = args.stage_end or args.target_stage or 4
    return {"mode": "independent_target" if args.target_stage else "sequential_prefix",
        "stageEnd": stage_end, "test": "tests/postgres/ctfStagesRoute.integration.test.js",
        "databases": ("dvaia_test_ctf_stages_identity", "dvaia_test_ctf_stages_store"),
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
    return "dvaia_ctf_delivery" if selection["mode"] in ("ctf_delivery_activation_controlled", "ctf_telemetry_controlled", "ctf_authority_runtime_controlled", "ctf_production_runtime_controlled", "ctf_authority_application_controlled", "ctf_stage6_adoption_controlled", "ctf_teaching_content_main", "ctf_predefense_recovery_controlled", "ctf_recovery_rendered_controlled", "ctf_ten_content_controlled") else None


def delivery_database(selection, database):
    return delivery_role(selection) is not None and database in selection["databases"][1::2]


def database_environment(selection, urls):
    if selection["mode"] == "application_maintenance_lease":
        return {f"PG_APPLICATION_LEASE_{index}_{role.upper()}_URL": urls[database][role]
            for index, database in enumerate(selection["databases"], 1) for role in ("runtime", "migration")}
    if selection["mode"] in ("ctf_operation_recovery_controlled", "ctf_recovery_rendered_controlled", "ctf_ten_content_controlled", "ctf_predefense_recovery_controlled", "ctf_authority_application_controlled", "ctf_stage6_adoption_controlled", "ctf_teaching_content_main", "ctf_production_runtime_controlled", "ctf_response_diagnostics_controlled", "ctf_authority_runtime_controlled", "ctf_admin_read_controlled", "ctf_registration_locator_controlled", "ctf_telemetry_controlled", "ctf_delivery_activation_controlled", "ctf_blocked_publication_controlled", "ctf_current_read_controlled", "ctf_worker_lifecycle_controlled", "ctf_blocked_predefense_controlled", "ctf_predefense_controlled", "ctf_admin_response_controlled", "ctf_student_deletion_controlled", "ctf_current_response_controlled", "authority_schema_controlled", "ctf_lifecycle_schema_controlled", "ctf_projection_worker_controlled", "ctf_decision_schema_controlled", "ctf_decision_projection_controlled", "ctf_decision_recovery_controlled", "ctf_current_publication_controlled", "ctf_authority_bootstrap_controlled"):
        result = {}
        for database, (state, kind) in zip(selection["databases"],
                ((state, kind) for state in ("FRESH", "POPULATED") for kind in ("IDENTITY", "CTF")), strict=True):
            for role in ("runtime", "migration"):
                prefix = {"ctf_operation_recovery_controlled": "PG_CTF_OPERATION_RECOVERY", "ctf_recovery_rendered_controlled": "PG_CTF_AUTHORITY_APPLICATION", "ctf_ten_content_controlled": "PG_CTF_AUTHORITY_APPLICATION", "ctf_predefense_recovery_controlled": "PG_CTF_AUTHORITY_APPLICATION", "ctf_authority_application_controlled": "PG_CTF_AUTHORITY_APPLICATION", "ctf_stage6_adoption_controlled": "PG_CTF_AUTHORITY_APPLICATION", "ctf_teaching_content_main": "PG_CTF_AUTHORITY_APPLICATION", "ctf_production_runtime_controlled": "PG_CTF_PRODUCTION_RUNTIME", "ctf_response_diagnostics_controlled": "PG_CTF_RESPONSE_DIAGNOSTICS", "ctf_authority_runtime_controlled": "PG_CTF_AUTHORITY_RUNTIME", "ctf_admin_read_controlled": "PG_CTF_ADMIN_READ", "ctf_registration_locator_controlled": "PG_CTF_REGISTRATION_LOCATOR", "ctf_telemetry_controlled": "PG_CTF_TELEMETRY", "ctf_delivery_activation_controlled": "PG_CTF_ACTIVATION", "ctf_blocked_publication_controlled": "PG_CTF_BLOCKED_PUBLICATION", "ctf_current_read_controlled": "PG_CTF_CURRENT_READ", "ctf_worker_lifecycle_controlled": "PG_CTF_WORKER_LIFECYCLE", "ctf_blocked_predefense_controlled": "PG_CTF_BLOCKED_PREDEFENSE", "ctf_predefense_controlled": "PG_CTF_PREDEFENSE", "ctf_admin_response_controlled": "PG_CTF_OPERATION_RECOVERY", "ctf_student_deletion_controlled": "PG_CTF_DELETION", "ctf_current_response_controlled": "PG_CTF_OPERATION_RECOVERY", "ctf_authority_bootstrap_controlled": "PG_CTF_BOOTSTRAP", "ctf_current_publication_controlled": "PG_CTF_CURRENT_PUBLICATION", "ctf_decision_recovery_controlled": "PG_CTF_DECISION_RECOVERY", "ctf_decision_projection_controlled": "PG_CTF_DECISION_PROJECTION", "ctf_decision_schema_controlled": "PG_CTF_DECISION", "ctf_projection_worker_controlled": "PG_CTF_WORKER", "ctf_lifecycle_schema_controlled": "PG_CTF_LIFECYCLE", "authority_schema_controlled": "PG_CTF_AUTHORITY"}[selection["mode"]]
                result[f"{prefix}_{state}_{kind}_{role.upper()}_URL"] = urls[database][role]
        if selection["mode"] in ("ctf_delivery_activation_controlled", "ctf_telemetry_controlled", "ctf_authority_runtime_controlled", "ctf_production_runtime_controlled", "ctf_authority_application_controlled", "ctf_stage6_adoption_controlled", "ctf_teaching_content_main", "ctf_predefense_recovery_controlled", "ctf_recovery_rendered_controlled", "ctf_ten_content_controlled"):
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


def validate_frontend_build_report(source, report_path, report_sha256, input_sha256, build_output_sha256, recorder_sha256, *, private_external=False, require_installed_match=True):
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
    spec = importlib.util.spec_from_file_location("dvaia_frontend_build_receipt", recorder)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if private_external:
        if report.get("inputMode") != "private-external-v1":
            raise RuntimeError("Stage 6 requires the exact private-external build mode")
        output_root = Path(report.get("outputRoot", ""))
        if not output_root.is_absolute() or output_root.resolve() != output_root or output_root.is_relative_to(source) or output_root.is_symlink():
            raise RuntimeError("Stage 6 external build root is not canonical and isolated")
        current_inputs = module.private_inputs(Path(source))
    else:
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


def process_group_exists(pgid, *, runner=subprocess.run, env=None):
    result = runner(["ps", "-axo", "pgid=,stat="], env=env, capture_output=True,
                    text=True, timeout=10)
    if result.returncode != 0:
        raise RuntimeError(f"Owned process-group probe failed: {pgid}")
    return any(fields and fields[0] == str(pgid)
               for fields in (line.split() for line in result.stdout.splitlines()))


def assert_group_identity(pgid, session_id, uid, *, runner=subprocess.run, env=None,
                          getsid=os.getsid):
    """Reject unknown/foreign membership before signaling the owned group."""
    if not isinstance(session_id, int) or session_id <= 1 or not isinstance(uid, int):
        raise RuntimeError("Owned process identity was not captured")
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
    child.poll()
    if group_exists(pgid, env=env):
        try:
            check_identity(pgid, child._owned_sid, child._owned_uid, env=env)
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
            check_identity(pgid, child._owned_sid, child._owned_uid, env=env)
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
            "sid": child._owned_sid, "uid": child._owned_uid}


def finalize_owned(children, logs, container_intents, docker, base_env, cleanup_receipt,
                   container_logs_root=None):
    errors, process_rows = [], []
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
        process_rows.append(row)
    for handle in reversed(logs):
        try:
            handle.close()
        except Exception as error:
            errors.append(error)
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
    return args.ctf_ten_content or args.ctf_stage6_current_main or args.ctf_stage6_adoption or args.ctf_teaching_content


def run_qualification(args):
    source = Path(__file__).resolve().parents[2]
    node = validate_executable(args.node, args.node_sha256, "Managed Node")
    browser = validate_executable(args.browser_executable, args.browser_sha256, "Owned browser") if (args.ctf_recovery_rendered or args.ctf_ten_content or args.ctf_stage6_current_main) else None
    docker_cli = validate_executable(args.docker_cli, args.docker_cli_sha256, "Docker CLI")
    root = Path(tempfile.mkdtemp(prefix="dvaia-ctf-stages-route-")).resolve()
    os.chmod(root, 0o700)
    workspace = root / "source"
    workspace.mkdir(mode=0o700)
    runtime = root / "runtime"
    runtime.mkdir(mode=0o700)
    main_no_copy = main_no_copy_selection(args)
    private_build_report = args.ctf_stage6_current_main
    test_workspace = runtime if main_no_copy else workspace
    app_logs = root / "application-logs"
    app_logs.mkdir(mode=0o700)
    base_env = {key: os.environ[key] for key in ("PATH",) if key in os.environ}
    if main_no_copy:
        base_env.update(HOME=str(runtime / "home"), TMPDIR=str(runtime / "tmp"),
                        XDG_CACHE_HOME=str(runtime / "cache"))
        for private_dir in (runtime / "home", runtime / "tmp", runtime / "cache"):
            private_dir.mkdir(mode=0o700)
    else:
        base_env.update({key: os.environ[key] for key in ("HOME", "TMPDIR") if key in os.environ})
    docker = [str(docker_cli), "--host", args.docker_host]
    nonce = uuid.uuid4().hex[:12]
    container = f"dvaia-ctf-stages-{nonce}"
    container_intents = [{"name": container, "nonce": nonce, "owner": CONTAINER_OWNER_LABEL,
        "image": POSTGRES_IMAGE_ID,
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
            "host": args.docker_host}, "postgresImageId": POSTGRES_IMAGE_ID,
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
            if not (args.ctf_stage6_adoption or args.ctf_teaching_content):
                client_source_entries = client_inventory(source / "client")
                if manifest_digest(client_source_entries) != args.client_source_sha256:
                    raise RuntimeError("Client source manifest pin mismatch")
                state["clientSource"] = {"count": len(client_source_entries), "sha256": args.client_source_sha256}
                state["clientDependencies"] = verified_dependency_snapshot(
                    source / "client" / "node_modules", args.client_dependency_sha256)
                if args.ctf_ten_content:
                    report_path = Path(args.client_build_report)
                    if report_path.is_symlink() or not report_path.is_file() or sha256(report_path) != args.client_build_report_sha256:
                        raise RuntimeError("Frontend build report pin mismatch")
                    report_mode = json.loads(report_path.read_text(encoding="utf-8")).get("inputMode")
                    if report_mode not in ("legacy", "private-external-v1"):
                        raise RuntimeError("CTF content build report mode is unsupported")
                    private_build_report = report_mode == "private-external-v1"
                state["buildReport"] = validate_frontend_build_report(source, args.client_build_report,
                    args.client_build_report_sha256, args.client_build_input_sha256,
                    args.client_build_output_sha256, args.client_build_recorder_sha256,
                    private_external=private_build_report, require_installed_match=not args.ctf_ten_content)
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
        image = run(docker + ["image", "inspect", POSTGRES_IMAGE_ID, "--format", "{{.Id}}"],
                    capture_output=True, text=True).stdout.strip()
        if image != POSTGRES_IMAGE_ID:
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
            POSTGRES_IMAGE_ID, "-c", "shared_buffers=16MB", "-c", "max_connections=40",
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
            LOGS_DIR=str(app_logs), DVAIA_ISOLATED_TEST_WORKSPACE=str(root if args.ctf_ten_content else test_workspace))
        if provision_case(selection):
            env["PG_ADMIN_DATABASE_URL"] = f"postgresql://ctf_stages_admin:{admin_password}@127.0.0.1:{port}/postgres"
        else:
            env.update(database_environment(selection, urls))
        env.update(selection["environment"])
        if browser is not None:
            rendered_evidence = root / "rendered-evidence"
            rendered_evidence.mkdir(mode=0o700)
            env.update(PUPPETEER_EXECUTABLE_PATH=str(browser), CTF_RENDERED_EVIDENCE=str(rendered_evidence))
            if main_no_copy:
                env.update(ANALYTICS_BROWSER_EXECUTABLE=str(browser), ANALYTICS_BROWSER_SHA256=args.browser_sha256)
        if args.ctf_stage6_current_main:
            env.update(CTF_STAGE6_EVIDENCE_ROOT=str(root),
                CTF_STAGE6_BUILD_DIRECTORY=str(Path(state["buildReport"]["outputRoot"]).resolve()),
                DVAIA_CONTENT_DENY_DOTENV="1")
        if args.ctf_ten_content:
            receipt_path = runtime / "ctf-ten-content-result.json"
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
                       CTF_TEN_CONTENT_RECEIPT=str(receipt_path),
                       DVAIA_CONTENT_DENY_DOTENV="1")
        child_test = str(source / selection["test"]) if main_no_copy else selection["test"]
        child = subprocess.Popen([str(node), "--test", "--test-reporter=tap",
            child_test], cwd=test_workspace, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        child._owned_name = "ctf_stages_route_test"
        child._owned_pgid = child.pid
        child._owned_sid = child.pid  # start_new_session=True
        child._owned_uid = os.getuid()
        children.append(child)
        write_private_json(child_intent_path, {"schemaVersion": 1,
            "processes": [child_identity(item) for item in children]})
        state["runStatus"] = "running"
        state["child"] = child_identity(child)
        write_private_json(ownership_path, state)
        deadline = time.monotonic() + selection["childSeconds"]
        code, size = stream_child_output(child, result_path, deadline=deadline)
        record_child_result(state, result_path, code, size)
        if args.ctf_ten_content:
            state["contentReceipt"] = validate_ten_content_receipt(receipt_path, state="FRESH")
        else:
            verified_dependency_snapshot(source / "node_modules",
                                         args.dependency_manifest_sha256)
        state["runStatus"] = "test_pass"
    except BaseException as error:
        primary = error
        state["failure"] = {"type": type(error).__name__, "message": str(error)[:512]}
    finally:
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
            if not (args.ctf_stage6_adoption or args.ctf_teaching_content):
                postflight("client", lambda: (_ for _ in ()).throw(RuntimeError("Client source changed during ten-content run"))
                    if manifest_digest(client_inventory(source / "client")) != args.client_source_sha256 else None)
                postflight("client-dependencies", lambda: verified_dependency_snapshot(source / "client" / "node_modules", args.client_dependency_sha256))
                postflight("build", lambda: validate_prebuilt_build(source, args.client_build_sha256))
                postflight("build-report", lambda: validate_frontend_build_report(source, args.client_build_report,
                    args.client_build_report_sha256, args.client_build_input_sha256,
                    args.client_build_output_sha256, args.client_build_recorder_sha256,
                    private_external=private_build_report, require_installed_match=not args.ctf_ten_content))
                postflight("browser", lambda: validate_executable(browser, args.browser_sha256, "Owned browser"))
            postflight("dotenv", lambda: (_ for _ in ()).throw(RuntimeError("Private dotenv inventory changed"))
                if dotenv_inventory(source) != dotenv_before else None)
            if args.ctf_ten_content:
                postflight("receipt", lambda: validate_ten_content_receipt(receipt_path))
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
                                            cleanup_receipt, root)
        except BaseException as cleanup_error:
            cleanup_errors = [cleanup_error]
        finally:
            if previous_alarm is not None:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, previous_alarm)
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
