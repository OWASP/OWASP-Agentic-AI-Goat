#!/usr/bin/env python3
"""Qualify production SecureShop bound review composition in one owned PG18."""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import uuid
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote


POSTGRES_IMAGE_ID = "sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280"
REFUND_MODEL = "llama3.1:8b"
REFUND_MODEL_DIGEST = "46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e"
REFUND_OLLAMA_BASE_URL = "http://127.0.0.1:11434"
MAX_LOG_BYTES = 1024 * 1024
PRODUCT_SIMILAR_WIRE_BYTES = 64 * 1024 * 1024
PRODUCT_SIMILAR_FLAGS = ("isolatedStores", "standaloneReady", "physicalCustomer",
    "noAutomaticSimilarRun", "serverIssuedSession", "originalModelTool",
    "durableOriginalTurn", "originalSavedRead", "renderedRecommendation",
    "reloadGetOnly", "zeroJudge", "fixtureCleaned")
PRODUCT_SIMILAR_SCOPE = ("current-main registered customer physically requests owned similar products; "
    "original configured-model tool and durable saved read, remount GET-only, no V26 poisoning credit")
PRODUCT_SIMILAR_TEST_SHA256 = "f791dc561bc8c0e6d9d37ceb458444936523c2203821ffbec616e4c5ab04f4ce"
PRODUCT_SUMMARY_FLAGS = ("isolatedStores", "standaloneReady", "fixtureLocalCandidateAdmission",
    "physicalMerchantEdit", "distinctCustomer", "originalSource", "originalConfiguredJudge", "canonicalCompletion",
    "renderedSummary", "savedRecoveryNoReplay", "modeRevisionRecovery", "fixedContrast", "siblingPreserved",
    "resetDenied", "credentialFenced", "renderedProgress", "fixtureCleaned")
PRODUCT_SUMMARY_SCOPE = ("V16 physical merchant product-description instruction, genuine customer summary and canonical Judge; "
    "saved, fixed, mode revision, credential, reset and sibling qualification in disposable candidate catalog")
PRODUCT_SUMMARY_ASSERTION = "V16 merchant description steers genuine customer summary with canonical saved assessment and lifecycle controls"
MANUAL_RAG_BROWSER_TEST_SHA256 = "1a624704910458e4d7cd9ea8e65b928029ca67755dcca0d07837d32229a8ea9f"
MANUAL_RAG_BROWSER_WIRE_BYTES = 64 * 1024 * 1024
MANUAL_RAG_BROWSER_FLAGS = ("isolatedStores", "standaloneReady", "physicalMerchantUpload",
    "distinctCustomer", "originalSource", "originalConfiguredJudge", "renderedAnswer",
    "getOnlyRecovery", "fixedContrast", "noCredit", "fixtureCleaned")
MANUAL_RAG_BROWSER_SCOPE = ("V26 original uploaded manual, actual customer Similar and configured "
    "canonical Judge diagnostic only; pending objective, no credit")
MANUAL_RAG_FIXED_FLAGS = ("isolatedStores", "standaloneReady", "physicalMerchantUpload",
    "distinctCustomer", "fixedOnly", "originalSource", "originalModelTool", "renderedAnswer",
    "getOnlyRecovery", "fixedContrast", "zeroJudge", "noCredit", "resetDenied",
    "siblingPreserved", "fixtureCleaned")
MANUAL_RAG_FIXED_SCOPE = ("V26 fixed-only owned uploaded manual and genuine Fixed Similar, "
    "original saved GET/remount/reset/sibling; zero Judge and no V26 assessment or credit")
MANUAL_RAG_PREIMAGES_TEST_SHA256 = "4f49aa4e8c43128aca1bb940e608ba01449eaae638d09215fa3d3af8f28886ce"
EMBEDDING_CACHE_SUITES = ("product-integration", "product-actual-8b", "manual-integration",
    "manual-actual-8b", "manual-retrieval-actual-8b", "manual-rendered",
    "product-similar-browser", "product-summary-browser", "manual-rag-browser", "manual-rag-fixed-browser")
ROLE_PAIRS = {
    "CTF": ("dvaia_ctf_migration", "dvaia_ctf_runtime"),
    "IDENTITY": ("dvaia_identity_migration", "dvaia_identity_runtime"),
    "XSS": ("dvaia_xss_migration", "dvaia_xss_runtime"),
    "AGENTS": ("dvaia_secureshop_agents_migration", "dvaia_secureshop_agents_runtime"),
    "REVIEW": ("dvaia_secureshop_review_migration", "dvaia_secureshop_review_runtime"),
    "COMMERCE": ("dvaia_secureshop_migration", "dvaia_secureshop_runtime"),
}
SUITES = {
    "v01-checkout-audit": {
        "stores": (("REVIEW", "REVIEW"),),
        "env_prefix": "PG_SECURESHOP_V01_CHECKOUT_AUDIT_",
        "test": "tests/postgres/secureshopV01CheckoutAudit.integration.test.js",
        "child_name": "v01_checkout_audit_test",
    },
    "audit-composition": {
        "stores": (("IDENTITY", "IDENTITY"), ("AGENTS", "AGENTS"), ("REVIEW", "REVIEW"), ("COMMERCE", "COMMERCE")),
        "env_prefix": "PG_SECURESHOP_BOUND_REVIEW_COMPOSITION_",
        "test": "tests/postgres/secureshopBoundReviewComposition.integration.test.js",
        "child_name": "audit_composition_test",
    },
    "audit-fresh-schema": {
        "stores": (("AGENTS", "AGENTS"), ("REVIEW", "REVIEW")),
        "env_prefix": "PG_SECURESHOP_BOUND_AUDIT_",
        "test": "tests/postgres/secureshopAuditFreshSchema.integration.test.js",
        "child_name": "audit_fresh_schema_test",
    },
    "audit-actual-8b": {
        "stores": (("IDENTITY", "IDENTITY"), ("AGENTS", "AGENTS"), ("REVIEW", "REVIEW"), ("COMMERCE", "COMMERCE")),
        "env_prefix": "PG_SECURESHOP_BOUND_AUDIT_",
        "test": "tests/postgres/secureshopBoundAudit.integration.test.js",
        "child_name": "audit_actual_8b_test",
    },
    "mcp-actual-8b": {
        "stores": (("IDENTITY", "IDENTITY"), ("AGENTS", "AGENTS")),
        "env_prefix": "PG_SECURESHOP_MCP_TRUST_LIVE_",
        "test": "tests/postgres/secureshopMcpTrustLive.integration.test.js",
        "child_name": "mcp_actual_8b_test",
    },
    "mcp-provenance-preflight": {
        "stores": (("IDENTITY", "IDENTITY"), ("AGENTS", "AGENTS")),
        "env_prefix": "PG_SECURESHOP_MCP_TRUST_LIVE_",
        "test": "tests/postgres/secureshopMcpTrustLive.integration.test.js",
        "child_name": "mcp_provenance_preflight_test",
    },
    "audit-journal": {
        "stores": (("IDENTITY", "IDENTITY"), ("AGENTS", "AGENTS"), ("REVIEW", "REVIEW"), ("COMMERCE", "COMMERCE")),
        "env_prefix": "PG_SECURESHOP_BOUND_AUDIT_",
        "test": "tests/postgres/secureshopBoundAudit.integration.test.js",
        "child_name": "audit_journal_test",
    },
    "manual-rendered": {
        "stores": (("IDENTITY", "IDENTITY"), ("AGENTS", "AGENTS"), ("REVIEW", "REVIEW"), ("COMMERCE", "COMMERCE")),
        "env_prefix": "PG_SECURESHOP_BOUND_REVIEW_COMPOSITION_",
        "test": "tests/postgres/secureshopBoundReviewComposition.integration.test.js",
        "child_name": "manual_rendered_test",
    },
    "manual-retrieval-actual-8b": {
        "stores": (("IDENTITY", "IDENTITY"), ("AGENTS", "AGENTS"), ("REVIEW", "REVIEW"), ("COMMERCE", "COMMERCE")),
        "env_prefix": "PG_SECURESHOP_BOUND_REVIEW_COMPOSITION_",
        "test": "tests/postgres/secureshopBoundReviewComposition.integration.test.js",
        "child_name": "manual_retrieval_actual_8b_test",
    },
    "manual-actual-8b": {
        "stores": (("IDENTITY", "IDENTITY"), ("AGENTS", "AGENTS"), ("REVIEW", "REVIEW"), ("COMMERCE", "COMMERCE")),
        "env_prefix": "PG_SECURESHOP_BOUND_REVIEW_COMPOSITION_",
        "test": "tests/postgres/secureshopBoundReviewComposition.integration.test.js",
        "child_name": "manual_actual_8b_test",
    },
    "manual-integration": {
        "stores": (("IDENTITY", "IDENTITY"), ("AGENTS", "AGENTS"), ("REVIEW", "REVIEW"), ("COMMERCE", "COMMERCE")),
        "env_prefix": "PG_SECURESHOP_BOUND_REVIEW_COMPOSITION_",
        "test": "tests/postgres/secureshopBoundReviewComposition.integration.test.js",
        "child_name": "manual_integration_test",
    },
    "manual-ingest": {
        "stores": (("FRESH_REVIEW", "REVIEW"), ("POPULATED_REVIEW", "REVIEW")),
        "env_prefix": "PG_SECURESHOP_BOUND_MANUAL_",
        "test": "tests/postgres/secureshopBoundManualIngest.integration.test.js",
        "child_name": "manual_ingest_test",
    },
    "embedding-revision": {
        "stores": (("FRESH", "REVIEW"), ("POPULATED", "REVIEW")),
        "env_prefix": "EMBEDDING_",
        "test": "tests/postgres/secureshopEmbeddingRevision.integration.test.js",
        "child_name": "embedding_revision_test",
    },
    "manual-rag-source": {
        "stores": (("IDENTITY", "IDENTITY"), ("AGENTS", "AGENTS"), ("REVIEW", "REVIEW")),
        "env_prefix": "PG_SECURESHOP_MANUAL_RAG_SOURCE_",
        "test": "tests/postgres/secureshopManualRagSourceAdapter.integration.test.js",
        "child_name": "manual_rag_source_test",
    },
    "manual-rag-preimages": {
        "stores": (("FRESH_REVIEW", "REVIEW"), ("POPULATED_REVIEW", "REVIEW")),
        "env_prefix": "PG_SECURESHOP_MANUAL_RAG_PREIMAGES_",
        "test": "tests/postgres/secureshopManualRagPreimages.integration.test.js",
        "child_name": "manual_rag_preimages_test",
    },
    "product-similar-browser": {
        "stores": (("IDENTITY", "IDENTITY"), ("AGENTS", "AGENTS"),
                   ("REVIEW", "REVIEW"), ("COMMERCE", "COMMERCE")),
        "env_prefix": "PG_SECURESHOP_PRODUCT_SIMILAR_BROWSER_",
        "test": "tests/postgres/secureshopStandaloneProductSimilarRendered.integration.test.js",
        "child_name": "product_similar_browser_test",
    },
    "product-summary-browser": {
        "stores": (("IDENTITY", "IDENTITY"), ("AGENTS", "AGENTS"),
                   ("REVIEW", "REVIEW"), ("COMMERCE", "COMMERCE")),
        "env_prefix": "PG_SECURESHOP_PRODUCT_SIMILAR_BROWSER_",
        "test": "tests/postgres/secureshopStandaloneProductSimilarRendered.integration.test.js",
        "child_name": "product_summary_browser_test",
    },
    "manual-rag-browser": {
        "stores": (("IDENTITY", "IDENTITY"), ("AGENTS", "AGENTS"),
                   ("REVIEW", "REVIEW"), ("COMMERCE", "COMMERCE")),
        "env_prefix": "PG_SECURESHOP_MANUAL_RAG_BROWSER_",
        "test": "tests/postgres/secureshopManualRagRendered.integration.test.js",
        "child_name": "manual_rag_browser_test",
    },
    "manual-rag-fixed-browser": {
        "stores": (("IDENTITY", "IDENTITY"), ("AGENTS", "AGENTS"),
                   ("REVIEW", "REVIEW"), ("COMMERCE", "COMMERCE")),
        "env_prefix": "PG_SECURESHOP_MANUAL_RAG_BROWSER_",
        "test": "tests/postgres/secureshopManualRagRendered.integration.test.js",
        "child_name": "manual_rag_fixed_browser_test",
    },
    "product-integration": {
        "stores": (("IDENTITY", "IDENTITY"), ("AGENTS", "AGENTS"), ("REVIEW", "REVIEW"), ("COMMERCE", "COMMERCE")),
        "env_prefix": "PG_SECURESHOP_BOUND_REVIEW_COMPOSITION_",
        "test": "tests/postgres/secureshopBoundReviewComposition.integration.test.js",
        "child_name": "product_integration_test",
    },
    "product-actual-8b": {
        "stores": (("IDENTITY", "IDENTITY"), ("AGENTS", "AGENTS"), ("REVIEW", "REVIEW"), ("COMMERCE", "COMMERCE")),
        "env_prefix": "PG_SECURESHOP_BOUND_REVIEW_COMPOSITION_",
        "test": "tests/postgres/secureshopBoundReviewComposition.integration.test.js",
        "child_name": "product_actual_8b_test",
    },
    "product-retrieval": {
        "stores": (("FRESH_REVIEW", "REVIEW"), ("POPULATED_REVIEW", "REVIEW")),
        "env_prefix": "PG_SECURESHOP_BOUND_RETRIEVAL_",
        "test": "tests/postgres/secureshopBoundProductRetrieval.integration.test.js",
        "child_name": "product_retrieval_test",
    },
    "identity": {
        "stores": (("TEST", "IDENTITY"),),
        "env_prefix": "PG_IDENTITY_",
        "test": "tests/postgres/identity.integration.test.js",
        "child_name": "identity_test",
    },
    "xss-email-owner-listing": {
        "stores": (("TEST", "XSS"),),
        "env_prefix": "PG_XSS_",
        "test": "tests/postgres/xss.integration.test.js",
        "child_name": "xss_email_owner_listing_test",
    },
    "xss-judgment-child": {
        "stores": (("TEST", "IDENTITY"),),
        "env_prefix": "PG_XSS_JUDGMENT_",
        "test": "tests/postgres/xssJudgmentChildBinding.integration.test.js",
        "child_name": "xss_judgment_child_test",
    },
    "composition": {
        "stores": (("IDENTITY", "IDENTITY"), ("AGENTS", "AGENTS"),
                   ("REVIEW", "REVIEW"), ("COMMERCE", "COMMERCE")),
        "env_prefix": "PG_SECURESHOP_BOUND_REVIEW_COMPOSITION_",
        "test": "tests/postgres/secureshopBoundReviewComposition.integration.test.js",
        "child_name": "composition_test",
    },
    "persona-sessions": {
        "stores": (("COMMERCE", "COMMERCE"), ("FRESH_AGENTS", "AGENTS"),
                   ("POPULATED_AGENTS", "AGENTS")),
        "env_prefix": "PG_SECURESHOP_BOUND_PERSONA_SESSIONS_",
        "test": "tests/postgres/secureshopBoundPersonaSessions.integration.test.js",
        "child_name": "persona_sessions_test",
    },
    "persona-password": {
        "stores": (("COMMERCE", "COMMERCE"), ("FRESH_AGENTS", "AGENTS"),
                   ("POPULATED_AGENTS", "AGENTS")),
        "env_prefix": "PG_SECURESHOP_BOUND_PERSONA_PASSWORD_",
        "test": "tests/postgres/secureshopBoundPersonaPassword.integration.test.js",
        "child_name": "persona_password_test",
    },
    "persona-api-keys": {
        "stores": (("COMMERCE", "COMMERCE"), ("REVIEW", "REVIEW"),
                   ("FRESH_AGENTS", "AGENTS"),
                   ("POPULATED_AGENTS", "AGENTS")),
        "env_prefix": "PG_SECURESHOP_BOUND_PERSONA_API_KEYS_",
        "test": "tests/postgres/secureshopBoundPersonaApiKeys.integration.test.js",
        "child_name": "persona_api_keys_test",
    },
    "merchant-listings": {
        "stores": (("FRESH_REVIEW", "REVIEW"), ("POPULATED_REVIEW", "REVIEW")),
        "env_prefix": "PG_SECURESHOP_BOUND_MERCHANT_LISTINGS_",
        "test": "tests/postgres/secureshopBoundMerchantListings.integration.test.js",
        "child_name": "merchant_listings_test",
    },
    "refund": {
        "stores": (("REVIEW", "REVIEW"),),
        "env_prefix": "PG_SECURESHOP_BOUND_REFUND_",
        "test": "tests/postgres/secureshopBoundRefund.integration.test.js",
        "child_name": "refund_test",
    },
    "refund-actual-8b": {
        "stores": (("IDENTITY", "IDENTITY"), ("AGENTS", "AGENTS"),
                   ("REVIEW", "REVIEW"), ("COMMERCE", "COMMERCE")),
        "env_prefix": "PG_SECURESHOP_BOUND_REVIEW_COMPOSITION_",
        "test": "tests/postgres/secureshopBoundReviewComposition.integration.test.js",
        "child_name": "refund_actual_8b_test",
    },
    "migration-tails": {
        "stores": (("POPULATED_CTF", "CTF"), ("POPULATED_AGENTS", "AGENTS")),
        "env_prefix": "PG_CURRENT_MIGRATION_TAILS_",
        "test": "tests/postgres/currentMigrationTails.integration.test.js",
        "child_name": "migration_tails_test",
    },
    "capacity": {
        "stores": (("CAPACITY", "IDENTITY"),),
        "env_prefix": "PG_",
        "test": "tests/postgres/workshopCapacity.integration.test.js",
        "child_name": "capacity_test",
    },
    "capacity-actual-8b": {
        "stores": (("IDENTITY", "IDENTITY"),),
        "env_prefix": "PG_CAPACITY_ACTUAL8B_",
        "test": "tests/postgres/workshopCapacityActual8b.integration.test.js",
        "child_name": "capacity_actual_8b_test",
    },
    "sql-teaching-copy": {
        "stores": (("IDENTITY", "IDENTITY"),),
        "env_prefix": None,
        "test": "tests/postgres/sqlTeachingCopyDefaults.integration.test.js",
        "child_name": "sql_teaching_copy_test",
    },
}
DATABASE_FAMILIES = {
    "v01-checkout-audit": "v01_checkout_audit",
    "audit-composition": "audit_composition",
    "audit-actual-8b": "audit_actual_8b",
    "mcp-actual-8b": "mcp_actual_8b",
    "mcp-provenance-preflight": "mcp_provenance",
    "audit-fresh-schema": "audit_fresh",
    "audit-journal": "audit",
    "manual-rendered": "manual_rendered",
    "manual-retrieval-actual-8b": "manual_retrieval_live",
    "manual-actual-8b": "manual_actual_8b",
    "manual-integration": "manual_integration",
    "manual-ingest": "manual_ingest",
    "embedding-revision": "embedding",
    "manual-rag-source": "manual_rag_source",
    "manual-rag-preimages": "manual_rag_preimages",
    "product-similar-browser": "agent_host",
    "product-summary-browser": "agent_host",
    "product-integration": "product_int",
    "product-actual-8b": "product_live",    "product-retrieval": "product_retrieval",
    "identity": "identity",
    "xss-email-owner-listing": "xss_email_owner_listing",
    "xss-judgment-child": "xss_judgment",
    "composition": "bound_review_composition",
    "persona-sessions": "bound_persona_sessions",
    "persona-password": "bound_persona_password",
    "persona-api-keys": "bound_persona_api_keys",
    "merchant-listings": "merchant",
    "refund": "bound_refund",
    "refund-actual-8b": "bound_refund_actual",
    "migration-tails": "migration_tails",
    "capacity": "capacity",
    "capacity-actual-8b": "capacity_actual_8b",
    "sql-teaching-copy": "sql_copy",
}
AGENT_HOST_STORE_NAMES = {"IDENTITY": "identity", "AGENTS": "secureshop_agents",
                          "REVIEW": "secureshop_review", "COMMERCE": "secureshop"}


def database_name(suite, store, run_id):
    value = (f"dvaia_sql_copy_{run_id}" if suite == "sql-teaching-copy"
             else f"dvaia_test_agent_host_{run_id}_{AGENT_HOST_STORE_NAMES[store]}" if suite in ("product-similar-browser", "product-summary-browser", "manual-rag-browser", "manual-rag-fixed-browser")
             else f"dvaia_test_{DATABASE_FAMILIES[suite]}_{store.lower()}_{run_id}")
    if len(value.encode("utf-8")) > 63:
        raise RuntimeError(f"PostgreSQL database identifier exceeds 63 bytes: {suite}/{store}")
    return value


class OwnedSignalExit(SystemExit):
    pass


def parse_args(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--docker-host", required=True)
    parser.add_argument("--docker-cli", required=True)
    parser.add_argument("--docker-cli-sha256", required=True)
    parser.add_argument("--node", required=True)
    parser.add_argument("--node-sha256", required=True)
    parser.add_argument("--suite", choices=tuple(SUITES), default="composition")
    parser.add_argument("--audit-injection", action="store_true", help="Positive listing-to-audit browser qualification; requires --audit-summary")
    parser.add_argument("--audit-summary", action="store_true", help="Actual 8B audit summary in manual-rendered only")
    parser.add_argument("--browser")
    parser.add_argument("--browser-sha256")
    parser.add_argument("--embedding-cache", help="Installed model cache for offline product qualification")
    parser.add_argument("--main-checkout", action="store_true",
                        help="Run selected native suites in the current checkout without a source copy")
    parser.add_argument("--run", action="store_true", help="Root-controlled execution gate")
    return parser.parse_args(argv)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


SOURCE_ROOTS = ("server/database/postgres", "server/services", "server/agent-runtime",
                "server/config", "server/utils", "db/postgres", "tests/postgres")
SOURCE_SUFFIXES = {".js", ".cjs", ".mjs", ".json", ".sql", ".py"}
MAIN_CHECKOUT_SUITES = ("v01-checkout-audit", "manual-ingest", "embedding-revision", "manual-rag-source",
                        "manual-rag-preimages",
                        "product-similar-browser", "product-summary-browser", "manual-rag-browser", "manual-rag-fixed-browser")
REQUIRES_MAIN_CHECKOUT = ("v01-checkout-audit", "manual-rag-source", "manual-rag-preimages",
                          "product-similar-browser", "product-summary-browser", "manual-rag-browser", "manual-rag-fixed-browser")
MAIN_CHECKOUT_EXTRA_FILES = {
    "manual-rag-source": ("tests/secureshopManualRagSourceContract.test.js",),
    "manual-rag-browser": ("sidecars/sandbox-runner/secureshopFiles.js",),
    "manual-rag-fixed-browser": ("sidecars/sandbox-runner/secureshopFiles.js",),
}


def source_inventory(source, extra_files=(), extra_roots=(), full_roots=()):
    """Closed current-checkout source inventory; no generated logs or learner data."""
    source = Path(source)
    paths = [source / name for name in ("package.json", "package-lock.json", *extra_files)]
    for directory in (*SOURCE_ROOTS, *extra_roots, *full_roots):
        root = source / directory
        if root.is_symlink() or not root.is_dir():
            raise RuntimeError(f"Current-checkout source root is unavailable: {directory}")
        for candidate in root.rglob("*"):
            if candidate.is_symlink():
                raise RuntimeError("Current-checkout source link forbidden")
            if candidate.is_file() and (directory in full_roots or candidate.suffix in SOURCE_SUFFIXES):
                paths.append(candidate)
    files = {}
    for candidate in sorted(paths):
        if candidate.is_symlink() or not candidate.is_file():
            raise RuntimeError("Current-checkout source file unavailable")
        files[candidate.relative_to(source).as_posix()] = sha256(candidate)
    digest = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":"))
                            .encode("utf-8")).hexdigest()
    return {"schemaVersion": 1, "digest": digest, "files": files}


def main_checkout_inventory(source, suite):
    extras = MAIN_CHECKOUT_EXTRA_FILES.get(suite, ())
    if suite == "manual-rag-preimages":
        inventory = source_inventory(source)
        if inventory["files"].get(SUITES[suite]["test"]) != MANUAL_RAG_PREIMAGES_TEST_SHA256:
            raise RuntimeError("Reviewed manual-RAG preimages native fixture pin changed")
        return inventory
    if suite in ("product-similar-browser", "product-summary-browser", "manual-rag-browser", "manual-rag-fixed-browser"):
        inventory = source_inventory(source, extras,
            ("server/routes", "server/middleware", "server/data"),
            ("client/src", "client/build"))
        expected = (PRODUCT_SIMILAR_TEST_SHA256 if suite in ("product-similar-browser", "product-summary-browser")
                    else MANUAL_RAG_BROWSER_TEST_SHA256)
        if inventory["files"].get(SUITES[suite]["test"]) != expected:
            raise RuntimeError(f"Reviewed {suite} native fixture pin changed")
        return inventory
    return source_inventory(source, extras) if extras else source_inventory(source)


def validate_executable(path, expected_sha256, label):
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file() or sha256(candidate) != expected_sha256:
        raise RuntimeError(f"{label} pin mismatch")
    return candidate.resolve()


def read_refund_model_digest(base_url=REFUND_OLLAMA_BASE_URL):
    if base_url != REFUND_OLLAMA_BASE_URL:
        raise RuntimeError("Refund actual-model gate requires the pinned loopback Ollama origin")
    request = urllib.request.Request(f"{base_url}/api/tags", method="GET")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            body = response.read(256 * 1024 + 1)
    except (urllib.error.URLError, TimeoutError) as error:
        raise RuntimeError("Pinned Ollama model inventory unavailable") from error
    if len(body) > 256 * 1024:
        raise RuntimeError("Pinned Ollama model inventory exceeds bound")
    try:
        rows = json.loads(body.decode("utf-8")).get("models")
    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError) as error:
        raise RuntimeError("Pinned Ollama model inventory is invalid") from error
    matches = [row for row in rows or [] if isinstance(row, dict) and row.get("name") == REFUND_MODEL]
    if len(matches) != 1 or matches[0].get("digest") != REFUND_MODEL_DIGEST:
        raise RuntimeError("Pinned Ollama refund model digest mismatch")
    return {"model": REFUND_MODEL, "digest": REFUND_MODEL_DIGEST, "endpoint": base_url}


def read_capacity_model_digest(base_url=REFUND_OLLAMA_BASE_URL):
    # Keep the capacity gate's identity check separate from refund metadata so
    # its private evidence cannot be mistaken for a refund qualification.
    return read_refund_model_digest(base_url)


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
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def open_private_log(path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(descriptor, "w", encoding="utf-8")


def assert_non_skipped_tap(path, suite):
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    counts = {}
    for line in text.splitlines():
        match = re.match(r"^# (tests|pass|fail|skipped|cancelled|todo) ([0-9]+)\s*$", line)
        if match:
            if match.group(1) in counts:
                raise RuntimeError(f"{suite} TAP terminal counts are duplicated")
            counts[match.group(1)] = int(match.group(2))
    if not {"tests", "pass", "fail", "skipped"} <= set(counts):
        raise RuntimeError(f"{suite} TAP terminal counts are missing or malformed")
    if counts["tests"] < 1 or counts["pass"] != counts["tests"] or counts["fail"] != 0 or counts["skipped"] != 0:
        raise RuntimeError(f"{suite} did not produce a non-skipped passing test")
    if counts.get("cancelled", 0) != 0 or counts.get("todo", 0) != 0:
        raise RuntimeError(f"{suite} TAP contains cancelled or todo tests")
    if any(re.search(r"^\s*(?:ok|not ok)\b.*#\s*skip(?:\b|$)", line, re.IGNORECASE)
           for line in text.splitlines()):
        raise RuntimeError(f"{suite} produced a skipped test")
    if any(re.match(r"^\s*not ok\b", line) for line in text.splitlines()):
        raise RuntimeError(f"{suite} contains a failed test directive")
    if not any(re.match(r"^\s*ok\b", line) for line in text.splitlines()):
        raise RuntimeError(f"{suite} TAP result is missing a passing test")


def assert_exact_single_tap(path, title):
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    if (len(re.findall(r"^ok 1 - ", text, flags=re.MULTILINE)) != 1
            or f"ok 1 - {title}" not in text.splitlines()
            or "1..1" not in text.splitlines()
            or "# tests 1" not in text.splitlines()):
        raise RuntimeError("Focused native TAP title or count mismatch")


def read_private_bounded_json(path, limit):
    path = Path(path)
    if path.is_symlink() or (path.stat().st_mode & 0o777) != 0o600:
        raise RuntimeError(f"Private evidence identity or mode invalid: {path.name}")
    if not 0 < path.stat().st_size <= limit:
        raise RuntimeError(f"Private evidence size invalid: {path.name}")
    return json.loads(path.read_text(encoding="utf-8"))


def assert_product_similar_evidence(root):
    root = Path(root)
    receipt = read_private_bounded_json(root / "product-similar-evidence.json", 65536)
    expected = set(PRODUCT_SIMILAR_FLAGS) | {"passed", "scope", "similarRuns", "modelCalls",
        "selectedSimilarCalls", "judgeCalls", "errors", "cleanupErrors"}
    if (not isinstance(receipt, dict) or set(receipt) != expected
            or any(receipt[flag] is not True for flag in PRODUCT_SIMILAR_FLAGS)
            or receipt["passed"] is not True or receipt["scope"] != PRODUCT_SIMILAR_SCOPE
            or type(receipt["similarRuns"]) is not int or receipt["similarRuns"] != 1
            or type(receipt["selectedSimilarCalls"]) is not int or receipt["selectedSimilarCalls"] != 1
            or type(receipt["judgeCalls"]) is not int or receipt["judgeCalls"] != 0
            or receipt["errors"] != []
            or receipt["cleanupErrors"] != [] or type(receipt["modelCalls"]) is not int
            or not 2 <= receipt["modelCalls"] <= 14):
        raise RuntimeError("Product-similar receipt failed closed validation")
    wire = read_private_bounded_json(root / "product-similar-original-wire.json",
                                     PRODUCT_SIMILAR_WIRE_BYTES)
    if (not isinstance(wire, dict)
            or set(wire) != {"model", "modelDigest", "calls", "actorSpans", "requests", "pageErrors"}
            or wire["model"] != REFUND_MODEL or wire["modelDigest"] != REFUND_MODEL_DIGEST
            or not isinstance(wire["calls"], list)
            or len(wire["calls"]) != receipt["modelCalls"] or wire["pageErrors"] != []
            or not isinstance(wire["actorSpans"], list)
            or not isinstance(wire["requests"], list)):
        raise RuntimeError("Product-similar original wire envelope mismatch")
    for call in wire["calls"]:
        if (not isinstance(call, dict) or call.get("kind") != "actor"
                or call.get("model") != REFUND_MODEL or call.get("status") != 200
                or call.get("responseComplete") is not True
                or call.get("responseCaptureTruncated") is not False
                or not isinstance(call.get("request"), str)
                or not isinstance(call.get("response"), str)
                or call.get("requestBytes") != len(call["request"].encode("utf-8"))
                or call.get("responseBytes") != len(call["response"].encode("utf-8"))
                or call["requestBytes"] > 256 * 1024 or call["responseBytes"] > 4 * 1024 * 1024
                or call.get("requestSha256") != hashlib.sha256(call["request"].encode("utf-8")).hexdigest()
                or call.get("responseSha256") != hashlib.sha256(call["response"].encode("utf-8")).hexdigest()):
            raise RuntimeError("Product-similar actor wire is incomplete or unbound")
    selected = [span for span in wire["actorSpans"] if isinstance(span, dict)
        and any(isinstance(tool, dict) and tool.get("name") == "product-search.similar"
                for tool in (span.get("result") or {}).get("tool_uses", []))]
    if len(selected) != 1:
        raise RuntimeError("Product-similar selected model tool count mismatch")
    similar_posts = [row for row in wire["requests"] if isinstance(row, dict)
        and row.get("method") == "POST"
        and re.fullmatch(r"/products/[0-9]+/similar", str(row.get("pathname")))]
    if len(similar_posts) != 1 or similar_posts[0].get("status") != 200 \
            or similar_posts[0].get("error") is not None:
        raise RuntimeError("Product-similar physical POST capture mismatch")
    return receipt


def assert_product_summary_evidence(root):
    root = Path(root)
    receipt = read_private_bounded_json(root / "product-similar-evidence.json", 65536)
    expected = set(PRODUCT_SUMMARY_FLAGS) | {"passed", "scope", "summaryRuns", "similarRuns", "modelCalls",
        "selectedSimilarCalls", "judgeCalls", "errors", "cleanupErrors"}
    if (not isinstance(receipt, dict) or set(receipt) != expected
            or any(receipt[flag] is not True for flag in PRODUCT_SUMMARY_FLAGS)
            or receipt["passed"] is not True or receipt["scope"] != PRODUCT_SUMMARY_SCOPE
            or any(type(receipt[k]) is not int or receipt[k] != v for k,v in
                (("summaryRuns",3),("similarRuns",0),("selectedSimilarCalls",0)))
            or type(receipt["modelCalls"]) is not int or not 6 <= receipt["modelCalls"] <= 12
            or type(receipt["judgeCalls"]) is not int or not 2 <= receipt["judgeCalls"] <= 8
            or receipt["errors"] != [] or receipt["cleanupErrors"] != []):
        raise RuntimeError("Product-summary receipt failed closed validation")
    wire = read_private_bounded_json(root / "product-similar-original-wire.json", PRODUCT_SIMILAR_WIRE_BYTES)
    if (not isinstance(wire,dict) or set(wire) != {"model","modelDigest","calls","actorSpans","requests","pageErrors",
            "judgeCalls","judgeInputs","judgeTranscripts","summaryCapture"}
            or wire["model"] != REFUND_MODEL or wire["modelDigest"] != REFUND_MODEL_DIGEST
            or wire["pageErrors"] != [] or not isinstance(wire["calls"],list)
            or len(wire["calls"]) != receipt["modelCalls"] or not isinstance(wire["judgeCalls"],list)
            or len(wire["judgeCalls"]) != receipt["judgeCalls"]):
        raise RuntimeError("Product-summary original wire envelope mismatch")
    for kind, calls in (("actor",wire["calls"]),("judge",wire["judgeCalls"])):
        for call in calls:
            if (not isinstance(call,dict) or call.get("kind") != kind or call.get("model") != REFUND_MODEL
                    or call.get("status") != 200 or call.get("responseComplete") is not True
                    or call.get("responseCaptureTruncated") is not False or call.get("error") is not None
                    or not isinstance(call.get("request"),str) or not isinstance(call.get("response"),str)
                    or call.get("requestBytes") != len(call["request"].encode())
                    or call.get("responseBytes") != len(call["response"].encode())
                    or call["requestBytes"] > 256*1024 or call["responseBytes"] > 4*1024*1024
                    or call.get("requestSha256") != hashlib.sha256(call["request"].encode()).hexdigest()
                    or call.get("responseSha256") != hashlib.sha256(call["response"].encode()).hexdigest()):
                raise RuntimeError("Product-summary physical wire incomplete or unbound")
    capture=wire["summaryCapture"]
    if (not isinstance(capture,dict) or not isinstance(capture.get("turns"),list) or len(capture["turns"]) != 3
            or not isinstance(capture.get("positiveWireProof"),dict) or not wire["judgeInputs"] or not wire["judgeTranscripts"]):
        raise RuntimeError("Product-summary original semantic proof absent")
    posts=[r for r in wire["requests"] if r.get("method")=="POST" and re.fullmatch(r"/products/[0-9]+/summary",str(r.get("pathname")))]
    if len(posts)!=3 or any(r.get("status")!=200 or r.get("error") is not None for r in posts):
        raise RuntimeError("Product-summary original physical POST count mismatch")
    if any(re.fullmatch(r"/products/[0-9]+/similar(?:/.*)?",str(r.get("pathname"))) for r in wire["requests"]):
        raise RuntimeError("Product-summary cohort performed Similar work")
    return receipt


def assert_manual_rag_browser_evidence(root):
    root = Path(root)
    receipt = read_private_bounded_json(root / "manual-rag-evidence.json", 65536)
    expected = set(MANUAL_RAG_BROWSER_FLAGS) | {"passed", "scope", "similarRuns", "modelCalls",
        "selectedSimilarCalls", "judgeCalls", "errors", "cleanupErrors", "credit", "diagnostic"}
    if (not isinstance(receipt, dict) or set(receipt) != expected
            or any(receipt[flag] is not True for flag in MANUAL_RAG_BROWSER_FLAGS)
            or receipt["passed"] is not True or receipt["scope"] != MANUAL_RAG_BROWSER_SCOPE
            or receipt["credit"] is not False or receipt["diagnostic"] is not True
            or receipt["similarRuns"] != 2 or receipt["selectedSimilarCalls"] != 2
            or receipt["errors"] != [] or receipt["cleanupErrors"] != []
            or type(receipt["modelCalls"]) is not int or not 6 <= receipt["modelCalls"] <= 14
            or type(receipt["judgeCalls"]) is not int or not 2 <= receipt["judgeCalls"] <= 4):
        raise RuntimeError("Manual-RAG browser diagnostic receipt failed closed validation")
    wire = read_private_bounded_json(root / "manual-rag-original-wire.json",
                                     MANUAL_RAG_BROWSER_WIRE_BYTES)
    if (not isinstance(wire, dict)
            or set(wire) != {"scope", "credit", "model", "modelDigest", "actorCalls",
                             "judgeCalls", "actorSpans", "judgeTranscripts", "requests",
                             "originalCapture", "pageErrors"}
            or wire["scope"] != MANUAL_RAG_BROWSER_SCOPE or wire["credit"] is not False
            or wire["model"] != REFUND_MODEL or wire["modelDigest"] != REFUND_MODEL_DIGEST
            or not isinstance(wire["actorCalls"], list)
            or not isinstance(wire["judgeCalls"], list)
            or len(wire["actorCalls"]) != receipt["modelCalls"]
            or len(wire["judgeCalls"]) != receipt["judgeCalls"]
            or not isinstance(wire["actorSpans"], list)
            or not isinstance(wire["judgeTranscripts"], list)
            or not isinstance(wire["requests"], list)
            or not isinstance(wire["originalCapture"], dict)
            or wire["pageErrors"] != []):
        raise RuntimeError("Manual-RAG browser original wire envelope mismatch")
    for kind, calls in (("actor", wire["actorCalls"]), ("judge", wire["judgeCalls"])):
        for call in calls:
            if (not isinstance(call, dict) or call.get("kind") != kind
                    or call.get("model") != REFUND_MODEL or call.get("status") != 200
                    or call.get("responseComplete") is not True
                    or call.get("responseCaptureTruncated") is not False
                    or not isinstance(call.get("request"), str)
                    or not isinstance(call.get("response"), str)
                    or call.get("requestBytes") != len(call["request"].encode("utf-8"))
                    or call.get("responseBytes") != len(call["response"].encode("utf-8"))
                    or call["requestBytes"] > 256 * 1024
                    or call["responseBytes"] > 4 * 1024 * 1024
                    or call.get("requestSha256") != hashlib.sha256(call["request"].encode("utf-8")).hexdigest()
                    or call.get("responseSha256") != hashlib.sha256(call["response"].encode("utf-8")).hexdigest()):
                raise RuntimeError(f"Manual-RAG {kind} wire is incomplete or unbound")
    selected = [span for span in wire["actorSpans"] if isinstance(span, dict)
        and any(isinstance(tool, dict) and tool.get("name") == "product-search.similar"
                for tool in (span.get("result") or {}).get("tool_uses", []))]
    posts = [row for row in wire["requests"] if isinstance(row, dict)
        and row.get("method") == "POST"
        and re.fullmatch(r"/products/[0-9]+/similar", str(row.get("pathname")))]
    if (len(selected) != 2 or len(posts) != 2
            or any(row.get("status") != 200 or row.get("error") is not None for row in posts)):
        raise RuntimeError("Manual-RAG physical model-selected Similar turns mismatch")
    captured = wire["originalCapture"]
    packet = captured.get("packet")
    judgment = captured.get("judgment")
    transcript = wire["judgeTranscripts"]
    if (not isinstance(packet, dict) or not isinstance(packet.get("evidenceDigest"), str)
            or not isinstance(packet.get("runId"), str)
            or not isinstance(judgment, dict) or judgment.get("provider") != "ollama"
            or judgment.get("model") != REFUND_MODEL or judgment.get("verdict") != "pass"
            or judgment.get("evidenceDigest") != packet["evidenceDigest"]
            or not isinstance(transcript, list) or len(transcript) != 1
            or not isinstance(transcript[0], dict) or transcript[0].get("complete") is not True
            or not isinstance(transcript[0].get("header"), dict)
            or transcript[0]["header"].get("runId") != packet["runId"]
            or transcript[0]["header"].get("evidenceDigest") != packet["evidenceDigest"]
            or not isinstance(transcript[0].get("calls"), list)
            or len(transcript[0]["calls"]) != receipt["judgeCalls"]
            or captured.get("savedAssessment") != {"status": 200,
                "body": {"completed": False, "status": "ineligible", "modelEvaluated": False}}
            or not isinstance(captured.get("reset"), dict)
            or captured["reset"].get("status") != "committed"
            or not isinstance(captured.get("resetDenied"), dict)
            or captured["resetDenied"].get("status") != 401):
        raise RuntimeError("Manual-RAG Judge diagnostic or no-credit lifecycle mismatch")
    return receipt


def assert_manual_rag_fixed_evidence(root):
    root = Path(root)
    receipt = read_private_bounded_json(root / "manual-rag-evidence.json", 65536)
    expected = set(MANUAL_RAG_FIXED_FLAGS) | {"passed", "scope", "similarRuns", "modelCalls",
        "selectedSimilarCalls", "judgeCalls", "errors", "cleanupErrors", "credit", "diagnostic"}
    if (not isinstance(receipt, dict) or set(receipt) != expected
            or any(receipt[flag] is not True for flag in MANUAL_RAG_FIXED_FLAGS)
            or receipt["passed"] is not True or receipt["scope"] != MANUAL_RAG_FIXED_SCOPE
            or receipt["credit"] is not False or receipt["diagnostic"] is not False
            or type(receipt["similarRuns"]) is not int or receipt["similarRuns"] != 1
            or type(receipt["selectedSimilarCalls"]) is not int or receipt["selectedSimilarCalls"] != 1
            or type(receipt["judgeCalls"]) is not int or receipt["judgeCalls"] != 0
            or receipt["errors"] != []
            or receipt["cleanupErrors"] != [] or type(receipt["modelCalls"]) is not int
            or not 4 <= receipt["modelCalls"] <= 10):
        raise RuntimeError("Manual-RAG fixed-only receipt failed closed validation")
    wire = read_private_bounded_json(root / "manual-rag-original-wire.json",
                                     MANUAL_RAG_BROWSER_WIRE_BYTES)
    if (not isinstance(wire, dict)
            or set(wire) != {"scope", "credit", "model", "modelDigest", "actorCalls",
                             "judgeCalls", "actorSpans", "judgeTranscripts", "requests",
                             "originalCapture", "pageErrors"}
            or wire["scope"] != MANUAL_RAG_FIXED_SCOPE or wire["credit"] is not False
            or wire["model"] != REFUND_MODEL or wire["modelDigest"] != REFUND_MODEL_DIGEST
            or not isinstance(wire["actorCalls"], list)
            or len(wire["actorCalls"]) != receipt["modelCalls"]
            or wire["judgeCalls"] != [] or wire["judgeTranscripts"] != []
            or not isinstance(wire["actorSpans"], list)
            or not isinstance(wire["requests"], list)
            or not isinstance(wire["originalCapture"], dict)
            or wire["pageErrors"] != []):
        raise RuntimeError("Manual-RAG fixed-only original wire envelope mismatch")
    for call in wire["actorCalls"]:
        if (not isinstance(call, dict) or call.get("kind") != "actor"
                or call.get("model") != REFUND_MODEL or call.get("status") != 200
                or call.get("responseComplete") is not True
                or call.get("responseCaptureTruncated") is not False
                or not isinstance(call.get("request"), str)
                or not isinstance(call.get("response"), str)
                or call.get("requestBytes") != len(call["request"].encode("utf-8"))
                or call.get("responseBytes") != len(call["response"].encode("utf-8"))
                or call["requestBytes"] > 256 * 1024 or call["responseBytes"] > 4 * 1024 * 1024
                or call.get("requestSha256") != hashlib.sha256(call["request"].encode("utf-8")).hexdigest()
                or call.get("responseSha256") != hashlib.sha256(call["response"].encode("utf-8")).hexdigest()):
            raise RuntimeError("Manual-RAG fixed-only actor wire is incomplete or unbound")
    selected = [span for span in wire["actorSpans"] if isinstance(span, dict)
        and any(isinstance(tool, dict) and tool.get("name") == "product-search.similar"
                for tool in (span.get("result") or {}).get("tool_uses", []))]
    posts = [row for row in wire["requests"] if isinstance(row, dict)
        and row.get("method") == "POST"
        and re.fullmatch(r"/products/[0-9]+/similar", str(row.get("pathname")))]
    captured = wire["originalCapture"]
    fixed = captured.get("fixed")
    receipt_row = captured.get("fixedReceipt")
    preimage = captured.get("fixedManualPreimage")
    if (len(selected) != 1 or len(posts) != 1
            or posts[0].get("status") != 200 or posts[0].get("error") is not None
            or not isinstance(fixed, dict) or fixed != posts[0]
            or not isinstance(receipt_row, dict) or not isinstance(preimage, dict)
            or preimage.get("receipt") != receipt_row
            or not isinstance(preimage.get("documentsJson"), str)
            or hashlib.sha256(preimage["documentsJson"].encode("utf-8")).hexdigest() != receipt_row.get("documentDigest")
            or not isinstance(captured.get("fixedUploader"), dict)
            or not isinstance(captured.get("fixedConsumer"), dict)
            or captured.get("fixedSavedAssessment") != {"status": 200,
                "body": {"completed": False, "status": "ineligible", "modelEvaluated": False}}
            or not isinstance(captured.get("peerBefore"), list)
            or not captured["peerBefore"]
            or not isinstance(captured.get("peerDenied"), dict)
            or captured["peerDenied"].get("status") != 401
            or not isinstance(captured.get("reset"), dict)
            or captured["reset"].get("status") != "committed"
            or not isinstance(captured.get("resetDenied"), dict)
            or captured["resetDenied"].get("status") != 401
            or any(key in captured for key in ("packet", "judgment", "source"))):
        raise RuntimeError("Manual-RAG fixed-only source, no-credit or recovery mismatch")
    try:
        result = json.loads(fixed["response"])
    except (KeyError, TypeError, ValueError):
        raise RuntimeError("Manual-RAG fixed-only physical response invalid") from None
    if (result.get("mode") != "catalog" or result.get("retrieved_context") != []
            or not isinstance(result.get("modeCapability"), dict)
            or result["modeCapability"].get("effectiveMode") != "fixed"):
        raise RuntimeError("Manual-RAG fixed-only physical response mismatch")
    return receipt


def process_group_exists(pgid, *, runner=subprocess.run, env=None):
    result = runner(["ps", "-axo", "pgid=,stat="], env=env, capture_output=True,
                    text=True, timeout=10)
    if result.returncode != 0:
        raise RuntimeError(f"Owned process-group probe failed: {pgid}")
    return any(fields and fields[0] == str(pgid)
               for fields in (line.split() for line in result.stdout.splitlines()))


def stop_group(child, *, env=None, group_exists=process_group_exists, killpg=os.killpg,
               monotonic=time.monotonic, sleep=time.sleep, term_seconds=8, kill_seconds=3):
    """Stop and prove absence of a captured group even after its leader exits."""
    pgid = getattr(child, "_owned_pgid", None)
    if not isinstance(pgid, int) or pgid <= 1:
        raise RuntimeError("Owned process group was not captured")
    child.poll()
    if group_exists(pgid, env=env):
        try:
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


def cleanup_containers(intents, docker, base_env, *, runner=subprocess.run):
    """Attempt removal and exact absence verification for every predeclared container."""
    rows, errors = [], []
    for intent in reversed(intents):
        row = dict(intent)
        try:
            result = runner(docker + ["rm", "--force", intent["name"]], env=base_env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            if result.returncode not in (0, 1):
                raise RuntimeError(f"Owned container removal failed: {intent['name']}")
        except Exception as error:
            errors.append(error)
        try:
            probe = runner(docker + ["ps", "-a", "--filter", f"name=^{intent['name']}$",
                                      "--format", "{{.Names}}"], env=base_env,
                           capture_output=True, text=True, timeout=30)
            if probe.returncode != 0 or probe.stdout.strip():
                raise RuntimeError(f"Owned container absence verification failed: {intent['name']}")
            row["cleanup"] = "absent_verified"
        except Exception as error:
            row["cleanup"] = "failed"
            row["error"] = f"{type(error).__name__}: {error}"
            errors.append(error)
        rows.append(row)
    return rows, errors


def child_identity(child):
    return {"name": child._owned_name, "pid": child.pid, "pgid": child._owned_pgid}


def finalize_owned(children, logs, container_intents, docker, base_env, cleanup_receipt):
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
    container_rows, container_errors = cleanup_containers(container_intents, docker, base_env)
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


def wait_postgres_host(psql, env, *, runner=subprocess.run, monotonic=time.monotonic,
                       sleep=time.sleep, timeout_seconds=30):
    """Wait for the final mapped TCP server, not initdb's temporary local server."""
    deadline = monotonic() + timeout_seconds
    probe = psql + ["-X", "-A", "-t", "-c", "SELECT 1"]
    while monotonic() < deadline:
        try:
            result = runner(probe, env=env, capture_output=True, text=True, timeout=2)
            if result.returncode == 0 and result.stdout.strip() == "1":
                return
        except subprocess.TimeoutExpired:
            pass
        sleep(0.25)
    raise RuntimeError("Owned PostgreSQL mapped host did not become ready")


def run_qualification(args):
    if args.audit_injection and not args.audit_summary:
        raise RuntimeError("--audit-injection requires --audit-summary")
    if args.audit_summary and args.suite != "manual-rendered":
        raise RuntimeError("--audit-summary requires manual-rendered")
    suite = SUITES[args.suite]
    source = Path(__file__).resolve().parents[2]
    if args.suite in REQUIRES_MAIN_CHECKOUT and not args.main_checkout:
        raise RuntimeError(f"{args.suite} requires --main-checkout")
    if args.main_checkout and args.suite not in MAIN_CHECKOUT_SUITES:
        raise RuntimeError("--main-checkout is limited to the focused native suites")
    source_before = main_checkout_inventory(source, args.suite) if args.main_checkout else None
    node = validate_executable(args.node, args.node_sha256, "Managed Node")
    docker_cli = validate_executable(args.docker_cli, args.docker_cli_sha256, "Docker CLI")
    browser = None
    browser_tools = None
    browser_record_spec = None
    if args.suite in ("manual-rendered", "product-similar-browser", "product-summary-browser", "manual-rag-browser", "manual-rag-fixed-browser"):
        if not args.browser or not args.browser_sha256:
            raise RuntimeError("Pinned browser executable and hash required")
        browser = validate_executable(args.browser, args.browser_sha256, "Chromium")
        spec = importlib.util.spec_from_file_location("owned_browser_tools",
            source / "tests/postgres/run-csrf-email-composed-isolated.py")
        browser_tools = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(browser_tools)
        browser_record_spec = {
            "manual-rendered": (("product-browser.json", "product_browser"),),
            "product-similar-browser": (("product-similar-browser.json", "product_similar_browser"),),
            "product-summary-browser": (("product-similar-browser.json", "product_similar_browser"),),
            "manual-rag-browser": (("manual-rag-browser.json", "manual_rag_browser"),),
            "manual-rag-fixed-browser": (("manual-rag-browser.json", "manual_rag_browser"),),
        }[args.suite]
    embedding_cache = None
    if args.suite in EMBEDDING_CACHE_SUITES:
        if not args.embedding_cache or not Path(args.embedding_cache).is_absolute():
            raise RuntimeError("An absolute installed embedding cache is required")
        embedding_cache = Path(args.embedding_cache).resolve(strict=True)
        if not embedding_cache.is_dir():
            raise RuntimeError("Embedding cache must be a directory")
    root = Path(tempfile.mkdtemp(prefix="dvaia-secureshop-bound-review-composition-"))
    os.chmod(root, 0o700)
    workspace = source if args.main_checkout else root / "source"
    if not args.main_checkout:
        workspace.mkdir(mode=0o700)
    base_env = {key: os.environ[key] for key in ("PATH", "HOME", "TMPDIR") if key in os.environ}
    if args.main_checkout:
        for private in ("home", "tmp", "docker-config"):
            (root / private).mkdir(mode=0o700)
        base_env.update(HOME=str(root / "home"), TMPDIR=str(root / "tmp"),
                        TMP=str(root / "tmp"), TEMP=str(root / "tmp"),
                        DOCKER_CONFIG=str(root / "docker-config"))
        write_private_json(root / "source-before.json", source_before)
    docker = [str(docker_cli), "--host", args.docker_host]
    run_id = uuid.uuid4().hex[:12]
    container_family = {
        "v01-checkout-audit": "v01-checkout-audit",
        "audit-composition": "audit-composition",
        "audit-actual-8b": "audit-actual-8b",
        "mcp-actual-8b": "mcp-actual-8b",
        "mcp-provenance-preflight": "mcp-provenance-preflight",
        "audit-fresh-schema": "audit-fresh-schema",
        "audit-journal": "audit-journal",
        "manual-rendered": "manual-rendered",
        "manual-retrieval-actual-8b": "manual-retrieval-actual-8b",
        "manual-actual-8b": "manual-actual-8b",
        "manual-integration": "manual-integration",
        "manual-ingest": "manual-ingest",
        "manual-rag-source": "manual-rag-source",
        "manual-rag-preimages": "manual-rag-preimages",
        "product-similar-browser": "product-similar-browser",
        "product-summary-browser": "product-summary-browser",
        "manual-rag-browser": "manual-rag-browser",
        "manual-rag-fixed-browser": "manual-rag-fixed-browser",
        "embedding-revision": "embedding-revision",
        "product-integration": "product-integration",
        "product-actual-8b": "product-actual-8b",        "product-retrieval": "product-retrieval",
        "capacity": "capacity",
        "capacity-actual-8b": "capacity-actual-8b",
        "sql-teaching-copy": "sql-teaching-copy",
        "identity": "identity",
        "xss-email-owner-listing": "xss-email-owner-listing",
        "xss-judgment-child": "xss-judgment-child",
        "composition": "bound-review-composition",
        "persona-sessions": "bound-persona-sessions",
        "persona-password": "bound-persona-password",
        "persona-api-keys": "bound-persona-api-keys",
        "merchant-listings": "bound-merchant-listings",
        "refund": "bound-refund",
        "refund-actual-8b": "bound-refund-actual-8b",
        "migration-tails": "migration-tails",
    }[args.suite]
    container = f"dvaia-secureshop-{container_family}-{run_id}"
    container_intents, children, logs = [], [], []
    child_intent_path = root / "child-process-intent.json"
    container_intent_path = root / "container-intent.json"
    cleanup_receipt = root / "cleanup.json"
    primary = None
    signal_state = {"finalizing": False, "signum": None}

    def interrupted(signum, _frame):
        signal_state["signum"] = signum
        if signal_state["finalizing"]:
            return
        raise OwnedSignalExit(128 + signum)

    previous_signals = {signal.SIGTERM: signal.signal(signal.SIGTERM, interrupted),
                        signal.SIGINT: signal.signal(signal.SIGINT, interrupted)}

    def run(command, **kwargs):
        kwargs.setdefault("timeout", 60)
        kwargs.setdefault("env", base_env)
        return subprocess.run(command, check=True, **kwargs)

    def ignore(_directory, names):
        denied = {".git", "node_modules", "build", "logs", "uploads", "sensitive_files",
                  "workshop_data", "vector-indexes", "coverage", ".cache", "__pycache__"}
        suffixes = (".db", ".db-wal", ".db-shm", ".db-journal", ".sqlite", ".sqlite3", ".log")
        return [name for name in names if name in denied or name.startswith(".env")
                or any(name.endswith(suffix) for suffix in suffixes)]

    try:
        if not args.main_checkout:
            for directory in ("server", "db", "tests", "docs"):
                shutil.copytree(source / directory, workspace / directory, ignore=ignore)
            (workspace / "sidecars/sandbox-runner").mkdir(parents=True)
            shutil.copy2(source / "sidecars/sandbox-runner/secureshopFiles.js",
                         workspace / "sidecars/sandbox-runner/secureshopFiles.js")
            if browser is not None:
                shutil.copytree(source / "client/build", workspace / "client/build")
            else:
                shutil.copytree(source / "client/build/secureshop-review-renderer",
                                workspace / "client/build/secureshop-review-renderer")
            (workspace / "node_modules").symlink_to(source / "node_modules", target_is_directory=True)

        image = run(docker + ["image", "inspect", POSTGRES_IMAGE_ID, "--format", "{{.Id}}"],
                    capture_output=True, text=True).stdout.strip()
        if image != POSTGRES_IMAGE_ID:
            raise RuntimeError("Pinned PostgreSQL image is unavailable")
        container_intents.append({"name": container, "image": POSTGRES_IMAGE_ID})
        write_private_json(container_intent_path, {"schemaVersion": 1,
            "containers": list(container_intents)})
        run(docker + ["run", "--detach", "--pull", "never", "--name", container,
            "--tmpfs", "/var/lib/postgresql:rw,size=335544320",
            "-e", "POSTGRES_USER=composition_admin", "-e", "POSTGRES_HOST_AUTH_METHOD=trust",
            "-e", "POSTGRES_INITDB_ARGS=--wal-segsize=1", "-p", "127.0.0.1::5432",
            POSTGRES_IMAGE_ID, "-c", "shared_buffers=16MB", "-c", "max_connections=48",
            "-c", "max_wal_size=16MB", "-c", "min_wal_size=4MB"], stdout=subprocess.DEVNULL)
        port = int(run(docker + ["port", container, "5432"], capture_output=True,
                       text=True).stdout.strip().rsplit(":", 1)[1])
        psql = ["psql", "-h", "127.0.0.1", "-p", str(port), "-U", "composition_admin",
                "-d", "postgres", "-v", "ON_ERROR_STOP=1"]
        wait_postgres_host(psql, base_env)
        required_role_pairs = {ROLE_PAIRS[family] for _, family in suite["stores"]}
        for migration, runtime in sorted(required_role_pairs):
            for role in (migration, runtime):
                run(psql + ["-c", f"CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"], stdout=subprocess.DEVNULL)
        env = dict(base_env, NODE_ENV="test", PLATFORM_DATABASE_ENGINE="postgres",
                   WORKSHOP_DATABASE_ENGINE="postgres", SS_PERSONA_INBOX_READY="false",
                   PG_TEST_DISPOSABLE="yes", DVAIA_ISOLATED_TEST_WORKSPACE=str(root if args.main_checkout else workspace),
                   AWS_EC2_METADATA_DISABLED="true", JWT_SECRET="owned-composition-secret-at-least-32-bytes")
        if browser is not None:
            env.update(SS_PRODUCT_BROWSER_QUALIFICATION="1",
                       SS_PRODUCT_BROWSER_EXECUTABLE=str(browser),
                       SS_PRODUCT_BROWSER_EXECUTABLE_SHA256=args.browser_sha256,
                       SS_PRODUCT_BROWSER_RECORD_PATH=str(root / "product-browser.json"))
        if args.suite == "v01-checkout-audit":
            env["SECURESHOP_V01_CHECKOUT_AUDIT_NATIVE"] = "1"
        if args.suite == "audit-composition":
            env["SS_AUDIT_SUMMARY_ENABLED"] = "true"
        if args.suite == "mcp-provenance-preflight":
            env["MCP_TRUST_MODEL_PREFLIGHT"] = "1"
        if args.suite == "manual-ingest":
            env["SS_MANUAL_INGEST_NATIVE"] = "1"
        if args.suite == "embedding-revision":
            env["EMBEDDING_REVISION_NATIVE"] = "1"
        if args.suite == "manual-rag-source":
            env["SECURESHOP_MANUAL_RAG_SOURCE_NATIVE"] = "1"
            env["DVAIA_CURRENT_MAIN_WORKSPACE"] = str(source)
        if args.suite == "manual-rag-preimages":
            env["SECURESHOP_MANUAL_RAG_PREIMAGES_NATIVE"] = "1"
            env["DVAIA_CURRENT_MAIN_WORKSPACE"] = str(source)
        if args.suite in ("product-similar-browser", "product-summary-browser"):
            env.update(LIVE_OLLAMA_TEST="1",
                DVAIA_CURRENT_MAIN_WORKSPACE=str(source),
                SECURESHOP_PRODUCT_SIMILAR_BROWSER_BUILD=str(source / "client/build"),
                SECURESHOP_PRODUCT_SIMILAR_EVIDENCE_PATH=str(root / "product-similar-evidence.json"),
                SECURESHOP_PRODUCT_SIMILAR_BROWSER_RECORD_PATH=str(root / "product-similar-browser.json"),
                SECURESHOP_PRODUCT_SIMILAR_BROWSER_SHA256=args.browser_sha256,
                PUPPETEER_EXECUTABLE_PATH=str(browser), AI_PROVIDER="ollama",
                OLLAMA_MODEL=REFUND_MODEL, OLLAMA_BASE_URL=REFUND_OLLAMA_BASE_URL,
                LAB_MODE="vuln")
            env["SECURESHOP_PRODUCT_SUMMARY_BROWSER_NATIVE" if args.suite == "product-summary-browser" else "SECURESHOP_PRODUCT_SIMILAR_BROWSER_NATIVE"] = "1"
        if args.suite in ("manual-rag-browser", "manual-rag-fixed-browser"):
            env.update(SECURESHOP_MANUAL_RAG_BROWSER_NATIVE="1", LIVE_OLLAMA_TEST="1",
                DVAIA_CURRENT_MAIN_WORKSPACE=str(source),
                SECURESHOP_MANUAL_RAG_BROWSER_BUILD=str(source / "client/build"),
                SECURESHOP_MANUAL_RAG_EVIDENCE_PATH=str(root / "manual-rag-evidence.json"),
                SECURESHOP_MANUAL_RAG_BROWSER_RECORD_PATH=str(root / "manual-rag-browser.json"),
                SECURESHOP_MANUAL_RAG_BROWSER_SHA256=args.browser_sha256,
                PUPPETEER_EXECUTABLE_PATH=str(browser), AI_PROVIDER="ollama",
                OLLAMA_MODEL=REFUND_MODEL, OLLAMA_BASE_URL=REFUND_OLLAMA_BASE_URL,
                LAB_MODE="vuln")
            if args.suite == "manual-rag-fixed-browser":
                env["SECURESHOP_MANUAL_RAG_FIXED_ONLY"] = "1"
        if args.suite == "product-retrieval":
            env["SECURESHOP_BOUND_RETRIEVAL_NATIVE"] = "1"
        if embedding_cache is not None:
            env.update(SS_PRODUCT_QUALIFICATION="1", HF_HUB_OFFLINE="1", XENOVA_CACHE=str(embedding_cache))
        if args.suite in ("manual-integration", "manual-actual-8b", "manual-retrieval-actual-8b", "manual-rendered"):
            env["SS_MANUAL_QUALIFICATION"] = "1"
        if args.suite == "manual-retrieval-actual-8b":
            env["SS_MANUAL_RETRIEVAL_QUALIFICATION"] = "1"
            env["SS_PRODUCT_LOOP_JUDGE_QUALIFICATION"] = "1"
        model_identity_before = None
        if args.audit_injection:
            env["SS_AUDIT_RENDERED_INJECTION"] = "1"
        if args.audit_summary:
            model_identity_before = read_refund_model_digest()
            env.update(SS_AUDIT_SUMMARY_ENABLED="true", SS_AUDIT_RENDERED_QUALIFICATION="1",
                       OLLAMA_MODEL=REFUND_MODEL, OLLAMA_BASE_URL=REFUND_OLLAMA_BASE_URL)
        if args.suite == "audit-actual-8b":
            model_identity_before = read_refund_model_digest()
            env.update(SS_AUDIT_GRAPH_LIVE_MODEL="1", OLLAMA_MODEL=REFUND_MODEL,
                       OLLAMA_BASE_URL=REFUND_OLLAMA_BASE_URL)
        if args.suite == "mcp-actual-8b":
            model_identity_before = read_refund_model_digest()
            env.update(LIVE_OLLAMA_TEST="1", OLLAMA_MODEL=REFUND_MODEL,
                       OLLAMA_BASE_URL=REFUND_OLLAMA_BASE_URL)
        if args.suite in ("product-similar-browser", "product-summary-browser", "manual-rag-browser", "manual-rag-fixed-browser"):
            model_identity_before = read_refund_model_digest()
        if args.suite in ("product-actual-8b", "manual-actual-8b", "manual-retrieval-actual-8b"):
            model_identity_before = read_refund_model_digest()
            env.update(SS_PRODUCT_LIVE_MODEL="1" if args.suite == "product-actual-8b" else "0",
                       SS_MANUAL_LIVE_MODEL="1" if args.suite in ("manual-actual-8b", "manual-retrieval-actual-8b") else "0", OLLAMA_MODEL=REFUND_MODEL,
                       OLLAMA_BASE_URL=REFUND_OLLAMA_BASE_URL)
        if args.suite == "refund-actual-8b":
            model_identity_before = read_refund_model_digest()
            env.update(SS_REFUND_LIVE_MODEL="1", OLLAMA_MODEL=REFUND_MODEL,
                       OLLAMA_BASE_URL=REFUND_OLLAMA_BASE_URL)
        if args.suite == "capacity":
            env["DVAIA_CAPACITY_QUALIFICATION"] = "yes"
        if args.suite == "capacity-actual-8b":
            model_identity_before = read_capacity_model_digest()
            env.update(DVAIA_CAPACITY_ACTUAL8B="yes", OLLAMA_MODEL=REFUND_MODEL,
                       OLLAMA_BASE_URL=REFUND_OLLAMA_BASE_URL,
                       AI_OLLAMA_CONCURRENCY="2", AI_OLLAMA_QUEUE_LIMIT="256",
                       PG_POOL_MAX_LEASE="6")
        migration_keys = {"IDENTITY": "IDENTITY_MIGRATION_DATABASE_URL", "AGENTS": "SECURESHOP_AGENTS_MIGRATION_DATABASE_URL",
                          "REVIEW": "SECURESHOP_REVIEW_MIGRATION_DATABASE_URL", "COMMERCE": "SECURESHOP_MIGRATION_DATABASE_URL"}
        runtime_keys = {"IDENTITY": "IDENTITY_DATABASE_URL", "AGENTS": "SECURESHOP_AGENTS_DATABASE_URL",
                        "REVIEW": "SECURESHOP_REVIEW_DATABASE_URL", "COMMERCE": "SECURESHOP_DATABASE_URL"}
        for store, family in suite["stores"]:
            migration, runtime = ROLE_PAIRS[family]
            database = database_name(args.suite, store, run_id)
            run(psql + ["-c", f"CREATE DATABASE {database} OWNER {migration}"], stdout=subprocess.DEVNULL)
            run(psql + ["-c", f"REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{runtime}"], stdout=subprocess.DEVNULL)
            migration_url = f"postgresql://{quote(migration)}@127.0.0.1:{port}/{database}"
            runtime_url = f"postgresql://{quote(runtime)}@127.0.0.1:{port}/{database}"
            if args.suite == "sql-teaching-copy":
                env["PG_SQL_TEACHING_COPY_TEST_URL"] = migration_url
            else:
                env[f'{suite["env_prefix"]}{store}_MIGRATION_URL'] = migration_url
                env[f'{suite["env_prefix"]}{store}_RUNTIME_URL'] = runtime_url
            if args.suite in ("audit-composition", "composition", "refund-actual-8b", "product-integration", "product-actual-8b", "manual-integration", "manual-actual-8b", "manual-retrieval-actual-8b", "manual-rendered"):
                env[migration_keys[store]] = migration_url
                env[runtime_keys[store]] = runtime_url

        log_path = root / "result.log"
        log = open_private_log(log_path)
        logs.append(log)
        child = subprocess.Popen([str(node), "--test", "--test-reporter=tap",
            suite["test"]], cwd=workspace,
            env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        child._owned_name = suite["child_name"]
        child._owned_pgid = child.pid
        children.append(child)
        write_private_json(child_intent_path, {"schemaVersion": 1,
            "processes": [child_identity(item) for item in children]})
        code = child.wait(timeout=600 if args.suite in ("product-summary-browser", "manual-rag-browser", "manual-rag-fixed-browser") else (360 if args.suite == "product-similar-browser" else (300 if args.suite in ("audit-actual-8b", "mcp-actual-8b", "capacity-actual-8b", "product-actual-8b", "manual-actual-8b", "manual-retrieval-actual-8b", "manual-rendered", "manual-rag-preimages") else (210 if args.suite in ("capacity", "manual-rag-source") else (150 if args.suite == "refund-actual-8b" else 120)))))
        if code:
            raise RuntimeError(f"SecureShop {args.suite} integration failed ({code})")
        if args.suite in ("v01-checkout-audit", "audit-composition", "audit-actual-8b", "mcp-actual-8b", "mcp-provenance-preflight", "audit-fresh-schema", "audit-journal", "manual-ingest", "embedding-revision", "manual-rag-source", "manual-rag-preimages", "product-similar-browser", "product-summary-browser", "manual-rag-browser", "manual-rag-fixed-browser", "xss-email-owner-listing", "product-retrieval", "product-integration", "product-actual-8b", "manual-integration", "manual-actual-8b", "manual-retrieval-actual-8b", "manual-rendered"):
            log.flush()
            assert_non_skipped_tap(log_path, args.suite)
            if args.suite == "v01-checkout-audit":
                assert_exact_single_tap(log_path, "native V01 lesson joins one real checkout audit and denies substituted lifecycle sources")
            if args.suite == "manual-rag-source":
                assert_exact_single_tap(log_path, "native manual RAG source adapter joins historical uploader and current consumer using immutable SQL evidence")
            if args.suite == "manual-rag-preimages":
                assert_exact_single_tap(log_path, "native manual RAG preimages preserve original dense vectors across upgrade, replay, rollback and retirement")
            if args.suite == "product-summary-browser":
                assert_exact_single_tap(log_path, PRODUCT_SUMMARY_ASSERTION)
                assert_product_summary_evidence(root)
            if args.suite == "product-similar-browser":
                assert_exact_single_tap(log_path, "registered customer physically requests similar products and reloads only the saved result")
                assert_product_similar_evidence(root)
            if args.suite == "manual-rag-browser":
                assert_exact_single_tap(log_path, "V26 physical uploaded manual instruction adoption with original configured Judge diagnostic and no credit")
                assert_manual_rag_browser_evidence(root)
            if args.suite == "manual-rag-fixed-browser":
                assert_exact_single_tap(log_path, "V26 fixed-only physical uploaded manual and genuine Fixed Similar without Judge or credit")
                assert_manual_rag_fixed_evidence(root)
        if args.audit_summary or args.suite in ("audit-actual-8b", "mcp-actual-8b", "product-actual-8b", "manual-actual-8b", "manual-retrieval-actual-8b"):
            model_identity_after = read_refund_model_digest()
            if model_identity_after != model_identity_before:
                raise RuntimeError(f"Pinned model changed during {args.suite} qualification")
            write_private_json(root / ("manual-model-identity.json" if args.suite in ("manual-actual-8b", "manual-retrieval-actual-8b") else "product-model-identity.json"), {
                "before": model_identity_before, "after": model_identity_after,
            })
        if args.suite == "refund-actual-8b":
            model_identity_after = read_refund_model_digest()
            if model_identity_after != model_identity_before:
                raise RuntimeError("Pinned Ollama model identity changed during refund qualification")
            write_private_json(root / "refund-model-identity.json", {
                "before": model_identity_before, "after": model_identity_after,
                "maxTransportCalls": 6,
            })
        if args.suite == "capacity-actual-8b":
            model_identity_after = read_capacity_model_digest()
            if model_identity_after != model_identity_before:
                raise RuntimeError("Pinned Ollama model identity changed during capacity qualification")
            write_private_json(root / "capacity-model-identity.json", {
                "before": model_identity_before, "after": model_identity_after,
                "maxProviderCalls": 10,
            })
        if args.suite in ("product-similar-browser", "product-summary-browser"):
            model_identity_after = read_refund_model_digest()
            if model_identity_after != model_identity_before:
                raise RuntimeError("Pinned Ollama model changed during product-similar qualification")
            write_private_json(root / "product-similar-model-identity.json", {
                "before": model_identity_before, "after": model_identity_after,
                "maxHttpCalls": 20 if args.suite == "product-summary-browser" else 14,
                **({"maxActorHttpCalls": 12, "maxJudgeHttpCalls": 8} if args.suite == "product-summary-browser" else {}),
            })
        if args.suite in ("manual-rag-browser", "manual-rag-fixed-browser"):
            model_identity_after = read_refund_model_digest()
            if model_identity_after != model_identity_before:
                raise RuntimeError("Pinned Ollama model changed during manual-RAG browser qualification")
            write_private_json(root / ("manual-rag-fixed-model-identity.json" if args.suite == "manual-rag-fixed-browser"
                                       else "manual-rag-model-identity.json"), {
                "before": model_identity_before, "after": model_identity_after,
                "maxActorHttpCalls": 10 if args.suite == "manual-rag-fixed-browser" else 14,
                "maxJudgeHttpCalls": 0 if args.suite == "manual-rag-fixed-browser" else 4,
            })
        if browser is not None:
            browser_tools.read_browser_records(root, browser, args.browser_sha256,
                                               require_all=True, records=browser_record_spec)
        log.flush()
        os.fsync(log.fileno())
        if log_path.stat().st_size > MAX_LOG_BYTES:
            raise RuntimeError(f"SecureShop {args.suite} log exceeds bound")
    except BaseException as error:
        primary = error
    finally:
        signal_state["finalizing"] = True
        cleanup_errors = finalize_owned(children, logs, container_intents, docker, base_env,
                                        cleanup_receipt)
        if browser is not None:
            try:
                records = browser_tools.read_browser_records(root, browser,
                    args.browser_sha256, require_all=primary is None,
                    records=browser_record_spec)
                results, errors = browser_tools.cleanup_browser_processes(records, browser, base_env)
                write_private_json(root / "browser-cleanup.json", {"schemaVersion": 1, "processes": results})
                cleanup_errors.extend(errors)
            except Exception as browser_error:
                cleanup_errors.append(browser_error)
        if source_before is not None:
            try:
                source_after = main_checkout_inventory(source, args.suite)
                write_private_json(root / "source-after.json", source_after)
                if source_after != source_before:
                    raise RuntimeError("Current checkout source changed during qualification")
            except Exception as source_error:
                cleanup_errors.append(source_error)
        for signum, previous in previous_signals.items():
            signal.signal(signum, previous)
        if primary is None and signal_state["signum"] is not None:
            primary = OwnedSignalExit(128 + signal_state["signum"])
        print(f"Owned evidence retained at {root}", flush=True)
        add_cleanup_errors(primary, cleanup_errors)
    if primary is not None:
        raise primary


def main(argv=None):
    args = parse_args(argv)
    if args.suite in REQUIRES_MAIN_CHECKOUT and not args.main_checkout:
        raise RuntimeError(f"{args.suite} requires --main-checkout")
    if args.main_checkout and args.suite not in MAIN_CHECKOUT_SUITES:
        raise RuntimeError("--main-checkout is limited to the focused native suites")
    if not args.run:
        if args.main_checkout:
            inventory = main_checkout_inventory(Path(__file__).resolve().parents[2], args.suite)
            print(json.dumps({"suite": args.suite, "mode": "main-checkout", "sourceCopy": False,
                              "sourceDigest": inventory["digest"], "sourceFiles": len(inventory["files"]),
                              "stores": [store for store, _ in SUITES[args.suite]["stores"]],
                              "nativeStarted": False}, sort_keys=True))
        else:
            print("plan: no workspace, container, database, browser, or model mutation")
        return 0
    run_qualification(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
