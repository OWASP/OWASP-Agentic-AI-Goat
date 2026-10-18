#!/usr/bin/env python3
"""Owned PostgreSQL + Mailpit admission for the assembled IPI email UI."""

import argparse
import hashlib
import json
import os
import secrets
import shutil
import signal
import subprocess
import tempfile
import time
import uuid
from pathlib import Path


EXPECTED_MODEL_DIGEST = "46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e"
MAX_EVIDENCE_BYTES = 1 << 20


class OwnedSignalExit(SystemExit):
    pass


def parse_args(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--docker-host", required=True)
    parser.add_argument("--node", required=True)
    parser.add_argument("--node-sha256", required=True)
    parser.add_argument("--browser", required=True)
    parser.add_argument("--browser-sha256", required=True)
    parser.add_argument("--run", action="store_true", help="Root-controlled execution gate")
    return parser.parse_args(argv)


def read_bounded_json(path, label, max_bytes=MAX_EVIDENCE_BYTES):
    try:
        size = path.stat().st_size
    except FileNotFoundError as error:
        raise RuntimeError(f"{label} missing") from error
    if size <= 0 or size > max_bytes:
        raise RuntimeError(f"{label} size invalid")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"{label} JSON invalid") from error
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} must be an object")
    return value


def validate_fixture_completion(fixture, readiness_path, expected_digest=EXPECTED_MODEL_DIGEST):
    """Admit only a clean fixture exit with an exact before/after digest receipt."""
    returncode = fixture.poll()
    if returncode is None:
        raise RuntimeError("Owned fixture still running after shutdown")
    if returncode != 0:
        raise RuntimeError(f"Owned fixture shutdown failed ({returncode}); see retained fixture.log")
    ready = read_bounded_json(readiness_path, "Owned fixture readiness")
    final = read_bounded_json(Path(f"{readiness_path}.final"), "Owned fixture final evidence")
    before = ready.get("modelDigestBefore")
    if before != expected_digest:
        raise RuntimeError("Owned fixture readiness model digest mismatch")
    if final.get("modelDigestBefore") != expected_digest or final.get("modelDigestAfter") != expected_digest:
        raise RuntimeError("Owned fixture final model digest mismatch")
    return final


def process_group_exists(pgid, *, runner=subprocess.run, env=None):
    result = runner(
        ["ps", "-axo", "pgid=,stat="],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Owned process-group probe failed: {pgid}")
    for line in result.stdout.splitlines():
        fields = line.split()
        if fields and fields[0] == str(pgid):
            return True
    return False


def stop_group(
    child,
    *,
    env=None,
    group_exists=process_group_exists,
    killpg=os.killpg,
    monotonic=time.monotonic,
    sleep=time.sleep,
    term_seconds=8,
    kill_seconds=3,
):
    """Stop and prove absence of the captured group, even if its leader exited."""
    pgid = getattr(child, "_owned_pgid", None)
    if not isinstance(pgid, int) or pgid <= 1:
        raise RuntimeError("Owned process group was not captured")

    child.poll()  # reap a terminal leader; descendants can still retain the PGID
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


def cleanup_containers(started, docker, base_env, *, runner=subprocess.run):
    """Attempt every removal and absence probe, then report all failures."""
    errors = []
    for name in reversed(started):
        try:
            result = runner(
                docker + ["rm", "--force", name], env=base_env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30,
            )
            if result.returncode not in (0, 1):
                raise RuntimeError(f"Owned container removal failed: {name}")
        except Exception as error:
            errors.append(error)
        try:
            probe = runner(
                docker + ["ps", "-a", "--filter", f"name=^{name}$", "--format", "{{.Names}}"],
                env=base_env, capture_output=True, text=True, timeout=30,
            )
            if probe.returncode != 0:
                raise RuntimeError(f"Owned container absence probe failed: {name}")
            if probe.stdout.strip():
                raise RuntimeError(f"Owned container cleanup failed: {name}")
        except Exception as error:
            errors.append(error)
    return errors


def postgres_container_command(docker, name):
    return docker + [
        "run", "--detach", "--pull", "never", "--name", name,
        "--tmpfs", "/var/lib/postgresql:rw,size=536870912",
        "-e", "POSTGRES_USER=ipi_rendered_admin",
        "-e", "POSTGRES_HOST_AUTH_METHOD=trust",
        "-e", "POSTGRES_INITDB_ARGS=--wal-segsize=1",
        "-p", "127.0.0.1::5432",
        "sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280",
        "-c", "shared_buffers=16MB", "-c", "max_connections=50",
        "-c", "max_wal_size=16MB", "-c", "min_wal_size=4MB",
    ]


def capture_container_logs(started, docker, base_env, evidence_root, *, runner=subprocess.run):
    """Retain bounded, private diagnostics before failed containers are removed."""
    errors = []
    for name in started:
        path = evidence_root / f"{name}.container.log"
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                result = runner(
                    docker + ["logs", "--tail", "256", name],
                    env=base_env, stdout=output, stderr=subprocess.STDOUT, timeout=15,
                )
            if result.returncode not in (0, 1):
                raise RuntimeError(f"Owned container log capture failed: {name}")
            if path.stat().st_size > MAX_EVIDENCE_BYTES:
                with path.open("r+b") as output:
                    output.truncate(MAX_EVIDENCE_BYTES)
                errors.append(RuntimeError(f"Owned container log exceeded bound and was truncated: {name}"))
        except Exception as error:
            errors.append(error)
    return errors


def write_private_json(path, value):
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def child_identity(child):
    return {
        "name": child._owned_name,
        "pid": child.pid,
        "pgid": child._owned_pgid,
    }


def write_child_intent(path, children):
    write_private_json(path, {
        "schemaVersion": 1,
        "processes": [child_identity(child) for child in children],
    })


def finalize_owned(children, logs, started, docker, base_env, cleanup_receipt=None):
    errors = []
    process_rows = []
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
    errors.extend(cleanup_containers(started, docker, base_env))
    if cleanup_receipt is not None:
        try:
            write_private_json(cleanup_receipt, {
                "schemaVersion": 1,
                "processes": sorted(process_rows, key=lambda row: row["name"]),
            })
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


def run_qualification(args):
    source = Path(__file__).resolve().parents[2]
    node_path = Path(args.node).resolve()
    browser_path = Path(args.browser).resolve()
    if not node_path.is_file() or hashlib.sha256(node_path.read_bytes()).hexdigest() != args.node_sha256:
        raise RuntimeError("Managed Node pin mismatch")
    if not browser_path.is_file() or hashlib.sha256(browser_path.read_bytes()).hexdigest() != args.browser_sha256:
        raise RuntimeError("Managed browser pin mismatch")

    root = Path(tempfile.mkdtemp(prefix="dvaia-ipi-email-rendered-"))
    os.chmod(root, 0o700)
    workspace = root / "source"
    workspace.mkdir()

    def ignore(_directory, names):
        excluded = {".git", "node_modules", "logs", "uploads", "sensitive_files", "workshop_data", "vector-indexes", "coverage", ".cache", "__pycache__"}
        suffixes = (".db", ".db-wal", ".db-shm", ".db-journal", ".sqlite", ".sqlite3", ".log")
        return [name for name in names if name in excluded or name.startswith(".env") or any(name.endswith(suffix) for suffix in suffixes)]

    shutil.copytree(source / "server", workspace / "server", ignore=ignore)
    shutil.copytree(source / "db", workspace / "db", ignore=ignore)
    shutil.copytree(source / "tests", workspace / "tests", ignore=ignore)
    (workspace / "client").mkdir()
    shutil.copytree(source / "client" / "build", workspace / "client" / "build")
    (workspace / "node_modules").symlink_to(source / "node_modules", target_is_directory=True)

    docker = ["docker", "--host", args.docker_host]
    pg_name = "dvaia-ipi-email-rendered-pg-" + uuid.uuid4().hex[:12]
    mail_name = "dvaia-ipi-email-rendered-mailpit-" + uuid.uuid4().hex[:12]
    base_env = {key: os.environ[key] for key in ("PATH", "HOME", "TMPDIR") if key in os.environ}
    started, children, logs = [], [], []
    readiness = root / "readiness.json"
    child_intent = root / "child-process-intent.json"
    child_cleanup = root / "child-process-cleanup.json"
    primary = None
    signal_state = {"finalizing": False, "signum": None}

    def interrupted(signum, _frame):
        signal_state["signum"] = signum
        if signal_state["finalizing"]:
            return
        raise OwnedSignalExit(128 + signum)

    previous_signals = {
        signal.SIGTERM: signal.signal(signal.SIGTERM, interrupted),
        signal.SIGINT: signal.signal(signal.SIGINT, interrupted),
    }

    def run(cmd, **kwargs):
        kwargs.setdefault("env", base_env)
        kwargs.setdefault("timeout", 60)
        return subprocess.run(cmd, check=True, **kwargs)

    def port(name, container_port):
        text = run(docker + ["port", name, container_port], capture_output=True, text=True).stdout.strip()
        if not text:
            raise RuntimeError(f"Owned container did not publish {container_port}")
        return int(text.splitlines()[-1].rsplit(":", 1)[1])

    def wait_http(url):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if subprocess.run(["curl", "--fail", "--silent", "--max-time", "1", url], env=base_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                return
            time.sleep(0.25)
        raise RuntimeError(f"Owned service readiness timeout: {url}")

    try:
        started.append(pg_name)
        run(postgres_container_command(docker, pg_name), stdout=subprocess.DEVNULL)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if subprocess.run(docker + ["exec", pg_name, "pg_isready", "-h", "127.0.0.1", "-U", "ipi_rendered_admin"], env=base_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                break
            time.sleep(0.25)
        else:
            raise RuntimeError("Owned PostgreSQL did not become ready")
        pg_port = port(pg_name, "5432/tcp")
        psql = docker + ["exec", pg_name, "psql", "-U", "ipi_rendered_admin", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c"]
        run(psql + ["CREATE ROLE dvaia_identity_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"])
        run(psql + ["CREATE ROLE dvaia_identity_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"])
        db = "dvaia_test_ipi_email_rendered_identity"
        run(psql + [f"CREATE DATABASE {db} OWNER dvaia_identity_migration"])
        run(psql + [f"REVOKE CONNECT ON DATABASE {db} FROM PUBLIC; GRANT CONNECT ON DATABASE {db} TO dvaia_identity_migration,dvaia_identity_runtime"])

        started.append(mail_name)
        run(docker + ["run", "--detach", "--pull", "never", "--name", mail_name, "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16777216", "-p", "127.0.0.1::1025", "-p", "127.0.0.1::8025", "sha256:98b916bd3c8d61f7633a52d3ea2f58d00620cb01ca57ab59edde68c347a95365"], stdout=subprocess.DEVNULL)
        mail_smtp, mail_api = port(mail_name, "1025/tcp"), port(mail_name, "8025/tcp")
        wait_http(f"http://127.0.0.1:{mail_api}/api/v1/info")

        def url(role):
            return f"postgresql://{role}@127.0.0.1:{pg_port}/{db}"

        env = dict(base_env, PG_TEST_DISPOSABLE="yes", DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace), IPI_EMAIL_RENDERED_UI="1", IPI_RENDERED_MAILPIT_API_URL=f"http://127.0.0.1:{mail_api}/", IPI_RENDERED_IDENTITY_RUNTIME_URL=url("dvaia_identity_runtime"), IPI_RENDERED_IDENTITY_MIGRATION_URL=url("dvaia_identity_migration"), MAILPIT_SMTP_HOST="127.0.0.1", MAILPIT_SMTP_PORT=str(mail_smtp), PLATFORM_DATABASE_ENGINE="postgres", WORKSHOP_DATABASE_ENGINE="postgres", IPI_RENDERED_USER="ipi-rendered-owner", IPI_RENDERED_PASSWORD="OwnedRenderedFixture@123", IPI_RENDERED_SIBLING_USER="ipi-rendered-sibling", IPI_RENDERED_SIBLING_PASSWORD="OwnedRenderedFixture@123", AI_PROVIDER="ollama", JUDGE_PROVIDER="ollama", OLLAMA_BASE_URL="http://127.0.0.1:11434", OLLAMA_MODEL="llama3.1:8b", NODE_OPTIONS="--use-system-ca", AWS_EC2_METADATA_DISABLED="true")
        env["PUPPETEER_EXECUTABLE_PATH"] = str(browser_path)
        env["IPI_RENDERED_MAIL_HMAC_SECRET"] = secrets.token_hex(32)
        env["IPI_RENDERED_READINESS_FILE"] = str(readiness)
        # Keep raw retrieval/Judge diagnostics under the retained evidence root,
        # outside disposable source. The launcher never removes `root`.
        diagnostics = root / "private-email-diagnostics"
        diagnostics.mkdir(mode=0o700)
        env["IPI_RENDERED_EMAIL_DIAGNOSTICS"] = str(diagnostics)

        fixture_log = (root / "fixture.log").open("w")
        logs.append(fixture_log)
        fixture = subprocess.Popen([args.node, "tests/postgres/ipiEmailRenderedFixture.js"], cwd=workspace, env=env, start_new_session=True, stdout=fixture_log, stderr=subprocess.STDOUT)
        fixture._owned_name = "fixture"
        fixture._owned_pgid = os.getpgid(fixture.pid)
        children.append(fixture)
        write_child_intent(child_intent, children)
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline and not readiness.exists():
            if fixture.poll() is not None:
                raise RuntimeError("Owned fixture exited before readiness")
            time.sleep(0.1)
        if not readiness.exists():
            raise RuntimeError("Owned fixture readiness timeout")
        ready = read_bounded_json(readiness, "Owned fixture readiness")
        env["IPI_RENDERED_APP_URL"] = ready["appUrl"]

        browser_test_log = (root / "browser-test.log").open("w")
        logs.append(browser_test_log)
        browser_test = subprocess.Popen([args.node, "--test", "tests/postgres/ipiEmailRenderedQualification.integration.test.js"], cwd=workspace, env=env, start_new_session=True, stdout=browser_test_log, stderr=subprocess.STDOUT)
        browser_test._owned_name = "browser_test"
        browser_test._owned_pgid = os.getpgid(browser_test.pid)
        children.append(browser_test)
        write_child_intent(child_intent, children)
        code = browser_test.wait(timeout=420)
        if code:
            raise RuntimeError(f"Rendered qualification failed ({code}); see retained browser-test.log")
        stop_group(browser_test, env=base_env)
        stop_group(fixture, env=base_env)
        validate_fixture_completion(fixture, readiness)
    except BaseException as error:
        primary = error
    finally:
        signal_state["finalizing"] = True
        capture_errors = capture_container_logs(started, docker, base_env, root) if primary is not None else []
        cleanup_errors = finalize_owned(children, logs, started, docker, base_env, child_cleanup)
        for signum, previous in previous_signals.items():
            signal.signal(signum, previous)
        if primary is None and signal_state["signum"] is not None:
            primary = OwnedSignalExit(128 + signal_state["signum"])
        print(f"Owned evidence retained at {root}", flush=True)
        add_cleanup_errors(primary, capture_errors + cleanup_errors)
    if primary is not None:
        raise primary


def main(argv=None):
    args = parse_args(argv)
    if not args.run:
        print("plan: no workspace, container, database, browser, or model mutation")
        return 0
    run_qualification(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
