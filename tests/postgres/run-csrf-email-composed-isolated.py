#!/usr/bin/env python3
"""Closed owned qualification for the composed CSRF email browser workflow."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import resource
import re
import shutil
import signal
import subprocess
import tempfile
import time
import uuid
from urllib.parse import quote
from urllib.request import urlopen


POSTGRES_IMAGE = "sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280"
MAILPIT_IMAGE = "sha256:98b916bd3c8d61f7633a52d3ea2f58d00620cb01ca57ab59edde68c347a95365"
MODEL = "llama3.1:8b"
MODEL_DIGEST = "46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e"
MAX_MODEL_CALLS = 12
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
SOURCE_DIRECTORIES = ("server", "db", "tests", "client")
SOURCE_FILES = ("package.json", "package-lock.json")
DENIED_NAMES = frozenset({".git", "node_modules", "logs", "uploads",
    "sensitive_files", "workshop_data", "vector-indexes", "coverage", ".cache", "__pycache__"})
DENIED_SUFFIXES = (".db", ".db-wal", ".db-shm", ".db-journal", ".sqlite", ".sqlite3", ".log")
OWNER_LABEL = "org.owasp-ai-goat.csrf-email-composed-owner"
NONCE_LABEL = "org.owasp-ai-goat.csrf-email-composed-nonce"
BROWSER_RECORDS = (("fixture-browser.json", "fixture_browser"),
                   ("qualification-browser.json", "qualification_browser"))


class OwnedSignalExit(SystemExit):
    pass


def parse_args(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--docker-host", required=True)
    parser.add_argument("--docker-cli", required=True)
    parser.add_argument("--docker-cli-sha256", required=True)
    parser.add_argument("--docker-server-id", required=True)
    parser.add_argument("--node", required=True)
    parser.add_argument("--node-sha256", required=True)
    parser.add_argument("--browser", required=True)
    parser.add_argument("--browser-sha256", required=True)
    parser.add_argument("--source-manifest-sha256", required=True)
    parser.add_argument("--dependency-manifest-sha256", required=True)
    parser.add_argument("--actual-selected", action="store_true", help="Current teaching runtime, three prospective actual-model cases")
    parser.add_argument("--controlled-selected", action="store_true", help="Current teaching runtime, synthetic providers, no inference")
    parser.add_argument("--run", action="store_true", help="Root-controlled execution gate")
    args = parser.parse_args(argv)
    if args.actual_selected and args.controlled_selected:
        parser.error("Selected modes are mutually exclusive")
    return args


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def validate_executable(path, expected, label):
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file() or not os.access(candidate, os.X_OK):
        raise RuntimeError(f"{label} identity mismatch")
    if sha256(candidate) != expected:
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
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def open_private_log(path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(descriptor, "wb")


def ignored(_directory, names):
    return [name for name in names if name in DENIED_NAMES or name.startswith(".env")
            or name.endswith(DENIED_SUFFIXES)]


def inventory(root):
    root = Path(root)
    rows = {}
    for name in SOURCE_FILES:
        path = root / name
        rows[name] = {"kind": "file", "bytes": path.stat().st_size, "sha256": sha256(path)}
    for directory in SOURCE_DIRECTORIES:
        base = root / directory
        for path in sorted(base.rglob("*")):
            relative = path.relative_to(root).as_posix()
            parts = path.relative_to(base).parts
            if any(part in DENIED_NAMES or part.startswith(".env")
                   or part.endswith(DENIED_SUFFIXES) for part in parts):
                continue
            if path.is_symlink():
                rows[relative] = {"kind": "symlink", "target": os.readlink(path)}
            elif path.is_file():
                rows[relative] = {"kind": "file", "bytes": path.stat().st_size,
                                  "sha256": sha256(path)}
    return rows


def manifest_digest(rows):
    encoded = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def dependency_inventory(source):
    rows = {}
    for prefix in ("node_modules", "client/node_modules"):
        base = Path(source) / prefix
        for path in sorted(base.rglob("*")):
            relative = path.relative_to(source).as_posix()
            if path.is_symlink():
                rows[relative] = {"kind": "symlink", "target": os.readlink(path)}
            elif path.is_file():
                rows[relative] = {"kind": "file", "bytes": path.stat().st_size,
                                  "sha256": sha256(path)}
    return rows


def copy_frozen_source(source, workspace, expected_source, expected_dependencies):
    before = inventory(source)
    actual_source = manifest_digest(before)
    if actual_source != expected_source:
        raise RuntimeError("Source manifest pin mismatch")
    dependencies = dependency_inventory(source)
    actual_dependencies = manifest_digest(dependencies)
    if actual_dependencies != expected_dependencies:
        raise RuntimeError("Dependency manifest pin mismatch")
    for directory in SOURCE_DIRECTORIES:
        shutil.copytree(source / directory, workspace / directory, ignore=ignored, symlinks=True)
    for name in SOURCE_FILES:
        shutil.copy2(source / name, workspace / name)
    if inventory(workspace) != before:
        raise RuntimeError("Frozen source copy differs from reviewed source")
    # copytree preserves reviewed read-only source directory modes. Only the
    # newly owned destination needs a brief write window for dependency links.
    client_destination = workspace / "client"
    if client_destination.is_symlink() or not client_destination.is_dir():
        raise RuntimeError("Owned client destination must be a real directory")
    os.chmod(client_destination, 0o700)
    (workspace / "node_modules").symlink_to(source / "node_modules", target_is_directory=True)
    (workspace / "client" / "node_modules").symlink_to(
        source / "client" / "node_modules", target_is_directory=True)
    for path in sorted(workspace.rglob("*"), reverse=True):
        if not path.is_symlink():
            os.chmod(path, 0o500 if path.is_dir() else 0o400)
    os.chmod(workspace, 0o500)
    if inventory(workspace) != before:
        raise RuntimeError("Frozen source changed during dependency linking or relock")
    return {"source": actual_source, "sourceFiles": len(before),
            "dependencies": actual_dependencies, "dependencyFiles": len(dependencies)}


def validate_docker_authority(docker, base_env, expected_server_id, *, runner=subprocess.run):
    try:
        host_index = docker.index("--host") + 1
        host = docker[host_index]
    except (ValueError, IndexError) as error:
        raise RuntimeError("Docker host authority missing") from error
    if not isinstance(host, str) or not host.startswith("unix://") or "\n" in host or "\r" in host:
        raise RuntimeError("Docker host must be an explicit local Unix socket")
    result = runner(docker + ["info", "--format", "{{json .ID}}"], env=base_env,
                    capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError("Docker daemon identity unavailable")
    try:
        server_id = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("Docker daemon identity malformed") from error
    if server_id != expected_server_id or not isinstance(server_id, str) or not server_id:
        raise RuntimeError("Docker daemon identity mismatch")
    return server_id


def validate_image(docker, base_env, image, *, runner=subprocess.run):
    result = runner(docker + ["image", "inspect", "--format", "{{json .Id}}", image],
                    env=base_env, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(f"Pinned image is not cached: {image}")
    try:
        actual = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("Pinned image identity malformed") from error
    if actual != image:
        raise RuntimeError(f"Pinned image identity mismatch: {image}")


def container_command(docker, *, name, nonce, image, kind):
    common = docker + ["run", "--detach", "--pull", "never", "--name", name,
        "--label", f"{OWNER_LABEL}=csrf-email-composed", "--label", f"{NONCE_LABEL}={nonce}"]
    if kind == "postgres":
        return common + ["--tmpfs", "/var/lib/postgresql:rw,size=536870912",
            "-e", "POSTGRES_USER=csrf_email_admin", "-e", "POSTGRES_HOST_AUTH_METHOD=trust",
            "-e", "POSTGRES_INITDB_ARGS=--wal-segsize=1", "-p", "127.0.0.1::5432", image,
            "-c", "shared_buffers=16MB", "-c", "max_connections=60",
            "-c", "max_wal_size=16MB", "-c", "min_wal_size=4MB"]
    if kind == "mailpit":
        return common + ["--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16777216",
            "-p", "127.0.0.1::1025", "-p", "127.0.0.1::8025", image]
    raise ValueError("Unknown owned container kind")


def inspect_owned(intent, docker, base_env, *, runner=subprocess.run):
    target = intent.get("containerId") or intent["name"]
    result = runner(docker + ["inspect", target], env=base_env,
                    capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(f"Owned container inspection failed: {intent['name']}")
    try:
        row = json.loads(result.stdout)[0]
        labels = row["Config"].get("Labels") or {}
        actual_id = str(row["Id"]).removeprefix("sha256:")
        expected_id = str(intent.get("containerId") or actual_id).removeprefix("sha256:")
        if len(actual_id) != 64 or actual_id != expected_id or row["Name"] != f"/{intent['name']}":
            raise ValueError("identity mismatch")
        if row["Config"]["Image"] != intent["image"]:
            raise ValueError("image mismatch")
        if labels.get(OWNER_LABEL) != "csrf-email-composed" or labels.get(NONCE_LABEL) != intent["nonce"]:
            raise ValueError("ownership mismatch")
    except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Unowned or malformed container: {intent['name']}") from error
    return actual_id


def cleanup_containers(intents, docker, base_env, *, runner=subprocess.run):
    rows, errors = [], []
    for intent in reversed(intents):
        row = {"name": intent["name"], "containerId": intent.get("containerId")}
        try:
            actual_id = inspect_owned(intent, docker, base_env, runner=runner)
            removal = runner(docker + ["rm", "--force", actual_id], env=base_env,
                             capture_output=True, text=True, timeout=30)
            if removal.returncode != 0:
                raise RuntimeError(f"Owned container removal failed: {intent['name']}")
        except RuntimeError as error:
            probe = runner(docker + ["inspect", intent.get("containerId") or intent["name"]],
                           env=base_env, capture_output=True, text=True, timeout=30)
            if probe.returncode == 0:
                errors.append(error)
        probe = runner(docker + ["ps", "-a", "--filter", f"name=^{intent['name']}$",
                                  "--format", "{{.Names}}"], env=base_env,
                       capture_output=True, text=True, timeout=30)
        id_probe = runner(docker + ["inspect", intent.get("containerId") or intent["name"]],
                          env=base_env, capture_output=True, text=True, timeout=30)
        row["idAbsent"] = id_probe.returncode != 0
        row["nameAbsent"] = probe.returncode == 0 and not probe.stdout.strip()
        row["absent"] = row["idAbsent"] and row["nameAbsent"]
        if not row["absent"]:
            errors.append(RuntimeError(f"Owned container remains: {intent['name']}"))
        rows.append(row)
    return rows, errors


def process_group_exists(pgid, *, runner=subprocess.run, env=None):
    result = runner(["ps", "-axo", "pgid=,stat="], env=env,
                    capture_output=True, text=True, timeout=10)
    if result.returncode != 0:
        raise RuntimeError(f"Owned process-group probe failed: {pgid}")
    return any(line.split() and line.split()[0] == str(pgid) for line in result.stdout.splitlines())


def stop_group(child, *, env=None, group_exists=process_group_exists, killpg=os.killpg,
               monotonic=time.monotonic, sleep=time.sleep):
    pgid = getattr(child, "_owned_pgid", None)
    if not isinstance(pgid, int) or pgid <= 1:
        raise RuntimeError("Owned process group was not captured")
    child.poll()
    for sig, seconds in ((signal.SIGTERM, 8), (signal.SIGKILL, 3)):
        if not group_exists(pgid, env=env):
            break
        try:
            killpg(pgid, sig)
        except ProcessLookupError:
            pass
        deadline = monotonic() + seconds
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


def read_browser_records(directory, browser, browser_sha256, *, require_all, records=BROWSER_RECORDS):
    rows = []
    expected_path = str(Path(browser).resolve())
    for filename, kind in records:
        path = Path(directory) / filename
        if not path.exists():
            if require_all:
                raise RuntimeError(f"Owned browser PID record missing: {kind}")
            continue
        if (path.stat().st_mode & 0o777) != 0o600:
            raise RuntimeError(f"Owned browser PID record is not private: {kind}")
        value = read_bounded_json(path, f"Owned browser PID record {kind}", 65536)
        processes = value.get("processes")
        if value.get("schemaVersion") != 1 or not isinstance(processes, list) or not processes or len(processes) > 4:
            raise RuntimeError(f"Owned browser PID record malformed: {kind}")
        for process in processes:
            if not isinstance(process, dict) or process.get("kind") != kind:
                raise RuntimeError(f"Owned browser process kind mismatch: {kind}")
            pid = process.get("pid")
            start_time = process.get("startTime")
            if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
                raise RuntimeError(f"Owned browser PID invalid: {kind}")
            if not isinstance(start_time, str) or not 10 <= len(start_time) <= 64 or "\n" in start_time:
                raise RuntimeError(f"Owned browser start identity invalid: {kind}")
            start_fields = start_time.split()
            if len(start_fields) != 5:
                raise RuntimeError(f"Owned browser start identity malformed: {kind}")
            start_time = " ".join(start_fields)
            if process.get("executablePath") != expected_path or process.get("executableSha256") != browser_sha256:
                raise RuntimeError(f"Owned browser executable identity mismatch: {kind}")
            rows.append({"kind": kind, "pid": pid, "startTime": start_time,
                         "executablePath": expected_path})
    if require_all and {row["kind"] for row in rows} != {kind for _, kind in records}:
        raise RuntimeError("Owned browser PID record set incomplete")
    return rows


def browser_process_identity(pid, *, runner=subprocess.run, env=None):
    result = runner(["ps", "-p", str(pid), "-o", "lstart=", "-o", "command="],
                    env=env, capture_output=True, text=True, timeout=10)
    if result.returncode == 1 and not result.stdout.strip() and not getattr(result, "stderr", "").strip():
        return None
    if result.returncode != 0:
        raise RuntimeError(f"Could not inspect owned browser process {pid}: ps exited {result.returncode}")
    if not result.stdout.strip():
        raise RuntimeError(f"Owned browser process identity empty: {pid}")
    fields = result.stdout.strip().split()
    if len(fields) < 6:
        raise RuntimeError(f"Owned browser process identity malformed: {pid}")
    return {"startTime": " ".join(fields[:5]), "command": " ".join(fields[5:])}


def cleanup_browser_processes(records, browser, base_env, *, runner=subprocess.run,
                              kill=os.kill, monotonic=time.monotonic, sleep=time.sleep):
    expected_path = str(Path(browser).resolve())
    results, errors = [], []
    for record in records:
        row = {"kind": record["kind"], "pid": record["pid"], "startTime": record["startTime"]}
        try:
            identity = browser_process_identity(record["pid"], runner=runner, env=base_env)
            if identity is not None:
                command = identity["command"]
                if identity["startTime"] != record["startTime"] \
                  or not (command == expected_path or command.startswith(expected_path + " ")):
                    raise RuntimeError(f"Refusing to signal mismatched browser process: {record['pid']}")
                try:
                    kill(record["pid"], signal.SIGTERM)
                except ProcessLookupError:
                    pass
                deadline = monotonic() + 8
                while monotonic() < deadline and browser_process_identity(
                        record["pid"], runner=runner, env=base_env) is not None:
                    sleep(0.1)
                identity = browser_process_identity(record["pid"], runner=runner, env=base_env)
                if identity is not None:
                    command = identity["command"]
                    if identity["startTime"] != record["startTime"] \
                      or not (command == expected_path or command.startswith(expected_path + " ")):
                        raise RuntimeError(f"Browser process identity changed during cleanup: {record['pid']}")
                    try:
                        kill(record["pid"], signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    deadline = monotonic() + 3
                    while monotonic() < deadline and browser_process_identity(
                            record["pid"], runner=runner, env=base_env) is not None:
                        sleep(0.1)
            row["absent"] = browser_process_identity(
                record["pid"], runner=runner, env=base_env) is None
            if not row["absent"]:
                raise RuntimeError(f"Owned browser process remains: {record['pid']}")
        except Exception as error:
            row["absent"] = False
            errors.append(error)
        results.append(row)
    return results, errors


def stream_child(child, log_path, timeout_seconds, *, max_bytes=MAX_OUTPUT_BYTES,
                 monotonic=time.monotonic, selector_factory=selectors.DefaultSelector):
    deadline = monotonic() + timeout_seconds
    selector = selector_factory()
    selector.register(child.stdout, selectors.EVENT_READ)
    total = 0
    with open_private_log(log_path) as output:
        while True:
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise TimeoutError(f"Owned {child._owned_name} exceeded deadline")
            for key, _ in selector.select(min(0.25, remaining)):
                chunk = key.fileobj.read1(min(65536, max_bytes + 1 - total))
                if chunk:
                    total += len(chunk)
                    if total > max_bytes:
                        raise RuntimeError(f"Owned {child._owned_name} output exceeded bound")
                    output.write(chunk)
                    output.flush()
                else:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
            if child.poll() is not None and not selector.get_map():
                break
        os.fsync(output.fileno())
    selector.close()
    return child.wait(timeout=1), total


def _limit_child_output():
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT_BYTES, MAX_OUTPUT_BYTES))


def launch_child(command, *, name, workspace, env, intent_path, output_path=None):
    output_handle = open_private_log(output_path) if output_path is not None else None
    child = subprocess.Popen(command, cwd=workspace, env=env, stdin=subprocess.DEVNULL,
                             stdout=output_handle or subprocess.PIPE, stderr=subprocess.STDOUT,
                             start_new_session=True,
                             preexec_fn=_limit_child_output if output_handle is not None else None)
    if output_handle is not None:
        output_handle.close()
    child._owned_name = name
    child._owned_pgid = os.getpgid(child.pid)
    write_private_json(intent_path, {"schemaVersion": 1, "name": name,
                                     "pid": child.pid, "pgid": child._owned_pgid})
    return child


def capture_container_logs(intents, docker, base_env, evidence, *, runner=subprocess.run):
    errors = []
    for intent in intents:
        if not intent.get("containerId"):
            continue
        path = evidence / f"{intent['kind']}.container.log"
        try:
            with open_private_log(path) as output:
                result = runner(docker + ["logs", "--tail", "256", intent["containerId"]],
                                env=base_env, stdout=output, stderr=subprocess.STDOUT, timeout=15,
                                preexec_fn=_limit_child_output)
            if result.returncode not in (0, 1):
                raise RuntimeError(f"Owned container log capture failed: {intent['name']}")
            if path.stat().st_size > MAX_OUTPUT_BYTES:
                raise RuntimeError(f"Owned container log exceeded bound: {intent['name']}")
        except Exception as error:
            errors.append(error)
    return errors


def wait_http(url, *, timeout_seconds=30):
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            with urlopen(url, timeout=1) as response:
                if 200 <= response.status < 300:
                    return
        except Exception:
            pass
        time.sleep(0.25)
    raise RuntimeError(f"Owned HTTP readiness timeout: {url}")


def read_bounded_json(path, label, max_bytes=1 << 20):
    path = Path(path)
    try:
        size = path.stat().st_size
    except FileNotFoundError as error:
        raise RuntimeError(f"{label} missing") from error
    if size <= 0 or size > max_bytes:
        raise RuntimeError(f"{label} size invalid")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"{label} invalid") from error
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} must be an object")
    return value


def validate_fixture_final(readiness_path, expected_digest=MODEL_DIGEST):
    ready = read_bounded_json(readiness_path, "Fixture readiness")
    final = read_bounded_json(Path(f"{readiness_path}.final"), "Fixture final evidence")
    if ready.get("modelDigestBefore") != expected_digest:
        raise RuntimeError("Fixture readiness model digest mismatch")
    if final.get("modelDigestBefore") != expected_digest or final.get("modelDigestAfter") != expected_digest:
        raise RuntimeError("Fixture final model digest mismatch")
    counters = final.get("counters")
    calls = counters.get("modelCalls") if isinstance(counters, dict) else None
    if not isinstance(calls, int) or isinstance(calls, bool) or not 1 <= calls <= MAX_MODEL_CALLS:
        raise RuntimeError("Fixture model call evidence invalid")
    return final


def validate_tap_result(path):
    path = Path(path)
    if path.stat().st_size <= 0 or path.stat().st_size > MAX_OUTPUT_BYTES:
        raise RuntimeError("Qualification TAP size invalid")
    text = path.read_text(encoding="utf-8", errors="strict")
    values = {}
    for key in ("tests", "pass", "fail", "cancelled", "skipped", "todo"):
        matches = re.findall(rf"^(?:#|ℹ)\s+{key}\s+(\d+)\s*$", text, re.MULTILINE)
        if len(matches) != 1:
            raise RuntimeError(f"Qualification TAP {key} summary invalid")
        values[key] = int(matches[0])
    if values["tests"] < 1 or values["pass"] != values["tests"]:
        raise RuntimeError("Qualification TAP did not execute every test")
    if any(values[key] for key in ("fail", "cancelled", "skipped", "todo")):
        raise RuntimeError("Qualification TAP contains non-passing tests")
    return values


def add_cleanup_errors(primary, errors):
    if not errors:
        return
    details = "; ".join(f"{type(error).__name__}: {error}" for error in errors)
    if primary is not None:
        primary.add_note(f"Owned cleanup errors: {details}")
    else:
        raise RuntimeError(f"Owned cleanup failed: {details}")


def run_qualification(args):
    source = Path(__file__).resolve().parents[2]
    node = validate_executable(args.node, args.node_sha256, "Managed Node")
    browser = validate_executable(args.browser, args.browser_sha256, "Managed browser")
    docker_cli = validate_executable(args.docker_cli, args.docker_cli_sha256, "Docker CLI")
    base_env = {key: os.environ[key] for key in ("PATH", "HOME", "TMPDIR") if key in os.environ}
    base_env["PATH"] = f"{node.parent}:{base_env.get('PATH', '')}"
    docker = [str(docker_cli), "--host", args.docker_host]
    daemon_id = validate_docker_authority(docker, base_env, args.docker_server_id)
    validate_image(docker, base_env, POSTGRES_IMAGE)
    validate_image(docker, base_env, MAILPIT_IMAGE)

    evidence = Path(tempfile.mkdtemp(prefix="owasp-ai-goat-csrf-email-composed-"))
    os.chmod(evidence, 0o700)
    workspace = evidence / "source"
    workspace.mkdir(mode=0o700)
    snapshot = copy_frozen_source(source, workspace, args.source_manifest_sha256,
                                  args.dependency_manifest_sha256)
    write_private_json(evidence / "admission.json", {"schemaVersion": 1,
        "dockerHost": args.docker_host, "dockerServerId": daemon_id,
        "dockerCliSha256": args.docker_cli_sha256, "nodeSha256": args.node_sha256,
        "browserSha256": args.browser_sha256, **snapshot})
    browser_pid_dir = evidence / "browser-pids"
    browser_pid_dir.mkdir(mode=0o700)

    nonce = uuid.uuid4().hex
    intents = [
        {"name": f"owasp-ai-goat-csrf-email-pg-{nonce[:12]}", "nonce": nonce,
         "image": POSTGRES_IMAGE, "kind": "postgres"},
        {"name": f"owasp-ai-goat-csrf-email-mail-{nonce[:12]}", "nonce": nonce,
         "image": MAILPIT_IMAGE, "kind": "mailpit"},
    ]
    write_private_json(evidence / "container-intent.json", {"schemaVersion": 1,
                                                              "containers": intents})
    children = []
    primary = None
    previous = {}
    finalizing = {"value": False}
    selected_requires_browser = False

    def interrupted(signum, _frame):
        if not finalizing["value"]:
            raise OwnedSignalExit(128 + signum)

    for sig in (signal.SIGTERM, signal.SIGINT):
        previous[sig] = signal.signal(sig, interrupted)

    def run(command, **kwargs):
        kwargs.setdefault("env", base_env)
        kwargs.setdefault("timeout", 60)
        return subprocess.run(command, check=True, **kwargs)

    try:
        for intent in intents:
            command = container_command(docker, name=intent["name"], nonce=nonce,
                                        image=intent["image"], kind=intent["kind"])
            if args.controlled_selected or args.actual_selected:
                position = command.index("run") + 1
                command[position:position] = ["--memory", "1g" if intent["kind"] == "postgres" else "256m", "--cpus", "1", "--pids-limit", "256"]
            intent["containerId"] = run(command, capture_output=True, text=True).stdout.strip()
            inspect_owned(intent, docker, base_env)
        pg, mailpit = intents
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            probe = subprocess.run(docker + ["exec", pg["containerId"], "pg_isready", "-h",
                "127.0.0.1", "-U", "csrf_email_admin"], env=base_env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            if probe.returncode == 0:
                break
            time.sleep(0.25)
        else:
            raise RuntimeError("Owned PostgreSQL readiness timeout")

        def port(intent, container_port):
            output = run(docker + ["port", intent["containerId"], container_port],
                         capture_output=True, text=True).stdout.strip()
            return int(output.splitlines()[-1].rsplit(":", 1)[1])

        pg_port = port(pg, "5432/tcp")
        smtp_port = port(mailpit, "1025/tcp")
        api_port = port(mailpit, "8025/tcp")
        mailpit_url = f"http://127.0.0.1:{api_port}"
        wait_http(f"{mailpit_url}/api/v1/info")
        psql = docker + ["exec", pg["containerId"], "psql", "-U", "csrf_email_admin",
                         "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c"]
        urls = {}
        for store in ("identity", "csrf"):
            migration = f"dvaia_{store}_migration"
            runtime = f"dvaia_{store}_runtime"
            database = f"owasp_ai_goat_test_csrf_email_{store}_{nonce[:10]}"
            for role in (migration, runtime):
                run(psql + [f"CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"])
            run(psql + [f"CREATE DATABASE {database} OWNER {migration}"])
            run(psql + [f"REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{runtime}"])
            urls[store] = {
                "runtime": f"postgresql://{quote(runtime)}@127.0.0.1:{pg_port}/{database}",
                "migration": f"postgresql://{quote(migration)}@127.0.0.1:{pg_port}/{database}",
            }

        readiness = evidence / "fixture-readiness.json"
        diagnostics = evidence / "private-diagnostics"
        diagnostics.mkdir(mode=0o700)
        app_data = evidence / "app-data"
        app_data.mkdir(mode=0o700)
        logs_root = app_data / "logs"
        logs_root.mkdir(mode=0o700)
        env = dict(base_env, NODE_ENV="test", PG_TEST_DISPOSABLE="yes", PYTHONDONTWRITEBYTECODE="1",
            PLATFORM_DATABASE_ENGINE="postgres", WORKSHOP_DATABASE_ENGINE="postgres",
            AWS_EC2_METADATA_DISABLED="true", AI_PROVIDER="ollama", JUDGE_PROVIDER="ollama",
            OLLAMA_BASE_URL="http://127.0.0.1:11434", OLLAMA_MODEL=MODEL,
            CSRF_EMAIL_COMPOSED_MODEL_DIGEST=MODEL_DIGEST,
            CSRF_EMAIL_COMPOSED_MAX_MODEL_CALLS=str(24 if args.actual_selected else MAX_MODEL_CALLS),
            CSRF_EMAIL_COMPOSED_MAILPIT_API_URL=mailpit_url,
            MAILPIT_SMTP_HOST="127.0.0.1", MAILPIT_SMTP_PORT=str(smtp_port),
            IPI_MAIL_HMAC_SECRET=uuid.uuid4().hex + uuid.uuid4().hex,
            PG_CSRF_EMAIL_COMPOSED_IDENTITY_RUNTIME_URL=urls["identity"]["runtime"],
            PG_CSRF_EMAIL_COMPOSED_IDENTITY_MIGRATION_URL=urls["identity"]["migration"],
            PG_CSRF_EMAIL_COMPOSED_CSRF_RUNTIME_URL=urls["csrf"]["runtime"],
            PG_CSRF_EMAIL_COMPOSED_CSRF_MIGRATION_URL=urls["csrf"]["migration"],
            IDENTITY_DATABASE_URL=urls["identity"]["runtime"],
            IDENTITY_MIGRATION_DATABASE_URL=urls["identity"]["migration"],
            CSRF_WORKSHOP_DATABASE_URL=urls["csrf"]["runtime"],
            CSRF_WORKSHOP_MIGRATION_DATABASE_URL=urls["csrf"]["migration"],
            OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=str(workspace), PUPPETEER_EXECUTABLE_PATH=str(browser),
            CSRF_EMAIL_COMPOSED_BROWSER_PID_DIR=str(browser_pid_dir),
            CSRF_EMAIL_COMPOSED_BROWSER_SHA256=args.browser_sha256,
            OWASP_AI_GOAT_APP_DATA_ROOT=str(app_data), LOGS_DIR=str(logs_root),
            CSRF_EMAIL_COMPOSED_OWNER_USER="csrf-email-owner",
            CSRF_EMAIL_COMPOSED_OWNER_PASSWORD="OwnedCsrfEmailFixture@123",
            CSRF_EMAIL_COMPOSED_SIBLING_USER="csrf-email-sibling",
            CSRF_EMAIL_COMPOSED_SIBLING_PASSWORD="OwnedCsrfSiblingFixture@456",
            CSRF_EMAIL_COMPOSED_DIAGNOSTICS=str(diagnostics),
            CSRF_EMAIL_COMPOSED_READINESS_FILE=str(readiness),
            JWT_SECRET="owned-csrf-email-composed-jwt-secret-at-least-32-bytes",
            NODE_OPTIONS="--use-system-ca")
        if args.controlled_selected or args.actual_selected:
            selected_profile = evidence / "selected-browser-profile"
            selected_profile.mkdir(mode=0o700)
            env["CSRF_SELECTED_BROWSER_PROFILE"] = str(selected_profile)
            env.update(CSRF_SELECTED_NATIVE="0" if args.actual_selected else "1", CSRF_SELECTED_ACTUAL="1" if args.actual_selected else "0", AI_PROVIDER="ollama" if args.actual_selected else "mock", JUDGE_PROVIDER="ollama" if args.actual_selected else "mock",
                       CSRF_SELECTED_RESULT=str(evidence / "selected-result.json"))
            test_child = launch_child([str(node), "--test", "--test-reporter=tap",
                "tests/postgres/csrfSelectedEmailActual.test.js" if args.actual_selected else "tests/postgres/csrfSelectedEmailNative.test.js"], name="qualification",
                workspace=workspace, env=env, intent_path=evidence / "qualification-child-intent.json")
            children.append(test_child)
            code, size = stream_child(test_child, evidence / "result.tap", 1680 if args.actual_selected else 720)
            if code != 0:
                raise RuntimeError(f"Selected-email controlled native qualification failed ({code})")
            tap = validate_tap_result(evidence / "result.tap")
            stop_group(test_child, env=base_env)
            observed = read_bounded_json(evidence / "selected-result.json", "Selected native result", max_bytes=(8 << 20) if args.actual_selected else (1 << 20))
            if args.actual_selected:
                selected_requires_browser = any(case.get("response", {}).get("body", {}).get("browserExecuted") is True for case in observed.get("cases", []))
                if observed.get("completed") is not True or observed.get("syntheticProvider") is not False or observed.get("modelDigestBefore") != MODEL_DIGEST or observed.get("modelDigestAfter") != MODEL_DIGEST or not 1 <= observed.get("counters", {}).get("modelCalls", 0) <= 24:
                    raise RuntimeError("Actual selected outcome incomplete or model authority invalid")
            elif observed.get("passed") is not True or observed.get("modelCalls") != 0:
                raise RuntimeError("Selected native outcome incomplete or inference occurred")
            write_private_json(evidence / "result.json", {"schemaVersion": 1, "returncode": code,
                "tapBytes": size, "tapSha256": sha256(evidence / "result.tap"), "tap": tap,
                "modelCalls": observed.get("counters", {}).get("modelCalls", 0), "syntheticProvider": not args.actual_selected, "qualificationStatus": ("passed" if observed.get("allExpected") else "observed_negative") if args.actual_selected else "passed-controlled", "observed": observed})
        else:
            fixture_path = workspace / "tests/postgres/csrfEmailComposedFixture.js"
            if not fixture_path.is_file():
                raise RuntimeError("Composed fixture app is missing from the frozen source")
            fixture = launch_child([str(node), str(fixture_path.relative_to(workspace))], name="fixture",
                workspace=workspace, env=env, intent_path=evidence / "fixture-child-intent.json",
                output_path=evidence / "fixture.log")
            children.append(fixture)
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline and not readiness.exists():
                if fixture.poll() is not None:
                    raise RuntimeError("Composed fixture exited before readiness")
                time.sleep(0.1)
            ready = read_bounded_json(readiness, "Fixture readiness")
            app_url = ready.get("appUrl")
            if not isinstance(app_url, str) or not app_url.startswith("http://127.0.0.1:"):
                raise RuntimeError("Fixture app URL is invalid")
            env["CSRF_EMAIL_COMPOSED_APP_URL"] = app_url
            env["CSRF_EMAIL_COMPOSED_LIVE"] = "1"
            test_child = launch_child([str(node), "--test", "--test-reporter=tap",
                "tests/postgres/csrfEmailComposed.integration.test.js"], name="qualification",
                workspace=workspace, env=env, intent_path=evidence / "qualification-child-intent.json")
            children.append(test_child)
            code, size = stream_child(test_child, evidence / "result.tap", 480)
            if code != 0:
                raise RuntimeError(f"Composed CSRF email qualification failed ({code})")
            tap = validate_tap_result(evidence / "result.tap")
            stop_group(test_child, env=base_env)
            fixture_code = stop_group(fixture, env=base_env)
            if fixture_code != 0:
                raise RuntimeError(f"Composed fixture did not shut down cleanly ({fixture_code})")
            final = validate_fixture_final(readiness)
            write_private_json(evidence / "result.json", {"schemaVersion": 1, "returncode": code,
                "tapBytes": size, "tapSha256": sha256(evidence / "result.tap"),
                "tap": tap, "modelCalls": final["counters"]["modelCalls"],
                "modelDigest": MODEL_DIGEST})
    except BaseException as error:
        primary = error
    finally:
        finalizing["value"] = True
        cleanup_errors = capture_container_logs(intents, docker, base_env, evidence) if primary else []
        process_rows = []
        for child in reversed(children):
            try:
                code = stop_group(child, env=base_env)
                process_rows.append({"name": child._owned_name, "pid": child.pid,
                                     "pgid": child._owned_pgid, "returncode": code, "absent": True})
            except Exception as error:
                cleanup_errors.append(error)
                process_rows.append({"name": child._owned_name, "pid": child.pid,
                                     "pgid": child._owned_pgid, "returncode": child.poll(), "absent": False})
        browser_rows = []
        try:
            browser_records = read_browser_records(browser_pid_dir, browser, args.browser_sha256,
                                                   require_all=primary is None and (not args.actual_selected or selected_requires_browser), records=BROWSER_RECORDS[:1] if (args.controlled_selected or args.actual_selected) else BROWSER_RECORDS)
            browser_rows, browser_errors = cleanup_browser_processes(
                browser_records, browser, base_env)
            cleanup_errors.extend(browser_errors)
        except Exception as error:
            cleanup_errors.append(error)
        selected_profile_absent = None
        if args.controlled_selected or args.actual_selected:
            profile = evidence / "selected-browser-profile"
            try:
                if any(not row.get("absent") for row in browser_rows) or cleanup_errors:
                    raise RuntimeError("Cannot remove selected browser profile before verified process cleanup")
                if profile.is_symlink():
                    raise RuntimeError("Owned selected browser profile became a symlink")
                if profile.exists():
                    shutil.rmtree(profile)
                selected_profile_absent = not profile.exists()
            except Exception as error:
                cleanup_errors.append(error)
                selected_profile_absent = False
        container_rows, container_errors = cleanup_containers(intents, docker, base_env)
        cleanup_errors.extend(container_errors)
        write_private_json(evidence / "cleanup.json", {"schemaVersion": 1,
            "processes": sorted(process_rows, key=lambda row: row["name"]),
            "browsers": sorted(browser_rows, key=lambda row: (row["kind"], row["pid"])),
            "containers": sorted(container_rows, key=lambda row: row["name"]),
            "selectedProfileAbsent": selected_profile_absent,
            "terminalCleanup": not cleanup_errors
                and all(row["absent"] for row in process_rows)
                and all(row["absent"] for row in browser_rows)
                and all(row["absent"] for row in container_rows)})
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        print(f"Owned evidence retained at {evidence}", flush=True)
        add_cleanup_errors(primary, cleanup_errors)
    if primary is not None:
        raise primary


def main(argv=None):
    args = parse_args(argv)
    if not args.run:
        print("plan: no workspace, container, database, Mailpit, browser, model, or network mutation")
        return 0
    if args.controlled_selected or args.actual_selected:
        prior = signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError("Selected native parent deadline")))
        signal.alarm(1800 if args.actual_selected else 900)
        try:
            run_qualification(args)
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, prior)
    else:
        run_qualification(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
