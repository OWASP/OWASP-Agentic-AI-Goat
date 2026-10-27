"""Non-launching ownership boundary for a proposed ephemeral BuildKit worker.

Importing and constructing a specification perform no I/O. This does NOT admit
a build: rootless-worker compatibility, builder-image availability and daemon
image/content disk limits remain separate, unresolved prerequisites.
"""
from dataclasses import dataclass
import json
import re

from sql_nosql_docker_ownership import verify_daemon

MIB = 1024 * 1024
MAX_CACHE_BYTES = 256 * MIB
MEMORY_BYTES = 512 * MIB
IMAGE = re.compile(r"sha256:[a-f0-9]{64}\Z")
IDENTIFIER = re.compile(r"[a-f0-9]{64}\Z")
OWNER = re.compile(r"[a-f0-9]{32}\Z")


@dataclass(frozen=True)
class CacheSpec:
    daemon_id: str
    owner: str
    image_id: str
    cache_bytes: int

    def __post_init__(self):
        if (not isinstance(self.daemon_id, str) or not self.daemon_id.strip()
                or not isinstance(self.owner, str) or not OWNER.fullmatch(self.owner)
                or not isinstance(self.image_id, str) or not IMAGE.fullmatch(self.image_id)
                or type(self.cache_bytes) is not int
                or not MIB <= self.cache_bytes <= MAX_CACHE_BYTES
                or self.cache_bytes % MIB):
            raise ValueError("Exact worker identity and bounded cache size required")

    @property
    def name(self):
        return "dvaia-mcp-build-" + self.owner

    @property
    def labels(self):
        return {"dvaia.owner": self.owner, "dvaia.resource": "ephemeral-buildkit-cache",
                "dvaia.cache.bytes": str(self.cache_bytes)}

    @property
    def tmpfs(self):
        # Build steps may need executable scratch; do not promise a noexec build.
        return {"/var/lib/buildkit": f"rw,nosuid,nodev,size={self.cache_bytes},mode=0700,uid=1000,gid=1000",
                "/tmp": f"rw,nosuid,nodev,size={16 * MIB},mode=1777",
                "/run": f"rw,nosuid,nodev,size={4 * MIB},mode=0755"}

    def limits(self):
        return {"cacheTmpfsBytes": self.cache_bytes,
                "otherTmpfsBytes": 20 * MIB, "containerMemoryBytes": MEMORY_BYTES,
                "daemonImageDiskBoundEnforced": False, "buildAdmitted": False}


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate inspect key")
        result[key] = value
    return result


def _inspect(command, target):
    response = command(["inspect", "--type", "container", target])
    if response.returncode:
        absent = {f"Error: No such object: {target}", f"Error: No such container: {target}",
                  f"Error response from daemon: No such container: {target}"}
        if response.stdout.strip() == "" and response.stderr.strip() in absent:
            return None
        raise RuntimeError("Builder inspection failed; absence unproven")
    try:
        if len(response.stdout.encode("utf-8")) > MIB:
            raise ValueError()
        rows = json.loads(response.stdout, object_pairs_hook=_object)
        if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
            raise ValueError()
        return rows[0]
    except (ValueError, TypeError):
        raise RuntimeError("Malformed builder inspection") from None


def _validate(row, spec, captured_id):
    try:
        config, host = row["Config"], row["HostConfig"]
        if (row["Id"] != captured_id or row["Name"] != "/" + spec.name
                or row["Image"] != spec.image_id
                or any(config["Labels"].get(key) != value for key, value in spec.labels.items())
                or config["User"] != "1000:1000"
                or config.get("Volumes") not in (None, {})
                or row["Mounts"] != [] or host["Tmpfs"] != spec.tmpfs
                or host["ReadonlyRootfs"] is not True or host["Privileged"] is not False
                or host.get("Binds") not in (None, []) or host.get("Mounts") not in (None, [])
                or host.get("VolumesFrom") not in (None, [])
                or host.get("Devices") not in (None, []) or host.get("DeviceRequests") not in (None, [])
                or host.get("CapAdd") not in (None, []) or host.get("CapDrop") != ["ALL"]
                or host.get("SecurityOpt") != ["no-new-privileges"]
                or host["Memory"] != MEMORY_BYTES or host["MemorySwap"] != MEMORY_BYTES
                or host["NanoCpus"] != 1_000_000_000 or host["PidsLimit"] != 128
                or host["LogConfig"] != {"Type": "none", "Config": {}}
                or host.get("AutoRemove") is not False):
            raise ValueError()
    except (KeyError, TypeError, AttributeError, ValueError):
        raise RuntimeError("Refusing builder with mismatched identity or storage profile") from None


def inspect_cache(command, spec, captured_id):
    """Require the immutable ID captured from this run's successful create.

    A label match or a newly discovered name is never enough to claim a worker.
    Missing/ambiguous create identity must be handled as failed cleanup by caller.
    """
    if not isinstance(spec, CacheSpec) or not isinstance(captured_id, str) or not IDENTIFIER.fullmatch(captured_id):
        raise ValueError("Captured builder container ID required")
    verify_daemon(command, spec.daemon_id)
    by_name = _inspect(command, spec.name)
    by_id = _inspect(command, captured_id)
    if by_name is None and by_id is None:
        return None
    if by_name is None or by_id is None:
        raise RuntimeError("Builder name and immutable identity disagree")
    _validate(by_name, spec, captured_id)
    _validate(by_id, spec, captured_id)
    return by_id


def cleanup_cache(command, spec, captured_id):
    """Remove only an admitted exact container ID; never prune or delete volumes/images.

    This proves removal of the worker and its tmpfs cache, not cleanup of daemon
    content/layers created by pulls or exports. The caller must report that gap.
    """
    row = inspect_cache(command, spec, captured_id)
    removed = row is not None
    if removed:
        verify_daemon(command, spec.daemon_id)
        result = command(["rm", "--force", captured_id])
        if result.returncode:
            raise RuntimeError("Exact builder removal failed")
    if inspect_cache(command, spec, captured_id) is not None:
        raise RuntimeError("Builder absence unproven")
    return {"containerId": captured_id, "containerName": spec.name,
            "status": "removed_absence_verified" if removed else "already_absent_verified",
            "cacheTmpfsAbsent": True, "daemonImageContentCleanupVerified": False,
            "qualificationComplete": False, **spec.limits()}
