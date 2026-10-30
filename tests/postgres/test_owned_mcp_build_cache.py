"""Pure fake-command controls; no Docker, subprocess, filesystem or network use."""
import json
from types import SimpleNamespace
import unittest

from owned_mcp_build_cache import CacheSpec, MIB, MEMORY_BYTES, cleanup_cache, inspect_cache

CID = "b" * 64
SPEC = CacheSpec("owned-daemon", "a" * 32, "sha256:" + "c" * 64, 64 * MIB)


def row():
    return {"Id": CID, "Name": "/" + SPEC.name, "Image": SPEC.image_id,
            "Config": {"Labels": SPEC.labels, "User": "1000:1000", "Volumes": None},
            "Mounts": [], "HostConfig": {"Tmpfs": SPEC.tmpfs, "ReadonlyRootfs": True,
                "Privileged": False, "Binds": None, "Mounts": None, "VolumesFrom": None,
                "Devices": [], "DeviceRequests": None, "CapAdd": None, "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"], "Memory": MEMORY_BYTES,
                "MemorySwap": MEMORY_BYTES, "NanoCpus": 1_000_000_000, "PidsLimit": 128,
                "LogConfig": {"Type": "none", "Config": {}}, "AutoRemove": False}}


class Docker:
    def __init__(self):
        self.worker = row()
        self.daemon = SPEC.daemon_id
        self.calls = []
        self.fail_inspect = self.fail_remove = self.keep_worker = False
        self.replace_after_remove = False

    def __call__(self, args):
        self.calls.append(args)
        def reply(code=0, out="", err=""):
            return SimpleNamespace(returncode=code, stdout=out, stderr=err)
        if args == ["info", "--format", "{{.ID}}"]:
            return reply(out=self.daemon + "\n")
        if args[:3] == ["inspect", "--type", "container"]:
            if self.fail_inspect:
                return reply(1, err="permission denied")
            if self.worker is None or args[3] not in (self.worker["Id"], self.worker["Name"][1:]):
                return reply(1, err="Error: No such container: " + args[3])
            return reply(out=json.dumps([self.worker]))
        if args == ["rm", "--force", CID]:
            if self.fail_remove:
                return reply(1, err="refused")
            if not self.keep_worker:
                self.worker = None
            if self.replace_after_remove:
                self.worker = row()
                self.worker["Id"] = "d" * 64
            return reply(out=CID)
        raise AssertionError("Unexpected command: " + repr(args))

    def destructive(self):
        return [args for args in self.calls if args[0] == "rm"]


class BuildCacheTests(unittest.TestCase):
    def test_exact_removal_without_prune_volume_or_image_commands(self):
        fake = Docker()
        result = cleanup_cache(fake, SPEC, CID)
        self.assertEqual(fake.destructive(), [["rm", "--force", CID]])
        self.assertTrue(result["cacheTmpfsAbsent"])
        for key in ("daemonImageContentCleanupVerified", "daemonImageDiskBoundEnforced",
                    "buildAdmitted", "qualificationComplete"):
            self.assertFalse(result[key])

    def test_idempotent_absence_requires_both_id_and_name(self):
        fake = Docker()
        fake.worker = None
        self.assertEqual(cleanup_cache(fake, SPEC, CID)["status"], "already_absent_verified")
        self.assertEqual(fake.destructive(), [])

    def test_invalid_identity_and_size_make_no_commands(self):
        fake = Docker()
        for value in (None, "", "short", "B" * 64):
            with self.assertRaises(ValueError):
                cleanup_cache(fake, SPEC, value)
        self.assertEqual(fake.calls, [])
        for size in (True, 0, MIB - 1, MIB + 1, 257 * MIB):
            with self.assertRaises(ValueError):
                CacheSpec(SPEC.daemon_id, SPEC.owner, SPEC.image_id, size)

    def test_identity_mismatches_never_remove(self):
        mutations = [lambda r: r.update(Id="d" * 64),
                     lambda r: r.update(Name="/unrelated"),
                     lambda r: r.update(Image="sha256:" + "e" * 64),
                     lambda r: r["Config"]["Labels"].update({"owasp-ai-goat.owner": "f" * 32})]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                fake = Docker()
                mutation(fake.worker)
                with self.assertRaises(RuntimeError):
                    cleanup_cache(fake, SPEC, CID)
                self.assertEqual(fake.destructive(), [])

    def test_storage_security_or_resource_profile_mismatch_never_removes(self):
        changes = {"Tmpfs": {}, "ReadonlyRootfs": False, "Privileged": True,
                   "Binds": ["/shared:/var/lib/buildkit"], "Mounts": [{"Type": "volume"}],
                   "VolumesFrom": ["foreign"], "Devices": [{}], "DeviceRequests": [{}],
                   "CapAdd": ["SYS_ADMIN"], "CapDrop": [], "SecurityOpt": ["seccomp=unconfined"],
                   "Memory": 0, "MemorySwap": -1, "NanoCpus": 0, "PidsLimit": -1,
                   "LogConfig": {"Type": "json-file", "Config": {}}, "AutoRemove": True}
        for key, value in changes.items():
            with self.subTest(key=key):
                fake = Docker()
                fake.worker["HostConfig"][key] = value
                with self.assertRaises(RuntimeError):
                    cleanup_cache(fake, SPEC, CID)
                self.assertEqual(fake.destructive(), [])
        for key, value in (("User", "0"), ("Volumes", {"/hidden": {}})):
            fake = Docker()
            fake.worker["Config"][key] = value
            with self.assertRaises(RuntimeError):
                cleanup_cache(fake, SPEC, CID)
            self.assertEqual(fake.destructive(), [])
        fake = Docker()
        fake.worker["Mounts"] = [{"Type": "volume", "Name": "foreign"}]
        with self.assertRaises(RuntimeError):
            cleanup_cache(fake, SPEC, CID)

    def test_wrong_daemon_and_denied_inspection_are_not_absence(self):
        for setting in ("daemon", "fail_inspect"):
            fake = Docker()
            setattr(fake, setting, "other" if setting == "daemon" else True)
            with self.assertRaises(RuntimeError):
                cleanup_cache(fake, SPEC, CID)
            self.assertEqual(fake.destructive(), [])

    def test_replaced_name_after_removal_is_not_removed_or_reported_clean(self):
        fake = Docker()
        fake.replace_after_remove = True
        with self.assertRaises(RuntimeError):
            cleanup_cache(fake, SPEC, CID)
        self.assertEqual(fake.destructive(), [["rm", "--force", CID]])
        self.assertEqual(fake.worker["Id"], "d" * 64)

    def test_remove_failure_or_still_present_fails_cleanup(self):
        for attribute in ("fail_remove", "keep_worker"):
            fake = Docker()
            setattr(fake, attribute, True)
            with self.assertRaises(RuntimeError):
                cleanup_cache(fake, SPEC, CID)

    def test_daemon_switch_before_removal_prevents_mutation(self):
        fake = Docker()
        def command(args):
            if args == ["info", "--format", "{{.ID}}"] and len(fake.calls) >= 3:
                fake.daemon = "other"
            return fake(args)
        with self.assertRaises(RuntimeError):
            cleanup_cache(command, SPEC, CID)
        self.assertEqual(fake.destructive(), [])

    def test_duplicate_json_and_truncated_records_fail_closed(self):
        for output in ('[{"Id":"x","Id":"y"}]', '[', '[]', '{}'):
            fake = Docker()
            def command(args):
                if args[0] == "inspect":
                    return SimpleNamespace(returncode=0, stdout=output, stderr="")
                return fake(args)
            with self.assertRaises(RuntimeError):
                inspect_cache(command, SPEC, CID)
            self.assertEqual(fake.destructive(), [])

    def test_ownership_inputs_cannot_mutate_spec_via_returned_maps(self):
        labels, tmpfs = SPEC.labels, SPEC.tmpfs
        labels.clear()
        tmpfs.clear()
        self.assertTrue(SPEC.labels)
        self.assertTrue(SPEC.tmpfs)
        self.assertEqual(inspect_cache(Docker(), SPEC, CID)["Id"], CID)


if __name__ == "__main__":
    unittest.main()
