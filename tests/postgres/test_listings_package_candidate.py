"""Candidate driver controls; no Docker/native/namespace/model execution."""
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import listings_package_candidate as candidate


class Controls(unittest.TestCase):
    def test_buildx_requires_exact_sibling_hash_root_owner_and_no_writable_mode(self):
        args=SimpleNamespace(docker='/vendor/docker')
        api=SimpleNamespace(digest=lambda p: candidate.BUILDX_SHA256)
        metadata=SimpleNamespace(st_mode=0o100755,st_uid=0)
        with patch.object(Path,'lstat',return_value=metadata), patch.object(Path,'resolve',lambda p:p), patch.object(candidate.os,'access',return_value=True):
            self.assertEqual(candidate.buildx_identity(api,args),{'path':'/vendor/docker-buildx','sha256':candidate.BUILDX_SHA256})
            metadata.st_uid=501
            with self.assertRaises(RuntimeError): candidate.buildx_identity(api,args)
            metadata.st_uid=0; metadata.st_mode=0o100777
            with self.assertRaises(RuntimeError): candidate.buildx_identity(api,args)
            metadata.st_mode=0o100755; api.digest=lambda p:'f'*64
            with self.assertRaises(RuntimeError): candidate.buildx_identity(api,args)

    def test_context_contains_only_exact_pinned_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve(); (root/'allowed.js').write_bytes(b'code'); (root/'secret').write_bytes(b'private')
            manifest={'files':{'allowed.js':hashlib.sha256(b'code').hexdigest()}}
            data=candidate.context_bytes(root,manifest)
            with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                self.assertEqual(archive.getnames(),['allowed.js'])
                self.assertEqual(archive.extractfile('allowed.js').read(),b'code')
            (root/'allowed.js').write_bytes(b'drift')
            with self.assertRaises(RuntimeError): candidate.context_bytes(root,manifest)

    def test_context_denies_path_escape_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve(); (root/'target').write_bytes(b'x'); (root/'link').symlink_to(root/'target')
            for name in ['../target','/target','link']:
                with self.assertRaises(RuntimeError): candidate.context_bytes(root,{'files':{name:'a'*64}})

    def test_result_requires_exact_fresh_then_restart_and_all_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'out'
            value={'status':'passed','modelCalls':0,'existingReceipt':False,'checks':candidate.CHECKS,'runtimeDigest':'a'*64}
            path.write_text(json.dumps(value)); self.assertEqual(candidate.read_result(path,False),value)
            with self.assertRaises(RuntimeError): candidate.read_result(path,True)
            value['existingReceipt']=True; path.write_text(json.dumps(value)); candidate.read_result(path,True)
            value['checks']=candidate.CHECKS[:-1]; path.write_text(json.dumps(value))
            with self.assertRaises(RuntimeError): candidate.read_result(path,True)

    def test_image_capture_rejects_foreign_label_tag_and_identity_drift(self):
        state={'imageTag':'nonce:candidate','labels':{'owner':'nonce'}}
        image={'Id':'sha256:'+'a'*64,'Architecture':'arm64','Os':'linux',
            'RepoTags':['nonce:candidate'],'Config':{'Labels':{'owner':'nonce'}}}
        command=lambda args: SimpleNamespace(returncode=0,stdout=json.dumps([image]))
        candidate.read_image(command,state); self.assertEqual(state['image'],image['Id'])
        for mutate in [lambda: image['Config']['Labels'].update(owner='foreign'),
                       lambda: image.update(RepoTags=['nonce:candidate','retained:tag']),
                       lambda: image.update(Id='sha256:'+'b'*64)]:
            image.update(Id='sha256:'+'a'*64,RepoTags=['nonce:candidate'],Config={'Labels':{'owner':'nonce'}})
            mutate()
            with self.assertRaises(RuntimeError): candidate.read_image(command,state)

    def test_unknown_image_absence_fails_closed(self):
        state={'imageTag':'nonce:candidate','labels':{}}
        command=lambda args: SimpleNamespace(returncode=1,stderr='permission denied')
        with self.assertRaises(RuntimeError): candidate.read_image(command,state)
        command=lambda args: SimpleNamespace(returncode=1,stderr='Error response from daemon: No such image: nonce:candidate')
        self.assertIsNone(candidate.read_image(command,state))

if __name__=='__main__': unittest.main()
