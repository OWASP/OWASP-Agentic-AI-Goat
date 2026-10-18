import copy, tempfile, unittest, json, os
from unittest.mock import patch
import csrf_managed_browser_cleanup as cleanup_module
from pathlib import Path
from csrf_managed_browser_cleanup import validate_identity, EXPECTED_EXECUTABLE

class OwnershipTests(unittest.TestCase):
    def test_exact_identity_and_denials(self):
        root=Path(tempfile.gettempdir()).resolve()/'owned-csrf-fixture'
        identity=dict(version=1,detached=True,pid=30,pgid=30,workerPid=20,qualificationPgid=10,uid=502,profile=str(root/'csrf-managed-profile'),executable=EXPECTED_EXECUTABLE,startIdentity='Sat Sep 26 08:30:00 2026',command=EXPECTED_EXECUTABLE+' --user-data-dir='+str(root/'csrf-managed-profile'))
        current={key:identity[key] for key in ['pid','pgid','uid','startIdentity','command']}
        self.assertEqual(validate_identity(identity,root,502,current),30)
        self.assertEqual(validate_identity(identity,root,502,None),30)
        for field,value in [('uid',503),('pgid',10),('pid',True),('profile','/tmp/foreign'),('executable','/tmp/foreign-chrome'),('startIdentity','')]:
            with self.subTest(field=field):
                bad=copy.deepcopy(identity);bad[field]=value
                with self.assertRaises(RuntimeError):validate_identity(bad,root,502,current)
        for field,value in [('uid',503),('pgid',10),('pid',31),('startIdentity','Sat Sep 26 08:31:00 2026'),('command',current['command']+' --different')]:
            with self.subTest(live=field):
                bad=copy.deepcopy(current);bad[field]=value
                with self.assertRaises(RuntimeError):validate_identity(identity,root,502,bad)

class SequenceCleanupTests(unittest.TestCase):
    def test_two_exact_profiles_and_groups_are_verified_and_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();(root/'csrf-managed-sequence.json').write_text(json.dumps({'version':1,'limit':2}))
            for index in (1,2):
                child=root/('csrf-managed-'+str(index));child.mkdir();profile=child/'csrf-managed-profile';profile.mkdir()
                identity=dict(version=1,detached=True,pid=300+index,pgid=300+index,workerPid=200,qualificationPgid=100,uid=os.getuid(),profile=str(profile),executable=EXPECTED_EXECUTABLE,startIdentity='Sat Sep 26 08:30:00 2026',command=EXPECTED_EXECUTABLE+' --user-data-dir='+str(profile))
                (child/'csrf-managed-process.json').write_text(json.dumps(identity))
            with patch.object(cleanup_module,'roster',return_value=[]),patch.object(cleanup_module.os,'killpg',side_effect=AssertionError('No absent group may be signalled')):
                result=cleanup_module.cleanup(root)
            self.assertEqual([r['pgid'] for r in result['launches']],[301,302]);self.assertTrue(result['groupAbsent']);self.assertTrue(result['profileAbsent'])
            for index in (1,2):self.assertFalse((root/('csrf-managed-'+str(index))/'csrf-managed-profile').exists())
    def test_cleanup_attempts_second_even_when_first_fails_and_rejects_third_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();manifest=root/'csrf-managed-sequence.json';manifest.write_text(json.dumps({'version':1,'limit':2}))
            with patch.object(cleanup_module,'cleanup_one',side_effect=[RuntimeError('foreign identity'),{'groupAbsent':True,'profileAbsent':True}]) as clean:
                with self.assertRaises(RuntimeError):cleanup_module.cleanup(root)
                self.assertEqual(clean.call_count,2)
            manifest.write_text(json.dumps({'version':1,'limit':3}))
            with patch.object(cleanup_module,'cleanup_one') as clean:
                with self.assertRaises(RuntimeError):cleanup_module.cleanup(root)
                clean.assert_not_called()

if __name__=='__main__':unittest.main()
