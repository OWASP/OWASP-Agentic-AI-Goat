import tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import coupon_dependency_integrity as c
class CouponIntegrity(unittest.TestCase):
 def test_root_client_bytes_and_exact_identities(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp)
   for name in c.IDENTITIES:
    p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('{}')
   for name in ['node_modules/a.js','client/node_modules/b.js']:(root/name).write_text('original')
   ids={p:c.sha(root/p) for p in c.IDENTITIES};expected=c.digest(c.inventory(root));c.verify(root,ids,expected)
   for name in ['node_modules/a.js','client/node_modules/b.js']:
    (root/name).write_text('drift')
    with self.assertRaisesRegex(RuntimeError,'byte drift'):c.verify(root,ids,expected)
    (root/name).write_text('original')
   with self.assertRaisesRegex(RuntimeError,'six'):c.verify(root,{},expected)
   (root/'client/package.json').write_text('changed')
   with self.assertRaisesRegex(RuntimeError,'identity drift'):c.verify(root,ids,expected)
 def test_invalid_digest_and_pins_fail_closed(self):
  with self.assertRaisesRegex(RuntimeError,'digest required'):c.verify('.',{},None)
  with patch.object(c,'sha',side_effect=[c.NODE_SHA,c.DOCKER_SHA]):c.pins('node','docker',c.DAEMON_ID)
  for node,docker,daemon in [('bad',c.DOCKER_SHA,c.DAEMON_ID),(c.NODE_SHA,'bad',c.DAEMON_ID),(c.NODE_SHA,c.DOCKER_SHA,'bad')]:
   with patch.object(c,'sha',side_effect=[node,docker]),self.assertRaisesRegex(RuntimeError,'mismatch'):c.pins('node','docker',daemon)
if __name__=='__main__':unittest.main()
