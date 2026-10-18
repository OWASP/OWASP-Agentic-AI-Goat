"""Pure parent contract control: raw wire remains separate from compact receipt."""
import copy,json,unittest
from dpi_current_owned_launcher_test import Controls,m
class CompactReceiptTests(unittest.TestCase):
    def test_parent_uses_separate_wire_not_compact_summary(self):
        value,wire=Controls().receipt()
        wire['calls'][0]['response']='x'*(2*1024*1024)
        before=copy.deepcopy(wire)
        value['wireSummary']={k:wire[k] for k in ['version','model','digest','counts','physicalPending','handlersPending','closed']}
        self.assertLess(len(json.dumps(value).encode()),1024*1024)
        self.assertTrue(m.verify_dpi_result(value,wire));self.assertEqual(wire,before)
        changed=copy.deepcopy(wire);changed['physicalPending']=1
        with self.assertRaisesRegex(RuntimeError,'physical wire'):m.verify_dpi_result(value,changed)
    def test_summary_cannot_substitute_for_raw_call_accounting(self):
        value,wire=Controls().receipt();value['wireSummary']={'closed':True,'physicalPending':0,'counts':wire['counts']}
        wire['calls']=[]
        with self.assertRaisesRegex(RuntimeError,'wire counts'):m.verify_dpi_result(value,wire)
if __name__=='__main__':unittest.main()
