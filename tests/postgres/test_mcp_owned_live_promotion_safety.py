import unittest
from mcp_owned_live_promotion_safety import select_backend_pid

SOURCE='/workspace'
def row(pid, *, ppid=41, cwd=SOURCE, command='node server/index.js', state='S'):
    return {'pid':pid,'ppid':ppid,'cwd':cwd,'command':command,'state':state}

class ProcessSelectionTest(unittest.TestCase):
    def test_requires_a_distinct_identity_checked_replacement(self):
        with self.assertRaises(RuntimeError):
            select_backend_pid([row(50)],watcher_pid=41,source=SOURCE,excluded_pid=50,require_running=True)
        self.assertEqual(select_backend_pid([row(50,state='Z'),row(51)],watcher_pid=41,
          source=SOURCE,excluded_pid=50,require_running=True),51)

    def test_rejects_wrong_parent_directory_command_stopped_and_ambiguous_children(self):
        bad=[row(60,ppid=42),row(61,cwd='/other'),row(62,command='node server/index.js-malicious'),
          row(63,state='T'),row(66,state=''),row(67,state='unknown')]
        with self.assertRaises(RuntimeError):
            select_backend_pid(bad,watcher_pid=41,source=SOURCE,require_running=True)
        with self.assertRaises(RuntimeError):
            select_backend_pid([row(64),row(65)],watcher_pid=41,source=SOURCE,require_running=True)
        for state in ('','unknown'):
            with self.subTest(state=state), self.assertRaises(RuntimeError):
                select_backend_pid([row(68,state=state)],watcher_pid=41,source=SOURCE,require_running=True)
        for command in ('node other.js', 'node server/index.js-malicious'):
            with self.subTest(command=command), self.assertRaises(RuntimeError):
                select_backend_pid([row(69,command=command)],watcher_pid=41,source=SOURCE,require_running=True)

    def test_repair_selection_can_identify_one_already_stopped_current_child(self):
        self.assertEqual(select_backend_pid([row(70,state='T')],watcher_pid=41,source=SOURCE),70)

if __name__ == '__main__': unittest.main()
