"""Regression: process-group cleanup when only zombies remain.

Found by CI on GitHub's macOS 26 runners: after a timeout, the descendants had
died but were not yet reaped, `killpg` failed with EPERM, and cleanup aborted
with PermissionError instead of reporting DeadlineExceeded.
"""
from pathlib import Path
import select
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from execution import stop_group


class ZombieGroupTests(unittest.TestCase):
    def test_stop_group_tolerates_a_zombie_only_group(self):
        proc = subprocess.Popen(["/bin/sleep", "0.2"], start_new_session=True,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Wait for the exit without reaping it, so the group holds only a zombie.
        queue = select.kqueue()
        self.addCleanup(queue.close)
        queue.control([select.kevent(proc.pid, select.KQ_FILTER_PROC,
                                     select.KQ_EV_ADD | select.KQ_EV_ONESHOT, select.KQ_NOTE_EXIT)], 1, 5)
        stop_group(proc)
        self.assertEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
