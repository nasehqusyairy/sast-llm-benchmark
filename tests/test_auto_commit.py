import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "auto_commit.py"
spec = importlib.util.spec_from_file_location("auto_commit", SCRIPT)
auto_commit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auto_commit)


class AutoCommitTests(unittest.TestCase):
    def test_commit_message_contains_timestamp_and_change_summary(self):
        message = auto_commit.make_commit_message("2026-05-01 12:30:00", ["M file.py", "?? new.txt"])
        self.assertIn("chore: automated sync 2026-05-01 12:30:00", message)
        self.assertIn("M file.py", message)
        self.assertIn("?? new.txt", message)

    def test_dirty_check_detects_untracked_and_modified_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            (root / "tracked.txt").write_text("original")
            subprocess.run(["git", "add", "tracked.txt"], cwd=root, check=True)
            subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", "initial"], cwd=root, check=True)
            (root / "tracked.txt").write_text("updated")
            (root / "untracked.txt").write_text("new")
            self.assertEqual(auto_commit.changed_paths(root), [" M tracked.txt", "?? untracked.txt"])

    def test_parser_interval_and_dry_run(self):
        args = auto_commit.build_parser().parse_args(["--interval", "5", "--dry-run"])
        self.assertEqual(args.interval, 5)
        self.assertTrue(args.dry_run)


if __name__ == "__main__":
    unittest.main()
