import hashlib
from pathlib import Path
import shutil
import unittest
from uuid import uuid4

from crypto_tools.hashing import hash_file, hash_text


class HashingTests(unittest.TestCase):
    def test_hash_text_matches_hashlib(self) -> None:
        self.assertEqual(hash_text("hello", "sha256"), hashlib.sha256(b"hello").hexdigest())

    def test_hash_file_matches_hashlib(self) -> None:
        workspace_temp = Path.cwd() / ".tmp-tests"
        workspace_temp.mkdir(exist_ok=True)
        temp_path = workspace_temp / f"hash-{uuid4().hex}"
        temp_path.mkdir()
        try:
            path = temp_path / "sample.txt"
            path.write_bytes(b"hash me")
            self.assertEqual(hash_file(path, "md5"), hashlib.md5(b"hash me").hexdigest())
        finally:
            if temp_path.exists():
                shutil.rmtree(temp_path, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
