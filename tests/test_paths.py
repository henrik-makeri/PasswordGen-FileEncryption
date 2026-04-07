import unittest
from pathlib import Path

from crypto_tools.files import _default_decrypted_path


class DefaultPathTests(unittest.TestCase):
    def test_default_decrypted_path_avoids_original_filename_collision(self) -> None:
        result = _default_decrypted_path(Path("notes.txt.enc"))
        self.assertEqual(result, Path("notes.decrypted.txt"))

    def test_default_decrypted_path_without_inner_suffix(self) -> None:
        result = _default_decrypted_path(Path("archive.enc"))
        self.assertEqual(result, Path("archive.decrypted"))


if __name__ == "__main__":
    unittest.main()
