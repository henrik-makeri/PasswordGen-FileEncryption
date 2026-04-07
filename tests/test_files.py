from pathlib import Path
import shutil
import unittest
from uuid import uuid4

from crypto_tools.files import decrypt_bytes, decrypt_file, encrypt_bytes, encrypt_file


class FileEncryptionTests(unittest.TestCase):
    def test_encrypt_then_decrypt_round_trip(self) -> None:
        original = b"top secret data"
        password = "correct horse battery staple"

        encrypted = encrypt_bytes(original, password)
        decrypted = decrypt_bytes(encrypted, password)

        self.assertNotEqual(encrypted, original)
        self.assertEqual(decrypted, original)

    def test_decrypt_rejects_wrong_password(self) -> None:
        encrypted = encrypt_bytes(b"classified", "right-password")

        with self.assertRaisesRegex(ValueError, "Wrong password"):
            decrypt_bytes(encrypted, "wrong-password")

    def test_streaming_encrypt_and_decrypt_file_round_trip(self) -> None:
        workspace_temp = Path.cwd() / ".tmp-tests"
        workspace_temp.mkdir(exist_ok=True)
        temp_path = workspace_temp / f"files-{uuid4().hex}"
        temp_path.mkdir()
        try:
            source = temp_path / "notes.txt"
            encrypted = temp_path / "notes.txt.enc"
            decrypted = temp_path / "notes.decrypted.txt"
            source.write_text("hello world", encoding="utf-8")

            encrypt_file(source, "swordfish", destination=encrypted)
            decrypt_file(encrypted, "swordfish", destination=decrypted)

            self.assertTrue(encrypted.exists())
            self.assertEqual(decrypted.read_text(encoding="utf-8"), "hello world")
        finally:
            if temp_path.exists():
                shutil.rmtree(temp_path, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
