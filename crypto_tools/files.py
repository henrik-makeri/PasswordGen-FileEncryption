from __future__ import annotations

from collections.abc import Callable
from getpass import getpass
from pathlib import Path
import secrets
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ct01 was the first format. ct02 added chunking for bigger files.
LEGACY_MAGIC = b"CT01"
STREAM_MAGIC = b"CT02"
ITERATIONS = 600_000
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
TAG_SIZE = 16
DEFAULT_CHUNK_SIZE = 1024 * 1024
LEGACY_HEADER_STRUCT = struct.Struct(">4sI16s12s")
STREAM_HEADER_STRUCT = struct.Struct(">4sIIQ16s12s")
ENCRYPTION_ALGORITHM = (
    f"AES-256-GCM with PBKDF2-HMAC-SHA256 ({ITERATIONS:,} iterations)"
)


def read_password(password: str | None) -> str:
    if password:
        return password

    entered = getpass("Password: ")
    if not entered:
        raise ValueError("Password cannot be empty.")
    return entered


def _derive_key(password: str, salt: bytes) -> bytes:
    # turns the user password into an aes key
    # TODO: support argon2 as another kdf option
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(data: bytes, password: str) -> bytes:
    # tiny helper for tests and small payloads
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    key = _derive_key(password, salt)
    encrypted = AESGCM(key).encrypt(nonce, data, None)
    header = LEGACY_HEADER_STRUCT.pack(LEGACY_MAGIC, ITERATIONS, salt, nonce)
    return header + encrypted


def decrypt_bytes(blob: bytes, password: str) -> bytes:
    header_size = LEGACY_HEADER_STRUCT.size
    if len(blob) <= header_size:
        raise ValueError("Encrypted file is too short.")

    magic, iterations, salt, nonce = LEGACY_HEADER_STRUCT.unpack(blob[:header_size])
    if magic != LEGACY_MAGIC:
        raise ValueError("Unsupported encrypted file format.")
    if iterations != ITERATIONS:
        raise ValueError("Unsupported KDF iteration count.")

    key = _derive_key(password, salt)
    try:
        return AESGCM(key).decrypt(nonce, blob[header_size:], None)
    except InvalidTag as exc:
        raise ValueError("Wrong password or corrupted file.") from exc


def _default_encrypted_path(source: Path) -> Path:
    return source.with_name(f"{source.name}.enc")


def _default_decrypted_path(source: Path) -> Path:
    if source.suffix == ".enc":
        original_name = source.stem
        original_path = Path(original_name)
        if original_path.suffix:
            return source.with_name(
                f"{original_path.stem}.decrypted{original_path.suffix}"
            )
        return source.with_name(f"{original_name}.decrypted")
    return source.with_name(f"{source.name}.decrypted")


def _legacy_decrypt_file(
    source_path: Path,
    password: str,
    destination_path: Path,
    *,
    overwrite: bool = False,
    progress_callback: Callable[[int, int], None] | None = None,
) -> Path:
    # old file format path
    if destination_path.exists() and not overwrite:
        raise FileExistsError(
            f"{destination_path} already exists. Pass --overwrite or choose a new output path."
        )

    temp_file = destination_path.with_name(f"{destination_path.name}.partial")
    if temp_file.exists():
        temp_file.unlink()

    blob = source_path.read_bytes()
    total = len(blob)
    if progress_callback:
        progress_callback(0, total)

    try:
        decrypted = decrypt_bytes(blob, password)
        temp_file.write_bytes(decrypted)
        temp_file.replace(destination_path)
    except Exception:
        if temp_file.exists():
            temp_file.unlink()
        raise

    if progress_callback:
        progress_callback(total, total)

    return destination_path


def encrypt_file(
    source: str | Path,
    password: str,
    destination: str | Path | None = None,
    *,
    overwrite: bool = False,
    progress_callback: Callable[[int, int], None] | None = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> Path:
    src = Path(source)
    if not src.is_file():
        raise FileNotFoundError(f"Input file not found: {src}")

    if destination:
        out_path = Path(destination)
    else:
        out_path = _default_encrypted_path(src)
    if out_path.exists() and not overwrite:
        raise FileExistsError(
            f"{out_path} already exists. Pass --overwrite or choose a new output path."
        )

    total_size = src.stat().st_size
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    key = _derive_key(password, salt)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    header = STREAM_HEADER_STRUCT.pack(
        STREAM_MAGIC,
        ITERATIONS,
        chunk_size,
        total_size,
        salt,
        nonce,
    )

    temp_path = out_path.with_name(f"{out_path.name}.partial")
    if temp_path.exists():
        temp_path.unlink()

    if progress_callback:
        progress_callback(0, total_size)

    done_bytes = 0

    try:
        with src.open("rb") as source_file, temp_path.open("wb") as target_file:
            target_file.write(header)

            while True:
                # chunked loop so big files do not feel awful
                chunk = source_file.read(chunk_size)
                if not chunk:
                    break

                target_file.write(encryptor.update(chunk))
                done_bytes += len(chunk)
                if progress_callback:
                    progress_callback(done_bytes, total_size)

            target_file.write(encryptor.finalize())
            target_file.write(encryptor.tag)

        temp_path.replace(out_path)
    except Exception:
        if temp_path.exists():
            temp_path.unlink()
        raise

    if progress_callback:
        progress_callback(total_size, total_size)

    return out_path


def decrypt_file(
    source: str | Path,
    password: str,
    destination: str | Path | None = None,
    *,
    overwrite: bool = False,
    progress_callback: Callable[[int, int], None] | None = None,
) -> Path:
    source_path = Path(source)
    if not source_path.is_file():
        raise FileNotFoundError(f"Encrypted file not found: {source_path}")

    if destination:
        destination_path = Path(destination)
    else:
        destination_path = _default_decrypted_path(source_path)

    with source_path.open("rb") as source_file:
        magic = source_file.read(4)

    if magic == LEGACY_MAGIC:
        return _legacy_decrypt_file(
            source_path,
            password,
            destination_path,
            overwrite=overwrite,
            progress_callback=progress_callback,
        )

    if magic != STREAM_MAGIC:
        raise ValueError("Unsupported encrypted file format.")

    if destination_path.exists() and not overwrite:
        raise FileExistsError(
            f"{destination_path} already exists. Pass --overwrite or choose a new output path."
        )

    file_size = source_path.stat().st_size
    header_len = STREAM_HEADER_STRUCT.size
    if file_size <= header_len + TAG_SIZE:
        raise ValueError("Encrypted file is too short.")

    temp_file = destination_path.with_name(f"{destination_path.name}.partial")
    if temp_file.exists():
        temp_file.unlink()

    try:
        with source_path.open("rb") as source_file:
            header_data = source_file.read(header_len)
            magic, iterations, chunk_size, _original_size, salt, nonce = STREAM_HEADER_STRUCT.unpack(
                header_data
            )
            if magic != STREAM_MAGIC:
                raise ValueError("Unsupported encrypted file format.")
            if iterations != ITERATIONS:
                raise ValueError("Unsupported KDF iteration count.")
            if chunk_size < 1:
                raise ValueError("Encrypted file has an invalid chunk size.")

            ciphertext_size = file_size - header_len - TAG_SIZE
            source_file.seek(file_size - TAG_SIZE)
            tag = source_file.read(TAG_SIZE)
            source_file.seek(header_len)

            key = _derive_key(password, salt)
            decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()

            if progress_callback:
                progress_callback(0, ciphertext_size)

            done = 0
            with temp_file.open("wb") as target_file:
                while done < ciphertext_size:
                    # same idea as encrypt, just backwards
                    to_read = min(chunk_size, ciphertext_size - done)
                    chunk = source_file.read(to_read)
                    if not chunk:
                        raise ValueError("Encrypted file is truncated.")

                    target_file.write(decryptor.update(chunk))
                    done += len(chunk)
                    if progress_callback:
                        progress_callback(done, ciphertext_size)

                target_file.write(decryptor.finalize())

        temp_file.replace(destination_path)
    except InvalidTag as exc:
        if temp_file.exists():
            temp_file.unlink()
        raise ValueError("Wrong password or corrupted file.") from exc
    except Exception:
        if temp_file.exists():
            temp_file.unlink()
        raise

    if progress_callback:
        progress_callback(ciphertext_size, ciphertext_size)

    return destination_path
