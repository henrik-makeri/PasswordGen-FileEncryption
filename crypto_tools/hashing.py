from __future__ import annotations

from collections.abc import Callable
import hashlib
from pathlib import Path


HASH_ALGORITHMS = {
    "md5": "MD5",
    "sha256": "SHA-256",
}
# TODO: add sha512 once i decide how many algos i actually want in the UI
DEFAULT_HASH_CHUNK_SIZE = 1024 * 1024


def normalize_algorithm(name: str) -> str:
    # cli users kept typing sha-256, so i just accept both :D
    normalized = name.lower().replace("-", "")
    if normalized not in HASH_ALGORITHMS:
        raise ValueError(f"Unsupported hash algorithm: {name}")
    return normalized


def format_hash_algorithm_label(name: str) -> str:
    return HASH_ALGORITHMS[normalize_algorithm(name)]


def hash_text(text: str, algorithm: str = "sha256") -> str:
    algo = normalize_algorithm(algorithm)
    hasher = hashlib.new(algo)
    hasher.update(text.encode("utf-8"))
    return hasher.hexdigest()


def hash_file(
    source: str | Path,
    algorithm: str = "sha256",
    *,
    progress_callback: Callable[[int, int], None] | None = None,
    chunk_size: int = DEFAULT_HASH_CHUNK_SIZE,
) -> str:
    source_path = Path(source)
    if not source_path.is_file():
        raise FileNotFoundError(f"Input file not found: {source_path}")

    algorithm_name = normalize_algorithm(algorithm)
    hasher = hashlib.new(algorithm_name)
    total_size = source_path.stat().st_size
    processed = 0

    if progress_callback:
        progress_callback(0, total_size)

    with source_path.open("rb") as source_file:
        while True:
            # chunked so the gui can show progress
            chunk = source_file.read(chunk_size)
            if not chunk:
                break

            hasher.update(chunk)
            processed += len(chunk)
            if progress_callback:
                progress_callback(processed, total_size)

    if progress_callback:
        progress_callback(total_size, total_size)

    return hasher.hexdigest()
