from __future__ import annotations

import json
from pathlib import Path


PREFERENCES_PATH = Path.home() / ".crypto_tools_gui.json"
DEFAULT_PREFERENCES = {
    "window_geometry": "",
    "password_mode": "random",
    "length": 20,
    "word_count": 4,
    "pronounceable_caps": False,
    "pronounceable_number": False,
    "pronounceable_symbol": False,
    "uppercase": True,
    "lowercase": True,
    "numbers": True,
    "symbols": True,
    "password_history": [],
    "file_mode": "encrypt",
    "overwrite": False,
    "show_file_password": False,
    "hash_algorithm": "sha256",
}


def load_preferences() -> dict[str, object]:
    preferences = dict(DEFAULT_PREFERENCES)

    if not PREFERENCES_PATH.exists():
        return preferences

    try:
        raw = json.loads(PREFERENCES_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return preferences

    if not isinstance(raw, dict):
        return preferences

    for key, value in raw.items():
        if key in preferences:
            preferences[key] = value

    return preferences


def save_preferences(preferences: dict[str, object]) -> None:
    payload = dict(DEFAULT_PREFERENCES)
    payload.update(preferences)
    PREFERENCES_PATH.write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )
