from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import math
import secrets
import string

from wordfreq import top_n_list


SYMBOLS = "!@#$%^&*()_+-={}[]:;<>,.?/"
PRONOUNCEABLE_WORD_LIST_SIZE = 5_000
PRONOUNCEABLE_MIN_LENGTH = 3
PRONOUNCEABLE_MAX_LENGTH = 8


@dataclass(frozen=True)
class PasswordOptions:
    length: int = 16
    uppercase: bool = True
    lowercase: bool = True
    numbers: bool = True
    symbols: bool = False


def _enabled_groups(options: PasswordOptions) -> list[str]:
    # active character buckets
    groups: list[str] = []

    if options.uppercase:
        groups.append(string.ascii_uppercase)
    if options.lowercase:
        groups.append(string.ascii_lowercase)
    if options.numbers:
        groups.append(string.digits)
    if options.symbols:
        groups.append(SYMBOLS)

    return groups


def _secure_shuffle(characters: list[str]) -> None:
    # random.shuffle would be shorter, but i wanted secrets end to end
    for index in range(len(characters) - 1, 0, -1):
        swap_index = secrets.randbelow(index + 1)
        characters[index], characters[swap_index] = (
            characters[swap_index],
            characters[index],
        )


@lru_cache(maxsize=1)
def get_pronounceable_words() -> tuple[str, ...]:
    # switched to wordfreq later. the hand-picked list got old fast lol
    # TODO: trim out more boring/common words
    filtered_words: list[str] = []
    seen: set[str] = set()

    for word in top_n_list("en", PRONOUNCEABLE_WORD_LIST_SIZE):
        normalized = word.strip().lower()
        if not normalized.isalpha():
            continue
        if not (PRONOUNCEABLE_MIN_LENGTH <= len(normalized) <= PRONOUNCEABLE_MAX_LENGTH):
            continue
        if normalized in seen:
            continue

        seen.add(normalized)
        filtered_words.append(normalized)

    if not filtered_words:
        raise ValueError("No pronounceable English words were loaded.")

    return tuple(filtered_words)


def generate_password(options: PasswordOptions) -> str:
    groups = _enabled_groups(options)

    if not groups:
        raise ValueError("Enable at least one character group.")
    if options.length < len(groups):
        raise ValueError(
            "Password length must be at least the number of enabled character groups."
        )

    password_chars = [secrets.choice(group) for group in groups]
    all_characters = "".join(groups)

    for _ in range(options.length - len(password_chars)):
        password_chars.append(secrets.choice(all_characters))

    _secure_shuffle(password_chars)
    return "".join(password_chars)


def estimate_entropy_bits(options: PasswordOptions) -> float:
    groups = _enabled_groups(options)
    if not groups:
        return 0.0

    charset_size = len("".join(groups))
    return options.length * math.log2(charset_size)


def generate_pronounceable_password(word_count: int = 4, separator: str = "-") -> str:
    if word_count < 1:
        raise ValueError("Word count must be at least 1.")

    words = get_pronounceable_words()
    picked: list[str] = []
    for _ in range(word_count):
        picked.append(secrets.choice(words))

    return separator.join(picked)


def estimate_pronounceable_entropy_bits(word_count: int = 4) -> float:
    if word_count < 1:
        return 0.0

    word_entropy = math.log2(len(get_pronounceable_words()))
    return word_count * word_entropy


def classify_entropy_bits(entropy: float) -> str:
    if entropy < 45:
        return "Weak"
    if entropy < 65:
        return "Fair"
    if entropy < 90:
        return "Strong"
    return "Insane"


def classify_strength(options: PasswordOptions) -> str:
    return classify_entropy_bits(estimate_entropy_bits(options))
