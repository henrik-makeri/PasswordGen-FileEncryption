import unittest

from crypto_tools.passwords import (
    PasswordOptions,
    estimate_pronounceable_entropy_bits,
    generate_password,
    generate_pronounceable_password,
    get_pronounceable_words,
)


class PasswordGeneratorTests(unittest.TestCase):
    def test_generate_password_contains_enabled_groups(self) -> None:
        options = PasswordOptions(
            length=20,
            uppercase=True,
            lowercase=True,
            numbers=True,
            symbols=True,
        )
        password = generate_password(options)

        self.assertEqual(len(password), 20)
        self.assertTrue(any(character.isupper() for character in password))
        self.assertTrue(any(character.islower() for character in password))
        self.assertTrue(any(character.isdigit() for character in password))
        self.assertTrue(any(not character.isalnum() for character in password))

    def test_generate_password_rejects_missing_groups(self) -> None:
        options = PasswordOptions(
            length=16,
            uppercase=False,
            lowercase=False,
            numbers=False,
            symbols=False,
        )

        with self.assertRaisesRegex(ValueError, "Enable at least one"):
            generate_password(options)

    def test_pronounceable_password_uses_requested_word_count(self) -> None:
        password = generate_pronounceable_password(word_count=4)
        self.assertEqual(len(password.split("-")), 4)

    def test_pronounceable_word_list_comes_from_filtered_english_words(self) -> None:
        words = get_pronounceable_words()
        self.assertGreater(len(words), 500)
        self.assertTrue(all(word.isalpha() for word in words[:50]))
        self.assertTrue(all(3 <= len(word) <= 8 for word in words[:50]))

    def test_pronounceable_entropy_increases_with_more_words(self) -> None:
        self.assertGreater(
            estimate_pronounceable_entropy_bits(5),
            estimate_pronounceable_entropy_bits(4),
        )


if __name__ == "__main__":
    unittest.main()
