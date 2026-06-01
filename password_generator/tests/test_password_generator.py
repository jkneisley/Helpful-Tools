"""Tests for password_generator.py"""

import sys
import os
import re
import string
import unittest
from io import StringIO
from unittest.mock import patch

# Allow importing from the parent directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from password_generator import (
    DEFAULT_SYMBOLS,
    LOOKALIKE_CHARS,
    WORD_LIST,
    PasswordGenerator,
    PassphraseGenerator,
    main,
)


class TestPasswordGeneratorDefaults(unittest.TestCase):
    """PasswordGenerator with default settings."""

    def setUp(self):
        self.gen = PasswordGenerator()

    def test_default_length(self):
        pw = self.gen.generate()
        self.assertEqual(len(pw), 16)

    def test_custom_length(self):
        for length in (1, 8, 32, 64):
            pw = PasswordGenerator(length=length).generate()
            self.assertEqual(len(pw), length)

    def test_contains_expected_categories(self):
        """A default-settings password should eventually produce all categories."""
        found_upper = found_lower = found_digit = found_symbol = False
        for _ in range(200):
            pw = self.gen.generate()
            if any(c in string.ascii_uppercase for c in pw):
                found_upper = True
            if any(c in string.ascii_lowercase for c in pw):
                found_lower = True
            if any(c in string.digits for c in pw):
                found_digit = True
            if any(c in DEFAULT_SYMBOLS for c in pw):
                found_symbol = True
            if found_upper and found_lower and found_digit and found_symbol:
                break
        self.assertTrue(found_upper, "No uppercase found in 200 passwords")
        self.assertTrue(found_lower, "No lowercase found in 200 passwords")
        self.assertTrue(found_digit, "No digit found in 200 passwords")
        self.assertTrue(found_symbol, "No symbol found in 200 passwords")

    def test_characters_within_alphabet(self):
        alphabet = set(
            string.ascii_uppercase
            + string.ascii_lowercase
            + string.digits
            + DEFAULT_SYMBOLS
        )
        for _ in range(50):
            pw = self.gen.generate()
            for ch in pw:
                self.assertIn(ch, alphabet, f"Unexpected character {ch!r} in password")


class TestPasswordGeneratorNoUppercase(unittest.TestCase):
    def test_no_uppercase(self):
        gen = PasswordGenerator(use_uppercase=False, length=100)
        for _ in range(20):
            pw = gen.generate()
            self.assertFalse(any(c in string.ascii_uppercase for c in pw))


class TestPasswordGeneratorNoLowercase(unittest.TestCase):
    def test_no_lowercase(self):
        gen = PasswordGenerator(use_lowercase=False, length=100)
        for _ in range(20):
            pw = gen.generate()
            self.assertFalse(any(c in string.ascii_lowercase for c in pw))


class TestPasswordGeneratorNoDigits(unittest.TestCase):
    def test_no_digits(self):
        gen = PasswordGenerator(use_digits=False, length=100)
        for _ in range(20):
            pw = gen.generate()
            self.assertFalse(any(c in string.digits for c in pw))


class TestPasswordGeneratorNoSymbols(unittest.TestCase):
    def test_no_symbols(self):
        gen = PasswordGenerator(symbols="", length=100)
        for _ in range(20):
            pw = gen.generate()
            self.assertFalse(any(c in DEFAULT_SYMBOLS for c in pw))


class TestPasswordGeneratorCustomSymbols(unittest.TestCase):
    def test_custom_symbols_only_allowed(self):
        allowed_symbols = "!@#"
        gen = PasswordGenerator(symbols=allowed_symbols, length=100)
        forbidden = set(DEFAULT_SYMBOLS) - set(allowed_symbols)
        for _ in range(20):
            pw = gen.generate()
            for ch in pw:
                self.assertNotIn(ch, forbidden, f"Forbidden symbol {ch!r} found")

    def test_custom_symbols_appear(self):
        """With only symbols (no letters/digits), all chars come from the symbol set."""
        gen = PasswordGenerator(
            use_uppercase=False,
            use_lowercase=False,
            use_digits=False,
            symbols="!@#",
            length=50,
        )
        for _ in range(20):
            pw = gen.generate()
            self.assertTrue(all(c in "!@#" for c in pw))


class TestPasswordGeneratorExcludeLookalikes(unittest.TestCase):
    def test_no_lookalikes(self):
        gen = PasswordGenerator(exclude_lookalikes=True, length=100)
        for _ in range(50):
            pw = gen.generate()
            for ch in pw:
                self.assertNotIn(
                    ch, LOOKALIKE_CHARS, f"Look-alike character {ch!r} found"
                )


class TestPasswordGeneratorValidation(unittest.TestCase):
    def test_length_zero_raises(self):
        with self.assertRaises(ValueError):
            PasswordGenerator(length=0)

    def test_length_negative_raises(self):
        with self.assertRaises(ValueError):
            PasswordGenerator(length=-5)

    def test_empty_pool_raises(self):
        gen = PasswordGenerator(
            use_uppercase=False,
            use_lowercase=False,
            use_digits=False,
            symbols="",
        )
        with self.assertRaises(ValueError):
            gen.generate()


class TestPassphraseGeneratorDefaults(unittest.TestCase):
    """PassphraseGenerator with default settings."""

    def setUp(self):
        self.gen = PassphraseGenerator()

    def test_default_word_count(self):
        pp = self.gen.generate()
        self.assertEqual(len(pp.split("-")), 4)

    def test_all_words_from_word_list(self):
        word_set = set(WORD_LIST)
        for _ in range(20):
            pp = self.gen.generate()
            for word in pp.split("-"):
                self.assertIn(word, word_set)

    def test_generates_different_passphrases(self):
        passphrases = {self.gen.generate() for _ in range(10)}
        self.assertGreater(len(passphrases), 1)


class TestPassphraseGeneratorNumWords(unittest.TestCase):
    def test_custom_num_words(self):
        for n in (1, 3, 6, 10):
            gen = PassphraseGenerator(num_words=n)
            pp = gen.generate()
            self.assertEqual(len(pp.split("-")), n)

    def test_num_words_zero_raises(self):
        with self.assertRaises(ValueError):
            PassphraseGenerator(num_words=0)


class TestPassphraseGeneratorSeparator(unittest.TestCase):
    def test_underscore_separator(self):
        gen = PassphraseGenerator(separator="_")
        pp = gen.generate()
        self.assertIn("_", pp)
        self.assertNotIn("-", pp)

    def test_space_separator(self):
        gen = PassphraseGenerator(num_words=3, separator=" ")
        pp = gen.generate()
        self.assertEqual(len(pp.split(" ")), 3)

    def test_empty_separator(self):
        gen = PassphraseGenerator(num_words=3, separator="")
        pp = gen.generate()
        # Words run together; can't split, but length > 0
        self.assertTrue(len(pp) > 0)


class TestPassphraseGeneratorCapitalize(unittest.TestCase):
    def test_capitalize(self):
        gen = PassphraseGenerator(capitalize=True)
        for _ in range(20):
            pp = gen.generate()
            for word in pp.split("-"):
                self.assertTrue(
                    word[0].isupper(),
                    f"Word {word!r} is not capitalized",
                )


class TestPassphraseGeneratorAddDigit(unittest.TestCase):
    def test_add_digit(self):
        gen = PassphraseGenerator(add_digit=True)
        for _ in range(20):
            pp = gen.generate()
            self.assertTrue(pp[-1].isdigit(), f"Last char of {pp!r} is not a digit")


class TestPassphraseGeneratorAddSymbol(unittest.TestCase):
    def test_add_symbol(self):
        gen = PassphraseGenerator(add_symbol=True)
        for _ in range(20):
            pp = gen.generate()
            self.assertIn(pp[-1], DEFAULT_SYMBOLS)

    def test_add_symbol_no_symbols_raises(self):
        gen = PassphraseGenerator(add_symbol=True, symbols="")
        with self.assertRaises(ValueError):
            gen.generate()


class TestPassphraseGeneratorExcludeLookalikes(unittest.TestCase):
    def test_no_lookalike_digit(self):
        # add_digit=True; the digit appended must not be 0 or 1
        gen = PassphraseGenerator(add_digit=True, exclude_lookalikes=True)
        digits_seen: set[str] = set()
        for _ in range(200):
            pp = gen.generate()
            digits_seen.add(pp[-1])
        # 0 and 1 should never appear
        self.assertNotIn("0", digits_seen)
        self.assertNotIn("1", digits_seen)


class TestCLI(unittest.TestCase):
    """Test the command-line interface via main()."""

    def _run_cli(self, args: list[str]) -> str:
        buf = StringIO()
        with patch("sys.stdout", buf):
            main(args)
        return buf.getvalue().strip()

    def test_default_output_length(self):
        output = self._run_cli([])
        self.assertEqual(len(output), 16)

    def test_length_option(self):
        output = self._run_cli(["--length", "24"])
        self.assertEqual(len(output), 24)

    def test_short_length_option(self):
        output = self._run_cli(["-l", "8"])
        self.assertEqual(len(output), 8)

    def test_count_option(self):
        output = self._run_cli(["--count", "5"])
        lines = output.splitlines()
        self.assertEqual(len(lines), 5)

    def test_no_symbols(self):
        output = self._run_cli(["--no-symbols", "--length", "100"])
        self.assertFalse(any(c in DEFAULT_SYMBOLS for c in output))

    def test_custom_symbols(self):
        output = self._run_cli(["--symbols", "!@#", "--length", "100"])
        forbidden = set(DEFAULT_SYMBOLS) - set("!@#")
        self.assertFalse(any(c in forbidden for c in output))

    def test_exclude_lookalikes(self):
        output = self._run_cli(["--exclude-lookalikes", "--length", "100"])
        self.assertFalse(any(c in LOOKALIKE_CHARS for c in output))

    def test_no_uppercase(self):
        output = self._run_cli(["--no-uppercase", "--length", "100"])
        self.assertFalse(any(c in string.ascii_uppercase for c in output))

    def test_no_lowercase(self):
        output = self._run_cli(["--no-lowercase", "--length", "100"])
        self.assertFalse(any(c in string.ascii_lowercase for c in output))

    def test_no_digits(self):
        output = self._run_cli(["--no-digits", "--length", "100"])
        self.assertFalse(any(c in string.digits for c in output))

    def test_words_mode_default(self):
        output = self._run_cli(["--words"])
        words = output.split("-")
        self.assertEqual(len(words), 4)

    def test_words_mode_num_words(self):
        output = self._run_cli(["--words", "--num-words", "6"])
        words = output.split("-")
        self.assertEqual(len(words), 6)

    def test_words_mode_separator(self):
        output = self._run_cli(["--words", "--separator", "_"])
        self.assertIn("_", output)

    def test_words_mode_capitalize(self):
        output = self._run_cli(["--words", "--capitalize"])
        for word in output.split("-"):
            self.assertTrue(word[0].isupper())

    def test_words_mode_add_digit(self):
        output = self._run_cli(["--words", "--add-digit"])
        self.assertTrue(output[-1].isdigit())

    def test_words_mode_add_symbol(self):
        output = self._run_cli(["--words", "--add-symbol"])
        self.assertIn(output[-1], DEFAULT_SYMBOLS)

    def test_words_mode_exclude_lookalikes_digit(self):
        # Run enough times to verify 0 and 1 never appear as the appended digit
        seen: set[str] = set()
        for _ in range(100):
            out = self._run_cli(["--words", "--add-digit", "--exclude-lookalikes"])
            seen.add(out[-1])
        self.assertNotIn("0", seen)
        self.assertNotIn("1", seen)

    def test_all_disabled_exits_nonzero(self):
        with self.assertRaises(SystemExit) as ctx:
            main(["--no-uppercase", "--no-lowercase", "--no-digits", "--no-symbols"])
        self.assertNotEqual(ctx.exception.code, 0)

    def test_length_zero_exits_nonzero(self):
        with self.assertRaises(SystemExit) as ctx:
            main(["--length", "0"])
        self.assertNotEqual(ctx.exception.code, 0)


class TestWordList(unittest.TestCase):
    def test_word_list_not_empty(self):
        self.assertGreater(len(WORD_LIST), 0)

    def test_all_words_lowercase(self):
        for word in WORD_LIST:
            self.assertEqual(word, word.lower(), f"Word {word!r} is not lowercase")

    def test_all_words_alphabetic(self):
        for word in WORD_LIST:
            self.assertTrue(word.isalpha(), f"Word {word!r} contains non-alpha chars")

    def test_no_duplicate_words(self):
        self.assertEqual(len(WORD_LIST), len(set(WORD_LIST)))


if __name__ == "__main__":
    unittest.main()
