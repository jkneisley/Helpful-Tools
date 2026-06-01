# Password Generator

A secure, customizable password and passphrase generator written in Python.
No third-party dependencies — uses only the Python standard library.

---

## Features

| Feature | Description |
|---------|-------------|
| **Custom length** | Set the exact number of characters with `--length` |
| **Symbol control** | Choose exactly which symbols are allowed with `--symbols`, or disable them entirely with `--no-symbols` |
| **Look-alike exclusion** | Remove visually similar characters (`0`, `O`, `o`, `1`, `l`, `I`) with `--exclude-lookalikes` |
| **Word-based passphrases** | Generate memorable passphrases from real English words with `--words` |
| **Toggle character sets** | Enable/disable uppercase, lowercase, and digits independently |
| **Bulk generation** | Generate multiple passwords at once with `--count` |

---

## Quick Start

```bash
# Default: 16-character password
python password_generator.py

# 24 characters
python password_generator.py --length 24

# Exclude look-alike characters
python password_generator.py --exclude-lookalikes

# Only allow these symbols
python password_generator.py --symbols '!@#'

# No symbols at all
python password_generator.py --no-symbols

# Word-based passphrase (4 words, dash-separated)
python password_generator.py --words

# 5-word passphrase, underscores, capitalized, with a trailing digit
python password_generator.py --words --num-words 5 --separator _ --capitalize --add-digit

# Generate 10 passwords at once
python password_generator.py --count 10
```

---

## Full Option Reference

```
usage: password_generator [-h] [--words] [--length N] [--no-uppercase]
                           [--no-lowercase] [--no-digits]
                           [--symbols CHARS | --no-symbols]
                           [--exclude-lookalikes] [--count N]
                           [--num-words N] [--separator SEP] [--capitalize]
                           [--add-digit] [--add-symbol]

Generate a secure password or passphrase.

Mode:
  --words               Generate a word-based passphrase instead of a
                        random-character password.

Character-password options (default mode):
  --length N, -l N      Total number of characters in the password (default: 16).
  --no-uppercase        Exclude uppercase letters.
  --no-lowercase        Exclude lowercase letters.
  --no-digits           Exclude digit characters.

Shared options:
  --symbols CHARS, -s CHARS
                        Symbols to include (default includes !@#$%^&* and more).
                        Pass an empty string to disable symbols.
  --no-symbols          Disable all symbol characters.
  --exclude-lookalikes, -e
                        Exclude visually similar characters: 0, 1, I, O, l, o.
  --count N, -n N       Number of passwords/passphrases to generate (default: 1).

Passphrase options (--words mode):
  --num-words N, -w N   Number of words in the passphrase (default: 4).
  --separator SEP       Separator placed between words (default: '-').
  --capitalize          Capitalize the first letter of each word.
  --add-digit           Append a random digit to the passphrase.
  --add-symbol          Append a random symbol to the passphrase.
```

---

## Examples

```bash
# Strong password, no look-alikes, only safe symbols
python password_generator.py -l 20 -s '!@#$%' --exclude-lookalikes

# Digits-only PIN (8 digits, no look-alikes)
python password_generator.py --no-uppercase --no-lowercase --no-symbols \
    --exclude-lookalikes --length 8

# Memorable passphrase for a master password
python password_generator.py --words --num-words 6 --separator . --capitalize

# Five passphrases with a symbol appended each
python password_generator.py --words --add-symbol --count 5
```

---

## Running Tests

```bash
python -m pytest password_generator/tests/
```
