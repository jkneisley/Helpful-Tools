#!/usr/bin/env python3
"""
Password Generator
==================
A customizable password / passphrase generator.

Features
--------
* Configurable length (character-based passwords)
* Choose which symbol characters to include
* Optional exclusion of look-alike characters (0/O/o, 1/l/I)
* Word-based passphrase mode (uses real English words)
* Toggleable uppercase letters and digits

Usage examples
--------------
  # 20-character password, all defaults
  python password_generator.py --length 20

  # Exclude look-alike characters
  python password_generator.py --exclude-lookalikes

  # Only use these symbols
  python password_generator.py --symbols '!@#'

  # Passphrase of 5 words separated by underscores
  python password_generator.py --words --num-words 5 --separator _

  # No symbols, no uppercase
  python password_generator.py --no-symbols --no-uppercase
"""

import argparse
import secrets
import string
import sys

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Characters that look similar to each other and are commonly confused.
LOOKALIKE_CHARS: frozenset[str] = frozenset("0Oo1lI")

# Default symbol pool used when the caller does not specify --symbols.
DEFAULT_SYMBOLS: str = "!@#$%^&*()-_=+[]{}|;:,.<>?"

# A curated list of common English words (4–8 letters) used for passphrases.
# Selected to be easy to read, type, and remember.
WORD_LIST: list[str] = [
    "able", "acid", "aged", "also", "area", "army", "away", "baby",
    "back", "ball", "band", "bank", "base", "bath", "bear", "beat",
    "been", "bell", "best", "bird", "bite", "blue", "boat", "body",
    "bold", "bond", "bone", "book", "born", "both", "bulk", "burn",
    "busy", "cake", "calm", "came", "camp", "card", "care", "cart",
    "case", "cash", "cast", "cave", "cell", "chat", "chip", "city",
    "clap", "clay", "clip", "coal", "coat", "code", "coil", "cold",
    "come", "cook", "cool", "cope", "copy", "cord", "corn", "cost",
    "coup", "crew", "crop", "cure", "dark", "data", "date", "dawn",
    "days", "dead", "deal", "dear", "debt", "deep", "deny", "desk",
    "dial", "dice", "died", "diet", "dirt", "disk", "dive", "dock",
    "does", "done", "door", "dose", "down", "draw", "drip", "drop",
    "drum", "dual", "dump", "dusk", "dust", "duty", "each", "earn",
    "east", "edge", "else", "emit", "epic", "even", "exam", "exit",
    "face", "fact", "fail", "fair", "fall", "fame", "farm", "fast",
    "fate", "feed", "feel", "feet", "fell", "file", "fill", "film",
    "find", "fine", "fire", "firm", "fish", "fist", "flag", "flat",
    "flew", "flip", "flow", "foam", "fold", "folk", "fond", "font",
    "food", "foot", "ford", "fork", "form", "fort", "foul", "four",
    "free", "from", "fuel", "full", "fund", "fuse", "gain", "game",
    "gate", "gear", "gift", "give", "glad", "glow", "glue", "gold",
    "golf", "good", "grab", "gray", "grew", "grid", "grin", "grip",
    "grow", "gulf", "gust", "hack", "half", "hall", "hand", "hang",
    "hard", "harm", "hash", "have", "head", "heat", "heel", "help",
    "here", "hero", "high", "hill", "hint", "hire", "hold", "hole",
    "home", "hope", "horn", "host", "hour", "huge", "hull", "hunt",
    "hurt", "idea", "idle", "inch", "into", "iris", "iron", "isle",
    "item", "jail", "join", "joke", "jump", "just", "keen", "keep",
    "keys", "kick", "kind", "king", "knit", "know", "lake", "lamp",
    "land", "lane", "last", "late", "lead", "leaf", "lean", "leap",
    "left", "lend", "lens", "lift", "like", "lime", "line", "link",
    "list", "live", "load", "lock", "loft", "lone", "long", "look",
    "loop", "lord", "lose", "loss", "loud", "love", "luck", "made",
    "mail", "main", "make", "many", "mark", "mass", "mast", "math",
    "meal", "mean", "meet", "melt", "menu", "mesh", "mild", "mile",
    "milk", "mind", "mine", "mint", "miss", "mist", "mode", "moon",
    "more", "most", "move", "much", "must", "myth", "nail", "name",
    "navy", "near", "need", "nest", "news", "next", "nice", "node",
    "none", "noon", "norm", "note", "noun", "nova", "obey", "odds",
    "okay", "once", "only", "open", "oral", "oval", "over", "pace",
    "pack", "page", "paid", "pain", "pair", "pale", "palm", "park",
    "part", "pass", "past", "path", "peak", "peel", "peer", "pick",
    "pile", "pine", "pink", "pipe", "plan", "play", "plot", "plug",
    "plus", "poem", "poet", "pole", "poll", "pond", "pool", "poor",
    "port", "pose", "post", "pour", "prey", "prod", "prop", "pull",
    "pump", "pure", "push", "rack", "raid", "rail", "rain", "ramp",
    "rank", "rate", "read", "real", "reed", "rent", "rest", "rice",
    "rich", "ride", "ring", "riot", "rise", "risk", "road", "rock",
    "role", "roll", "roof", "room", "root", "rope", "rose", "ruin",
    "rule", "rush", "rust", "safe", "sage", "sail", "salt", "same",
    "sand", "save", "scan", "seal", "seed", "seek", "self", "sell",
    "send", "shed", "ship", "shoe", "shop", "shot", "show", "shut",
    "sick", "side", "sign", "silk", "sink", "site", "size", "skin",
    "skip", "slim", "slip", "slow", "snap", "snow", "soak", "soar",
    "soft", "soil", "sold", "sole", "some", "song", "soon", "sort",
    "soul", "soup", "span", "spin", "spot", "star", "stay", "stem",
    "step", "stir", "stop", "stub", "such", "suit", "sung", "sunk",
    "swap", "swim", "tail", "take", "tale", "talk", "tall", "tank",
    "tape", "task", "team", "tech", "tell", "tent", "term", "text",
    "than", "that", "then", "they", "thin", "this", "tick", "tide",
    "tile", "time", "tiny", "tire", "told", "toll", "tone", "took",
    "tool", "torn", "tour", "town", "trap", "tree", "trim", "trip",
    "true", "tube", "tune", "turn", "twin", "type", "unit", "upon",
    "used", "user", "vary", "vast", "verb", "very", "vest", "view",
    "vine", "void", "vote", "wade", "wage", "wait", "wake", "walk",
    "wall", "want", "ward", "warm", "warp", "wash", "wave", "weak",
    "weed", "week", "well", "went", "west", "what", "when", "wide",
    "wild", "will", "wind", "wine", "wing", "wink", "wire", "wise",
    "wish", "with", "woke", "wolf", "word", "work", "worn", "wrap",
    "yard", "year", "yell", "your", "zero", "zone", "zoom",
    # longer words (5–8 letters)
    "above", "abuse", "adopt", "adult", "after", "again", "agent",
    "agree", "ahead", "alarm", "album", "alert", "align", "alike",
    "alive", "allow", "alone", "along", "alter", "angel", "angle",
    "angry", "ankle", "annex", "apple", "apply", "arena", "argue",
    "arise", "armed", "armor", "array", "arrow", "aside", "asset",
    "audio", "audit", "avoid", "awake", "award", "aware", "awful",
    "azure", "badge", "basic", "batch", "beach", "begin", "being",
    "below", "bench", "berry", "black", "blade", "bland", "blank",
    "blast", "blaze", "blend", "bless", "block", "blood", "bloom",
    "blown", "board", "bonus", "boost", "bound", "boxer", "brace",
    "braid", "brand", "brave", "break", "breed", "brine", "bring",
    "brisk", "broad", "brook", "brown", "brush", "build", "built",
    "bunch", "burst", "buyer", "cable", "candy", "cargo", "carry",
    "catch", "cause", "cedar", "chain", "chair", "chalk", "chart",
    "chase", "check", "cheek", "chess", "chest", "chief", "child",
    "chord", "civic", "civil", "claim", "class", "clean", "clear",
    "clerk", "click", "cliff", "climb", "cling", "clone", "close",
    "cloud", "coach", "coast", "color", "comic", "comma", "coral",
    "count", "cover", "craft", "crash", "crazy", "cream", "creek",
    "crisp", "cross", "crowd", "crown", "cruel", "crumb", "cubic",
    "curly", "curve", "cycle", "daily", "dairy", "dance", "decay",
    "delta", "dense", "depot", "depth", "derby", "digit", "dirge",
    "disco", "dizzy", "dodge", "doing", "doubt", "dough", "draft",
    "drain", "drama", "drank", "dream", "dress", "dried", "drift",
    "drill", "drink", "drive", "drove", "dying", "eagle", "early",
    "earth", "eight", "elect", "elite", "ember", "empty", "enemy",
    "enjoy", "enter", "entry", "equal", "error", "essay", "event",
    "every", "exact", "extra", "fable", "faint", "faith", "fancy",
    "field", "fifth", "fifty", "fight", "final", "first", "fixed",
    "flame", "flare", "flash", "flask", "fleet", "flesh", "flick",
    "fling", "float", "flock", "floor", "floss", "flour", "flown",
    "fluid", "flute", "focus", "force", "forge", "forth", "found",
    "foyer", "frame", "frank", "fraud", "fresh", "front", "frost",
    "froze", "frugal", "fully", "fungi", "funny", "gauge", "ghost",
    "giant", "given", "gland", "glass", "globe", "gloom", "gloss",
    "glove", "going", "grace", "grade", "grain", "grand", "grant",
    "graph", "grasp", "gravel", "great", "green", "greet", "grief",
    "grind", "groan", "gross", "group", "grove", "guard", "guess",
    "guest", "guide", "guild", "guile", "guise", "gusto", "happy",
    "harsh", "haven", "heart", "heavy", "hinge", "hippo", "honor",
    "horse", "hotel", "hover", "human", "humid", "humor", "hurry",
    "image", "imply", "inbox", "index", "infer", "inner", "input",
    "inter", "intro", "issue", "ivory", "jazzy", "jewel", "joint",
    "joyful", "judge", "juice", "juicy", "karma", "kayak", "kebab",
    "knack", "knife", "knock", "known", "label", "large", "laser",
    "later", "laugh", "layer", "learn", "lease", "least", "legal",
    "level", "light", "limit", "linen", "liver", "local", "lodge",
    "logic", "loose", "lover", "lower", "loyal", "lucky", "lunar",
    "lyric", "magic", "major", "maker", "manor", "maple", "march",
    "match", "mayor", "media", "mercy", "merge", "merit", "metal",
    "metro", "model", "money", "month", "moral", "motor", "mount",
    "mouse", "mouth", "mural", "music", "naive", "nerve", "never",
    "night", "ninja", "noble", "noise", "north", "noted", "novel",
    "nylon", "occur", "ocean", "offer", "often", "onion", "onset",
    "opera", "orbit", "order", "other", "outer", "oxide", "ozone",
    "paint", "panel", "paper", "party", "paste", "patch", "pause",
    "peace", "pearl", "penny", "perch", "phase", "phone", "photo",
    "piano", "piece", "pilot", "pixel", "pizza", "place", "plain",
    "plane", "plant", "plate", "plaza", "plead", "pluck", "plumb",
    "plume", "plunge", "point", "polar", "poppy", "power", "press",
    "price", "pride", "prime", "print", "prior", "prize", "probe",
    "prone", "proof", "prose", "proud", "prove", "proxy", "pulse",
    "punch", "pupil", "queen", "query", "queue", "quick", "quiet",
    "quota", "quote", "radar", "radio", "raise", "rally", "range",
    "rapid", "ratio", "reach", "ready", "realm", "rebel", "refer",
    "reign", "relax", "relay", "remix", "renew", "repay", "reply",
    "rider", "ridge", "rigid", "risky", "rival", "river", "robin",
    "robot", "rocky", "rouge", "rough", "round", "route", "rover",
    "ruler", "rural", "salad", "sauce", "scale", "scene", "score",
    "scout", "screw", "seize", "sense", "serve", "seven", "shade",
    "shake", "shall", "shame", "shape", "share", "shark", "sharp",
    "shelf", "shell", "shift", "shine", "shirt", "short", "shout",
    "sight", "since", "sixth", "sixty", "skill", "skull", "slate",
    "slave", "sleep", "sleek", "sleet", "slide", "slope", "smart",
    "smell", "smile", "smite", "smoke", "solid", "solve", "sonic",
    "sorry", "south", "space", "spare", "spark", "speak", "speed",
    "spend", "spent", "spice", "spike", "spine", "split", "spoke",
    "spoon", "spray", "spree", "sprig", "squad", "stack", "staff",
    "stage", "stain", "stale", "stall", "stamp", "stand", "start",
    "state", "stave", "steel", "steep", "steer", "stick", "stiff",
    "still", "sting", "stock", "stomp", "stone", "stood", "store",
    "storm", "story", "stove", "strap", "straw", "stray", "strip",
    "stuck", "study", "stump", "style", "sugar", "suite", "sunny",
    "super", "surge", "swamp", "swear", "sweep", "sweet", "swept",
    "swift", "swirl", "swoop", "sword", "table", "talon", "taste",
    "teach", "tense", "tenth", "theme", "there", "these", "thick",
    "thing", "think", "third", "thorn", "those", "three", "threw",
    "throw", "thumb", "tiger", "tight", "timer", "tired", "title",
    "today", "token", "topic", "total", "touch", "tough", "towel",
    "tower", "track", "trade", "trail", "train", "trait", "trash",
    "treat", "trend", "trial", "tribe", "trick", "tried", "troop",
    "trout", "truce", "truly", "trump", "trunk", "trust", "truth",
    "twice", "twist", "tying", "ultra", "under", "unify", "union",
    "unique", "unite", "until", "upper", "upset", "urban", "usher",
    "usual", "utter", "vague", "valid", "value", "valve", "vapor",
    "video", "vigor", "viral", "virus", "visit", "vital", "vivid",
    "vocal", "voice", "voila", "vouch", "vault", "vinyl", "viola",
    "visor", "wagon", "waste", "watch", "water", "weave", "wedge",
    "weird", "whale", "wheat", "wheel", "where", "which", "while",
    "white", "whole", "whose", "wield", "witty", "woman", "women",
    "world", "worry", "worse", "worst", "worth", "would", "wrath",
    "write", "wrote", "yacht", "yearn", "yield", "young", "youth",
    "zebra",
]


# ---------------------------------------------------------------------------
# Core generator
# ---------------------------------------------------------------------------

class PasswordGenerator:
    """Generates passwords or passphrases according to the given options."""

    def __init__(
        self,
        *,
        length: int = 16,
        use_uppercase: bool = True,
        use_lowercase: bool = True,
        use_digits: bool = True,
        symbols: str = DEFAULT_SYMBOLS,
        exclude_lookalikes: bool = False,
    ) -> None:
        """
        Parameters
        ----------
        length:
            Total number of characters in the generated password.
        use_uppercase:
            Include uppercase ASCII letters (A-Z).
        use_lowercase:
            Include lowercase ASCII letters (a-z).
        use_digits:
            Include digit characters (0-9).
        symbols:
            String of symbol characters to allow.  Pass an empty string to
            disable symbols entirely.
        exclude_lookalikes:
            When True, remove characters that are visually similar to each
            other (``0``, ``O``, ``o``, ``1``, ``l``, ``I``).
        """
        if length < 1:
            raise ValueError("length must be at least 1")

        self.length = length
        self.use_uppercase = use_uppercase
        self.use_lowercase = use_lowercase
        self.use_digits = use_digits
        self.symbols = symbols
        self.exclude_lookalikes = exclude_lookalikes

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_alphabet(self) -> str:
        """Return the full set of characters available for sampling."""
        pool = ""
        if self.use_uppercase:
            pool += string.ascii_uppercase
        if self.use_lowercase:
            pool += string.ascii_lowercase
        if self.use_digits:
            pool += string.digits
        pool += self.symbols

        if self.exclude_lookalikes:
            pool = "".join(ch for ch in pool if ch not in LOOKALIKE_CHARS)

        if not pool:
            raise ValueError(
                "The character pool is empty. "
                "Enable at least one character category."
            )
        return pool

    def _required_chars(self) -> list[str]:
        """
        Return one guaranteed character from each enabled category so the
        password always satisfies its own stated constraints.
        """
        required: list[str] = []

        def _filtered(chars: str) -> str:
            if self.exclude_lookalikes:
                chars = "".join(c for c in chars if c not in LOOKALIKE_CHARS)
            return chars

        if self.use_uppercase:
            pool = _filtered(string.ascii_uppercase)
            if pool:
                required.append(secrets.choice(pool))
        if self.use_lowercase:
            pool = _filtered(string.ascii_lowercase)
            if pool:
                required.append(secrets.choice(pool))
        if self.use_digits:
            pool = _filtered(string.digits)
            if pool:
                required.append(secrets.choice(pool))
        if self.symbols:
            pool = _filtered(self.symbols)
            if pool:
                required.append(secrets.choice(pool))

        return required

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self) -> str:
        """Generate and return a single password string."""
        alphabet = self._build_alphabet()
        required = self._required_chars()

        if len(required) > self.length:
            # Truncate guaranteed characters to fit the requested length
            required = required[: self.length]

        # Fill remaining slots from the full alphabet
        remaining = self.length - len(required)
        password_chars = required + [secrets.choice(alphabet) for _ in range(remaining)]

        # Shuffle to avoid predictable positions for the required characters
        secrets.SystemRandom().shuffle(password_chars)
        return "".join(password_chars)


class PassphraseGenerator:
    """Generates human-readable passphrases from a built-in word list."""

    def __init__(
        self,
        *,
        num_words: int = 4,
        separator: str = "-",
        capitalize: bool = False,
        add_digit: bool = False,
        add_symbol: bool = False,
        symbols: str = DEFAULT_SYMBOLS,
        exclude_lookalikes: bool = False,
        word_list: list[str] | None = None,
    ) -> None:
        """
        Parameters
        ----------
        num_words:
            Number of words in the passphrase.
        separator:
            String placed between words (e.g., ``"-"``, ``"_"``, ``" "``).
        capitalize:
            Capitalize the first letter of each word.
        add_digit:
            Append a random digit at the end.
        add_symbol:
            Append a random symbol character at the end.
        symbols:
            Pool of symbols to draw from when *add_symbol* is True.
        exclude_lookalikes:
            Filter look-alike characters from digits and the word list.
        word_list:
            Override the built-in word list.
        """
        if num_words < 1:
            raise ValueError("num_words must be at least 1")

        self.num_words = num_words
        self.separator = separator
        self.capitalize = capitalize
        self.add_digit = add_digit
        self.add_symbol = add_symbol
        self.symbols = symbols
        self.exclude_lookalikes = exclude_lookalikes
        self._word_list = word_list if word_list is not None else WORD_LIST

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self) -> str:
        """Generate and return a single passphrase string."""
        words = [secrets.choice(self._word_list) for _ in range(self.num_words)]
        if self.capitalize:
            words = [w.capitalize() for w in words]

        passphrase = self.separator.join(words)

        if self.add_digit:
            digits = string.digits
            if self.exclude_lookalikes:
                digits = "".join(d for d in digits if d not in LOOKALIKE_CHARS)
            if digits:
                passphrase += secrets.choice(digits)

        if self.add_symbol:
            pool = self.symbols
            if not pool:
                raise ValueError("No symbols available to append.")
            passphrase += secrets.choice(pool)

        return passphrase


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="password_generator",
        description="Generate a secure password or passphrase.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # ---- Mode ---------------------------------------------------------------
    mode = parser.add_argument_group("Mode")
    mode.add_argument(
        "--words",
        action="store_true",
        default=False,
        help="Generate a word-based passphrase instead of a random-character password.",
    )

    # ---- Character-password options ----------------------------------------
    char_opts = parser.add_argument_group("Character-password options (default mode)")
    char_opts.add_argument(
        "--length", "-l",
        type=int,
        default=16,
        metavar="N",
        help="Total number of characters in the password (default: 16).",
    )
    char_opts.add_argument(
        "--no-uppercase",
        dest="use_uppercase",
        action="store_false",
        default=True,
        help="Exclude uppercase letters.",
    )
    char_opts.add_argument(
        "--no-lowercase",
        dest="use_lowercase",
        action="store_false",
        default=True,
        help="Exclude lowercase letters.",
    )
    char_opts.add_argument(
        "--no-digits",
        dest="use_digits",
        action="store_false",
        default=True,
        help="Exclude digit characters.",
    )

    # ---- Shared options (apply to both modes) --------------------------------
    shared = parser.add_argument_group("Shared options")
    sym_group = shared.add_mutually_exclusive_group()
    sym_group.add_argument(
        "--symbols", "-s",
        type=str,
        default=DEFAULT_SYMBOLS,
        metavar="CHARS",
        help=(
            "Symbols to include (default: %(default)r). "
            "Pass an empty string to disable symbols."
        ),
    )
    sym_group.add_argument(
        "--no-symbols",
        dest="symbols",
        action="store_const",
        const="",
        help="Disable all symbol characters.",
    )
    shared.add_argument(
        "--exclude-lookalikes", "-e",
        action="store_true",
        default=False,
        help=(
            "Exclude visually similar characters: "
            + ", ".join(sorted(LOOKALIKE_CHARS))
            + "."
        ),
    )
    shared.add_argument(
        "--count", "-n",
        type=int,
        default=1,
        metavar="N",
        help="Number of passwords/passphrases to generate (default: 1).",
    )

    # ---- Passphrase-specific options ----------------------------------------
    phrase_opts = parser.add_argument_group("Passphrase options (--words mode)")
    phrase_opts.add_argument(
        "--num-words", "-w",
        type=int,
        default=4,
        metavar="N",
        help="Number of words in the passphrase (default: 4).",
    )
    phrase_opts.add_argument(
        "--separator",
        type=str,
        default="-",
        metavar="SEP",
        help="Separator placed between words (default: '-').",
    )
    phrase_opts.add_argument(
        "--capitalize",
        action="store_true",
        default=False,
        help="Capitalize the first letter of each word.",
    )
    phrase_opts.add_argument(
        "--add-digit",
        action="store_true",
        default=False,
        help="Append a random digit to the passphrase.",
    )
    phrase_opts.add_argument(
        "--add-symbol",
        action="store_true",
        default=False,
        help="Append a random symbol to the passphrase.",
    )

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Validate shared arguments
    if args.count < 1:
        parser.error("--count must be at least 1")

    if args.words:
        # --- Passphrase mode ---
        if args.num_words < 1:
            parser.error("--num-words must be at least 1")
        gen = PassphraseGenerator(
            num_words=args.num_words,
            separator=args.separator,
            capitalize=args.capitalize,
            add_digit=args.add_digit,
            add_symbol=args.add_symbol,
            symbols=args.symbols,
            exclude_lookalikes=args.exclude_lookalikes,
        )
    else:
        # --- Character-password mode ---
        if args.length < 1:
            parser.error("--length must be at least 1")
        if not args.use_uppercase and not args.use_lowercase and not args.use_digits and not args.symbols:
            parser.error(
                "All character categories are disabled. "
                "Enable at least one of: uppercase, lowercase, digits, symbols."
            )
        gen = PasswordGenerator(
            length=args.length,
            use_uppercase=args.use_uppercase,
            use_lowercase=args.use_lowercase,
            use_digits=args.use_digits,
            symbols=args.symbols,
            exclude_lookalikes=args.exclude_lookalikes,
        )

    for _ in range(args.count):
        print(gen.generate())


if __name__ == "__main__":
    main()
