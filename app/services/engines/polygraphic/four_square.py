import random
import string
from typing import Any, ClassVar

from app.models.schemas import CipherFamily, CipherType, PlaintextCandidate, StatisticsProfile
from app.services.analysis.statistics import StatisticalAnalyzer
from app.services.engines.base import CipherEngine, DecryptionResult
from app.services.engines.registry import EngineRegistry


@EngineRegistry.register
class FourSquareEngine(CipherEngine):
    """
    Four-Square cipher engine.

    The Four-Square cipher uses four 5x5 key squares arranged in a 2x2 grid:

        Plaintext 1  |  Ciphertext 1
        ─────────────┼───────────────
        Ciphertext 2 |  Plaintext 2

    The plaintext squares (top-left, bottom-right) use standard alphabet.
    The ciphertext squares (top-right, bottom-left) are keyed.

    Encryption:
    1. Find first plaintext letter in top-left square
    2. Find second plaintext letter in bottom-right square
    3. Form a rectangle and read corners from keyed squares
    """

    name = "Four-Square Cipher"
    cipher_type = CipherType.FOUR_SQUARE
    cipher_family = CipherFamily.POLYGRAPHIC
    description = (
        "A digraph substitution cipher using four 5x5 key squares. "
        "Two squares contain the standard alphabet, two contain keyed alphabets. "
        "Pairs of letters are encrypted by forming rectangles between squares."
    )

    ALPHABET: ClassVar[str] = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # 25 letters, I=J
    COMMON_KEY_PAIRS: ClassVar[list[tuple[str, str]]] = [
        ("EXAMPLE", "KEYWORD"),
        ("SECRET", "CIPHER"),
        ("CRYPTO", "SECURE"),
        ("HIDDEN", "MESSAGE"),
        ("SQUARE", "PLAYFAIR"),
    ]

    def detect(self, statistics: StatisticsProfile) -> float:
        """
        Determine if this could be Four-Square encrypted.

        Similar to Playfair but with different frequency characteristics.
        """
        ioc = statistics.index_of_coincidence
        length = statistics.length

        even_bonus = 0.1 if length % 2 == 0 else 0

        if 0.045 < ioc < 0.06:
            base = 0.25
        elif ioc > 0.06:
            base = 0.1
        else:
            base = 0.15

        return min(1.0, base + even_bonus)

    def attempt_decrypt(
        self,
        ciphertext: str,
        statistics: StatisticsProfile,
        options: dict[str, Any],
    ) -> list[PlaintextCandidate]:
        """
        Try common key pairs.
        """
        analyzer = StatisticalAnalyzer()
        candidates = []

        filtered = "".join(c for c in ciphertext.upper() if c in self.ALPHABET or c == "J")

        if len(filtered) < 2:
            return []

        # Try common key pairs
        for key1, key2 in self.COMMON_KEY_PAIRS:
            try:
                plaintext = self._decrypt(ciphertext, key1, key2)
                score = analyzer.english_score(plaintext)
                confidence = max(0.0, min(1.0, 1.0 - (score / 500)))

                candidates.append(PlaintextCandidate(
                    plaintext=plaintext,
                    score=score,
                    confidence=confidence,
                    cipher_type=self.cipher_type,
                    key={"key1": key1, "key2": key2},
                    method="dictionary",
                ))
            except ValueError:
                continue

        # Try with standard squares (no keywords)
        try:
            plaintext = self._decrypt(ciphertext, "", "")
            score = analyzer.english_score(plaintext)
            confidence = max(0.0, min(1.0, 1.0 - (score / 500)))

            candidates.append(PlaintextCandidate(
                plaintext=plaintext,
                score=score,
                confidence=confidence,
                cipher_type=self.cipher_type,
                key={"key1": "(standard)", "key2": "(standard)"},
                method="standard_key",
            ))
        except ValueError:
            pass

        candidates.sort(key=lambda x: x.score)
        return candidates[:5]

    def decrypt_with_key(
        self,
        ciphertext: str,
        key: str | dict[str, Any],
    ) -> DecryptionResult:
        """Decrypt with known key squares."""
        key1, key2 = self._parse_key(key)
        plaintext = self._decrypt(ciphertext, key1, key2)

        return DecryptionResult(
            plaintext=plaintext,
            key={"key1": key1, "key2": key2},
            confidence=1.0,
            explanation=self.explain(ciphertext, plaintext, {"key1": key1, "key2": key2}),
        )

    def find_key_and_decrypt(
        self,
        ciphertext: str,
        options: dict[str, Any],
    ) -> DecryptionResult:
        """Find the keys and decrypt."""
        analyzer = StatisticalAnalyzer()
        statistics = analyzer.analyze(ciphertext)

        candidates = self.attempt_decrypt(ciphertext, statistics, options)

        if not candidates:
            raise ValueError("Could not decrypt ciphertext")

        best = candidates[0]
        return DecryptionResult(
            plaintext=best.plaintext,
            key=best.key,
            confidence=best.confidence,
            explanation=self.explain(ciphertext, best.plaintext, best.key),
        )

    def encrypt(
        self,
        plaintext: str,
        key: str | dict[str, Any],
    ) -> str:
        """Encrypt using the key squares."""
        key1, key2 = self._parse_key(key)
        return self._encrypt(plaintext, key1, key2)

    def generate_random_key(self) -> dict[str, str]:
        """Generate random keywords for both keyed squares."""
        length1 = random.randint(5, 10)
        length2 = random.randint(5, 10)
        return {
            "key1": "".join(random.choice(self.ALPHABET) for _ in range(length1)),
            "key2": "".join(random.choice(self.ALPHABET) for _ in range(length2)),
        }

    def validate_key(self, key: str | dict[str, Any]) -> bool:
        """Validate that keys are alphabetic."""
        try:
            key1, key2 = self._parse_key(key)
            return all(c in self.ALPHABET or c == "J" for c in (key1 + key2).upper())
        except (ValueError, TypeError):
            return False

    def explain(
        self,
        ciphertext: str,
        plaintext: str,
        key: str | dict[str, Any],
    ) -> str:
        """Generate human-readable explanation."""
        key1, key2 = self._parse_key(key)

        return (
            f"Four-Square cipher with keywords '{key1}' and '{key2}'. "
            f"Uses four 5x5 squares: two standard (top-left, bottom-right) "
            f"and two keyed (top-right from '{key1}', bottom-left from '{key2}'). "
            f"Digraphs are encrypted by forming rectangles between squares."
        )

    def _parse_key(self, key: str | dict[str, Any]) -> tuple[str, str]:
        """Parse key to two keyword strings."""
        if isinstance(key, dict):
            key1 = str(key.get("key1", key.get("keyword1", ""))).upper()
            key2 = str(key.get("key2", key.get("keyword2", ""))).upper()
        elif isinstance(key, str):
            # Try to split on comma
            parts = key.split(",")
            if len(parts) == 2:
                key1, key2 = parts[0].strip().upper(), parts[1].strip().upper()
            else:
                key1, key2 = key.upper(), ""
        else:
            raise ValueError("Invalid key format")

        return key1.replace("J", "I"), key2.replace("J", "I")

    def _build_key_square(self, keyword: str) -> list[list[str]]:
        """Build a 5x5 key square from a keyword."""
        keyword = keyword.upper().replace("J", "I")

        seen = set()
        key_letters = []
        for char in keyword:
            if char in self.ALPHABET and char not in seen:
                seen.add(char)
                key_letters.append(char)

        for char in self.ALPHABET:
            if char not in seen:
                key_letters.append(char)

        square = []
        for i in range(5):
            square.append(key_letters[i * 5:(i + 1) * 5])

        return square

    def _find_position(self, square: list[list[str]], char: str) -> tuple[int, int]:
        """Find row and column of character in square."""
        char = char.upper().replace("J", "I")
        for row in range(5):
            for col in range(5):
                if square[row][col] == char:
                    return (row, col)
        raise ValueError(f"Character '{char}' not found")

    def _encrypt(self, plaintext: str, key1: str, key2: str) -> str:
        """Encrypt using Four-Square cipher."""
        # Build squares
        # Top-left: standard alphabet (for plaintext 1)
        # Top-right: keyed with key1 (for ciphertext 1)
        # Bottom-left: keyed with key2 (for ciphertext 2)
        # Bottom-right: standard alphabet (for plaintext 2)

        standard = self._build_key_square("")
        keyed1 = self._build_key_square(key1)  # top-right
        keyed2 = self._build_key_square(key2)  # bottom-left

        plaintext = plaintext.upper().replace("J", "I")
        plaintext = "".join(c for c in plaintext if c in self.ALPHABET)

        if len(plaintext) % 2 != 0:
            plaintext += "X"

        result = []
        for i in range(0, len(plaintext), 2):
            # First plaintext letter in top-left (standard)
            row1, col1 = self._find_position(standard, plaintext[i])
            # Second plaintext letter in bottom-right (standard)
            row2, col2 = self._find_position(standard, plaintext[i + 1])

            # Form rectangle: read from keyed squares
            # Top-right corner: same row as first, same column as second
            c1 = keyed1[row1][col2]
            # Bottom-left corner: same row as second, same column as first
            c2 = keyed2[row2][col1]

            result.append(c1)
            result.append(c2)

        return "".join(result)

    def _decrypt(self, ciphertext: str, key1: str, key2: str) -> str:
        """Decrypt using Four-Square cipher."""
        standard = self._build_key_square("")
        keyed1 = self._build_key_square(key1)
        keyed2 = self._build_key_square(key2)

        ciphertext = ciphertext.upper().replace("J", "I")
        ciphertext = "".join(c for c in ciphertext if c in self.ALPHABET)

        if len(ciphertext) % 2 != 0:
            ciphertext += "X"

        result = []
        for i in range(0, len(ciphertext), 2):
            # First ciphertext letter in top-right (keyed1)
            row1, col1 = self._find_position(keyed1, ciphertext[i])
            # Second ciphertext letter in bottom-left (keyed2)
            row2, col2 = self._find_position(keyed2, ciphertext[i + 1])

            # Form rectangle: read from standard squares
            # Top-left: same row as first cipher, same column as second cipher's row
            p1 = standard[row1][col2]
            # Bottom-right: same row as second cipher, same column as first cipher's row
            p2 = standard[row2][col1]

            result.append(p1)
            result.append(p2)

        return "".join(result)
