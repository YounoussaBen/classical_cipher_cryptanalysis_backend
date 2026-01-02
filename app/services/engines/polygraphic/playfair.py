import random
import string
from typing import Any, ClassVar

from app.models.schemas import CipherFamily, CipherType, PlaintextCandidate, StatisticsProfile
from app.services.analysis.statistics import StatisticalAnalyzer
from app.services.engines.base import CipherEngine, DecryptionResult
from app.services.engines.registry import EngineRegistry


@EngineRegistry.register
class PlayfairEngine(CipherEngine):
    """
    Playfair cipher engine.

    The Playfair cipher encrypts digraphs (pairs of letters) using a 5x5 key square.
    The alphabet is reduced to 25 letters (I and J are combined).

    Rules for encryption:
    1. Same row: replace each letter with the one to its right
    2. Same column: replace each letter with the one below
    3. Rectangle: swap corners horizontally

    Double letters are separated by an 'X' (e.g., "BALLOON" -> "BA LX LO ON").
    """

    name = "Playfair Cipher"
    cipher_type = CipherType.PLAYFAIR
    cipher_family = CipherFamily.POLYGRAPHIC
    description = (
        "A digraph substitution cipher using a 5x5 key square. "
        "Pairs of letters are encrypted together based on their positions "
        "in the square. I and J are treated as the same letter."
    )

    ALPHABET: ClassVar[str] = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # 25 letters, I=J
    COMMON_KEYS: ClassVar[list[str]] = [
        "PLAYFAIR", "SECRET", "KEYWORD", "CIPHER", "MONARCHY",
        "EXAMPLE", "CRYPTO", "HIDDEN", "SECURE", "SQUARE",
    ]

    def detect(self, statistics: StatisticsProfile) -> float:
        """
        Determine if this could be Playfair-encrypted.

        Playfair has distinctive properties:
        - Even-length ciphertext (digraphs)
        - Disrupted normal bigram frequencies
        - No repeated digraphs (like AA, BB)
        """
        ioc = statistics.index_of_coincidence
        length = statistics.length

        # Check for even length
        even_bonus = 0.1 if length % 2 == 0 else 0.0

        # Playfair has moderate IOC (between mono and poly)
        if 0.045 < ioc < 0.065:
            base = 0.4
        elif ioc > 0.06:
            base = 0.2  # Too high, probably not Playfair
        else:
            base = 0.1

        return min(1.0, base + even_bonus)

    def attempt_decrypt(
        self,
        ciphertext: str,
        statistics: StatisticsProfile,
        options: dict[str, Any],
    ) -> list[PlaintextCandidate]:
        """
        Try common keywords as keys.

        Full Playfair cryptanalysis is complex and typically requires
        known-plaintext attack or simulated annealing.
        """
        analyzer = StatisticalAnalyzer()
        candidates = []

        filtered = "".join(c for c in ciphertext.upper() if c in self.ALPHABET or c == "J")
        filtered = filtered.replace("J", "I")

        if len(filtered) < 2:
            return []

        # Try common keywords
        for keyword in self.COMMON_KEYS:
            try:
                plaintext = self._decrypt(ciphertext, keyword)
                score = analyzer.english_score(plaintext)
                confidence = max(0.0, min(1.0, 1.0 - (score / 500)))

                candidates.append(PlaintextCandidate(
                    plaintext=plaintext,
                    score=score,
                    confidence=confidence,
                    cipher_type=self.cipher_type,
                    key=keyword,
                    method="dictionary",
                ))
            except ValueError:
                continue

        # Try empty key (standard alphabet ordering)
        try:
            plaintext = self._decrypt(ciphertext, "")
            score = analyzer.english_score(plaintext)
            confidence = max(0.0, min(1.0, 1.0 - (score / 500)))

            candidates.append(PlaintextCandidate(
                plaintext=plaintext,
                score=score,
                confidence=confidence,
                cipher_type=self.cipher_type,
                key="(standard)",
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
        """Decrypt with a known keyword."""
        key_str = self._parse_key(key)
        plaintext = self._decrypt(ciphertext, key_str)

        return DecryptionResult(
            plaintext=plaintext,
            key=key_str,
            confidence=1.0,
            explanation=self.explain(ciphertext, plaintext, key_str),
        )

    def find_key_and_decrypt(
        self,
        ciphertext: str,
        options: dict[str, Any],
    ) -> DecryptionResult:
        """Find the key and decrypt."""
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
        """Encrypt using the keyword."""
        key_str = self._parse_key(key)
        return self._encrypt(plaintext, key_str)

    def generate_random_key(self) -> str:
        """Generate a random keyword."""
        length = random.randint(5, 10)
        return "".join(random.choice(self.ALPHABET) for _ in range(length))

    def validate_key(self, key: str | dict[str, Any]) -> bool:
        """Validate that key is alphabetic."""
        try:
            key_str = self._parse_key(key)
            return all(c in self.ALPHABET or c == "J" for c in key_str.upper())
        except (ValueError, TypeError):
            return False

    def explain(
        self,
        ciphertext: str,
        plaintext: str,
        key: str | dict[str, Any],
    ) -> str:
        """Generate human-readable explanation."""
        key_str = self._parse_key(key)
        square = self._build_key_square(key_str)

        # Show first two rows of the key square
        square_preview = " ".join(square[0]) + "\n" + " ".join(square[1])

        return (
            f"Playfair cipher with keyword '{key_str}'. "
            f"5x5 key square (first 2 rows):\n{square_preview}\n"
            f"Letters are encrypted in pairs using row/column rules."
        )

    def _parse_key(self, key: str | dict[str, Any]) -> str:
        """Parse key to string."""
        if isinstance(key, dict):
            key = key.get("key", key.get("keyword", ""))
        return str(key).upper().replace("J", "I")

    def _build_key_square(self, keyword: str) -> list[list[str]]:
        """Build the 5x5 key square from a keyword."""
        keyword = keyword.upper().replace("J", "I")

        # Remove duplicates while preserving order
        seen = set()
        key_letters = []
        for char in keyword:
            if char in self.ALPHABET and char not in seen:
                seen.add(char)
                key_letters.append(char)

        # Add remaining alphabet letters
        for char in self.ALPHABET:
            if char not in seen:
                key_letters.append(char)

        # Build 5x5 grid
        square = []
        for i in range(5):
            square.append(key_letters[i * 5:(i + 1) * 5])

        return square

    def _find_position(self, square: list[list[str]], char: str) -> tuple[int, int]:
        """Find the row and column of a character in the square."""
        char = char.upper().replace("J", "I")
        for row in range(5):
            for col in range(5):
                if square[row][col] == char:
                    return (row, col)
        raise ValueError(f"Character '{char}' not found in key square")

    def _prepare_digraphs(self, text: str) -> list[tuple[str, str]]:
        """
        Prepare text for Playfair encryption.

        - Convert to uppercase
        - Replace J with I
        - Insert X between double letters
        - Pad with X if odd length
        """
        text = text.upper().replace("J", "I")
        text = "".join(c for c in text if c in self.ALPHABET)

        # Insert X between double letters
        result = []
        i = 0
        while i < len(text):
            if i + 1 < len(text):
                if text[i] == text[i + 1]:
                    result.append((text[i], "X"))
                    i += 1
                else:
                    result.append((text[i], text[i + 1]))
                    i += 2
            else:
                result.append((text[i], "X"))
                i += 1

        return result

    def _encrypt(self, plaintext: str, keyword: str) -> str:
        """Encrypt using Playfair cipher."""
        square = self._build_key_square(keyword)
        digraphs = self._prepare_digraphs(plaintext)

        result = []
        for a, b in digraphs:
            row_a, col_a = self._find_position(square, a)
            row_b, col_b = self._find_position(square, b)

            if row_a == row_b:
                # Same row: shift right
                result.append(square[row_a][(col_a + 1) % 5])
                result.append(square[row_b][(col_b + 1) % 5])
            elif col_a == col_b:
                # Same column: shift down
                result.append(square[(row_a + 1) % 5][col_a])
                result.append(square[(row_b + 1) % 5][col_b])
            else:
                # Rectangle: swap columns
                result.append(square[row_a][col_b])
                result.append(square[row_b][col_a])

        return "".join(result)

    def _decrypt(self, ciphertext: str, keyword: str) -> str:
        """Decrypt using Playfair cipher."""
        square = self._build_key_square(keyword)

        ciphertext = ciphertext.upper().replace("J", "I")
        ciphertext = "".join(c for c in ciphertext if c in self.ALPHABET)

        if len(ciphertext) % 2 != 0:
            ciphertext += "X"

        result = []
        for i in range(0, len(ciphertext), 2):
            a, b = ciphertext[i], ciphertext[i + 1]
            row_a, col_a = self._find_position(square, a)
            row_b, col_b = self._find_position(square, b)

            if row_a == row_b:
                # Same row: shift left
                result.append(square[row_a][(col_a - 1) % 5])
                result.append(square[row_b][(col_b - 1) % 5])
            elif col_a == col_b:
                # Same column: shift up
                result.append(square[(row_a - 1) % 5][col_a])
                result.append(square[(row_b - 1) % 5][col_b])
            else:
                # Rectangle: swap columns
                result.append(square[row_a][col_b])
                result.append(square[row_b][col_a])

        return "".join(result)
