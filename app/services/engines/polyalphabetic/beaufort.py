import random
import string
from typing import Any, ClassVar

from app.models.schemas import CipherFamily, CipherType, PlaintextCandidate, StatisticsProfile
from app.services.analysis.statistics import StatisticalAnalyzer
from app.services.engines.base import CipherEngine, DecryptionResult
from app.services.engines.registry import EngineRegistry


@EngineRegistry.register
class BeaufortEngine(CipherEngine):
    """
    Beaufort cipher engine.

    The Beaufort cipher is a reciprocal cipher similar to Vigenère, but with
    subtraction in the opposite direction:
    - Encryption: C = (K - P) mod 26
    - Decryption: P = (K - C) mod 26

    Since both operations are identical, Beaufort is self-reciprocal.
    """

    name = "Beaufort Cipher"
    cipher_type = CipherType.BEAUFORT
    cipher_family = CipherFamily.POLYALPHABETIC
    description = (
        "A reciprocal cipher where C = (K - P) mod 26. "
        "Unlike Vigenère, Beaufort is self-reciprocal: "
        "encrypting ciphertext with the same key returns plaintext."
    )

    ALPHABET: ClassVar[str] = string.ascii_uppercase
    COMMON_WORDS: ClassVar[list[str]] = [
        "KEY", "SECRET", "PASSWORD", "CIPHER", "CODE", "CRYPTO",
        "BEAUFORT", "HIDDEN", "LOCK", "SAFE", "SECURE",
    ]

    def detect(self, statistics: StatisticsProfile) -> float:
        """
        Determine if this could be Beaufort-encrypted.

        Similar to Vigenère - look for low IOC indicating polyalphabetic.
        """
        ioc = statistics.index_of_coincidence

        if ioc < 0.05:
            return 0.4  # Lower than Vigenère since less common
        elif ioc < 0.055:
            return 0.3
        elif ioc < 0.06:
            return 0.2
        else:
            return 0.05

    def attempt_decrypt(
        self,
        ciphertext: str,
        statistics: StatisticsProfile,
        options: dict[str, Any],
    ) -> list[PlaintextCandidate]:
        """
        Attempt to break Beaufort cipher.

        Similar approach to Vigenère but using Beaufort's decryption formula.
        """
        analyzer = StatisticalAnalyzer()
        candidates = []

        filtered = "".join(c for c in ciphertext.upper() if c in self.ALPHABET)

        if len(filtered) < 10:
            return []

        # Try different key lengths
        max_key_length = options.get("max_key_length", 15)
        likely_lengths = self._estimate_key_lengths(filtered, max_key_length)

        for key_length in likely_lengths[:5]:
            key = self._find_key(filtered, key_length)
            plaintext = self._transform(ciphertext, key)

            score = analyzer.english_score(plaintext)
            confidence = max(0.0, min(1.0, 1.0 - (score / 500)))

            candidates.append(PlaintextCandidate(
                plaintext=plaintext,
                score=score,
                confidence=confidence,
                cipher_type=self.cipher_type,
                key=key,
                method="frequency_analysis",
            ))

        # Try common words as keys
        for word in self.COMMON_WORDS:
            plaintext = self._transform(ciphertext, word)
            score = analyzer.english_score(plaintext)
            confidence = max(0.0, min(1.0, 1.0 - (score / 500)))

            candidates.append(PlaintextCandidate(
                plaintext=plaintext,
                score=score,
                confidence=confidence,
                cipher_type=self.cipher_type,
                key=word,
                method="dictionary",
            ))

        candidates.sort(key=lambda x: x.score)
        return candidates[:5]

    def decrypt_with_key(
        self,
        ciphertext: str,
        key: str | dict[str, Any],
    ) -> DecryptionResult:
        """Decrypt with a known keyword (same as encrypt for Beaufort)."""
        key_str = self._parse_key(key)

        if not self.validate_key(key_str):
            raise ValueError("Invalid key: must be alphabetic")

        plaintext = self._transform(ciphertext, key_str)

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
        """Encrypt (same operation as decrypt for Beaufort)."""
        key_str = self._parse_key(key)

        if not self.validate_key(key_str):
            raise ValueError("Invalid key: must be alphabetic")

        return self._transform(plaintext, key_str)

    def generate_random_key(self) -> str:
        """Generate a random keyword."""
        length = random.randint(4, 10)
        return "".join(random.choice(self.ALPHABET) for _ in range(length))

    def validate_key(self, key: str | dict[str, Any]) -> bool:
        """Validate that key is alphabetic."""
        try:
            key_str = self._parse_key(key)
            return len(key_str) > 0 and all(c in self.ALPHABET for c in key_str.upper())
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

        return (
            f"Beaufort cipher with keyword '{key_str}'. "
            f"Formula: C = (K - P) mod 26. "
            f"Beaufort is self-reciprocal: the same operation encrypts and decrypts."
        )

    def _parse_key(self, key: str | dict[str, Any]) -> str:
        """Parse key to string."""
        if isinstance(key, dict):
            key = key.get("key", key.get("keyword", ""))
        return str(key).upper()

    def _estimate_key_lengths(self, ciphertext: str, max_length: int) -> list[int]:
        """Estimate key lengths using IOC analysis."""
        n = len(ciphertext)
        if n < 2:
            return [1]

        candidates = []

        for length in range(1, min(max_length + 1, n // 2)):
            columns = [ciphertext[i::length] for i in range(length)]

            total_ioc = 0.0
            for col in columns:
                if len(col) > 1:
                    total_ioc += self._calculate_ioc(col)

            avg_ioc = total_ioc / length if length > 0 else 0
            candidates.append((length, avg_ioc))

        candidates.sort(key=lambda x: x[1], reverse=True)
        return [length for length, _ in candidates]

    def _calculate_ioc(self, text: str) -> float:
        """Calculate Index of Coincidence."""
        from collections import Counter

        n = len(text)
        if n <= 1:
            return 0.0

        counter = Counter(text)
        numerator = sum(f * (f - 1) for f in counter.values())
        denominator = n * (n - 1)

        return numerator / denominator if denominator > 0 else 0.0

    def _find_key(self, ciphertext: str, key_length: int) -> str:
        """Find the key by analyzing each column."""
        key = []

        for i in range(key_length):
            column = ciphertext[i::key_length]

            best_shift = 0
            best_score = float("inf")

            for shift in range(26):
                # Beaufort decryption: P = (K - C) mod 26
                decrypted = "".join(
                    self.ALPHABET[(shift - self.ALPHABET.index(c)) % 26]
                    for c in column
                )

                from app.services.analysis.statistics import StatisticalAnalyzer
                analyzer = StatisticalAnalyzer()
                score = analyzer.english_score(decrypted)

                if score < best_score:
                    best_score = score
                    best_shift = shift

            key.append(self.ALPHABET[best_shift])

        return "".join(key)

    def _transform(self, text: str, key: str) -> str:
        """
        Apply Beaufort transformation (works for both encrypt and decrypt).

        Formula: result = (K - input) mod 26
        """
        result = []
        text = text.upper()
        key = key.upper()
        key_idx = 0

        for char in text:
            if char in self.ALPHABET:
                k = self.ALPHABET.index(key[key_idx % len(key)])
                c = self.ALPHABET.index(char)
                result_idx = (k - c) % 26
                result.append(self.ALPHABET[result_idx])
                key_idx += 1
            else:
                result.append(char)

        return "".join(result)
