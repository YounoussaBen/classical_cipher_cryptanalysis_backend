import random
import string
from typing import Any, ClassVar

from app.models.schemas import CipherFamily, CipherType, PlaintextCandidate, StatisticsProfile
from app.services.analysis.statistics import StatisticalAnalyzer
from app.services.engines.base import CipherEngine, DecryptionResult
from app.services.engines.registry import EngineRegistry


@EngineRegistry.register
class CaesarEngine(CipherEngine):
    """
    Caesar cipher engine.

    The Caesar cipher is a simple substitution cipher that shifts each letter
    by a fixed amount. With only 26 possible keys, it can be trivially broken
    by trying all shifts and scoring each result.
    """

    name = "Caesar Cipher"
    cipher_type = CipherType.CAESAR
    cipher_family = CipherFamily.MONOALPHABETIC
    description = (
        "A substitution cipher where each letter is shifted by a fixed amount. "
        "Named after Julius Caesar who used it for military communications."
    )

    ALPHABET: ClassVar[str] = string.ascii_uppercase

    def detect(self, statistics: StatisticsProfile) -> float:
        """
        Determine if this ciphertext could be Caesar-encrypted.

        Caesar cipher preserves letter frequencies, so high IOC suggests
        monoalphabetic substitution. Caesar is always a candidate when
        IOC is high.
        """
        ioc = statistics.index_of_coincidence

        # High IOC (close to natural language ~0.065-0.078) suggests monoalphabetic
        if ioc > 0.06:
            # Could be Caesar or general substitution
            # Caesar is simplest, so give it moderate confidence
            return 0.7
        elif ioc > 0.05:
            return 0.4
        else:
            # Low IOC suggests polyalphabetic - unlikely Caesar
            return 0.1

    def attempt_decrypt(
        self,
        ciphertext: str,
        statistics: StatisticsProfile,
        options: dict[str, Any],
    ) -> list[PlaintextCandidate]:
        """
        Try all 26 shifts and return scored candidates.
        Scores against all supported languages to find the best match.
        """
        analyzer = StatisticalAnalyzer()
        candidates = []

        for shift in range(26):
            plaintext = self._decrypt(ciphertext, shift)
            # Score against all languages and find best match
            best_lang, score = analyzer.best_language_score(plaintext)

            # Convert score to confidence (lower score = higher confidence)
            # Typical chi-squared for matching language is around 20-50
            confidence = max(0.0, min(1.0, 1.0 - (score / 500)))

            candidates.append(PlaintextCandidate(
                plaintext=plaintext,
                score=score,
                confidence=confidence,
                cipher_type=self.cipher_type,
                key=str(shift),
                method=f"brute_force_{best_lang}",
            ))

        # Sort by score (ascending - lower is better)
        candidates.sort(key=lambda x: x.score)

        # Return top 5 candidates
        return candidates[:5]

    def decrypt_with_key(
        self,
        ciphertext: str,
        key: str | dict[str, Any],
    ) -> DecryptionResult:
        """Decrypt with a known shift value."""
        shift = self._parse_key(key)
        plaintext = self._decrypt(ciphertext, shift)

        return DecryptionResult(
            plaintext=plaintext,
            key=str(shift),
            confidence=1.0,  # Known key = certain
            explanation=self.explain(ciphertext, plaintext, shift),
        )

    def find_key_and_decrypt(
        self,
        ciphertext: str,
        options: dict[str, Any],
    ) -> DecryptionResult:
        """Find the best shift and decrypt."""
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
            explanation=self.explain(ciphertext, best.plaintext, int(best.key)),
        )

    def encrypt(
        self,
        plaintext: str,
        key: str | dict[str, Any],
    ) -> str:
        """Encrypt plaintext with the given shift."""
        shift = self._parse_key(key)
        return self._encrypt(plaintext, shift)

    def generate_random_key(self) -> str:
        """Generate a random shift (1-25, excluding 0 and 26)."""
        return str(random.randint(1, 25))

    def validate_key(self, key: str | dict[str, Any]) -> bool:
        """Validate that key is a valid shift (0-25)."""
        try:
            shift = self._parse_key(key)
            return 0 <= shift <= 25
        except (ValueError, TypeError):
            return False

    def explain(
        self,
        ciphertext: str,
        plaintext: str,
        key: str | dict[str, Any],
    ) -> str:
        """Generate human-readable explanation."""
        shift = self._parse_key(key) if not isinstance(key, int) else key

        return (
            f"Caesar cipher with shift of {shift}. "
            f"Each letter was shifted back {shift} positions in the alphabet. "
            f"For example, the first ciphertext letter '{ciphertext[0] if ciphertext else 'N/A'}' "
            f"becomes '{plaintext[0] if plaintext else 'N/A'}'."
        )

    def _parse_key(self, key: str | dict[str, Any]) -> int:
        """Parse key to integer shift value."""
        if isinstance(key, dict):
            key = key.get("shift", key.get("key", 0))
        return int(key) % 26

    def _encrypt(self, plaintext: str, shift: int) -> str:
        """Encrypt using Caesar cipher."""
        result = []
        plaintext = plaintext.upper()

        for char in plaintext:
            if char in self.ALPHABET:
                idx = self.ALPHABET.index(char)
                result.append(self.ALPHABET[(idx + shift) % 26])
            else:
                result.append(char)

        return "".join(result)

    def _decrypt(self, ciphertext: str, shift: int) -> str:
        """Decrypt by shifting in reverse."""
        return self._encrypt(ciphertext, -shift)
