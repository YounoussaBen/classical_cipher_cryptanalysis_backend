import string
from typing import Any, ClassVar

from app.models.schemas import CipherFamily, CipherType, PlaintextCandidate, StatisticsProfile
from app.services.engines.base import CipherEngine, DecryptionResult
from app.services.engines.registry import EngineRegistry


@EngineRegistry.register
class ROT13Engine(CipherEngine):
    """
    ROT13 cipher engine.

    ROT13 is a special case of the Caesar cipher with a fixed shift of 13.
    Since 13 is exactly half of 26, applying ROT13 twice returns the original text,
    making encryption and decryption identical operations.
    """

    name = "ROT13 Cipher"
    cipher_type = CipherType.ROT13
    cipher_family = CipherFamily.MONOALPHABETIC
    description = (
        "A special case of Caesar cipher with shift 13. "
        "Applying ROT13 twice returns the original text. "
        "Commonly used for simple obfuscation (e.g., hiding spoilers)."
    )

    ALPHABET: ClassVar[str] = string.ascii_uppercase
    SHIFT: ClassVar[int] = 13

    def detect(self, statistics: StatisticsProfile) -> float:
        """
        Determine if this ciphertext could be ROT13-encrypted.

        ROT13 is always a possibility when IOC suggests monoalphabetic,
        but it's just one specific shift value out of 26.
        """
        ioc = statistics.index_of_coincidence

        if ioc > 0.06:
            # High IOC suggests monoalphabetic - ROT13 is one possibility
            return 0.3  # Lower than Caesar since it's very specific
        elif ioc > 0.05:
            return 0.15
        else:
            return 0.05

    def attempt_decrypt(
        self,
        ciphertext: str,
        statistics: StatisticsProfile,
        options: dict[str, Any],
    ) -> list[PlaintextCandidate]:
        """
        Attempt decryption. For ROT13, there's only one possibility.
        """
        from app.services.analysis.statistics import StatisticalAnalyzer

        analyzer = StatisticalAnalyzer()
        plaintext = self._transform(ciphertext)
        score = analyzer.english_score(plaintext)

        # Convert score to confidence
        confidence = max(0.0, min(1.0, 1.0 - (score / 500)))

        return [PlaintextCandidate(
            plaintext=plaintext,
            score=score,
            confidence=confidence,
            cipher_type=self.cipher_type,
            key="13",
            method="fixed_shift",
        )]

    def decrypt_with_key(
        self,
        ciphertext: str,
        key: str | dict[str, Any],
    ) -> DecryptionResult:
        """Decrypt (same as encrypt for ROT13)."""
        plaintext = self._transform(ciphertext)

        return DecryptionResult(
            plaintext=plaintext,
            key="13",
            confidence=1.0,
            explanation=self.explain(ciphertext, plaintext, "13"),
        )

    def find_key_and_decrypt(
        self,
        ciphertext: str,
        options: dict[str, Any],
    ) -> DecryptionResult:
        """Find key and decrypt. For ROT13, the key is always 13."""
        return self.decrypt_with_key(ciphertext, "13")

    def encrypt(
        self,
        plaintext: str,
        key: str | dict[str, Any],
    ) -> str:
        """Encrypt (same as decrypt for ROT13)."""
        return self._transform(plaintext)

    def generate_random_key(self) -> str:
        """ROT13 has a fixed key of 13."""
        return "13"

    def validate_key(self, key: str | dict[str, Any]) -> bool:
        """ROT13 only accepts key value of 13."""
        try:
            if isinstance(key, dict):
                key = key.get("shift", key.get("key", ""))
            return int(key) == 13
        except (ValueError, TypeError):
            return True  # Accept any key, we'll use 13 anyway

    def explain(
        self,
        ciphertext: str,
        plaintext: str,
        key: str | dict[str, Any],
    ) -> str:
        """Generate human-readable explanation."""
        return (
            "ROT13 cipher with fixed shift of 13. "
            "Each letter is shifted 13 positions, which means "
            "A becomes N, B becomes O, etc. "
            "ROT13 is self-reciprocal: applying it twice returns the original text."
        )

    def _transform(self, text: str) -> str:
        """Apply ROT13 transformation (works for both encrypt and decrypt)."""
        result = []
        text = text.upper()

        for char in text:
            if char in self.ALPHABET:
                idx = self.ALPHABET.index(char)
                result.append(self.ALPHABET[(idx + self.SHIFT) % 26])
            else:
                result.append(char)

        return "".join(result)
