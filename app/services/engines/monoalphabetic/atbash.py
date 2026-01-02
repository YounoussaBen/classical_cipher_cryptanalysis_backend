import string
from typing import Any, ClassVar

from app.models.schemas import CipherFamily, CipherType, PlaintextCandidate, StatisticsProfile
from app.services.engines.base import CipherEngine, DecryptionResult
from app.services.engines.registry import EngineRegistry


@EngineRegistry.register
class AtbashEngine(CipherEngine):
    """
    Atbash cipher engine.

    Atbash is a monoalphabetic substitution cipher where the alphabet is reversed:
    A -> Z, B -> Y, C -> X, etc.

    Originally used for the Hebrew alphabet, it's self-reciprocal like ROT13.
    """

    name = "Atbash Cipher"
    cipher_type = CipherType.ATBASH
    cipher_family = CipherFamily.MONOALPHABETIC
    description = (
        "A substitution cipher where the alphabet is reversed. "
        "A becomes Z, B becomes Y, etc. "
        "Self-reciprocal: applying twice returns the original text."
    )

    ALPHABET: ClassVar[str] = string.ascii_uppercase
    REVERSED: ClassVar[str] = string.ascii_uppercase[::-1]

    def detect(self, statistics: StatisticsProfile) -> float:
        """
        Determine if this ciphertext could be Atbash-encrypted.

        Atbash is a specific substitution, so it's always a candidate
        when IOC suggests monoalphabetic.
        """
        ioc = statistics.index_of_coincidence

        if ioc > 0.06:
            return 0.2  # Low confidence since it's very specific
        elif ioc > 0.05:
            return 0.1
        else:
            return 0.05

    def attempt_decrypt(
        self,
        ciphertext: str,
        statistics: StatisticsProfile,
        options: dict[str, Any],
    ) -> list[PlaintextCandidate]:
        """
        Attempt decryption. For Atbash, there's only one possibility.
        """
        from app.services.analysis.statistics import StatisticalAnalyzer

        analyzer = StatisticalAnalyzer()
        plaintext = self._transform(ciphertext)
        score = analyzer.english_score(plaintext)

        confidence = max(0.0, min(1.0, 1.0 - (score / 500)))

        return [PlaintextCandidate(
            plaintext=plaintext,
            score=score,
            confidence=confidence,
            cipher_type=self.cipher_type,
            key="atbash",
            method="fixed_substitution",
        )]

    def decrypt_with_key(
        self,
        ciphertext: str,
        key: str | dict[str, Any],
    ) -> DecryptionResult:
        """Decrypt (same as encrypt for Atbash)."""
        plaintext = self._transform(ciphertext)

        return DecryptionResult(
            plaintext=plaintext,
            key="atbash",
            confidence=1.0,
            explanation=self.explain(ciphertext, plaintext, "atbash"),
        )

    def find_key_and_decrypt(
        self,
        ciphertext: str,
        options: dict[str, Any],
    ) -> DecryptionResult:
        """Find key and decrypt. Atbash has no key."""
        return self.decrypt_with_key(ciphertext, "atbash")

    def encrypt(
        self,
        plaintext: str,
        key: str | dict[str, Any],
    ) -> str:
        """Encrypt (same as decrypt for Atbash)."""
        return self._transform(plaintext)

    def generate_random_key(self) -> str:
        """Atbash has no variable key."""
        return "atbash"

    def validate_key(self, key: str | dict[str, Any]) -> bool:
        """Atbash accepts any key (it's ignored)."""
        return True

    def explain(
        self,
        ciphertext: str,
        plaintext: str,
        key: str | dict[str, Any],
    ) -> str:
        """Generate human-readable explanation."""
        return (
            "Atbash cipher reverses the alphabet. "
            "A becomes Z, B becomes Y, C becomes X, and so on. "
            "This is a fixed substitution with no key required. "
            f"For example, '{ciphertext[0] if ciphertext else 'A'}' "
            f"decrypts to '{plaintext[0] if plaintext else 'Z'}'."
        )

    def _transform(self, text: str) -> str:
        """Apply Atbash transformation (self-reciprocal)."""
        result = []
        text = text.upper()

        for char in text:
            if char in self.ALPHABET:
                idx = self.ALPHABET.index(char)
                result.append(self.REVERSED[idx])
            else:
                result.append(char)

        return "".join(result)
