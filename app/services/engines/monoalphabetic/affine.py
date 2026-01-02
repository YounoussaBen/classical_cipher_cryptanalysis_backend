import math
import random
import string
from typing import Any, ClassVar

from app.models.schemas import CipherFamily, CipherType, PlaintextCandidate, StatisticsProfile
from app.services.analysis.statistics import StatisticalAnalyzer
from app.services.engines.base import CipherEngine, DecryptionResult
from app.services.engines.registry import EngineRegistry


@EngineRegistry.register
class AffineEngine(CipherEngine):
    """
    Affine cipher engine.

    The Affine cipher encrypts using the formula: E(x) = (ax + b) mod 26
    where 'a' must be coprime with 26 (valid values: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25).

    Decryption uses: D(y) = a^(-1) * (y - b) mod 26
    where a^(-1) is the modular multiplicative inverse of a mod 26.
    """

    name = "Affine Cipher"
    cipher_type = CipherType.AFFINE
    cipher_family = CipherFamily.MONOALPHABETIC
    description = (
        "A monoalphabetic substitution cipher using the formula E(x) = (ax + b) mod 26. "
        "Combines multiplicative and additive shifts. "
        "The 'a' value must be coprime with 26."
    )

    ALPHABET: ClassVar[str] = string.ascii_uppercase
    # Valid 'a' values (coprime with 26)
    VALID_A: ClassVar[list[int]] = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]

    def detect(self, statistics: StatisticsProfile) -> float:
        """
        Determine if this ciphertext could be Affine-encrypted.

        Affine is monoalphabetic, so high IOC is required.
        """
        ioc = statistics.index_of_coincidence

        if ioc > 0.06:
            return 0.5  # Good candidate
        elif ioc > 0.05:
            return 0.3
        else:
            return 0.1

    def attempt_decrypt(
        self,
        ciphertext: str,
        statistics: StatisticsProfile,
        options: dict[str, Any],
    ) -> list[PlaintextCandidate]:
        """
        Brute-force all valid (a, b) combinations.

        There are 12 valid 'a' values and 26 'b' values = 312 combinations.
        """
        analyzer = StatisticalAnalyzer()
        candidates = []

        for a in self.VALID_A:
            a_inv = self._mod_inverse(a, 26)
            if a_inv is None:
                continue

            for b in range(26):
                plaintext = self._decrypt(ciphertext, a, b, a_inv)
                score = analyzer.english_score(plaintext)
                confidence = max(0.0, min(1.0, 1.0 - (score / 500)))

                candidates.append(PlaintextCandidate(
                    plaintext=plaintext,
                    score=score,
                    confidence=confidence,
                    cipher_type=self.cipher_type,
                    key={"a": a, "b": b},
                    method="brute_force",
                ))

        # Sort by score and return top 5
        candidates.sort(key=lambda x: x.score)
        return candidates[:5]

    def decrypt_with_key(
        self,
        ciphertext: str,
        key: str | dict[str, Any],
    ) -> DecryptionResult:
        """Decrypt with known (a, b) values."""
        a, b = self._parse_key(key)
        a_inv = self._mod_inverse(a, 26)

        if a_inv is None:
            raise ValueError(f"Invalid 'a' value: {a}. Must be coprime with 26.")

        plaintext = self._decrypt(ciphertext, a, b, a_inv)

        return DecryptionResult(
            plaintext=plaintext,
            key={"a": a, "b": b},
            confidence=1.0,
            explanation=self.explain(ciphertext, plaintext, {"a": a, "b": b}),
        )

    def find_key_and_decrypt(
        self,
        ciphertext: str,
        options: dict[str, Any],
    ) -> DecryptionResult:
        """Find the best (a, b) and decrypt."""
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
        """Encrypt using E(x) = (ax + b) mod 26."""
        a, b = self._parse_key(key)

        if a not in self.VALID_A:
            raise ValueError(f"Invalid 'a' value: {a}. Must be coprime with 26.")

        return self._encrypt(plaintext, a, b)

    def generate_random_key(self) -> dict[str, int]:
        """Generate random valid (a, b) values."""
        a = random.choice(self.VALID_A)
        b = random.randint(0, 25)
        return {"a": a, "b": b}

    def validate_key(self, key: str | dict[str, Any]) -> bool:
        """Validate that key contains valid (a, b) values."""
        try:
            a, b = self._parse_key(key)
            return a in self.VALID_A and 0 <= b <= 25
        except (ValueError, TypeError, KeyError):
            return False

    def explain(
        self,
        ciphertext: str,
        plaintext: str,
        key: str | dict[str, Any],
    ) -> str:
        """Generate human-readable explanation."""
        a, b = self._parse_key(key)

        return (
            f"Affine cipher with a={a} and b={b}. "
            f"Encryption formula: E(x) = ({a}x + {b}) mod 26. "
            f"Decryption uses the modular inverse of {a}, which is {self._mod_inverse(a, 26)}. "
            f"Each letter position is multiplied by {a}, then {b} is added."
        )

    def _parse_key(self, key: str | dict[str, Any]) -> tuple[int, int]:
        """Parse key to (a, b) tuple."""
        if isinstance(key, dict):
            a = int(key.get("a", 1))
            b = int(key.get("b", 0))
        elif isinstance(key, str):
            # Try parsing "a,b" format
            parts = key.replace(" ", "").split(",")
            if len(parts) == 2:
                a, b = int(parts[0]), int(parts[1])
            else:
                raise ValueError(f"Invalid key format: {key}")
        else:
            raise ValueError(f"Invalid key type: {type(key)}")

        return a, b

    def _mod_inverse(self, a: int, m: int) -> int | None:
        """Calculate modular multiplicative inverse using extended Euclidean algorithm."""
        if math.gcd(a, m) != 1:
            return None

        # Extended Euclidean algorithm
        def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y

        _, x, _ = extended_gcd(a % m, m)
        return (x % m + m) % m

    def _encrypt(self, plaintext: str, a: int, b: int) -> str:
        """Encrypt using E(x) = (ax + b) mod 26."""
        result = []
        plaintext = plaintext.upper()

        for char in plaintext:
            if char in self.ALPHABET:
                x = self.ALPHABET.index(char)
                encrypted_idx = (a * x + b) % 26
                result.append(self.ALPHABET[encrypted_idx])
            else:
                result.append(char)

        return "".join(result)

    def _decrypt(self, ciphertext: str, a: int, b: int, a_inv: int) -> str:
        """Decrypt using D(y) = a^(-1) * (y - b) mod 26."""
        result = []
        ciphertext = ciphertext.upper()

        for char in ciphertext:
            if char in self.ALPHABET:
                y = self.ALPHABET.index(char)
                decrypted_idx = (a_inv * (y - b)) % 26
                result.append(self.ALPHABET[decrypted_idx])
            else:
                result.append(char)

        return "".join(result)
