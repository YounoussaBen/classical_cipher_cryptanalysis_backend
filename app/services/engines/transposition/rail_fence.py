import random
import string
from typing import Any, ClassVar

from app.models.schemas import CipherFamily, CipherType, PlaintextCandidate, StatisticsProfile
from app.services.analysis.statistics import StatisticalAnalyzer
from app.services.engines.base import CipherEngine, DecryptionResult
from app.services.engines.registry import EngineRegistry


@EngineRegistry.register
class RailFenceEngine(CipherEngine):
    """
    Rail Fence cipher engine.

    The Rail Fence cipher writes the plaintext in a zigzag pattern across
    a number of "rails" (rows), then reads off each rail in order to
    produce the ciphertext.

    Example with 3 rails:
    Plaintext: WEAREDISCOVEREDRUNATONCE

    W . . . E . . . C . . . R . . . R . . . O . . .
    . E . R . D . S . O . E . E . U . A . O . C .
    . . A . . . I . . . V . . . D . . . N . . . E

    Read off rows: WECRL + ERDSOEERUAOC + AIVDN + E
    """

    name = "Rail Fence Cipher"
    cipher_type = CipherType.RAIL_FENCE
    cipher_family = CipherFamily.TRANSPOSITION
    description = (
        "A transposition cipher that writes plaintext in a zigzag pattern "
        "across multiple 'rails' (rows), then reads each rail in sequence. "
        "The number of rails is the key."
    )

    ALPHABET: ClassVar[str] = string.ascii_uppercase

    def detect(self, statistics: StatisticsProfile) -> float:
        """
        Determine if this could be Rail Fence encrypted.

        Transposition preserves letter frequencies exactly, so IOC should
        match English very closely.
        """
        ioc = statistics.index_of_coincidence

        if ioc > 0.065:
            return 0.5  # High IOC = likely transposition
        elif ioc > 0.06:
            return 0.3
        else:
            return 0.1  # Low IOC = likely substitution

    def attempt_decrypt(
        self,
        ciphertext: str,
        statistics: StatisticsProfile,
        options: dict[str, Any],
    ) -> list[PlaintextCandidate]:
        """
        Try different numbers of rails to find the correct key.
        """
        analyzer = StatisticalAnalyzer()
        candidates = []

        filtered = "".join(c for c in ciphertext.upper() if c in self.ALPHABET)
        max_rails = min(options.get("max_rails", 10), len(filtered) // 2)

        for rails in range(2, max_rails + 1):
            plaintext = self._decrypt(ciphertext, rails)
            score = analyzer.english_score(plaintext)
            confidence = max(0.0, min(1.0, 1.0 - (score / 500)))

            candidates.append(PlaintextCandidate(
                plaintext=plaintext,
                score=score,
                confidence=confidence,
                cipher_type=self.cipher_type,
                key=str(rails),
                method="brute_force",
            ))

        candidates.sort(key=lambda x: x.score)
        return candidates[:5]

    def decrypt_with_key(
        self,
        ciphertext: str,
        key: str | dict[str, Any],
    ) -> DecryptionResult:
        """Decrypt with a known number of rails."""
        rails = self._parse_key(key)

        if not self.validate_key(rails):
            raise ValueError(f"Invalid key: rails must be >= 2")

        plaintext = self._decrypt(ciphertext, rails)

        return DecryptionResult(
            plaintext=plaintext,
            key=str(rails),
            confidence=1.0,
            explanation=self.explain(ciphertext, plaintext, rails),
        )

    def find_key_and_decrypt(
        self,
        ciphertext: str,
        options: dict[str, Any],
    ) -> DecryptionResult:
        """Find the number of rails and decrypt."""
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
        """Encrypt using the specified number of rails."""
        rails = self._parse_key(key)

        if not self.validate_key(rails):
            raise ValueError(f"Invalid key: rails must be >= 2")

        return self._encrypt(plaintext, rails)

    def generate_random_key(self) -> str:
        """Generate a random number of rails (2-10)."""
        return str(random.randint(2, 10))

    def validate_key(self, key: str | dict[str, Any]) -> bool:
        """Validate that key is a valid number of rails."""
        try:
            rails = self._parse_key(key)
            return rails >= 2
        except (ValueError, TypeError):
            return False

    def explain(
        self,
        ciphertext: str,
        plaintext: str,
        key: str | dict[str, Any],
    ) -> str:
        """Generate human-readable explanation."""
        rails = self._parse_key(key) if not isinstance(key, int) else key

        return (
            f"Rail Fence cipher with {rails} rails. "
            f"The plaintext is written in a zigzag pattern across {rails} rows, "
            f"then each row is read in sequence to form the ciphertext. "
            f"Decryption reverses this process."
        )

    def _parse_key(self, key: str | dict[str, Any]) -> int:
        """Parse key to number of rails."""
        if isinstance(key, dict):
            key = key.get("rails", key.get("key", 2))
        return int(key)

    def _encrypt(self, plaintext: str, rails: int) -> str:
        """Encrypt using Rail Fence cipher."""
        plaintext = plaintext.upper()

        if rails <= 1 or rails >= len(plaintext):
            return plaintext

        # Create rail fence structure
        fence = [[] for _ in range(rails)]
        rail = 0
        direction = 1  # 1 = down, -1 = up

        for char in plaintext:
            fence[rail].append(char)

            # Change direction at top or bottom
            if rail == 0:
                direction = 1
            elif rail == rails - 1:
                direction = -1

            rail += direction

        # Read off each rail
        return "".join("".join(row) for row in fence)

    def _decrypt(self, ciphertext: str, rails: int) -> str:
        """Decrypt using Rail Fence cipher."""
        ciphertext = ciphertext.upper()
        n = len(ciphertext)

        if rails <= 1 or rails >= n:
            return ciphertext

        # Calculate how many characters go in each rail
        rail_lengths = [0] * rails
        rail = 0
        direction = 1

        for _ in range(n):
            rail_lengths[rail] += 1

            if rail == 0:
                direction = 1
            elif rail == rails - 1:
                direction = -1

            rail += direction

        # Split ciphertext into rails
        fence = []
        idx = 0
        for length in rail_lengths:
            fence.append(list(ciphertext[idx:idx + length]))
            idx += length

        # Read off in zigzag pattern
        result = []
        rail = 0
        direction = 1
        rail_indices = [0] * rails

        for _ in range(n):
            if rail_indices[rail] < len(fence[rail]):
                result.append(fence[rail][rail_indices[rail]])
                rail_indices[rail] += 1

            if rail == 0:
                direction = 1
            elif rail == rails - 1:
                direction = -1

            rail += direction

        return "".join(result)
