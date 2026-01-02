import random
import string
from typing import Any, ClassVar

from app.models.schemas import CipherFamily, CipherType, PlaintextCandidate, StatisticsProfile
from app.services.analysis.statistics import StatisticalAnalyzer
from app.services.engines.base import CipherEngine, DecryptionResult
from app.services.engines.registry import EngineRegistry
from app.services.optimization.hill_climbing import SubstitutionHillClimber
from app.services.optimization.scoring import LanguageScorer


@EngineRegistry.register
class SimpleSubstitutionEngine(CipherEngine):
    """
    Simple Substitution cipher engine.

    Each letter is replaced with another letter according to a fixed permutation
    of the alphabet. Unlike Caesar (shift) or Affine (linear), this is a random
    permutation with 26! possible keys.

    Breaking requires frequency analysis and hill-climbing optimization.
    """

    name = "Simple Substitution Cipher"
    cipher_type = CipherType.SIMPLE_SUBSTITUTION
    cipher_family = CipherFamily.MONOALPHABETIC
    description = (
        "Each letter is mapped to a different letter using a random permutation. "
        "With 26! (about 4 x 10^26) possible keys, brute force is impossible. "
        "Solved using frequency analysis and hill-climbing optimization."
    )

    ALPHABET: ClassVar[str] = string.ascii_uppercase

    def detect(self, statistics: StatisticsProfile) -> float:
        """
        Determine if this ciphertext could be a simple substitution.

        High IOC suggests monoalphabetic substitution.
        If chi-squared is high (doesn't match English frequencies directly),
        it's more likely a complex substitution rather than Caesar.
        """
        ioc = statistics.index_of_coincidence
        chi_sq = statistics.chi_squared or 0

        if ioc > 0.06:
            # High IOC = monoalphabetic
            if chi_sq > 100:
                # High chi-squared = not a simple shift
                return 0.8
            else:
                return 0.5
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
        Use hill-climbing to find the best substitution key.
        """
        scorer = LanguageScorer()

        # Configure hill climber
        max_iterations = options.get("max_iterations", 5000)
        restarts = options.get("restarts", 10)

        climber = SubstitutionHillClimber(
            ciphertext=ciphertext,
            fitness_fn=scorer.fitness,
            max_iterations=max_iterations,
            restarts=restarts,
        )

        result = climber.optimize()

        if result.best_key is None:
            return []

        plaintext = self._decrypt(ciphertext, result.best_key)
        score = scorer.chi_squared_score(plaintext)
        confidence = max(0.0, min(1.0, 1.0 - (score / 500)))

        return [PlaintextCandidate(
            plaintext=plaintext,
            score=score,
            confidence=confidence,
            cipher_type=self.cipher_type,
            key=result.best_key,
            method="hill_climbing",
        )]

    def decrypt_with_key(
        self,
        ciphertext: str,
        key: str | dict[str, Any],
    ) -> DecryptionResult:
        """Decrypt with a known substitution key."""
        key_str = self._parse_key(key)

        if not self.validate_key(key_str):
            raise ValueError(f"Invalid key: must be a 26-letter permutation")

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
        """Find the best key using hill-climbing."""
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
        """Encrypt using the substitution key."""
        key_str = self._parse_key(key)

        if not self.validate_key(key_str):
            raise ValueError(f"Invalid key: must be a 26-letter permutation")

        return self._encrypt(plaintext, key_str)

    def generate_random_key(self) -> str:
        """Generate a random permutation of the alphabet."""
        letters = list(self.ALPHABET)
        random.shuffle(letters)
        return "".join(letters)

    def validate_key(self, key: str | dict[str, Any]) -> bool:
        """Validate that key is a valid 26-letter permutation."""
        try:
            key_str = self._parse_key(key)
            key_upper = key_str.upper()

            if len(key_upper) != 26:
                return False

            return set(key_upper) == set(self.ALPHABET)
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

        # Show first few letter mappings
        sample_mappings = ", ".join(
            f"{self.ALPHABET[i]}→{key_str[i]}"
            for i in range(min(5, len(key_str)))
        )

        return (
            f"Simple substitution cipher with key: {key_str}. "
            f"The alphabet is mapped as: {sample_mappings}, etc. "
            f"This was solved using hill-climbing optimization with "
            f"frequency analysis scoring."
        )

    def _parse_key(self, key: str | dict[str, Any]) -> str:
        """Parse key to string."""
        if isinstance(key, dict):
            key = key.get("key", key.get("permutation", ""))
        return str(key).upper()

    def _encrypt(self, plaintext: str, key: str) -> str:
        """Encrypt using substitution key."""
        result = []
        plaintext = plaintext.upper()

        # Create mapping: ALPHABET[i] -> key[i]
        mapping = {self.ALPHABET[i]: key[i] for i in range(26)}

        for char in plaintext:
            if char in mapping:
                result.append(mapping[char])
            else:
                result.append(char)

        return "".join(result)

    def _decrypt(self, ciphertext: str, key: str) -> str:
        """Decrypt using substitution key."""
        result = []
        ciphertext = ciphertext.upper()

        # Inverse mapping: key[i] -> ALPHABET[i]
        inverse = {key[i]: self.ALPHABET[i] for i in range(26)}

        for char in ciphertext:
            if char in inverse:
                result.append(inverse[char])
            else:
                result.append(char)

        return "".join(result)
