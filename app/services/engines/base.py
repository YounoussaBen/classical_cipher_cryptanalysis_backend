from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from app.models.schemas import CipherFamily, CipherType, PlaintextCandidate, StatisticsProfile


@dataclass
class DecryptionResult:
    """Result of a decryption operation."""

    plaintext: str
    key: str | dict[str, Any]
    confidence: float
    explanation: str


class CipherEngine(ABC):
    """
    Abstract base class for all cipher engines.

    Each cipher implementation must provide:
    - detect(): Check if this cipher is applicable
    - attempt_decrypt(): Try to decrypt without known key
    - decrypt_with_key(): Decrypt with a known key
    - encrypt(): Encrypt plaintext
    - score(): Score a plaintext candidate
    - explain(): Generate human-readable explanation
    """

    # Cipher metadata
    name: str
    cipher_type: CipherType
    cipher_family: CipherFamily
    description: str

    @abstractmethod
    def detect(self, statistics: StatisticsProfile) -> float:
        """
        Determine applicability of this cipher to the ciphertext.

        Args:
            statistics: Statistical profile of the ciphertext

        Returns:
            Confidence score (0.0 to 1.0) that this cipher was used
        """
        pass

    @abstractmethod
    def attempt_decrypt(
        self,
        ciphertext: str,
        statistics: StatisticsProfile,
        options: dict[str, Any],
    ) -> list[PlaintextCandidate]:
        """
        Attempt to decrypt without a known key.

        Uses statistical analysis and optimization to find the key.

        Args:
            ciphertext: The ciphertext to decrypt
            statistics: Pre-computed statistics
            options: Additional options for the decryption

        Returns:
            List of plaintext candidates with scores
        """
        pass

    @abstractmethod
    def decrypt_with_key(
        self,
        ciphertext: str,
        key: str | dict[str, Any],
    ) -> DecryptionResult:
        """
        Decrypt with a known key.

        Args:
            ciphertext: The ciphertext to decrypt
            key: The decryption key

        Returns:
            DecryptionResult with plaintext and metadata
        """
        pass

    @abstractmethod
    def find_key_and_decrypt(
        self,
        ciphertext: str,
        options: dict[str, Any],
    ) -> DecryptionResult:
        """
        Find the best key and decrypt.

        Similar to attempt_decrypt but returns a single best result.

        Args:
            ciphertext: The ciphertext to decrypt
            options: Additional options

        Returns:
            Best decryption result
        """
        pass

    @abstractmethod
    def encrypt(
        self,
        plaintext: str,
        key: str | dict[str, Any],
    ) -> str:
        """
        Encrypt plaintext with the given key.

        Args:
            plaintext: The plaintext to encrypt
            key: The encryption key

        Returns:
            Ciphertext
        """
        pass

    @abstractmethod
    def generate_random_key(self) -> str | dict[str, Any]:
        """
        Generate a random valid key for this cipher.

        Returns:
            A randomly generated key
        """
        pass

    @abstractmethod
    def validate_key(self, key: str | dict[str, Any]) -> bool:
        """
        Validate that a key is valid for this cipher.

        Args:
            key: The key to validate

        Returns:
            True if key is valid
        """
        pass

    def score(self, plaintext: str) -> float:
        """
        Score a plaintext candidate.

        Default implementation uses chi-squared against English.
        Lower score = better match.

        Args:
            plaintext: The candidate plaintext

        Returns:
            Score (lower is better)
        """
        from app.services.analysis.statistics import StatisticalAnalyzer

        analyzer = StatisticalAnalyzer()
        return analyzer.english_score(plaintext)

    @abstractmethod
    def explain(
        self,
        ciphertext: str,
        plaintext: str,
        key: str | dict[str, Any],
    ) -> str:
        """
        Generate human-readable explanation of the decryption.

        Args:
            ciphertext: The original ciphertext
            plaintext: The decrypted plaintext
            key: The key used

        Returns:
            Explanation string
        """
        pass
