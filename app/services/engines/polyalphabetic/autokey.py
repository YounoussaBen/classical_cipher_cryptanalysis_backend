import random
import string
from typing import Any, ClassVar

from app.models.schemas import CipherFamily, CipherType, PlaintextCandidate, StatisticsProfile
from app.services.analysis.statistics import StatisticalAnalyzer
from app.services.engines.base import CipherEngine, DecryptionResult
from app.services.engines.registry import EngineRegistry
from app.services.optimization.scoring import LanguageScorer


@EngineRegistry.register
class AutokeyEngine(CipherEngine):
    """
    Autokey cipher engine.

    The Autokey cipher is a variant of Vigenère where the key is extended
    using the plaintext itself. After the initial keyword, subsequent key
    characters come from the plaintext being encrypted.

    This makes the effective key as long as the message, eliminating
    the periodic weakness of standard Vigenère.
    """

    name = "Autokey Cipher"
    cipher_type = CipherType.AUTOKEY
    cipher_family = CipherFamily.POLYALPHABETIC
    description = (
        "A polyalphabetic cipher where the key is extended using the plaintext. "
        "After the initial primer/keyword, the plaintext letters become the key. "
        "Stronger than Vigenère due to non-repeating key."
    )

    ALPHABET: ClassVar[str] = string.ascii_uppercase
    COMMON_PRIMERS: ClassVar[list[str]] = [
        "A", "B", "C", "KEY", "SECRET", "THE", "CODE", "CIPHER",
    ]

    def detect(self, statistics: StatisticsProfile) -> float:
        """
        Determine if this could be Autokey-encrypted.

        Autokey has higher IOC than Vigenère because the "key" is
        based on English plaintext.
        """
        ioc = statistics.index_of_coincidence

        # Autokey IOC is typically between random and English
        if 0.04 < ioc < 0.06:
            return 0.4
        elif ioc < 0.04:
            return 0.1  # Too random for autokey
        else:
            return 0.2  # Too high, probably monoalphabetic

    def attempt_decrypt(
        self,
        ciphertext: str,
        statistics: StatisticsProfile,
        options: dict[str, Any],
    ) -> list[PlaintextCandidate]:
        """
        Attempt to break Autokey cipher.

        Try different primer lengths and use frequency analysis.
        """
        analyzer = StatisticalAnalyzer()
        scorer = LanguageScorer()
        candidates = []

        filtered = "".join(c for c in ciphertext.upper() if c in self.ALPHABET)

        if len(filtered) < 5:
            return []

        # Try common primers
        for primer in self.COMMON_PRIMERS:
            plaintext = self._decrypt(ciphertext, primer)
            score = analyzer.english_score(plaintext)
            confidence = max(0.0, min(1.0, 1.0 - (score / 500)))

            candidates.append(PlaintextCandidate(
                plaintext=plaintext,
                score=score,
                confidence=confidence,
                cipher_type=self.cipher_type,
                key=primer,
                method="dictionary",
            ))

        # Try single-letter primers with frequency analysis
        max_primer_length = options.get("max_primer_length", 5)

        for primer_len in range(1, max_primer_length + 1):
            best_primer = self._find_primer(filtered, primer_len)
            if best_primer:
                plaintext = self._decrypt(ciphertext, best_primer)
                score = analyzer.english_score(plaintext)
                confidence = max(0.0, min(1.0, 1.0 - (score / 500)))

                candidates.append(PlaintextCandidate(
                    plaintext=plaintext,
                    score=score,
                    confidence=confidence,
                    cipher_type=self.cipher_type,
                    key=best_primer,
                    method="frequency_analysis",
                ))

        candidates.sort(key=lambda x: x.score)
        return candidates[:5]

    def decrypt_with_key(
        self,
        ciphertext: str,
        key: str | dict[str, Any],
    ) -> DecryptionResult:
        """Decrypt with a known primer."""
        key_str = self._parse_key(key)

        if not self.validate_key(key_str):
            raise ValueError("Invalid key: must be alphabetic")

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
        """Find the primer and decrypt."""
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
        """Encrypt using the primer."""
        key_str = self._parse_key(key)

        if not self.validate_key(key_str):
            raise ValueError("Invalid key: must be alphabetic")

        return self._encrypt(plaintext, key_str)

    def generate_random_key(self) -> str:
        """Generate a random primer."""
        length = random.randint(1, 5)
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
            f"Autokey cipher with primer '{key_str}'. "
            f"The key starts with the primer, then uses plaintext letters. "
            f"Full key: {key_str + plaintext[:10].replace(' ', '')}... "
            f"This eliminates the periodic weakness of standard Vigenère."
        )

    def _parse_key(self, key: str | dict[str, Any]) -> str:
        """Parse key to string."""
        if isinstance(key, dict):
            key = key.get("key", key.get("primer", ""))
        return str(key).upper()

    def _find_primer(self, ciphertext: str, primer_length: int) -> str | None:
        """
        Find the best primer of given length using frequency analysis.

        For each possible primer, decrypt and score.
        """
        best_primer = None
        best_score = float("inf")

        # For short primers, try all combinations
        if primer_length <= 2:
            from itertools import product

            for combo in product(self.ALPHABET, repeat=primer_length):
                primer = "".join(combo)
                plaintext = self._decrypt(ciphertext, primer)

                from app.services.analysis.statistics import StatisticalAnalyzer
                analyzer = StatisticalAnalyzer()
                score = analyzer.english_score(plaintext)

                if score < best_score:
                    best_score = score
                    best_primer = primer
        else:
            # For longer primers, use frequency-based approach
            # Try most common letters as primer characters
            common_letters = "ETAOINSHRDLU"

            from itertools import product
            for combo in product(common_letters[:4], repeat=primer_length):
                primer = "".join(combo)
                plaintext = self._decrypt(ciphertext, primer)

                from app.services.analysis.statistics import StatisticalAnalyzer
                analyzer = StatisticalAnalyzer()
                score = analyzer.english_score(plaintext)

                if score < best_score:
                    best_score = score
                    best_primer = primer

        return best_primer

    def _encrypt(self, plaintext: str, primer: str) -> str:
        """Encrypt using Autokey cipher."""
        result = []
        plaintext_upper = plaintext.upper()
        primer = primer.upper()

        # Build full key: primer + plaintext
        plaintext_letters = [c for c in plaintext_upper if c in self.ALPHABET]
        full_key = primer + "".join(plaintext_letters)

        key_idx = 0
        for char in plaintext_upper:
            if char in self.ALPHABET:
                shift = self.ALPHABET.index(full_key[key_idx])
                encrypted_idx = (self.ALPHABET.index(char) + shift) % 26
                result.append(self.ALPHABET[encrypted_idx])
                key_idx += 1
            else:
                result.append(char)

        return "".join(result)

    def _decrypt(self, ciphertext: str, primer: str) -> str:
        """Decrypt using Autokey cipher."""
        result = []
        ciphertext_upper = ciphertext.upper()
        primer = primer.upper()

        # Start with primer as key
        key = list(primer)
        key_idx = 0

        for char in ciphertext_upper:
            if char in self.ALPHABET:
                if key_idx < len(key):
                    shift = self.ALPHABET.index(key[key_idx])
                else:
                    # This shouldn't happen if we build key correctly
                    shift = 0

                decrypted_idx = (self.ALPHABET.index(char) - shift) % 26
                plaintext_char = self.ALPHABET[decrypted_idx]
                result.append(plaintext_char)

                # Add decrypted character to key for next iteration
                key.append(plaintext_char)
                key_idx += 1
            else:
                result.append(char)

        return "".join(result)
