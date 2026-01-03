import math
import random
import string
from typing import Any, ClassVar

from app.models.schemas import CipherFamily, CipherType, PlaintextCandidate, StatisticsProfile
from app.services.analysis.statistics import StatisticalAnalyzer
from app.services.engines.base import CipherEngine, DecryptionResult
from app.services.engines.registry import EngineRegistry


@EngineRegistry.register
class VigenereEngine(CipherEngine):
    """
    Vigenère cipher engine.

    A polyalphabetic substitution cipher that uses a keyword to determine
    the shift for each letter. Each letter of the keyword represents a
    different Caesar shift applied in sequence.

    Breaking involves:
    1. Finding key length using Kasiski examination or IOC analysis
    2. Breaking each Caesar cipher independently
    """

    name = "Vigenère Cipher"
    cipher_type = CipherType.VIGENERE
    cipher_family = CipherFamily.POLYALPHABETIC
    description = (
        "A polyalphabetic cipher where each letter is shifted by a different amount "
        "based on a repeating keyword. More secure than Caesar but vulnerable to "
        "Kasiski examination and frequency analysis per key position."
    )

    ALPHABET: ClassVar[str] = string.ascii_uppercase
    COMMON_WORDS: ClassVar[list[str]] = [
        "KEY", "SECRET", "PASSWORD", "CIPHER", "CODE", "CRYPTO",
        "HIDDEN", "LOCK", "SAFE", "SECURE", "VIGENERE",
    ]

    def detect(self, statistics: StatisticsProfile) -> float:
        """
        Determine if this ciphertext could be Vigenère-encrypted.

        Low IOC suggests polyalphabetic. Repeated sequences suggest Vigenère
        rather than truly random polyalphabetic.
        """
        ioc = statistics.index_of_coincidence

        # Low IOC suggests polyalphabetic
        if ioc < 0.05:
            base_confidence = 0.8
        elif ioc < 0.055:
            base_confidence = 0.6
        elif ioc < 0.06:
            base_confidence = 0.4
        else:
            # High IOC suggests monoalphabetic
            base_confidence = 0.1

        # Boost confidence if we found repeated sequences
        if statistics.kasiski_distances:
            base_confidence = min(0.95, base_confidence + 0.15)

        return base_confidence

    def attempt_decrypt(
        self,
        ciphertext: str,
        statistics: StatisticsProfile,
        options: dict[str, Any],
    ) -> list[PlaintextCandidate]:
        """
        Attempt to break Vigenère cipher.

        1. Estimate key length using Kasiski/IOC
        2. Break each Caesar cipher independently
        3. Score candidates against multiple languages
        """
        analyzer = StatisticalAnalyzer()
        candidates = []

        # Filter to letters only
        filtered = "".join(c for c in ciphertext.upper() if c in self.ALPHABET)

        if len(filtered) < 10:
            return []

        # Get target language from options, or use auto-detection
        target_language = options.get("language")

        # Try different key lengths
        max_key_length = options.get("max_key_length", 15)
        likely_lengths = self._estimate_key_lengths(filtered, statistics, max_key_length)

        for key_length in likely_lengths[:5]:  # Try top 5 candidates
            key = self._find_key(filtered, key_length, target_language)
            plaintext = self._decrypt(ciphertext, key)

            # Score against best matching language
            best_lang, score = analyzer.best_language_score(plaintext)
            confidence = max(0.0, min(1.0, 1.0 - (score / 500)))

            candidates.append(PlaintextCandidate(
                plaintext=plaintext,
                score=score,
                confidence=confidence,
                cipher_type=self.cipher_type,
                key=key,
                method=f"kasiski_frequency_{best_lang}",
            ))

        # Also try common words as keys
        for word in self.COMMON_WORDS:
            plaintext = self._decrypt(ciphertext, word)
            best_lang, score = analyzer.best_language_score(plaintext)
            confidence = max(0.0, min(1.0, 1.0 - (score / 500)))

            candidates.append(PlaintextCandidate(
                plaintext=plaintext,
                score=score,
                confidence=confidence,
                cipher_type=self.cipher_type,
                key=word,
                method=f"dictionary_{best_lang}",
            ))

        # Sort by score and return best
        candidates.sort(key=lambda x: x.score)
        return candidates[:5]

    def decrypt_with_key(
        self,
        ciphertext: str,
        key: str | dict[str, Any],
    ) -> DecryptionResult:
        """Decrypt with a known keyword."""
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

        if not self.validate_key(key_str):
            raise ValueError("Invalid key: must be alphabetic")

        return self._encrypt(plaintext, key_str)

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

        shifts = [self.ALPHABET.index(c) for c in key_str.upper()]
        shift_desc = ", ".join(f"{key_str[i]}={shifts[i]}" for i in range(len(key_str)))

        return (
            f"Vigenère cipher with keyword '{key_str}' (length {len(key_str)}). "
            f"Letter shifts: {shift_desc}. "
            f"Each letter of the ciphertext is shifted back by the corresponding "
            f"key letter's position in the alphabet."
        )

    def _parse_key(self, key: str | dict[str, Any]) -> str:
        """Parse key to string."""
        if isinstance(key, dict):
            key = key.get("key", key.get("keyword", ""))
        return str(key).upper()

    def _estimate_key_lengths(
        self,
        ciphertext: str,
        statistics: StatisticsProfile,
        max_length: int,
    ) -> list[int]:
        """
        Estimate likely key lengths using IOC analysis.

        For each potential key length, compute the average IOC of
        each "column" (every nth letter). Higher average IOC suggests
        correct key length.
        """
        n = len(ciphertext)
        if n < 2:
            return [1]

        candidates = []

        for length in range(1, min(max_length + 1, n // 2)):
            # Split into columns
            columns = [ciphertext[i::length] for i in range(length)]

            # Calculate average IOC across columns
            total_ioc = 0.0
            for col in columns:
                if len(col) > 1:
                    total_ioc += self._calculate_ioc(col)

            avg_ioc = total_ioc / length if length > 0 else 0
            candidates.append((length, avg_ioc))

        # Sort by IOC (higher is better)
        candidates.sort(key=lambda x: x[1], reverse=True)

        # Also factor in Kasiski distances (GCD analysis)
        kasiski_lengths = self._analyze_kasiski(statistics.kasiski_distances, max_length)

        # Combine both methods
        result_lengths = []
        for length, _ in candidates:
            if length in kasiski_lengths:
                result_lengths.insert(0, length)  # Priority
            else:
                result_lengths.append(length)

        return result_lengths[:max_length]

    def _analyze_kasiski(self, distances: list[int], max_length: int) -> set[int]:
        """Find likely key lengths from Kasiski distances using GCD."""
        if not distances:
            return set()

        likely = set()

        # Find common factors of distances
        for d in distances:
            for factor in range(2, min(d + 1, max_length + 1)):
                if d % factor == 0:
                    likely.add(factor)

        return likely

    def _calculate_ioc(self, text: str) -> float:
        """Calculate Index of Coincidence for text."""
        from collections import Counter

        n = len(text)
        if n <= 1:
            return 0.0

        counter = Counter(text)
        numerator = sum(f * (f - 1) for f in counter.values())
        denominator = n * (n - 1)

        return numerator / denominator if denominator > 0 else 0.0

    def _find_key(
        self,
        ciphertext: str,
        key_length: int,
        target_language: str | None = None,
    ) -> str:
        """
        Find the key by breaking each Caesar cipher independently.

        For each position, try all 26 shifts and pick the one that
        produces the best distribution for the target language.

        Args:
            ciphertext: The ciphertext to analyze
            key_length: Expected key length
            target_language: Target language ('english', 'french', etc.) or None for auto
        """
        from app.services.analysis.statistics import StatisticalAnalyzer
        analyzer = StatisticalAnalyzer()

        key = []

        for i in range(key_length):
            # Extract every nth letter starting at position i
            column = ciphertext[i::key_length]

            # Find best shift for this column
            best_shift = 0
            best_score = float("inf")

            for shift in range(26):
                # Decrypt column with this shift
                decrypted = "".join(
                    self.ALPHABET[(self.ALPHABET.index(c) - shift) % 26]
                    for c in column
                )

                # Score against target language or find best language
                if target_language:
                    score = analyzer.language_score(decrypted, target_language)
                else:
                    _, score = analyzer.best_language_score(decrypted)

                if score < best_score:
                    best_score = score
                    best_shift = shift

            key.append(self.ALPHABET[best_shift])

        return "".join(key)

    def _encrypt(self, plaintext: str, key: str) -> str:
        """Encrypt using Vigenère cipher."""
        result = []
        plaintext = plaintext.upper()
        key = key.upper()
        key_idx = 0

        for char in plaintext:
            if char in self.ALPHABET:
                shift = self.ALPHABET.index(key[key_idx % len(key)])
                encrypted_idx = (self.ALPHABET.index(char) + shift) % 26
                result.append(self.ALPHABET[encrypted_idx])
                key_idx += 1
            else:
                result.append(char)

        return "".join(result)

    def _decrypt(self, ciphertext: str, key: str) -> str:
        """Decrypt using Vigenère cipher."""
        result = []
        ciphertext = ciphertext.upper()
        key = key.upper()
        key_idx = 0

        for char in ciphertext:
            if char in self.ALPHABET:
                shift = self.ALPHABET.index(key[key_idx % len(key)])
                decrypted_idx = (self.ALPHABET.index(char) - shift) % 26
                result.append(self.ALPHABET[decrypted_idx])
                key_idx += 1
            else:
                result.append(char)

        return "".join(result)
