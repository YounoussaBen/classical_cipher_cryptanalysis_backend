import math
import string
from collections import Counter
from typing import ClassVar

from app.models.schemas import FrequencyData, StatisticsProfile


class StatisticalAnalyzer:
    """
    Comprehensive statistical analysis for cryptanalysis.

    Computes various statistics that help identify cipher types:
    - Character frequencies
    - Bigram/trigram frequencies
    - Index of Coincidence (IOC)
    - Entropy
    - Chi-squared against English
    - Pattern detection (Kasiski examination)
    """

    ALPHABET: ClassVar[str] = string.ascii_uppercase

    # English letter frequencies for chi-squared testing
    ENGLISH_FREQ: ClassVar[dict[str, float]] = {
        "E": 12.70, "T": 9.06, "A": 8.17, "O": 7.51, "I": 6.97,
        "N": 6.75, "S": 6.33, "H": 6.09, "R": 5.99, "D": 4.25,
        "L": 4.03, "C": 2.78, "U": 2.76, "M": 2.41, "W": 2.36,
        "F": 2.23, "G": 2.02, "Y": 1.97, "P": 1.93, "B": 1.29,
        "V": 0.98, "K": 0.77, "J": 0.15, "X": 0.15, "Q": 0.10,
        "Z": 0.07,
    }

    def analyze(self, text: str) -> StatisticsProfile:
        """
        Perform complete statistical analysis on text.

        Args:
            text: Normalized ciphertext (uppercase letters only)

        Returns:
            StatisticsProfile with all computed statistics
        """
        # Filter to alphabet only
        filtered = "".join(c for c in text.upper() if c in self.ALPHABET)

        if not filtered:
            return self._empty_profile()

        # Compute all statistics
        char_freqs = self._character_frequencies(filtered)
        bigrams = self._ngram_frequencies(filtered, 2)
        trigrams = self._ngram_frequencies(filtered, 3)
        ioc = self._index_of_coincidence(filtered)
        entropy = self._entropy(filtered)
        chi_sq = self._chi_squared(filtered)
        repeated = self._find_repeated_sequences(filtered)
        kasiski = self._kasiski_distances(repeated)

        return StatisticsProfile(
            length=len(filtered),
            unique_chars=len(set(filtered)),
            character_frequencies=char_freqs,
            bigram_frequencies=bigrams,
            trigram_frequencies=trigrams,
            index_of_coincidence=ioc,
            entropy=entropy,
            chi_squared=chi_sq,
            repeated_sequences=repeated,
            kasiski_distances=kasiski,
        )

    def _empty_profile(self) -> StatisticsProfile:
        """Return an empty statistics profile."""
        return StatisticsProfile(
            length=0,
            unique_chars=0,
            character_frequencies=[],
            bigram_frequencies=[],
            trigram_frequencies=[],
            index_of_coincidence=0.0,
            entropy=0.0,
            chi_squared=None,
            repeated_sequences=[],
            kasiski_distances=[],
        )

    def _character_frequencies(self, text: str) -> list[FrequencyData]:
        """Calculate character frequencies."""
        counter = Counter(text)
        total = len(text)

        result = []
        for char in self.ALPHABET:
            count = counter.get(char, 0)
            freq = count / total if total > 0 else 0.0
            result.append(FrequencyData(
                character=char,
                count=count,
                frequency=freq,
            ))

        # Sort by frequency descending
        result.sort(key=lambda x: x.frequency, reverse=True)
        return result

    def _ngram_frequencies(self, text: str, n: int) -> list[dict]:
        """Calculate n-gram frequencies."""
        if len(text) < n:
            return []

        counter = Counter(text[i:i + n] for i in range(len(text) - n + 1))
        total = sum(counter.values())

        result = [
            {
                "ngram": ngram,
                "count": count,
                "frequency": count / total if total > 0 else 0.0,
            }
            for ngram, count in counter.most_common(50)  # Top 50
        ]

        return result

    def _index_of_coincidence(self, text: str) -> float:
        """
        Calculate Index of Coincidence.

        IOC measures how likely two randomly chosen letters are the same.
        - English text: ~0.0667
        - Random text: ~0.0385 (1/26)
        """
        n = len(text)
        if n <= 1:
            return 0.0

        counter = Counter(text)
        numerator = sum(f * (f - 1) for f in counter.values())
        denominator = n * (n - 1)

        return numerator / denominator if denominator > 0 else 0.0

    def _entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy.

        Measures the uncertainty/randomness of the text.
        - Lower entropy suggests more structure (like natural language)
        - Higher entropy suggests more randomness
        """
        n = len(text)
        if n == 0:
            return 0.0

        counter = Counter(text)
        entropy = 0.0

        for count in counter.values():
            p = count / n
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy

    def _chi_squared(self, text: str) -> float:
        """
        Calculate chi-squared statistic against English frequencies.

        Lower values indicate closer match to English.
        """
        n = len(text)
        if n == 0:
            return 0.0

        counter = Counter(text)
        chi_squared = 0.0

        for letter in self.ALPHABET:
            observed = counter.get(letter, 0)
            expected = (self.ENGLISH_FREQ.get(letter, 0) / 100) * n

            if expected > 0:
                chi_squared += ((observed - expected) ** 2) / expected

        return chi_squared

    def _find_repeated_sequences(
        self,
        text: str,
        min_length: int = 3,
        max_length: int = 10,
    ) -> list[dict]:
        """
        Find repeated sequences in text (for Kasiski examination).

        Used to determine key length in polyalphabetic ciphers.
        """
        repeated = []

        for length in range(min_length, min(max_length + 1, len(text) // 2)):
            seen: dict[str, list[int]] = {}

            for i in range(len(text) - length + 1):
                seq = text[i:i + length]
                if seq not in seen:
                    seen[seq] = []
                seen[seq].append(i)

            for seq, positions in seen.items():
                if len(positions) > 1:
                    distances = [
                        positions[i + 1] - positions[i]
                        for i in range(len(positions) - 1)
                    ]
                    repeated.append({
                        "sequence": seq,
                        "positions": positions,
                        "distances": distances,
                        "count": len(positions),
                    })

        # Sort by count and length
        repeated.sort(key=lambda x: (-x["count"], -len(x["sequence"])))
        return repeated[:20]  # Top 20

    def _kasiski_distances(self, repeated_sequences: list[dict]) -> list[int]:
        """
        Extract distances from repeated sequences for Kasiski examination.

        The GCD of these distances often reveals the key length.
        """
        all_distances = []

        for seq_info in repeated_sequences:
            all_distances.extend(seq_info.get("distances", []))

        return sorted(set(all_distances))

    def letter_frequencies(self, text: str) -> dict[str, float]:
        """
        Get letter frequencies as a dictionary.

        Returns frequencies as percentages (0-100).
        """
        filtered = "".join(c for c in text.upper() if c in self.ALPHABET)
        n = len(filtered)

        if n == 0:
            return {letter: 0.0 for letter in self.ALPHABET}

        counter = Counter(filtered)
        return {
            letter: (counter.get(letter, 0) / n) * 100
            for letter in self.ALPHABET
        }

    def english_score(self, text: str) -> float:
        """
        Score text based on how well it matches English frequencies.

        Lower score = better match to English.
        This is useful for ranking decryption candidates.
        """
        return self._chi_squared(text)
