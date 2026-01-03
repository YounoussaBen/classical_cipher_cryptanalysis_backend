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
    - Chi-squared against multiple languages (English, French, German, Spanish)
    - Pattern detection (Kasiski examination)
    """

    ALPHABET: ClassVar[str] = string.ascii_uppercase

    # Multi-language letter frequencies for chi-squared testing
    LANGUAGE_FREQUENCIES: ClassVar[dict[str, dict[str, float]]] = {
        "english": {
            "E": 12.70, "T": 9.06, "A": 8.17, "O": 7.51, "I": 6.97,
            "N": 6.75, "S": 6.33, "H": 6.09, "R": 5.99, "D": 4.25,
            "L": 4.03, "C": 2.78, "U": 2.76, "M": 2.41, "W": 2.36,
            "F": 2.23, "G": 2.02, "Y": 1.97, "P": 1.93, "B": 1.29,
            "V": 0.98, "K": 0.77, "J": 0.15, "X": 0.15, "Q": 0.10,
            "Z": 0.07,
        },
        "french": {
            "E": 14.72, "A": 7.64, "S": 7.95, "I": 7.53, "T": 7.24,
            "N": 7.10, "R": 6.55, "U": 6.31, "L": 5.46, "O": 5.27,
            "D": 3.67, "C": 3.18, "M": 2.97, "P": 2.52, "V": 1.83,
            "Q": 1.36, "F": 1.07, "B": 0.90, "G": 0.87, "H": 0.74,
            "J": 0.55, "X": 0.39, "Y": 0.31, "Z": 0.14, "W": 0.05,
            "K": 0.05,
        },
        "german": {
            "E": 16.40, "N": 9.78, "I": 7.55, "S": 7.27, "R": 7.00,
            "A": 6.51, "T": 6.15, "D": 5.08, "H": 4.76, "U": 4.35,
            "L": 3.44, "C": 3.06, "G": 3.01, "M": 2.53, "O": 2.51,
            "B": 1.89, "W": 1.89, "F": 1.66, "K": 1.21, "Z": 1.13,
            "P": 0.79, "V": 0.67, "J": 0.27, "Y": 0.04, "X": 0.03,
            "Q": 0.02,
        },
        "spanish": {
            "E": 13.68, "A": 12.53, "O": 8.68, "S": 7.98, "R": 6.87,
            "N": 6.71, "I": 6.25, "D": 5.86, "L": 4.97, "C": 4.68,
            "T": 4.63, "U": 3.93, "M": 3.16, "P": 2.51, "B": 1.42,
            "G": 1.01, "V": 0.90, "Y": 0.90, "Q": 0.88, "H": 0.70,
            "F": 0.69, "Z": 0.52, "J": 0.44, "X": 0.22, "W": 0.02,
            "K": 0.01,
        },
    }

    # Expected IoC for each language
    LANGUAGE_IOC: ClassVar[dict[str, float]] = {
        "english": 0.0667,
        "french": 0.0778,
        "german": 0.0762,
        "spanish": 0.0775,
    }

    # Backwards compatible alias
    ENGLISH_FREQ: ClassVar[dict[str, float]] = LANGUAGE_FREQUENCIES["english"]

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

    def _chi_squared(self, text: str, language: str = "english") -> float:
        """
        Calculate chi-squared statistic against language frequencies.

        Args:
            text: Text to analyze
            language: Language to compare against ('english', 'french', 'german', 'spanish')

        Returns:
            Chi-squared value. Lower values indicate closer match to the language.
        """
        n = len(text)
        if n == 0:
            return 0.0

        frequencies = self.LANGUAGE_FREQUENCIES.get(language.lower(), self.ENGLISH_FREQ)
        counter = Counter(text)
        chi_squared = 0.0

        for letter in self.ALPHABET:
            observed = counter.get(letter, 0)
            expected = (frequencies.get(letter, 0.1) / 100) * n

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
        return self._chi_squared(text, "english")

    def language_score(self, text: str, language: str = "english") -> float:
        """
        Score text based on how well it matches a specific language's frequencies.

        Args:
            text: Text to score
            language: Language to compare against ('english', 'french', 'german', 'spanish')

        Returns:
            Chi-squared score. Lower = better match to the language.
        """
        return self._chi_squared(text, language)

    def best_language_score(self, text: str) -> tuple[str, float]:
        """
        Find the best matching language and its score.

        Tries all supported languages and returns the one with the lowest
        chi-squared score (best match).

        Args:
            text: Text to analyze

        Returns:
            Tuple of (language_name, chi_squared_score)
        """
        best_lang = "english"
        best_score = float("inf")

        for lang in self.LANGUAGE_FREQUENCIES:
            score = self._chi_squared(text, lang)
            if score < best_score:
                best_score = score
                best_lang = lang

        return best_lang, best_score

    def detect_language_from_ioc(self, ioc: float) -> list[str]:
        """
        Suggest likely languages based on observed IoC.

        Higher IoC (0.07+) suggests French/Spanish/German.
        Medium IoC (~0.067) suggests English.

        Args:
            ioc: Observed index of coincidence

        Returns:
            List of language codes ordered by likelihood
        """
        if ioc < 0.05:
            # Likely polyalphabetic or random - return default
            return ["english"]

        # Calculate distance from each language's expected IoC
        distances = []
        for lang, expected_ioc in self.LANGUAGE_IOC.items():
            distance = abs(ioc - expected_ioc)
            distances.append((lang, distance))

        # Sort by distance (closest first)
        distances.sort(key=lambda x: x[1])

        return [lang for lang, _ in distances]
