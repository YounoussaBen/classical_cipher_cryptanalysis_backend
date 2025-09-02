from dataclasses import dataclass
from typing import ClassVar

from app.services.analysis.statistics import StatisticalAnalyzer


@dataclass
class LanguageProfile:
    """Statistical profile for a language."""

    name: str
    code: str
    letter_frequencies: dict[str, float]
    common_bigrams: list[str]
    common_trigrams: list[str]
    expected_ioc: float


@dataclass
class LanguageDetectionResult:
    """Result of language detection."""

    language: str
    code: str
    confidence: float
    chi_squared: float


class LanguageDetector:
    """
    Detects the language of plaintext based on statistical analysis.

    Uses letter frequency analysis and chi-squared testing to identify
    the most likely language.
    """

    # English letter frequencies (percentage)
    ENGLISH_FREQ: ClassVar[dict[str, float]] = {
        "E": 12.70, "T": 9.06, "A": 8.17, "O": 7.51, "I": 6.97,
        "N": 6.75, "S": 6.33, "H": 6.09, "R": 5.99, "D": 4.25,
        "L": 4.03, "C": 2.78, "U": 2.76, "M": 2.41, "W": 2.36,
        "F": 2.23, "G": 2.02, "Y": 1.97, "P": 1.93, "B": 1.29,
        "V": 0.98, "K": 0.77, "J": 0.15, "X": 0.15, "Q": 0.10,
        "Z": 0.07,
    }

    # French letter frequencies
    FRENCH_FREQ: ClassVar[dict[str, float]] = {
        "E": 14.72, "A": 7.64, "S": 7.95, "I": 7.53, "T": 7.24,
        "N": 7.10, "R": 6.55, "U": 6.31, "L": 5.46, "O": 5.27,
        "D": 3.67, "C": 3.18, "M": 2.97, "P": 2.52, "V": 1.83,
        "Q": 1.36, "F": 1.07, "B": 0.90, "G": 0.87, "H": 0.74,
        "J": 0.55, "X": 0.39, "Y": 0.31, "Z": 0.14, "W": 0.05,
        "K": 0.05,
    }

    # German letter frequencies
    GERMAN_FREQ: ClassVar[dict[str, float]] = {
        "E": 16.40, "N": 9.78, "I": 7.55, "S": 7.27, "R": 7.00,
        "A": 6.51, "T": 6.15, "D": 5.08, "H": 4.76, "U": 4.35,
        "L": 3.44, "C": 3.06, "G": 3.01, "M": 2.53, "O": 2.51,
        "B": 1.89, "W": 1.89, "F": 1.66, "K": 1.21, "Z": 1.13,
        "P": 0.79, "V": 0.67, "J": 0.27, "Y": 0.04, "X": 0.03,
        "Q": 0.02,
    }

    # Spanish letter frequencies
    SPANISH_FREQ: ClassVar[dict[str, float]] = {
        "E": 13.68, "A": 12.53, "O": 8.68, "S": 7.98, "R": 6.87,
        "N": 6.71, "I": 6.25, "D": 5.86, "L": 4.97, "C": 4.68,
        "T": 4.63, "U": 3.93, "M": 3.16, "P": 2.51, "B": 1.42,
        "G": 1.01, "V": 0.90, "Y": 0.90, "Q": 0.88, "H": 0.70,
        "F": 0.69, "Z": 0.52, "J": 0.44, "X": 0.22, "W": 0.02,
        "K": 0.01,
    }

    LANGUAGE_PROFILES: ClassVar[dict[str, LanguageProfile]] = {
        "english": LanguageProfile(
            name="English",
            code="en",
            letter_frequencies=ENGLISH_FREQ,
            common_bigrams=["TH", "HE", "IN", "ER", "AN", "RE", "ON", "AT"],
            common_trigrams=["THE", "AND", "ING", "HER", "HAT", "HIS"],
            expected_ioc=0.0667,
        ),
        "french": LanguageProfile(
            name="French",
            code="fr",
            letter_frequencies=FRENCH_FREQ,
            common_bigrams=["ES", "LE", "DE", "EN", "RE", "NT", "ON", "ER"],
            common_trigrams=["LES", "ENT", "QUE", "ION", "DES", "AIT"],
            expected_ioc=0.0778,
        ),
        "german": LanguageProfile(
            name="German",
            code="de",
            letter_frequencies=GERMAN_FREQ,
            common_bigrams=["EN", "ER", "CH", "DE", "EI", "ND", "TE", "IN"],
            common_trigrams=["EIN", "ICH", "DER", "UND", "DIE", "DEN"],
            expected_ioc=0.0762,
        ),
        "spanish": LanguageProfile(
            name="Spanish",
            code="es",
            letter_frequencies=SPANISH_FREQ,
            common_bigrams=["DE", "EN", "ES", "EL", "LA", "OS", "UE", "AS"],
            common_trigrams=["QUE", "DEL", "LOS", "ADE", "ION", "NTE"],
            expected_ioc=0.0775,
        ),
    }

    def __init__(self):
        self.analyzer = StatisticalAnalyzer()

    def detect(self, text: str) -> LanguageDetectionResult:
        """
        Detect the language of the given text.

        Args:
            text: Text to analyze (should be plaintext)

        Returns:
            LanguageDetectionResult with language and confidence
        """
        # Get frequency distribution
        frequencies = self.analyzer.letter_frequencies(text)

        best_match = None
        best_chi_squared = float("inf")

        for lang_name, profile in self.LANGUAGE_PROFILES.items():
            chi_squared = self._chi_squared_test(frequencies, profile.letter_frequencies)

            if chi_squared < best_chi_squared:
                best_chi_squared = chi_squared
                best_match = profile

        if best_match is None:
            return LanguageDetectionResult(
                language="unknown",
                code="unk",
                confidence=0.0,
                chi_squared=float("inf"),
            )

        # Convert chi-squared to confidence (lower is better)
        # This is a simple heuristic conversion
        confidence = max(0.0, min(1.0, 1.0 - (best_chi_squared / 1000)))

        return LanguageDetectionResult(
            language=best_match.name,
            code=best_match.code,
            confidence=confidence,
            chi_squared=best_chi_squared,
        )

    def _chi_squared_test(
        self,
        observed: dict[str, float],
        expected: dict[str, float],
    ) -> float:
        """
        Calculate chi-squared statistic between observed and expected frequencies.

        Args:
            observed: Observed letter frequencies (as percentages)
            expected: Expected letter frequencies (as percentages)

        Returns:
            Chi-squared statistic
        """
        chi_squared = 0.0

        for letter in expected:
            obs = observed.get(letter, 0.0)
            exp = expected[letter]

            if exp > 0:
                chi_squared += ((obs - exp) ** 2) / exp

        return chi_squared

    def get_profile(self, language: str) -> LanguageProfile | None:
        """Get the statistical profile for a language."""
        return self.LANGUAGE_PROFILES.get(language.lower())
