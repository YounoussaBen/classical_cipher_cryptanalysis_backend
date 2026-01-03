from dataclasses import dataclass
from typing import ClassVar

from app.models.schemas import CipherFamily, CipherHypothesis, CipherType, StatisticsProfile


@dataclass
class DetectionThresholds:
    """Thresholds for cipher family detection."""

    # Index of Coincidence thresholds per language
    ioc_languages: dict = None  # Initialized in __post_init__
    ioc_random: float = 0.0385   # Expected IOC for random (1/26)
    ioc_high: float = 0.060     # Above this: likely monoalphabetic
    ioc_mid: float = 0.045      # Between mid and high: unclear
    ioc_low: float = 0.040      # Below this: likely polyalphabetic or random

    # Entropy thresholds (for 26-letter alphabet)
    entropy_natural: float = 4.1  # Typical natural language
    entropy_max: float = 4.7      # Max (log2(26))

    # Chi-squared thresholds
    chi_good: float = 50.0       # Good match to expected language
    chi_moderate: float = 200.0  # Moderate match

    def __post_init__(self):
        if self.ioc_languages is None:
            self.ioc_languages = {
                "french": 0.0778,
                "spanish": 0.0775,
                "german": 0.0762,
                "italian": 0.0738,
                "portuguese": 0.0745,
                "english": 0.0667,
            }

    def detect_likely_language(self, ioc: float) -> tuple[str, float]:
        """
        Detect the most likely language based on observed IoC.

        Returns:
            Tuple of (language_name, expected_ioc)
        """
        if ioc < self.ioc_mid:
            # Low IoC suggests polyalphabetic - can't determine language
            return "natural language", 0.0667

        best_lang = "english"
        best_distance = float("inf")

        for lang, expected_ioc in self.ioc_languages.items():
            distance = abs(ioc - expected_ioc)
            if distance < best_distance:
                best_distance = distance
                best_lang = lang

        return best_lang.capitalize(), self.ioc_languages.get(best_lang.lower(), 0.0667)


class CipherDetector:
    """
    Rule-based cipher family detection.

    Analyzes statistical properties to determine likely cipher families
    and specific cipher types. This is a heuristic approach that narrows
    down possibilities before attempting decryption.
    """

    THRESHOLDS: ClassVar[DetectionThresholds] = DetectionThresholds()

    def detect(self, statistics: StatisticsProfile) -> list[CipherHypothesis]:
        """
        Detect likely cipher families based on statistics.

        Args:
            statistics: Statistical profile of the ciphertext

        Returns:
            List of cipher hypotheses sorted by confidence
        """
        hypotheses = []

        # Analyze IOC to determine cipher family
        family_analysis = self._analyze_ioc(statistics.index_of_coincidence)

        # Check for monoalphabetic ciphers
        if family_analysis["monoalphabetic"] > 0.3:
            hypotheses.extend(self._detect_monoalphabetic(statistics, family_analysis))

        # Check for polyalphabetic ciphers
        if family_analysis["polyalphabetic"] > 0.3:
            hypotheses.extend(self._detect_polyalphabetic(statistics, family_analysis))

        # Check for transposition ciphers
        if family_analysis["transposition"] > 0.2:
            hypotheses.extend(self._detect_transposition(statistics, family_analysis))

        # Always include unknown as fallback
        if not hypotheses:
            hypotheses.append(CipherHypothesis(
                cipher_family=CipherFamily.UNKNOWN,
                cipher_type=None,
                confidence=0.5,
                reasoning=["Unable to determine cipher type from statistics"],
            ))

        # Sort by confidence
        hypotheses.sort(key=lambda x: x.confidence, reverse=True)

        return hypotheses

    def _analyze_ioc(self, ioc: float) -> dict[str, float]:
        """
        Analyze IOC to determine likely cipher families.

        Returns confidence scores for each family.
        """
        t = self.THRESHOLDS

        if ioc >= t.ioc_high:
            # High IOC: likely monoalphabetic or transposition
            return {
                "monoalphabetic": 0.8,
                "polyalphabetic": 0.1,
                "transposition": 0.6,
            }
        elif ioc >= t.ioc_mid:
            # Medium IOC: could be several things
            return {
                "monoalphabetic": 0.4,
                "polyalphabetic": 0.5,
                "transposition": 0.3,
            }
        else:
            # Low IOC: likely polyalphabetic
            return {
                "monoalphabetic": 0.1,
                "polyalphabetic": 0.8,
                "transposition": 0.2,
            }

    def _detect_monoalphabetic(
        self,
        statistics: StatisticsProfile,
        family_analysis: dict[str, float],
    ) -> list[CipherHypothesis]:
        """Detect specific monoalphabetic cipher types."""
        hypotheses = []
        base_confidence = family_analysis["monoalphabetic"]
        ioc = statistics.index_of_coincidence

        # Detect likely language from IoC
        likely_lang, expected_ioc = self.THRESHOLDS.detect_likely_language(ioc)

        # Caesar cipher is always a possibility
        # It's the simplest and most common
        caesar_reasoning = [
            f"IOC ({ioc:.4f}) close to {likely_lang} ({expected_ioc:.4f})",
            "Monoalphabetic substitution preserves letter frequencies",
            "Caesar is the simplest monoalphabetic cipher",
        ]

        hypotheses.append(CipherHypothesis(
            cipher_family=CipherFamily.MONOALPHABETIC,
            cipher_type=CipherType.CAESAR,
            confidence=base_confidence * 0.8,
            reasoning=caesar_reasoning,
        ))

        # ROT13 is just Caesar with shift=13
        hypotheses.append(CipherHypothesis(
            cipher_family=CipherFamily.MONOALPHABETIC,
            cipher_type=CipherType.ROT13,
            confidence=base_confidence * 0.3,
            reasoning=["ROT13 is Caesar with shift 13", "Common in simple obfuscation"],
        ))

        # General substitution cipher
        subst_reasoning = [
            f"IOC ({ioc:.4f}) indicates monoalphabetic substitution",
            f"Likely language: {likely_lang} (based on IoC match)",
            "Could be more complex than Caesar (random permutation)",
        ]

        # Check if letter frequency distribution is unusual for simple Caesar
        if statistics.chi_squared and statistics.chi_squared > 100:
            subst_reasoning.append(
                f"Chi-squared ({statistics.chi_squared:.1f}) suggests non-trivial substitution"
            )

        hypotheses.append(CipherHypothesis(
            cipher_family=CipherFamily.MONOALPHABETIC,
            cipher_type=CipherType.SIMPLE_SUBSTITUTION,
            confidence=base_confidence * 0.6,
            reasoning=subst_reasoning,
        ))

        # Atbash (reverse alphabet)
        hypotheses.append(CipherHypothesis(
            cipher_family=CipherFamily.MONOALPHABETIC,
            cipher_type=CipherType.ATBASH,
            confidence=base_confidence * 0.2,
            reasoning=["Atbash reverses alphabet (A↔Z, B↔Y, etc.)"],
        ))

        return hypotheses

    def _detect_polyalphabetic(
        self,
        statistics: StatisticsProfile,
        family_analysis: dict[str, float],
    ) -> list[CipherHypothesis]:
        """Detect specific polyalphabetic cipher types."""
        hypotheses = []
        base_confidence = family_analysis["polyalphabetic"]
        ioc = statistics.index_of_coincidence

        # Vigenère is the most common polyalphabetic cipher
        vigenere_reasoning = [
            f"IOC ({ioc:.4f}) lower than natural language, suggesting multiple alphabets",
            "Vigenère uses a keyword to shift each letter differently",
        ]

        # Check for Kasiski patterns
        if statistics.kasiski_distances:
            vigenere_reasoning.append(
                f"Found repeated sequences with distances: {statistics.kasiski_distances[:5]}"
            )
            # Repeated patterns suggest Vigenère
            base_confidence = min(0.9, base_confidence + 0.2)

        hypotheses.append(CipherHypothesis(
            cipher_family=CipherFamily.POLYALPHABETIC,
            cipher_type=CipherType.VIGENERE,
            confidence=base_confidence * 0.8,
            reasoning=vigenere_reasoning,
        ))

        # Beaufort cipher (variant of Vigenère)
        hypotheses.append(CipherHypothesis(
            cipher_family=CipherFamily.POLYALPHABETIC,
            cipher_type=CipherType.BEAUFORT,
            confidence=base_confidence * 0.3,
            reasoning=[
                "Beaufort is similar to Vigenère but with reciprocal operation",
            ],
        ))

        # Autokey (uses plaintext as part of key)
        hypotheses.append(CipherHypothesis(
            cipher_family=CipherFamily.POLYALPHABETIC,
            cipher_type=CipherType.AUTOKEY,
            confidence=base_confidence * 0.2,
            reasoning=["Autokey uses plaintext to extend the keyword"],
        ))

        return hypotheses

    def _detect_transposition(
        self,
        statistics: StatisticsProfile,
        family_analysis: dict[str, float],
    ) -> list[CipherHypothesis]:
        """Detect transposition ciphers."""
        hypotheses = []
        base_confidence = family_analysis["transposition"]
        ioc = statistics.index_of_coincidence

        # Detect likely language from IoC
        likely_lang, expected_ioc = self.THRESHOLDS.detect_likely_language(ioc)

        # Transposition preserves letter frequencies exactly
        # So IOC should be very close to the original language
        if ioc > 0.065:
            base_confidence = min(0.9, base_confidence + 0.2)

        # Columnar transposition
        hypotheses.append(CipherHypothesis(
            cipher_family=CipherFamily.TRANSPOSITION,
            cipher_type=CipherType.COLUMNAR,
            confidence=base_confidence * 0.6,
            reasoning=[
                f"IOC ({ioc:.4f}) matches {likely_lang} (letters rearranged, not substituted)",
                "Columnar transposition writes text in rows, reads in columns",
            ],
        ))

        # Rail fence
        hypotheses.append(CipherHypothesis(
            cipher_family=CipherFamily.TRANSPOSITION,
            cipher_type=CipherType.RAIL_FENCE,
            confidence=base_confidence * 0.4,
            reasoning=[
                "Rail fence writes text in zigzag pattern",
                "Simple transposition with few parameters",
            ],
        ))

        return hypotheses
