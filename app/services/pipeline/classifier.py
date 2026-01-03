"""
Cipher family classifier using statistical invariants.

This module implements Phase 0 of the cryptanalysis pipeline:
classification by invariants before any decryption is attempted.

Every classical cipher preserves or destroys specific statistical structures.
Those structures leak the cipher family before decryption.
"""

import math
import string
from collections import Counter
from dataclasses import dataclass, field
from typing import ClassVar

from scipy import stats


@dataclass
class CipherFamilyProbabilities:
    """Probability distribution over cipher families."""
    
    monoalphabetic: float = 0.0
    polyalphabetic: float = 0.0
    transposition: float = 0.0
    
    # Detailed breakdown within families
    likely_monoalphabetic: list[str] = field(default_factory=list)
    likely_polyalphabetic: list[str] = field(default_factory=list)
    likely_transposition: list[str] = field(default_factory=list)
    
    # Key length hints for polyalphabetic
    estimated_key_lengths: list[int] = field(default_factory=list)
    
    # Confidence in the classification
    classification_confidence: float = 0.0
    
    # Reasoning for transparency
    reasoning: list[str] = field(default_factory=list)


class CipherClassifier:
    """
    Classifies cipher families using statistical invariants.
    
    This is O(n) and runs in microseconds. It uses:
    1. Index of Coincidence (IoC) - fastest discriminator
    2. Frequency curve shape - matches natural language patterns
    3. Bigram rank correlation - distinguishes transposition vs substitution
    4. Kasiski patterns - detects periodic polyalphabetic
    5. Entropy analysis - identifies flattening from polyalphabetic
    """
    
    ALPHABET: ClassVar[str] = string.ascii_uppercase
    
    # IoC reference values
    IOC_RANDOM: ClassVar[float] = 0.0385  # 1/26
    IOC_ENGLISH: ClassVar[float] = 0.0667
    IOC_FRENCH: ClassVar[float] = 0.0778
    IOC_GERMAN: ClassVar[float] = 0.0762
    IOC_SPANISH: ClassVar[float] = 0.0775
    IOC_ITALIAN: ClassVar[float] = 0.0738
    IOC_PORTUGUESE: ClassVar[float] = 0.0745
    
    # Natural language IoC range (across all supported languages)
    IOC_NATURAL_MIN: ClassVar[float] = 0.0650
    IOC_NATURAL_MAX: ClassVar[float] = 0.0800
    
    # Thresholds for classification
    IOC_HIGH_THRESHOLD: ClassVar[float] = 0.060  # Above: likely mono/transposition
    IOC_MID_THRESHOLD: ClassVar[float] = 0.050   # Between: short-key poly
    IOC_LOW_THRESHOLD: ClassVar[float] = 0.042   # Below: long-key poly or random
    
    # Reference frequency distributions for correlation
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
        "italian": {
            "E": 11.79, "A": 11.74, "I": 11.28, "O": 9.83, "N": 6.88,
            "T": 5.62, "R": 6.37, "L": 6.51, "S": 4.98, "C": 4.50,
            "D": 3.73, "U": 3.01, "P": 3.05, "M": 2.51, "G": 1.64,
            "V": 2.10, "B": 0.92, "F": 0.95, "H": 1.54, "Z": 0.49,
            "Q": 0.51, "Y": 0.02, "W": 0.02, "X": 0.02, "K": 0.01,
            "J": 0.01,
        },
        "portuguese": {
            "E": 12.57, "A": 14.63, "O": 10.73, "S": 7.81, "R": 6.53,
            "I": 6.18, "N": 5.05, "D": 4.99, "M": 4.74, "U": 4.63,
            "T": 4.34, "C": 3.88, "L": 2.78, "P": 2.52, "V": 1.67,
            "G": 1.30, "Q": 1.20, "B": 1.04, "F": 1.02, "H": 1.28,
            "Z": 0.47, "J": 0.40, "X": 0.21, "Y": 0.01, "W": 0.01,
            "K": 0.02,
        },
    }
    
    # Common bigrams for correlation testing
    LANGUAGE_BIGRAMS: ClassVar[dict[str, list[str]]] = {
        "english": ["TH", "HE", "IN", "ER", "AN", "RE", "ON", "AT", "EN", "ND"],
        "french": ["ES", "LE", "DE", "EN", "RE", "NT", "ON", "ER", "OU", "AN"],
        "german": ["EN", "ER", "CH", "DE", "EI", "ND", "TE", "IN", "IE", "GE"],
        "spanish": ["DE", "EN", "ES", "EL", "LA", "OS", "UE", "AS", "ER", "RA"],
        "italian": ["RE", "ER", "ON", "DI", "TO", "EN", "TA", "TE", "AN", "AT"],
        "portuguese": ["DE", "OS", "AS", "ES", "DO", "DA", "EM", "EN", "NO", "RA"],
    }
    
    def classify(self, ciphertext: str) -> CipherFamilyProbabilities:
        """
        Classify the cipher family using statistical invariants.
        
        Args:
            ciphertext: The ciphertext to classify
            
        Returns:
            CipherFamilyProbabilities with confidence scores for each family
        """
        # Normalize to uppercase letters only
        text = "".join(c for c in ciphertext.upper() if c in self.ALPHABET)
        
        if len(text) < 20:
            # Too short for reliable classification
            return CipherFamilyProbabilities(
                monoalphabetic=0.33,
                polyalphabetic=0.33,
                transposition=0.33,
                classification_confidence=0.1,
                reasoning=["Text too short for reliable classification"],
            )
        
        # Compute statistical features
        ioc = self._calculate_ioc(text)
        entropy = self._calculate_entropy(text)
        freq_distribution = self._get_frequency_distribution(text)
        bigram_correlations = self._calculate_bigram_correlations(text)
        kasiski_key_lengths = self._kasiski_examination(text)
        freq_curve_match = self._frequency_curve_analysis(freq_distribution)
        
        # Initialize probabilities and reasoning
        reasoning = []
        
        # === IoC Analysis (Primary Discriminator) ===
        if ioc >= self.IOC_HIGH_THRESHOLD:
            # High IoC: Monoalphabetic or Transposition
            mono_prob = 0.7
            trans_prob = 0.6
            poly_prob = 0.1
            reasoning.append(
                f"IoC={ioc:.4f} (high) suggests monoalphabetic or transposition"
            )
        elif ioc >= self.IOC_MID_THRESHOLD:
            # Medium IoC: Short-key polyalphabetic
            mono_prob = 0.3
            trans_prob = 0.2
            poly_prob = 0.6
            reasoning.append(
                f"IoC={ioc:.4f} (medium) suggests short-key polyalphabetic"
            )
        elif ioc >= self.IOC_LOW_THRESHOLD:
            # Low IoC: Polyalphabetic with longer key
            mono_prob = 0.1
            trans_prob = 0.1
            poly_prob = 0.8
            reasoning.append(
                f"IoC={ioc:.4f} (low) suggests polyalphabetic cipher"
            )
        else:
            # Very low IoC: Long-key poly or random
            mono_prob = 0.05
            trans_prob = 0.05
            poly_prob = 0.7
            reasoning.append(
                f"IoC={ioc:.4f} (very low) suggests long-key polyalphabetic or random"
            )
        
        # === Frequency Curve Analysis ===
        # Spearman rank correlation compares the SHAPE of the distribution
        # - Substitution ciphers: frequencies are permuted but shape is similar
        # - Transposition ciphers: exact same letters, so exact same frequencies
        # 
        # Key insight: For transposition, we need to check if the ACTUAL frequencies
        # match a language, not just the shape. The rank correlation checks shape.
        best_lang_match, best_correlation = freq_curve_match
        if best_correlation > 0.85:
            # Strong correlation means the frequency SHAPE matches natural language
            # This is consistent with BOTH monoalphabetic (permuted) and transposition
            # We boost both, but mono more since it's more common
            mono_prob = min(0.9, mono_prob + 0.2)
            trans_prob = min(0.9, trans_prob + 0.1)
            reasoning.append(
                f"Frequency curve strongly matches {best_lang_match} "
                f"(r={best_correlation:.2f}) - suggests mono/transposition"
            )
        elif best_correlation > 0.6:
            # Moderate correlation - likely monoalphabetic (permuted frequencies)
            mono_prob = min(0.9, mono_prob + 0.15)
            reasoning.append(
                f"Frequency curve moderately matches {best_lang_match} "
                f"(r={best_correlation:.2f}) - suggests monoalphabetic"
            )
        else:
            # Low correlation - frequencies are flattened (polyalphabetic)
            poly_prob = min(0.9, poly_prob + 0.2)
            reasoning.append(
                f"Frequency curve poorly matches any language "
                f"(r={best_correlation:.2f}) - suggests polyalphabetic"
            )
        
        # === Bigram Correlation Analysis ===
        best_bigram_lang, bigram_corr = max(
            bigram_correlations.items(), key=lambda x: x[1]
        )
        if bigram_corr > 0.7:
            # High bigram correlation = transposition
            trans_prob = min(0.95, trans_prob + 0.2)
            reasoning.append(
                f"High bigram correlation with {best_bigram_lang} "
                f"({bigram_corr:.2f}) - strong transposition signal"
            )
        elif bigram_corr < 0.3:
            # Low bigram correlation = substitution or polyalphabetic
            trans_prob = max(0.05, trans_prob - 0.2)
            reasoning.append(
                f"Low bigram correlation ({bigram_corr:.2f}) - "
                f"rules out transposition"
            )
        
        # === Kasiski Examination ===
        if kasiski_key_lengths:
            # Repeated patterns with regular spacing = periodic polyalphabetic
            poly_prob = min(0.95, poly_prob + 0.2)
            mono_prob = max(0.05, mono_prob - 0.15)
            reasoning.append(
                f"Kasiski patterns found - likely key lengths: "
                f"{kasiski_key_lengths[:3]}"
            )
        
        # === Entropy Analysis ===
        max_entropy = math.log2(26)  # ~4.7 bits
        entropy_ratio = entropy / max_entropy
        
        if entropy_ratio > 0.95:
            # Very high entropy = flattened distribution (poly)
            poly_prob = min(0.9, poly_prob + 0.1)
            reasoning.append(
                f"High entropy ({entropy:.2f}/{max_entropy:.2f}) suggests "
                f"flattened distribution"
            )
        elif entropy_ratio < 0.85:
            # Lower entropy = more structure (mono/trans)
            mono_prob = min(0.9, mono_prob + 0.1)
            trans_prob = min(0.9, trans_prob + 0.1)
            reasoning.append(
                f"Moderate entropy ({entropy:.2f}) suggests preserved structure"
            )
        
        # Normalize probabilities
        total = mono_prob + poly_prob + trans_prob
        mono_prob /= total
        poly_prob /= total
        trans_prob /= total
        
        # Determine likely specific ciphers within each family
        likely_mono = self._rank_monoalphabetic_ciphers(ioc, freq_curve_match)
        likely_poly = self._rank_polyalphabetic_ciphers(ioc, kasiski_key_lengths)
        likely_trans = self._rank_transposition_ciphers(ioc, bigram_corr)
        
        # Calculate overall classification confidence
        probs = [mono_prob, poly_prob, trans_prob]
        max_prob = max(probs)
        second_prob = sorted(probs)[-2]
        confidence = max_prob - second_prob  # Higher gap = more confident
        
        return CipherFamilyProbabilities(
            monoalphabetic=mono_prob,
            polyalphabetic=poly_prob,
            transposition=trans_prob,
            likely_monoalphabetic=likely_mono,
            likely_polyalphabetic=likely_poly,
            likely_transposition=likely_trans,
            estimated_key_lengths=kasiski_key_lengths[:5] if kasiski_key_lengths else [],
            classification_confidence=confidence,
            reasoning=reasoning,
        )
    
    def _calculate_ioc(self, text: str) -> float:
        """Calculate Index of Coincidence."""
        n = len(text)
        if n <= 1:
            return 0.0
        
        counter = Counter(text)
        numerator = sum(f * (f - 1) for f in counter.values())
        denominator = n * (n - 1)
        
        return numerator / denominator if denominator > 0 else 0.0
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy."""
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
    
    def _get_frequency_distribution(self, text: str) -> dict[str, float]:
        """Get letter frequency distribution as percentages."""
        n = len(text)
        if n == 0:
            return {letter: 0.0 for letter in self.ALPHABET}
        
        counter = Counter(text)
        return {
            letter: (counter.get(letter, 0) / n) * 100
            for letter in self.ALPHABET
        }
    
    def _frequency_curve_analysis(
        self, 
        observed: dict[str, float]
    ) -> tuple[str, float]:
        """
        Compare frequency curve shape to natural language patterns.
        
        Uses Spearman rank correlation to detect if the frequency
        distribution has the same "shape" as natural language
        (just permuted for substitution ciphers).
        
        Returns:
            Tuple of (best_matching_language, correlation_coefficient)
        """
        # Sort observed frequencies (descending)
        observed_sorted = sorted(observed.values(), reverse=True)
        
        best_lang = "english"
        best_corr = 0.0
        
        for lang, freqs in self.LANGUAGE_FREQUENCIES.items():
            # Sort expected frequencies (descending)
            expected_sorted = sorted(freqs.values(), reverse=True)
            
            # Compute Spearman rank correlation
            try:
                corr, _ = stats.spearmanr(observed_sorted, expected_sorted)
                if not math.isnan(corr) and corr > best_corr:
                    best_corr = corr
                    best_lang = lang
            except Exception:
                continue
        
        return best_lang, best_corr
    
    def _calculate_bigram_correlations(self, text: str) -> dict[str, float]:
        """
        Calculate bigram rank correlation with each language.
        
        High correlation suggests transposition (bigrams preserved).
        Low correlation suggests substitution or polyalphabetic.
        """
        if len(text) < 2:
            return {lang: 0.0 for lang in self.LANGUAGE_BIGRAMS}
        
        # Get observed bigram counts
        bigram_counts = Counter(text[i:i+2] for i in range(len(text) - 1))
        total_bigrams = sum(bigram_counts.values())
        
        correlations = {}
        
        for lang, common_bigrams in self.LANGUAGE_BIGRAMS.items():
            # Count how many of the top bigrams appear
            matches = sum(
                bigram_counts.get(bg, 0) / total_bigrams * 100
                for bg in common_bigrams
            )
            # Normalize to 0-1 range (rough heuristic)
            correlations[lang] = min(1.0, matches / 10)
        
        return correlations
    
    def _kasiski_examination(self, text: str, min_len: int = 3, max_len: int = 6) -> list[int]:
        """
        Perform Kasiski examination to find likely key lengths.
        
        Looks for repeated sequences and analyzes the GCD of their distances.
        """
        if len(text) < 20:
            return []
        
        distances = []
        
        for length in range(min_len, min(max_len + 1, len(text) // 3)):
            seen: dict[str, list[int]] = {}
            
            for i in range(len(text) - length + 1):
                seq = text[i:i + length]
                if seq not in seen:
                    seen[seq] = []
                seen[seq].append(i)
            
            for seq, positions in seen.items():
                if len(positions) > 1:
                    for i in range(len(positions) - 1):
                        distances.append(positions[i + 1] - positions[i])
        
        if not distances:
            return []
        
        # Find common factors
        factor_counts: Counter = Counter()
        for d in distances:
            for f in range(2, min(d + 1, 16)):
                if d % f == 0:
                    factor_counts[f] += 1
        
        # Return most common factors as likely key lengths
        return [f for f, _ in factor_counts.most_common(5)]
    
    def _rank_monoalphabetic_ciphers(
        self, 
        ioc: float,
        freq_match: tuple[str, float]
    ) -> list[str]:
        """Rank likely monoalphabetic ciphers."""
        ciphers = []
        
        # Caesar is always most likely for monoalphabetic (simplest)
        ciphers.append("caesar")
        
        # If IoC is high and frequency correlation is moderate,
        # could be more complex substitution
        if freq_match[1] < 0.8:
            ciphers.append("simple_substitution")
            ciphers.append("affine")
        
        # Atbash is rare but possible
        ciphers.append("atbash")
        
        # ROT13 is just Caesar with key=13
        ciphers.append("rot13")
        
        return ciphers
    
    def _rank_polyalphabetic_ciphers(
        self,
        ioc: float,
        key_lengths: list[int]
    ) -> list[str]:
        """Rank likely polyalphabetic ciphers."""
        ciphers = []
        
        # Vigenère is most common
        ciphers.append("vigenere")
        
        # Beaufort is similar
        ciphers.append("beaufort")
        
        # Autokey if no clear periodic pattern
        if not key_lengths:
            ciphers.insert(1, "autokey")
        
        return ciphers
    
    def _rank_transposition_ciphers(
        self,
        ioc: float,
        bigram_corr: float
    ) -> list[str]:
        """Rank likely transposition ciphers."""
        ciphers = []
        
        # Rail Fence is simpler
        ciphers.append("rail_fence")
        
        # Columnar is more common in practice
        ciphers.append("columnar")
        
        return ciphers
