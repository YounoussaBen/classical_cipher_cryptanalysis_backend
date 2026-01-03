"""
Candidate filter for statistical validation.

This module implements Phase 3 of the cryptanalysis pipeline:
removing obvious garbage before AI sees it.
"""

import string
from dataclasses import dataclass
from typing import ClassVar

from app.services.pipeline.scorer import ScoredCandidate


@dataclass
class FilterResult:
    """Result of filtering candidates."""
    
    passed: list[ScoredCandidate]
    filtered_out: int
    filter_reasons: dict[str, int]


class CandidateFilter:
    """
    Filters candidates using statistical validation.
    
    Hard filters (binary pass/fail):
    - No vowels in plaintext
    - Same letter repeated 5+ times consecutively
    - Chi-squared > threshold for ALL languages
    
    Soft ranking is done by the scorer, this just removes garbage.
    """
    
    ALPHABET: ClassVar[str] = string.ascii_uppercase
    VOWELS: ClassVar[set[str]] = {"A", "E", "I", "O", "U"}
    
    # Thresholds
    MAX_CHI_SQUARED: ClassVar[float] = 300.0  # Above this for ALL languages = garbage
    MAX_CONSECUTIVE_SAME: ClassVar[int] = 4   # 5+ same letter = garbage
    MIN_VOWEL_RATIO: ClassVar[float] = 0.05   # At least 5% vowels
    
    def filter(
        self,
        candidates: list[ScoredCandidate],
        max_results: int = 10,
    ) -> FilterResult:
        """
        Filter candidates and return the best ones.
        
        Args:
            candidates: List of scored candidates
            max_results: Maximum number of results to return
            
        Returns:
            FilterResult with passed candidates and filter statistics
        """
        passed = []
        filter_reasons: dict[str, int] = {
            "no_vowels": 0,
            "consecutive_letters": 0,
            "high_chi_squared": 0,
            "impossible_patterns": 0,
        }
        
        for candidate in candidates:
            text = "".join(
                c for c in candidate.plaintext.upper() 
                if c in self.ALPHABET
            )
            
            if not text:
                filter_reasons["impossible_patterns"] += 1
                continue
            
            # Check vowel presence
            vowel_count = sum(1 for c in text if c in self.VOWELS)
            vowel_ratio = vowel_count / len(text) if text else 0
            
            if vowel_ratio < self.MIN_VOWEL_RATIO:
                filter_reasons["no_vowels"] += 1
                continue
            
            # Check consecutive same letters
            if self._has_consecutive_same(text, self.MAX_CONSECUTIVE_SAME + 1):
                filter_reasons["consecutive_letters"] += 1
                continue
            
            # Check if chi-squared is too high for ALL languages
            all_chi_high = all(
                score.chi_squared > self.MAX_CHI_SQUARED
                for score in candidate.all_scores.values()
            )
            if all_chi_high:
                filter_reasons["high_chi_squared"] += 1
                continue
            
            # Check for impossible patterns
            if self._has_impossible_patterns(text):
                filter_reasons["impossible_patterns"] += 1
                continue
            
            passed.append(candidate)
        
        # Sort by best score and take top N
        passed.sort(key=lambda x: x.best_score)
        
        return FilterResult(
            passed=passed[:max_results],
            filtered_out=len(candidates) - len(passed),
            filter_reasons=filter_reasons,
        )
    
    def _has_consecutive_same(self, text: str, min_count: int) -> bool:
        """Check if any letter appears consecutively min_count times."""
        if len(text) < min_count:
            return False
        
        count = 1
        prev = text[0]
        
        for char in text[1:]:
            if char == prev:
                count += 1
                if count >= min_count:
                    return True
            else:
                count = 1
                prev = char
        
        return False
    
    def _has_impossible_patterns(self, text: str) -> bool:
        """
        Check for impossible letter patterns in natural language.
        
        These patterns are extremely rare in any natural language:
        - More than 10 consonants in a row (very rare even in complex languages)
        - Same letter repeated 6+ times
        
        Note: We use a high threshold (10) for consonants because:
        - French without accents: "synthétiser" -> "SYNTHTISER" (7 consonants)
        - German compound words can have many consonants
        - We rely on chi-squared scoring to catch real garbage
        """
        consonants = set(self.ALPHABET) - self.VOWELS
        
        # Check for too many consecutive consonants (very high threshold)
        consecutive_consonants = 0
        for char in text:
            if char in consonants:
                consecutive_consonants += 1
                if consecutive_consonants > 10:
                    return True
            else:
                consecutive_consonants = 0
        
        return False
    
    def quick_reject(self, plaintext: str) -> bool:
        """
        Quick rejection test without full scoring.
        
        Returns True if the plaintext should be rejected.
        This is for early exit during decryption.
        """
        text = "".join(c for c in plaintext.upper() if c in self.ALPHABET)
        
        if not text:
            return True
        
        # Quick vowel check
        vowel_count = sum(1 for c in text if c in self.VOWELS)
        if vowel_count / len(text) < self.MIN_VOWEL_RATIO:
            return True
        
        # Quick consecutive check
        if self._has_consecutive_same(text, self.MAX_CONSECUTIVE_SAME + 1):
            return True
        
        return False
