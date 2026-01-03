"""
Multi-language candidate scorer.

This module implements Phase 2 of the cryptanalysis pipeline:
scoring candidates against ALL supported languages to find the best match.
"""

import string
from collections import Counter
from dataclasses import dataclass
from typing import ClassVar


@dataclass
class LanguageScore:
    """Score for a single language."""
    
    language: str
    chi_squared: float
    bigram_score: float
    word_score: float
    combined_score: float


@dataclass
class ScoredCandidate:
    """A candidate with multi-language scoring."""
    
    plaintext: str
    cipher_type: str
    key: str | dict
    
    # Best language match
    best_language: str
    best_score: float
    
    # All language scores
    all_scores: dict[str, LanguageScore]
    
    # Confidence derived from score
    confidence: float
    
    # Method used to generate this candidate
    method: str


class CandidateScorer:
    """
    Scores plaintext candidates against all supported languages.
    
    Uses multiple scoring methods:
    - Chi-squared against letter frequencies
    - Common bigram detection
    - Common word detection
    """
    
    ALPHABET: ClassVar[str] = string.ascii_uppercase
    
    # Language profiles
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
    
    # Common words for each language (for word detection scoring)
    COMMON_WORDS: ClassVar[dict[str, set[str]]] = {
        "english": {
            "THE", "AND", "FOR", "ARE", "BUT", "NOT", "YOU", "ALL",
            "CAN", "HAD", "HER", "WAS", "ONE", "OUR", "OUT", "HAS",
            "HIS", "HOW", "ITS", "MAY", "NEW", "NOW", "OLD", "SEE",
            "TWO", "WAY", "WHO", "BOY", "DID", "GET", "HIM", "LET",
            "PUT", "SAY", "SHE", "TOO", "USE", "THAT", "WITH", "HAVE",
            "THIS", "WILL", "YOUR", "FROM", "THEY", "BEEN", "HAVE",
            "MANY", "SOME", "THEM", "THEN", "THESE", "WOULD", "MAKE",
            "LIKE", "INTO", "TIME", "VERY", "WHEN", "COME", "COULD",
            "MORE", "THAN", "FIRST", "WATER", "OTHER", "PEOPLE",
        },
        "french": {
            "LE", "LA", "LES", "DE", "DES", "DU", "UN", "UNE", "ET",
            "EST", "EN", "QUE", "QUI", "IL", "ELLE", "ON", "NE", "PAS",
            "PLUS", "DANS", "CE", "CETTE", "CES", "POUR", "PAR", "SUR",
            "AVEC", "SANS", "SOUS", "MAIS", "OU", "AU", "AUX", "SON",
            "SA", "SES", "MON", "MA", "MES", "TON", "TA", "TES",
            "NOTRE", "VOTRE", "LEUR", "NOUS", "VOUS", "ILS", "ELLES",
            "SONT", "ETRE", "AVOIR", "FAIT", "FAIRE", "PEUT", "TOUT",
            "TOUS", "TOUTE", "BIEN", "COMME", "AUSSI", "AUTRE",
            "TRES", "TEMPS", "MONDE", "HOMME", "FEMME", "JOUR",
        },
        "german": {
            "DER", "DIE", "DAS", "UND", "IST", "VON", "ZU", "DEN",
            "MIT", "SICH", "DES", "AUF", "FUR", "NICHT", "ALS",
            "AUCH", "ES", "AN", "WIR", "HAT", "AUS", "ER", "AM",
            "EINE", "EINER", "EINEM", "EINEN", "WIE", "NACH", "IM",
            "SIND", "NUR", "NOCH", "KANN", "BEI", "ABER", "WENN",
            "MAN", "MEHR", "ODER", "WAR", "SEIN", "SCHON", "SO",
            "WIRD", "SEHR", "DIESE", "NUN", "UNTER", "MUSS",
            "HABEN", "HATTE", "IHRE", "SEIN", "WERDEN", "WURDE",
        },
        "spanish": {
            "DE", "LA", "QUE", "EL", "EN", "LOS", "DEL", "SE",
            "LAS", "POR", "UN", "PARA", "CON", "NO", "UNA", "SU",
            "AL", "ES", "LO", "COMO", "MAS", "PERO", "SUS", "LE",
            "YA", "HA", "ERA", "SIDO", "ESTE", "ESTA", "DESDE",
            "SIN", "ENTRE", "CUANDO", "TODO", "SER", "SON", "DOS",
            "TIENE", "HASTA", "HACE", "PUEDE", "TODOS", "ASI",
            "NOS", "MUY", "BIEN", "TIEMPO", "VIDA", "MUNDO",
        },
        "italian": {
            "DI", "CHE", "IL", "LA", "UN", "UNA", "PER", "NON",
            "CON", "DEL", "DA", "SONO", "DELLA", "ANCHE", "PIU",
            "HA", "ERA", "LORO", "SUO", "SUE", "MA", "COME", "IO",
            "TU", "LUI", "LEI", "NOI", "VOI", "ESSERE", "AVERE",
            "QUESTO", "QUELLO", "TUTTO", "TUTTI", "BENE", "SEMPRE",
            "DOVE", "QUANDO", "PRIMA", "DOPO", "ANCORA", "MOLTO",
        },
        "portuguese": {
            "DE", "QUE", "NAO", "EM", "PARA", "COM", "UMA", "OS",
            "NO", "SE", "NA", "POR", "MAIS", "AS", "DOS", "COMO",
            "MAS", "AO", "ELE", "DAS", "SEM", "MESMO", "AOS", "TEM",
            "SEUS", "QUEM", "NAS", "ME", "ESSE", "ELES", "VOCE",
            "ESSA", "NUM", "NEM", "SUAS", "MEU", "MINHA", "NUMA",
            "PELOS", "ELAS", "ERA", "SER", "QUANDO", "MUITO",
        },
    }
    
    # Common bigrams for each language
    COMMON_BIGRAMS: ClassVar[dict[str, set[str]]] = {
        "english": {
            "TH", "HE", "IN", "ER", "AN", "RE", "ON", "AT", "EN", "ND",
            "TI", "ES", "OR", "TE", "OF", "ED", "IS", "IT", "AL", "AR",
            "ST", "TO", "NT", "NG", "SE", "HA", "AS", "OU", "IO", "LE",
        },
        "french": {
            "ES", "LE", "DE", "EN", "RE", "NT", "ON", "ER", "OU", "AN",
            "TE", "AI", "SE", "IT", "ET", "ME", "IS", "QU", "LA", "NE",
            "LI", "EL", "UR", "EU", "CE", "TI", "EM", "PA", "RI", "NS",
        },
        "german": {
            "EN", "ER", "CH", "DE", "EI", "ND", "TE", "IN", "IE", "GE",
            "ES", "NE", "UN", "ST", "RE", "HE", "AN", "BE", "SE", "NG",
            "AU", "SS", "IC", "SC", "DI", "LE", "LI", "VE", "DA", "RI",
        },
        "spanish": {
            "DE", "EN", "ES", "EL", "LA", "OS", "UE", "AS", "ER", "RA",
            "AN", "AL", "AD", "ON", "AR", "RE", "SE", "NT", "OR", "DO",
            "CO", "TA", "CI", "TE", "IO", "IA", "ND", "QU", "NO", "ST",
        },
        "italian": {
            "RE", "ER", "ON", "DI", "TO", "EN", "TA", "TE", "AN", "AT",
            "NE", "NO", "RA", "LA", "TI", "DE", "CO", "LE", "NT", "IO",
            "RI", "IN", "AL", "AR", "SE", "SO", "SI", "EL", "CH", "ZI",
        },
        "portuguese": {
            "DE", "OS", "AS", "ES", "DO", "DA", "EM", "EN", "NO", "RA",
            "ER", "NT", "AN", "AD", "AO", "OR", "AR", "SE", "QU", "TE",
            "CO", "TA", "AL", "RE", "ST", "AM", "IA", "NA", "CA", "IS",
        },
    }
    
    def score_candidate(
        self,
        plaintext: str,
        cipher_type: str,
        key: str | dict,
        method: str = "unknown",
    ) -> ScoredCandidate:
        """
        Score a candidate against all languages and return the best match.
        
        Args:
            plaintext: The decrypted plaintext
            cipher_type: The cipher type used
            key: The key used
            method: The method used to generate this candidate
            
        Returns:
            ScoredCandidate with scoring information
        """
        # Normalize
        text = "".join(c for c in plaintext.upper() if c in self.ALPHABET)
        
        if not text:
            return ScoredCandidate(
                plaintext=plaintext,
                cipher_type=cipher_type,
                key=key,
                best_language="unknown",
                best_score=float("inf"),
                all_scores={},
                confidence=0.0,
                method=method,
            )
        
        # Score against each language
        all_scores: dict[str, LanguageScore] = {}
        best_language = "english"
        best_score = float("inf")
        
        for lang in self.LANGUAGE_FREQUENCIES:
            chi_sq = self._chi_squared(text, lang)
            bigram = self._bigram_score(text, lang)
            word = self._word_score(text, lang)
            
            # Combined score: chi-squared is primary, bigrams and words help
            # Lower is better
            combined = chi_sq - (bigram * 50) - (word * 100)
            
            all_scores[lang] = LanguageScore(
                language=lang,
                chi_squared=chi_sq,
                bigram_score=bigram,
                word_score=word,
                combined_score=combined,
            )
            
            if combined < best_score:
                best_score = combined
                best_language = lang
        
        # Calculate confidence based on best chi-squared
        best_chi = all_scores[best_language].chi_squared
        if best_chi < 40:
            confidence = 0.95  # Excellent match
        elif best_chi < 60:
            confidence = 0.85  # Very good match
        elif best_chi < 100:
            confidence = 0.70  # Good match
        elif best_chi < 150:
            confidence = 0.50  # Moderate match
        elif best_chi < 250:
            confidence = 0.30  # Weak match
        else:
            confidence = 0.10  # Poor match
        
        return ScoredCandidate(
            plaintext=plaintext,
            cipher_type=cipher_type,
            key=key,
            best_language=best_language,
            best_score=best_score,
            all_scores=all_scores,
            confidence=confidence,
            method=method,
        )
    
    def _chi_squared(self, text: str, language: str) -> float:
        """Calculate chi-squared against language frequencies."""
        n = len(text)
        if n == 0:
            return float("inf")
        
        freqs = self.LANGUAGE_FREQUENCIES.get(language, self.LANGUAGE_FREQUENCIES["english"])
        counter = Counter(text)
        chi_squared = 0.0
        
        for letter in self.ALPHABET:
            observed = counter.get(letter, 0)
            expected = (freqs.get(letter, 0.1) / 100) * n
            
            if expected > 0:
                chi_squared += ((observed - expected) ** 2) / expected
        
        return chi_squared
    
    def _bigram_score(self, text: str, language: str) -> float:
        """Score based on common bigram presence. Higher is better."""
        if len(text) < 2:
            return 0.0
        
        common = self.COMMON_BIGRAMS.get(language, self.COMMON_BIGRAMS["english"])
        total = len(text) - 1
        matches = sum(
            1 for i in range(total)
            if text[i:i+2] in common
        )
        
        return matches / total if total > 0 else 0.0
    
    def _word_score(self, text: str, language: str) -> float:
        """Score based on common word presence. Higher is better."""
        words = self.COMMON_WORDS.get(language, self.COMMON_WORDS["english"])
        
        # Check for word presence (rough - no spaces in ciphertext)
        found = 0
        for word in words:
            if len(word) >= 3 and word in text:
                found += 1
        
        # Normalize by number of words checked
        return found / len(words) if words else 0.0
    
    def score_all(
        self,
        candidates: list[tuple[str, str, str | dict, str]]
    ) -> list[ScoredCandidate]:
        """
        Score multiple candidates and return sorted by best score.
        
        Args:
            candidates: List of (plaintext, cipher_type, key, method) tuples
            
        Returns:
            List of ScoredCandidate sorted by best_score (ascending)
        """
        scored = [
            self.score_candidate(pt, ct, key, method)
            for pt, ct, key, method in candidates
        ]
        
        # Sort by best_score (lower is better)
        scored.sort(key=lambda x: x.best_score)
        
        return scored
