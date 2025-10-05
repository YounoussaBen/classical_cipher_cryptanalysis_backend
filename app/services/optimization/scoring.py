import math
import string
from collections import Counter
from typing import ClassVar


class LanguageScorer:
    """
    Scores text based on how well it matches expected language patterns.

    Uses multiple scoring methods:
    - Chi-squared against letter frequencies
    - Quadgram scoring (4-letter sequences)
    - Common word detection
    """

    ALPHABET: ClassVar[str] = string.ascii_uppercase

    # English letter frequencies (percentage)
    ENGLISH_FREQ: ClassVar[dict[str, float]] = {
        "E": 12.70, "T": 9.06, "A": 8.17, "O": 7.51, "I": 6.97,
        "N": 6.75, "S": 6.33, "H": 6.09, "R": 5.99, "D": 4.25,
        "L": 4.03, "C": 2.78, "U": 2.76, "M": 2.41, "W": 2.36,
        "F": 2.23, "G": 2.02, "Y": 1.97, "P": 1.93, "B": 1.29,
        "V": 0.98, "K": 0.77, "J": 0.15, "X": 0.15, "Q": 0.10,
        "Z": 0.07,
    }

    # Common English words for quick detection
    COMMON_WORDS: ClassVar[set[str]] = {
        "THE", "AND", "FOR", "ARE", "BUT", "NOT", "YOU", "ALL",
        "CAN", "HAD", "HER", "WAS", "ONE", "OUR", "OUT", "HAS",
        "HIS", "HOW", "ITS", "MAY", "NEW", "NOW", "OLD", "SEE",
        "TWO", "WAY", "WHO", "BOY", "DID", "GET", "HIM", "LET",
        "PUT", "SAY", "SHE", "TOO", "USE", "THAT", "WITH", "HAVE",
        "THIS", "WILL", "YOUR", "FROM", "THEY", "BEEN", "CALL",
        "FIRST", "COULD", "PEOPLE", "ABOUT", "WOULD", "THEIR",
    }

    # Common bigrams for pattern matching
    COMMON_BIGRAMS: ClassVar[set[str]] = {
        "TH", "HE", "IN", "ER", "AN", "RE", "ON", "AT", "EN", "ND",
        "TI", "ES", "OR", "TE", "OF", "ED", "IS", "IT", "AL", "AR",
        "ST", "TO", "NT", "NG", "SE", "HA", "AS", "OU", "IO", "LE",
    }

    def __init__(self):
        """Initialize scorer with log probabilities for quadgrams."""
        # Simplified quadgram scoring using common patterns
        # In production, load from a file with actual counts
        self._quadgram_floor = -10.0  # Log probability floor

    def chi_squared_score(self, text: str) -> float:
        """
        Calculate chi-squared score against English frequencies.

        Lower score = better match to English.
        """
        text = "".join(c for c in text.upper() if c in self.ALPHABET)
        n = len(text)

        if n == 0:
            return float("inf")

        counter = Counter(text)
        chi_squared = 0.0

        for letter in self.ALPHABET:
            observed = counter.get(letter, 0)
            expected = (self.ENGLISH_FREQ[letter] / 100) * n

            if expected > 0:
                chi_squared += ((observed - expected) ** 2) / expected

        return chi_squared

    def bigram_score(self, text: str) -> float:
        """
        Score based on common bigram frequency.

        Higher score = more common bigrams = more likely English.
        """
        text = "".join(c for c in text.upper() if c in self.ALPHABET)

        if len(text) < 2:
            return 0.0

        common_count = 0
        total_bigrams = len(text) - 1

        for i in range(total_bigrams):
            bigram = text[i:i + 2]
            if bigram in self.COMMON_BIGRAMS:
                common_count += 1

        return common_count / total_bigrams if total_bigrams > 0 else 0.0

    def word_score(self, text: str) -> float:
        """
        Score based on presence of common English words.

        Higher score = more recognizable words.
        """
        text = text.upper()

        # Extract potential words (sequences of letters)
        words = []
        current_word = []

        for char in text:
            if char in self.ALPHABET:
                current_word.append(char)
            else:
                if current_word:
                    words.append("".join(current_word))
                    current_word = []
        if current_word:
            words.append("".join(current_word))

        if not words:
            return 0.0

        common_count = sum(1 for word in words if word in self.COMMON_WORDS)
        return common_count / len(words)

    def combined_score(self, text: str) -> float:
        """
        Combined scoring function for ranking candidates.

        Returns a score where lower = better (more likely English).
        """
        chi_sq = self.chi_squared_score(text)
        bigram = self.bigram_score(text)
        word = self.word_score(text)

        # Combine scores (chi-squared is inverted since lower is better)
        # Weight the components
        score = chi_sq - (bigram * 100) - (word * 200)

        return score

    def fitness(self, text: str) -> float:
        """
        Fitness function for optimization algorithms.

        Returns a value where higher = better (more fit).
        This is the negative of combined_score.
        """
        return -self.combined_score(text)

    def is_likely_english(self, text: str, threshold: float = 0.6) -> bool:
        """
        Quick check if text is likely English.

        Args:
            text: Text to check
            threshold: Minimum combined confidence threshold

        Returns:
            True if text appears to be English
        """
        chi_sq = self.chi_squared_score(text)
        bigram = self.bigram_score(text)
        word = self.word_score(text)

        # Simple heuristic combining all factors
        # Chi-squared below 100 is decent match
        # Bigram score above 0.15 suggests real text
        # Word score above 0.1 suggests real words

        chi_ok = chi_sq < 100
        bigram_ok = bigram > 0.1
        word_ok = word > 0.05

        return sum([chi_ok, bigram_ok, word_ok]) >= 2


class QuadgramScorer:
    """
    Quadgram-based scoring for more accurate language detection.

    Uses pre-computed log probabilities of 4-letter sequences.
    This is more accurate than simple frequency analysis for
    distinguishing real text from random characters.
    """

    def __init__(self, quadgram_file: str | None = None):
        """
        Initialize with quadgram data.

        Args:
            quadgram_file: Path to quadgram frequency file.
                          If None, uses simplified internal scoring.
        """
        self.quadgrams: dict[str, float] = {}
        self.floor = -10.0

        if quadgram_file:
            self._load_quadgrams(quadgram_file)
        else:
            self._use_simplified_scoring()

    def _load_quadgrams(self, filepath: str) -> None:
        """Load quadgram frequencies from file."""
        total = 0
        counts: dict[str, int] = {}

        try:
            with open(filepath) as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        quadgram, count = parts[0], int(parts[1])
                        counts[quadgram.upper()] = count
                        total += count

            # Convert to log probabilities
            for quadgram, count in counts.items():
                self.quadgrams[quadgram] = math.log10(count / total)

            # Set floor to slightly below minimum
            if self.quadgrams:
                self.floor = min(self.quadgrams.values()) - 1

        except FileNotFoundError:
            self._use_simplified_scoring()

    def _use_simplified_scoring(self) -> None:
        """Use simplified scoring when quadgram file not available."""
        # Common quadgrams with approximate log probabilities
        common = {
            "TION": -2.5, "THAT": -2.6, "THER": -2.8, "WITH": -2.9,
            "MENT": -3.0, "OULD": -3.1, "IGHT": -3.2, "HAVE": -3.2,
            "ATIO": -3.3, "FROM": -3.4, "EVER": -3.4, "OUGH": -3.5,
            "ANCE": -3.5, "ENCE": -3.5, "HICH": -3.6, "OULD": -3.6,
            "INGS": -3.7, "NESS": -3.7, "ALLY": -3.8, "THIS": -3.8,
        }
        self.quadgrams = common

    def score(self, text: str) -> float:
        """
        Score text based on quadgram frequencies.

        Higher score = more likely to be English text.

        Args:
            text: Text to score

        Returns:
            Log probability score (higher is better)
        """
        text = "".join(c for c in text.upper() if c.isalpha())

        if len(text) < 4:
            return self.floor * 10  # Very low score

        score = 0.0
        for i in range(len(text) - 3):
            quadgram = text[i:i + 4]
            score += self.quadgrams.get(quadgram, self.floor)

        # Normalize by length
        return score / (len(text) - 3)

    def fitness(self, text: str) -> float:
        """
        Fitness function for optimization.

        Returns score directly (higher is better).
        """
        return self.score(text)
