import math
import string
from collections import Counter
from dataclasses import dataclass
from typing import ClassVar


@dataclass
class LanguageProfile:
    """Profile for a specific language with statistical patterns."""
    name: str
    code: str
    frequencies: dict[str, float]
    common_words: set[str]
    common_bigrams: set[str]
    expected_ioc: float


class LanguageScorer:
    """
    Scores text based on how well it matches expected language patterns.

    Supports multiple languages: English, French, German, Spanish.
    Uses multiple scoring methods:
    - Chi-squared against letter frequencies
    - Quadgram scoring (4-letter sequences)
    - Common word detection
    - Common bigram detection
    """

    ALPHABET: ClassVar[str] = string.ascii_uppercase

    # Language profiles with frequencies, words, and bigrams
    LANGUAGE_PROFILES: ClassVar[dict[str, LanguageProfile]] = {
        "english": LanguageProfile(
            name="English",
            code="en",
            frequencies={
                "E": 12.70, "T": 9.06, "A": 8.17, "O": 7.51, "I": 6.97,
                "N": 6.75, "S": 6.33, "H": 6.09, "R": 5.99, "D": 4.25,
                "L": 4.03, "C": 2.78, "U": 2.76, "M": 2.41, "W": 2.36,
                "F": 2.23, "G": 2.02, "Y": 1.97, "P": 1.93, "B": 1.29,
                "V": 0.98, "K": 0.77, "J": 0.15, "X": 0.15, "Q": 0.10,
                "Z": 0.07,
            },
            common_words={
                "THE", "AND", "FOR", "ARE", "BUT", "NOT", "YOU", "ALL",
                "CAN", "HAD", "HER", "WAS", "ONE", "OUR", "OUT", "HAS",
                "HIS", "HOW", "ITS", "MAY", "NEW", "NOW", "OLD", "SEE",
                "TWO", "WAY", "WHO", "BOY", "DID", "GET", "HIM", "LET",
                "PUT", "SAY", "SHE", "TOO", "USE", "THAT", "WITH", "HAVE",
                "THIS", "WILL", "YOUR", "FROM", "THEY", "BEEN", "CALL",
                "FIRST", "COULD", "PEOPLE", "ABOUT", "WOULD", "THEIR",
            },
            common_bigrams={
                "TH", "HE", "IN", "ER", "AN", "RE", "ON", "AT", "EN", "ND",
                "TI", "ES", "OR", "TE", "OF", "ED", "IS", "IT", "AL", "AR",
                "ST", "TO", "NT", "NG", "SE", "HA", "AS", "OU", "IO", "LE",
            },
            expected_ioc=0.0667,
        ),
        "french": LanguageProfile(
            name="French",
            code="fr",
            frequencies={
                "E": 14.72, "A": 7.64, "S": 7.95, "I": 7.53, "T": 7.24,
                "N": 7.10, "R": 6.55, "U": 6.31, "L": 5.46, "O": 5.27,
                "D": 3.67, "C": 3.18, "M": 2.97, "P": 2.52, "V": 1.83,
                "Q": 1.36, "F": 1.07, "B": 0.90, "G": 0.87, "H": 0.74,
                "J": 0.55, "X": 0.39, "Y": 0.31, "Z": 0.14, "W": 0.05,
                "K": 0.05,
            },
            common_words={
                # Common French words
                "LE", "LA", "LES", "DE", "DES", "DU", "UN", "UNE",
                "ET", "EST", "EN", "QUE", "QUI", "IL", "ELLE", "ON",
                "NE", "PAS", "PLUS", "DANS", "CE", "CETTE", "CES",
                "POUR", "PAR", "SUR", "AVEC", "SANS", "SOUS", "MAIS",
                "OU", "AU", "AUX", "SON", "SA", "SES", "MON", "MA",
                "MES", "TON", "TA", "TES", "NOTRE", "VOTRE", "LEUR",
                "NOUS", "VOUS", "ILS", "ELLES", "SONT", "ETRE", "AVOIR",
                "FAIT", "FAIRE", "PEUT", "TOUT", "TOUS", "TOUTE", "BIEN",
                "COMME", "AUSSI", "AUTRE", "APRES", "AVANT", "MEME",
                "TRES", "TEMPS", "JOUR", "HOMME", "FEMME", "MONDE",
            },
            common_bigrams={
                "ES", "LE", "DE", "EN", "RE", "NT", "ON", "ER", "OU",
                "AN", "TE", "AI", "SE", "IT", "ET", "ME", "IS", "QU",
                "LA", "NE", "LI", "EL", "UR", "EU", "CE", "TI", "EM",
                "PA", "RI", "NS", "SS", "LL", "AU", "CO", "TR", "RA",
            },
            expected_ioc=0.0778,
        ),
        "german": LanguageProfile(
            name="German",
            code="de",
            frequencies={
                "E": 16.40, "N": 9.78, "I": 7.55, "S": 7.27, "R": 7.00,
                "A": 6.51, "T": 6.15, "D": 5.08, "H": 4.76, "U": 4.35,
                "L": 3.44, "C": 3.06, "G": 3.01, "M": 2.53, "O": 2.51,
                "B": 1.89, "W": 1.89, "F": 1.66, "K": 1.21, "Z": 1.13,
                "P": 0.79, "V": 0.67, "J": 0.27, "Y": 0.04, "X": 0.03,
                "Q": 0.02,
            },
            common_words={
                "DER", "DIE", "DAS", "UND", "IST", "VON", "ZU", "DEN",
                "MIT", "SICH", "DES", "AUF", "FUR", "NICHT", "ALS",
                "AUCH", "ES", "AN", "WIR", "HAT", "AUS", "ER", "AM",
                "EINE", "EINER", "EINEM", "EINEN", "WIE", "NACH", "IM",
                "SIND", "NUR", "NOCH", "KANN", "BEI", "ABER", "WENN",
                "MAN", "MEHR", "ODER", "WAR", "SEIN", "SCHON", "SO",
                "WIRD", "SEHR", "DIESE", "NUN", "UNTER", "MUSS",
            },
            common_bigrams={
                "EN", "ER", "CH", "DE", "EI", "ND", "TE", "IN", "IE",
                "GE", "ES", "NE", "UN", "ST", "RE", "HE", "AN", "BE",
                "SE", "NG", "AU", "SS", "IC", "SC", "DI", "LE", "LI",
            },
            expected_ioc=0.0762,
        ),
        "spanish": LanguageProfile(
            name="Spanish",
            code="es",
            frequencies={
                "E": 13.68, "A": 12.53, "O": 8.68, "S": 7.98, "R": 6.87,
                "N": 6.71, "I": 6.25, "D": 5.86, "L": 4.97, "C": 4.68,
                "T": 4.63, "U": 3.93, "M": 3.16, "P": 2.51, "B": 1.42,
                "G": 1.01, "V": 0.90, "Y": 0.90, "Q": 0.88, "H": 0.70,
                "F": 0.69, "Z": 0.52, "J": 0.44, "X": 0.22, "W": 0.02,
                "K": 0.01,
            },
            common_words={
                "DE", "LA", "QUE", "EL", "EN", "LOS", "DEL", "SE",
                "LAS", "POR", "UN", "PARA", "CON", "NO", "UNA", "SU",
                "AL", "ES", "LO", "COMO", "MAS", "PERO", "SUS", "LE",
                "YA", "HA", "ERA", "SIDO", "ESTE", "ESTA", "DESDE",
                "SIN", "ENTRE", "CUANDO", "TODO", "SER", "SON", "DOS",
                "TIENE", "HASTA", "HACE", "PUEDE", "TODOS", "ASI",
            },
            common_bigrams={
                "DE", "EN", "ES", "EL", "LA", "OS", "UE", "AS", "ER",
                "RA", "AN", "AL", "AD", "ON", "AR", "RE", "SE", "NT",
                "OR", "DO", "CO", "TA", "CI", "TE", "IO", "IA", "ND",
            },
            expected_ioc=0.0775,
        ),
    }

    # Backwards-compatible class-level aliases for default (English)
    ENGLISH_FREQ: ClassVar[dict[str, float]] = LANGUAGE_PROFILES["english"].frequencies
    COMMON_WORDS: ClassVar[set[str]] = LANGUAGE_PROFILES["english"].common_words
    COMMON_BIGRAMS: ClassVar[set[str]] = LANGUAGE_PROFILES["english"].common_bigrams

    def __init__(self, language: str = "english"):
        """
        Initialize scorer for a specific language.

        Args:
            language: Language to score against ('english', 'french', 'german', 'spanish')
        """
        self._language = language.lower()
        if self._language not in self.LANGUAGE_PROFILES:
            self._language = "english"

        self._profile = self.LANGUAGE_PROFILES[self._language]
        self._quadgram_floor = -10.0  # Log probability floor

    @classmethod
    def detect_likely_language_from_ioc(cls, ioc: float) -> list[str]:
        """
        Suggest likely languages based on observed IoC.

        Higher IoC (0.07+) suggests French/Spanish/German.
        Medium IoC (~0.067) suggests English.
        Low IoC (<0.05) suggests polyalphabetic cipher or random.

        Args:
            ioc: Observed index of coincidence

        Returns:
            List of likely language codes, ordered by likelihood
        """
        if ioc < 0.05:
            # Likely polyalphabetic or random text
            return ["english"]  # Default for cryptanalysis attempts

        # Calculate distance from each language's expected IoC
        distances = []
        for lang_key, profile in cls.LANGUAGE_PROFILES.items():
            distance = abs(ioc - profile.expected_ioc)
            distances.append((lang_key, distance, profile.expected_ioc))

        # Sort by distance (closest first)
        distances.sort(key=lambda x: x[1])

        return [lang for lang, _, _ in distances]

    @classmethod
    def create_multi_language_scorer(cls, ioc: float | None = None) -> list["LanguageScorer"]:
        """
        Create scorers for all likely languages based on IoC.

        Args:
            ioc: Observed IoC (if known). If None, returns all languages.

        Returns:
            List of LanguageScorer instances for likely languages
        """
        if ioc is not None:
            languages = cls.detect_likely_language_from_ioc(ioc)
        else:
            languages = list(cls.LANGUAGE_PROFILES.keys())

        return [cls(lang) for lang in languages]

    @property
    def language(self) -> str:
        """Get the current language."""
        return self._language

    @property
    def language_name(self) -> str:
        """Get the human-readable language name."""
        return self._profile.name

    def chi_squared_score(self, text: str) -> float:
        """
        Calculate chi-squared score against the configured language frequencies.

        Lower score = better match to the language.
        """
        text = "".join(c for c in text.upper() if c in self.ALPHABET)
        n = len(text)

        if n == 0:
            return float("inf")

        counter = Counter(text)
        chi_squared = 0.0

        for letter in self.ALPHABET:
            observed = counter.get(letter, 0)
            expected_freq = self._profile.frequencies.get(letter, 0.1)
            expected = (expected_freq / 100) * n

            if expected > 0:
                chi_squared += ((observed - expected) ** 2) / expected

        return chi_squared

    def bigram_score(self, text: str) -> float:
        """
        Score based on common bigram frequency for the configured language.

        Higher score = more common bigrams = more likely real text.
        """
        text = "".join(c for c in text.upper() if c in self.ALPHABET)

        if len(text) < 2:
            return 0.0

        common_count = 0
        total_bigrams = len(text) - 1

        for i in range(total_bigrams):
            bigram = text[i:i + 2]
            if bigram in self._profile.common_bigrams:
                common_count += 1

        return common_count / total_bigrams if total_bigrams > 0 else 0.0

    def word_score(self, text: str) -> float:
        """
        Score based on presence of common words in the configured language.

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

        common_count = sum(1 for word in words if word in self._profile.common_words)
        return common_count / len(words)

    def combined_score(self, text: str) -> float:
        """
        Combined scoring function for ranking candidates.

        Returns a score where lower = better (more likely to be the configured language).
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

    def is_likely_language(self, text: str, threshold: float = 0.6) -> bool:
        """
        Quick check if text is likely the configured language.

        Args:
            text: Text to check
            threshold: Minimum combined confidence threshold

        Returns:
            True if text appears to be the configured language
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

    def is_likely_english(self, text: str, threshold: float = 0.6) -> bool:
        """Backwards compatible alias for is_likely_language with English."""
        if self._language != "english":
            english_scorer = LanguageScorer("english")
            return english_scorer.is_likely_language(text, threshold)
        return self.is_likely_language(text, threshold)


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


class MultiLanguageScorer:
    """
    Scorer that tries all supported languages and returns the best result.

    This is useful for cryptanalysis when you don't know the plaintext language
    in advance. It will score against all languages and return the best match.
    """

    def __init__(self, ioc: float | None = None, languages: list[str] | None = None):
        """
        Initialize with optional IoC hint or explicit language list.

        Args:
            ioc: Observed IoC to prioritize languages (optional)
            languages: Explicit list of languages to try (optional)
        """
        if languages:
            self._languages = [
                lang for lang in languages
                if lang in LanguageScorer.LANGUAGE_PROFILES
            ]
        elif ioc is not None:
            self._languages = LanguageScorer.detect_likely_language_from_ioc(ioc)
        else:
            self._languages = list(LanguageScorer.LANGUAGE_PROFILES.keys())

        self._scorers = {lang: LanguageScorer(lang) for lang in self._languages}

    def score_all_languages(self, text: str) -> dict[str, float]:
        """
        Score text against all configured languages.

        Args:
            text: Text to score

        Returns:
            Dictionary mapping language code to chi-squared score (lower is better)
        """
        return {
            lang: scorer.chi_squared_score(text)
            for lang, scorer in self._scorers.items()
        }

    def best_language(self, text: str) -> tuple[str, float]:
        """
        Determine the best matching language for the text.

        Args:
            text: Text to analyze

        Returns:
            Tuple of (language_code, chi_squared_score)
        """
        scores = self.score_all_languages(text)
        best_lang = min(scores, key=scores.get)
        return best_lang, scores[best_lang]

    def combined_score(self, text: str) -> float:
        """
        Return the best combined score across all languages.

        This picks the language with the best match and returns that score.
        Lower is better.
        """
        best_scores = []
        for scorer in self._scorers.values():
            best_scores.append(scorer.combined_score(text))
        return min(best_scores) if best_scores else float("inf")

    def fitness(self, text: str) -> float:
        """
        Fitness function that uses the best-matching language.

        Returns the highest fitness (lowest combined_score) across all languages.
        """
        return -self.combined_score(text)

    def score_with_language_detection(self, text: str) -> dict:
        """
        Score text and detect the most likely language.

        Args:
            text: Text to score

        Returns:
            Dictionary with:
            - best_language: Most likely language code
            - best_language_name: Human-readable language name
            - chi_squared: Chi-squared score for best language
            - combined_score: Combined score for best language
            - all_scores: Scores for all languages
        """
        all_scores = {}
        for lang, scorer in self._scorers.items():
            all_scores[lang] = {
                "chi_squared": scorer.chi_squared_score(text),
                "combined": scorer.combined_score(text),
                "bigram": scorer.bigram_score(text),
                "word": scorer.word_score(text),
            }

        # Find best language by combined score (lower is better)
        best_lang = min(all_scores, key=lambda l: all_scores[l]["combined"])
        best_scorer = self._scorers[best_lang]

        return {
            "best_language": best_lang,
            "best_language_name": best_scorer.language_name,
            "chi_squared": all_scores[best_lang]["chi_squared"],
            "combined_score": all_scores[best_lang]["combined"],
            "all_scores": all_scores,
        }
