import re
import string
import unicodedata
from dataclasses import dataclass
from enum import Enum


class NormalizationMode(str, Enum):
    """Text normalization modes."""

    STRICT = "strict"  # Letters only, uppercase
    PRESERVE_CASE = "preserve_case"  # Letters only, preserve case
    PRESERVE_SPACES = "preserve_spaces"  # Letters and spaces
    PRESERVE_PUNCTUATION = "preserve_punctuation"  # Letters, spaces, punctuation
    RAW = "raw"  # Minimal normalization


@dataclass
class NormalizedText:
    """Result of text normalization."""

    text: str
    original: str
    alphabet: str
    removed_chars: dict[str, int]
    mode: NormalizationMode


class TextNormalizer:
    """
    Normalizes text for cryptanalysis.

    Handles:
    - Unicode normalization (NFKC)
    - Case conversion
    - Non-alphabetic character removal
    - Alphabet detection
    """

    ALPHABETS = {
        "english": string.ascii_uppercase,
        "extended": string.ascii_uppercase + string.digits,
        "full": string.ascii_uppercase + string.digits + " .,!?;:'\"()-",
    }

    def __init__(self, alphabet: str = "english"):
        """Initialize normalizer with specified alphabet."""
        self.alphabet = self.ALPHABETS.get(alphabet, alphabet.upper())

    def normalize(
        self,
        text: str,
        mode: NormalizationMode = NormalizationMode.STRICT,
    ) -> str:
        """
        Normalize text for cryptanalysis.

        Args:
            text: Input text to normalize
            mode: Normalization mode

        Returns:
            Normalized text string
        """
        result = self.normalize_full(text, mode)
        return result.text

    def normalize_full(
        self,
        text: str,
        mode: NormalizationMode = NormalizationMode.STRICT,
    ) -> NormalizedText:
        """
        Normalize text and return detailed result.

        Args:
            text: Input text to normalize
            mode: Normalization mode

        Returns:
            NormalizedText with details about the normalization
        """
        original = text
        removed_chars: dict[str, int] = {}

        # Step 1: Unicode normalization
        text = unicodedata.normalize("NFKC", text)

        # Step 2: Apply mode-specific processing
        if mode == NormalizationMode.RAW:
            # Minimal processing
            normalized = text.upper()
        elif mode == NormalizationMode.PRESERVE_PUNCTUATION:
            # Keep letters, digits, spaces, and common punctuation
            normalized = self._filter_chars(
                text.upper(),
                string.ascii_uppercase + string.digits + " .,!?;:'\"()-",
                removed_chars,
            )
        elif mode == NormalizationMode.PRESERVE_SPACES:
            # Keep letters and spaces
            normalized = self._filter_chars(
                text.upper(),
                string.ascii_uppercase + " ",
                removed_chars,
            )
        elif mode == NormalizationMode.PRESERVE_CASE:
            # Keep letters only, preserve case
            normalized = self._filter_chars(
                text,
                string.ascii_letters,
                removed_chars,
            )
        else:  # STRICT mode
            # Letters only, uppercase
            normalized = self._filter_chars(
                text.upper(),
                string.ascii_uppercase,
                removed_chars,
            )

        return NormalizedText(
            text=normalized,
            original=original,
            alphabet=self.alphabet,
            removed_chars=removed_chars,
            mode=mode,
        )

    def _filter_chars(
        self,
        text: str,
        allowed: str,
        removed_chars: dict[str, int],
    ) -> str:
        """Filter text to only allowed characters, tracking removed ones."""
        result = []
        allowed_set = set(allowed)

        for char in text:
            if char in allowed_set:
                result.append(char)
            else:
                removed_chars[char] = removed_chars.get(char, 0) + 1

        return "".join(result)

    def detect_alphabet(self, text: str) -> str:
        """
        Detect the alphabet used in the text.

        Returns:
            Name of detected alphabet or 'custom'
        """
        text_upper = text.upper()
        unique_chars = set(c for c in text_upper if c.isalpha())

        # Check if it's standard English
        if unique_chars.issubset(set(string.ascii_uppercase)):
            return "english"

        # Check for extended (includes digits)
        if unique_chars.issubset(set(string.ascii_uppercase + string.digits)):
            return "extended"

        return "custom"

    def strip_whitespace(self, text: str) -> str:
        """Remove all whitespace from text."""
        return re.sub(r"\s+", "", text)

    def collapse_whitespace(self, text: str) -> str:
        """Collapse multiple whitespace characters to single space."""
        return re.sub(r"\s+", " ", text).strip()
