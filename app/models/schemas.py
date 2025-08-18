from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# ============================================================================
# Enums
# ============================================================================


class CipherFamily(str, Enum):
    """Supported cipher families."""

    MONOALPHABETIC = "monoalphabetic"
    POLYALPHABETIC = "polyalphabetic"
    TRANSPOSITION = "transposition"
    POLYGRAPHIC = "polygraphic"
    UNKNOWN = "unknown"


class CipherType(str, Enum):
    """Specific cipher types."""

    CAESAR = "caesar"
    ROT13 = "rot13"
    ATBASH = "atbash"
    SIMPLE_SUBSTITUTION = "simple_substitution"
    AFFINE = "affine"
    VIGENERE = "vigenere"
    BEAUFORT = "beaufort"
    AUTOKEY = "autokey"
    COLUMNAR = "columnar"
    RAIL_FENCE = "rail_fence"
    PLAYFAIR = "playfair"
    HILL = "hill"
    FOUR_SQUARE = "four_square"


# ============================================================================
# Statistics Schemas
# ============================================================================


class FrequencyData(BaseModel):
    """Character frequency data."""

    character: str
    count: int
    frequency: float = Field(ge=0.0, le=1.0)


class StatisticsProfile(BaseModel):
    """Complete statistical analysis profile."""

    model_config = ConfigDict(from_attributes=True)

    # Basic metrics
    length: int
    unique_chars: int

    # Frequency analysis
    character_frequencies: list[FrequencyData]
    bigram_frequencies: list[dict[str, Any]]
    trigram_frequencies: list[dict[str, Any]]

    # Statistical measures
    index_of_coincidence: float
    entropy: float
    chi_squared: float | None = None

    # Pattern detection
    repeated_sequences: list[dict[str, Any]] = []
    kasiski_distances: list[int] = []


# ============================================================================
# Cipher Detection Schemas
# ============================================================================


class CipherHypothesis(BaseModel):
    """A hypothesis about the cipher type."""

    cipher_family: CipherFamily
    cipher_type: CipherType | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: list[str] = []


# ============================================================================
# Decryption Schemas
# ============================================================================


class PlaintextCandidate(BaseModel):
    """A candidate plaintext with scoring."""

    plaintext: str
    score: float
    confidence: float = Field(ge=0.0, le=1.0)
    cipher_type: CipherType
    key: str | dict[str, Any]
    method: str


# ============================================================================
# Request Schemas
# ============================================================================


class AnalyzeRequest(BaseModel):
    """Request schema for /analyze endpoint."""

    ciphertext: str = Field(min_length=1, max_length=100_000)
    options: dict[str, Any] = Field(default_factory=dict)


class DecryptRequest(BaseModel):
    """Request schema for /decrypt endpoint."""

    ciphertext: str = Field(min_length=1, max_length=100_000)
    cipher_type: CipherType
    key: str | dict[str, Any] | None = None
    options: dict[str, Any] = Field(default_factory=dict)


class EncryptRequest(BaseModel):
    """Request schema for /encrypt endpoint."""

    plaintext: str = Field(min_length=1, max_length=100_000)
    cipher_type: CipherType
    key: str | dict[str, Any] | None = None
    options: dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# Response Schemas
# ============================================================================


class AnalyzeResponse(BaseModel):
    """Response schema for /analyze endpoint."""

    model_config = ConfigDict(from_attributes=True)

    statistics: StatisticsProfile
    suspected_ciphers: list[CipherHypothesis]
    plaintext_candidates: list[PlaintextCandidate]
    explanations: list[str]
    visual_data: dict[str, Any] = Field(default_factory=dict)


class DecryptResponse(BaseModel):
    """Response schema for /decrypt endpoint."""

    plaintext: str
    confidence: float
    key_used: str | dict[str, Any]
    explanation: str


class EncryptResponse(BaseModel):
    """Response schema for /encrypt endpoint."""

    ciphertext: str
    cipher_type: CipherType
    key_used: str | dict[str, Any]


class AnalysisHistoryItem(BaseModel):
    """Single history item."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    ciphertext_hash: str
    ciphertext_preview: str
    best_cipher: CipherType | None
    best_confidence: float | None
    created_at: datetime


class HistoryResponse(BaseModel):
    """Response schema for /history endpoint."""

    items: list[AnalysisHistoryItem]
    total: int
    page: int
    page_size: int


class AnalysisDetailResponse(BaseModel):
    """Full analysis detail response."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    ciphertext_hash: str
    ciphertext: str
    statistics: dict[str, Any]
    detected_language: str | None
    suspected_ciphers: list[dict[str, Any]]
    plaintext_candidates: list[dict[str, Any]]
    best_plaintext: str | None
    best_confidence: float | None
    parameters_used: dict[str, Any]
    explanations: list[str]
    created_at: datetime
    updated_at: datetime


# ============================================================================
# Error Schemas
# ============================================================================


class ErrorResponse(BaseModel):
    """Standard error response."""

    error: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)
