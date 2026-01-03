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


class DecryptionResultSchema(BaseModel):
    """The decryption result - the answer."""

    plaintext: str = Field(description="Raw decrypted plaintext")
    formatted_plaintext: str | None = Field(
        None, description="Human-readable formatted version with spacing/punctuation"
    )
    cipher_type: CipherType = Field(description="The cipher type that was used")
    key: str | dict[str, Any] = Field(description="The key used for decryption")
    detected_language: str | None = Field(
        None, description="Detected language of the plaintext"
    )
    confidence: float = Field(
        ge=0.0, le=1.0, description="Confidence in the decryption (0-1)"
    )
    explanation: str | None = Field(
        None, description="Explanation of how the cipher was broken"
    )


class ClassificationResult(BaseModel):
    """Cipher family classification result."""

    monoalphabetic_probability: float = Field(
        ge=0.0, le=1.0, description="Probability of monoalphabetic cipher"
    )
    polyalphabetic_probability: float = Field(
        ge=0.0, le=1.0, description="Probability of polyalphabetic cipher"
    )
    transposition_probability: float = Field(
        ge=0.0, le=1.0, description="Probability of transposition cipher"
    )
    classification_confidence: float = Field(
        ge=0.0, le=1.0, description="Confidence in the classification"
    )
    reasoning: list[str] = Field(
        default_factory=list, description="Reasoning for the classification"
    )


class AnalyzeResponse(BaseModel):
    """Response schema for /analyze endpoint - simplified black box output."""

    model_config = ConfigDict(from_attributes=True)

    # Statistics for frontend visualization
    statistics: StatisticsProfile
    
    # Classification that guided the analysis
    classification: ClassificationResult
    
    # THE answer - the decrypted result
    result: DecryptionResultSchema | None = Field(
        None, description="The decryption result, or None if decryption failed"
    )
    
    # Visual data for frontend charts
    visual_data: dict[str, Any] = Field(default_factory=dict)
    
    # Performance/debug info (optional)
    analysis_info: dict[str, Any] = Field(
        default_factory=dict, 
        description="Analysis metadata (candidates tried, early exit, etc.)"
    )


# Keep old schemas for backward compatibility but mark as deprecated
class AIAnalysisResult(BaseModel):
    """AI-enhanced analysis result for the best plaintext candidate.
    
    DEPRECATED: Use DecryptionResultSchema instead.
    """

    best_candidate_index: int | None = Field(
        None, description="0-based index of the AI-selected best candidate"
    )
    formatted_plaintext: str | None = Field(
        None, description="Human-readable formatted version of the best plaintext"
    )
    detected_language: str | None = Field(
        None, description="Language detected in the plaintext"
    )
    language_confidence: float | None = Field(
        None, ge=0.0, le=1.0, description="Confidence in language detection"
    )
    reasoning: str | None = Field(
        None, description="Brief explanation of why this candidate was selected"
    )


class DecryptResponse(BaseModel):
    """Response schema for /decrypt endpoint."""

    plaintext: str
    confidence: float
    key_used: str | dict[str, Any]
    explanation: str
    formatted_plaintext: str | None = None
    detected_language: str | None = None
    language_confidence: float | None = None


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
    """Full analysis detail response - matches AnalyzeResponse structure."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    ciphertext_hash: str
    ciphertext: str
    
    # Statistics for frontend visualization
    statistics: dict[str, Any]
    
    # Classification result
    classification: dict[str, Any] | None = None
    
    # The decryption result
    result: DecryptionResultSchema | None = None
    
    # Visual data for frontend charts
    visual_data: dict[str, Any] | None = None
    
    # Analysis info (performance metrics)
    analysis_info: dict[str, Any] | None = None
    
    # Metadata
    detected_language: str | None = None
    parameters_used: dict[str, Any] = Field(default_factory=dict)
    
    # Timestamps
    created_at: datetime
    updated_at: datetime
    
    # Legacy fields (kept for backward compatibility)
    suspected_ciphers: list[dict[str, Any]] = Field(default_factory=list)
    plaintext_candidates: list[dict[str, Any]] = Field(default_factory=list)
    best_plaintext: str | None = None
    best_confidence: float | None = None
    explanations: list[str] = Field(default_factory=list)


# ============================================================================
# Error Schemas
# ============================================================================


class ErrorResponse(BaseModel):
    """Standard error response."""

    error: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)
