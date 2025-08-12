from typing import Any


class CryptanalysisError(Exception):
    """Base exception for all cryptanalysis errors."""

    def __init__(self, message: str, details: dict[str, Any] | None = None):
        self.message = message
        self.details = details or {}
        super().__init__(self.message)


class ValidationError(CryptanalysisError):
    """Raised when input validation fails."""

    pass


class CiphertextTooLongError(ValidationError):
    """Raised when ciphertext exceeds maximum length."""

    def __init__(self, length: int, max_length: int):
        super().__init__(
            f"Ciphertext length {length} exceeds maximum {max_length}",
            {"length": length, "max_length": max_length},
        )


class InvalidCiphertextError(ValidationError):
    """Raised when ciphertext format is invalid."""

    pass


class EngineError(CryptanalysisError):
    """Base exception for cipher engine errors."""

    pass


class EngineNotFoundError(EngineError):
    """Raised when requested cipher engine is not found."""

    def __init__(self, engine_name: str):
        super().__init__(
            f"Cipher engine '{engine_name}' not found",
            {"engine_name": engine_name},
        )


class DecryptionError(EngineError):
    """Raised when decryption fails."""

    pass


class TimeoutError(EngineError):
    """Raised when engine operation times out."""

    def __init__(self, engine_name: str, timeout: float):
        super().__init__(
            f"Engine '{engine_name}' timed out after {timeout}s",
            {"engine_name": engine_name, "timeout": timeout},
        )


class AnalysisError(CryptanalysisError):
    """Raised when statistical analysis fails."""

    pass
