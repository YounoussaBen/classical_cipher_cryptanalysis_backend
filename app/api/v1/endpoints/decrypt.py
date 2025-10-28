from fastapi import APIRouter, HTTPException, status

from app.dependencies import SettingsDep
from app.models.schemas import DecryptRequest, DecryptResponse, ErrorResponse
from app.services.engines.registry import EngineRegistry
from app.services.preprocessing.normalizer import TextNormalizer

router = APIRouter()


@router.post(
    "",
    response_model=DecryptResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid input"},
        404: {"model": ErrorResponse, "description": "Cipher type not supported"},
        500: {"model": ErrorResponse, "description": "Decryption failed"},
    },
    summary="Decrypt ciphertext",
    description="Decrypt ciphertext using a specified cipher type and optional key.",
)
async def decrypt_ciphertext(
    request: DecryptRequest,
    settings: SettingsDep,
) -> DecryptResponse:
    """
    Decrypt ciphertext with a forced cipher type.

    If no key is provided, the engine will attempt to find the best key
    through analysis and optimization.
    """
    # Validate ciphertext length
    if len(request.ciphertext) > settings.max_ciphertext_length:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Ciphertext exceeds maximum length of {settings.max_ciphertext_length}",
        )

    # Get the appropriate engine
    registry = EngineRegistry()
    engine = registry.get_engine(request.cipher_type)

    if engine is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Cipher type '{request.cipher_type}' is not supported",
        )

    try:
        # Normalize input
        normalizer = TextNormalizer()
        normalized = normalizer.normalize(request.ciphertext)

        # Decrypt with provided key or find best key
        if request.key is not None:
            result = engine.decrypt_with_key(normalized, request.key)
        else:
            result = engine.find_key_and_decrypt(normalized, request.options)

        return DecryptResponse(
            plaintext=result.plaintext,
            confidence=result.confidence,
            key_used=result.key,
            explanation=result.explanation,
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Decryption failed: {str(e)}",
        )
