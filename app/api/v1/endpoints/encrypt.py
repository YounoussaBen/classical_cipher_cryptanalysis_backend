from fastapi import APIRouter, HTTPException, status

from app.dependencies import SettingsDep
from app.models.schemas import EncryptRequest, EncryptResponse, ErrorResponse
from app.services.engines.registry import EngineRegistry
from app.services.preprocessing.normalizer import TextNormalizer

router = APIRouter()


@router.post(
    "",
    response_model=EncryptResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid input"},
        404: {"model": ErrorResponse, "description": "Cipher type not supported"},
    },
    summary="Encrypt plaintext",
    description="Encrypt plaintext using a specified cipher type. Educational tool for generating test ciphertexts.",
)
async def encrypt_plaintext(
    request: EncryptRequest,
    settings: SettingsDep,
) -> EncryptResponse:
    """
    Encrypt plaintext with a specified cipher type.

    This is an educational tool for generating ciphertexts to test
    the analysis and decryption capabilities.
    """
    # Validate plaintext length
    if len(request.plaintext) > settings.max_ciphertext_length:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Plaintext exceeds maximum length of {settings.max_ciphertext_length}",
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
        normalized = normalizer.normalize(request.plaintext)

        # Generate key if not provided
        key = request.key
        if key is None:
            key = engine.generate_random_key()

        # Encrypt
        ciphertext = engine.encrypt(normalized, key)

        return EncryptResponse(
            ciphertext=ciphertext,
            cipher_type=request.cipher_type,
            key_used=key,
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Encryption failed: {str(e)}",
        )
