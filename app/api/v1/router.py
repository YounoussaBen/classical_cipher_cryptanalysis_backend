from fastapi import APIRouter

from app.api.v1.endpoints import analyze, decrypt, encrypt, history

api_router = APIRouter()

api_router.include_router(
    analyze.router,
    prefix="/analyze",
    tags=["Analysis"],
)

api_router.include_router(
    decrypt.router,
    prefix="/decrypt",
    tags=["Decryption"],
)

api_router.include_router(
    encrypt.router,
    prefix="/encrypt",
    tags=["Encryption"],
)

api_router.include_router(
    history.router,
    prefix="/history",
    tags=["History"],
)
