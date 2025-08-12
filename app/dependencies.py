from typing import Annotated, AsyncGenerator

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.db.session import get_db_session


# Settings dependency
SettingsDep = Annotated[Settings, Depends(get_settings)]

# Database session dependency
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Get database session."""
    async with get_db_session() as session:
        yield session

DbSessionDep = Annotated[AsyncSession, Depends(get_db)]
