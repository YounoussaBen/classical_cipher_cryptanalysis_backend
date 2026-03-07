from typing import Annotated

from fastapi import Depends

from app.core.config import Settings, get_settings

# Settings dependency
SettingsDep = Annotated[Settings, Depends(get_settings)]
