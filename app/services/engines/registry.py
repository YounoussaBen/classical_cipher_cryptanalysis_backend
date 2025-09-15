from typing import Type

from app.models.schemas import CipherFamily, CipherType
from app.services.engines.base import CipherEngine


class EngineRegistry:
    """
    Registry for cipher engines.

    Manages available cipher engines and provides lookup by type or family.
    """

    _engines: dict[CipherType, Type[CipherEngine]] = {}
    _instances: dict[CipherType, CipherEngine] = {}

    @classmethod
    def register(cls, engine_class: Type[CipherEngine]) -> Type[CipherEngine]:
        """
        Register a cipher engine class.

        Can be used as a decorator:
            @EngineRegistry.register
            class CaesarEngine(CipherEngine):
                ...

        Args:
            engine_class: The engine class to register

        Returns:
            The engine class (for decorator usage)
        """
        cls._engines[engine_class.cipher_type] = engine_class
        return engine_class

    def get_engine(self, cipher_type: CipherType) -> CipherEngine | None:
        """
        Get an engine instance for the specified cipher type.

        Args:
            cipher_type: The type of cipher

        Returns:
            Engine instance or None if not found
        """
        if cipher_type not in self._engines:
            return None

        # Lazy instantiation with caching
        if cipher_type not in self._instances:
            self._instances[cipher_type] = self._engines[cipher_type]()

        return self._instances[cipher_type]

    def get_engines_by_family(self, family: CipherFamily) -> list[CipherEngine]:
        """
        Get all engines belonging to a cipher family.

        Args:
            family: The cipher family

        Returns:
            List of engine instances
        """
        engines = []
        for cipher_type, engine_class in self._engines.items():
            if engine_class.cipher_family == family:
                engine = self.get_engine(cipher_type)
                if engine:
                    engines.append(engine)
        return engines

    def get_all_engines(self) -> list[CipherEngine]:
        """
        Get all registered engines.

        Returns:
            List of all engine instances
        """
        return [
            self.get_engine(cipher_type)
            for cipher_type in self._engines
            if self.get_engine(cipher_type) is not None
        ]

    @classmethod
    def list_registered(cls) -> list[CipherType]:
        """
        List all registered cipher types.

        Returns:
            List of registered cipher types
        """
        return list(cls._engines.keys())

    @classmethod
    def is_registered(cls, cipher_type: CipherType) -> bool:
        """
        Check if a cipher type is registered.

        Args:
            cipher_type: The cipher type to check

        Returns:
            True if registered
        """
        return cipher_type in cls._engines


# Import engines to trigger registration
def _load_engines() -> None:
    """Load all engine modules to trigger registration."""
    from app.services.engines.monoalphabetic import caesar  # noqa: F401


# Load engines when module is imported
_load_engines()
