"""
Registro centralizado de parsers RMM.
Gestiona el descubrimiento y selección automática de parsers.
"""

from __future__ import annotations
from typing import Optional

from ..models.base import RMMType
from .base import BaseParser


class ParserRegistry:
    """
    Registro singleton de parsers disponibles.
    Los parsers se auto-registran al importar su módulo.
    """

    _parsers: dict[RMMType, BaseParser] = {}

    @classmethod
    def register(cls, parser: BaseParser) -> None:
        """Registra una instancia de parser."""
        cls._parsers[parser.rmm_type] = parser

    @classmethod
    def get(cls, rmm_type: RMMType) -> Optional[BaseParser]:
        """Obtiene el parser para un tipo de RMM."""
        return cls._parsers.get(rmm_type)

    @classmethod
    def get_all(cls) -> list[BaseParser]:
        """Retorna todos los parsers registrados."""
        return list(cls._parsers.values())

    @classmethod
    def get_for_file(cls, filepath: str) -> Optional[BaseParser]:
        """Busca el parser adecuado para un archivo dado."""
        for parser in cls._parsers.values():
            if parser.can_parse(filepath):
                return parser
        return None

    @classmethod
    def get_by_names(cls, names: list[str]) -> list[BaseParser]:
        """Filtra parsers por nombres de RMM (case-insensitive)."""
        names_lower = [n.lower().strip() for n in names]
        result = []
        for rmm_type, parser in cls._parsers.items():
            if rmm_type.value.lower() in names_lower:
                result.append(parser)
        return result

    @classmethod
    def available_rmms(cls) -> list[str]:
        """Lista de nombres de RMMs disponibles."""
        return [t.value for t in cls._parsers.keys()]

    @classmethod
    def file_patterns(cls) -> dict[RMMType, list[str]]:
        """Retorna todos los patrones de archivo de todos los parsers."""
        return {
            rmm_type: parser.file_patterns()
            for rmm_type, parser in cls._parsers.items()
        }


def _auto_register() -> None:
    """Importa todos los módulos de parsers para que se auto-registren."""
    try:
        from .anydesk import parser as _  # noqa: F401
    except ImportError:
        pass
    try:
        from .teamviewer import parser as _  # noqa: F401
    except ImportError:
        pass
    try:
        from .screenconnect import parser as _  # noqa: F401
    except ImportError:
        pass
    try:
        from .chrome_remote_desktop import parser as _  # noqa: F401
    except ImportError:
        pass
    try:
        from .splashtop import parser as _  # noqa: F401
    except ImportError:
        pass
    try:
        from .rustdesk import parser as _  # noqa: F401
    except ImportError:
        pass


_auto_register()
